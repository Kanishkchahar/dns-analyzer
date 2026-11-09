"""Native Non-Blocking TLS & HTTPS Security Auditor.

Audits X.509 certificate validity, expiration, SAN wildcard coverage,
negotiated TLS protocol version, HTTP-to-HTTPS redirection, and essential
web security headers (HSTS, CSP, X-Frame-Options) without external binaries.
Hardened with strict SSRF controls, direct IP binding, and validated redirects.
"""

import asyncio
from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse
import httpcore
import httpx

from app.models import Finding
from app.work_budget import ScanBudgetExhausted, ScanWorkBudget
from app.http_config import outbound_http_headers

logger = logging.getLogger(__name__)
CERT_EXPIRY_WARNING_DAYS = 30


class PinnedIPBackend(httpcore.AsyncNetworkBackend):
    """Network backend that pins TCP connections directly to a validated safe IP, eliminating DNS rebinding."""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._backend.connect_tcp(
            self.target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._backend.connect_unix_socket(
            path,
            timeout=timeout,
            socket_options=socket_options,
        )

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _PinnedResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any):
        self._stream = stream

    async def __aiter__(self):
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close:
            await close()


class PinnedIPTransport(httpx.AsyncBaseTransport):
    """HTTPX transport that connects to a prevalidated IP and keeps URL-host TLS identity."""

    def __init__(
        self,
        target_ip: str,
        *,
        verify: bool | str | ssl.SSLContext = True,
        limits: httpx.Limits | None = None,
        http1: bool = True,
        http2: bool = False,
    ):
        self.target_ip = target_ip
        if isinstance(verify, ssl.SSLContext):
            ssl_context = verify
        elif isinstance(verify, str):
            ssl_context = ssl.create_default_context(cafile=verify)
        elif verify:
            ssl_context = ssl.create_default_context()
        else:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        limits = limits or httpx.Limits()
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            network_backend=PinnedIPBackend(target_ip),
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = await self._pool.handle_async_request(core_request)
        except httpcore.HTTPError as exc:
            raise httpx.TransportError(str(exc), request=request) from exc
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_PinnedResponseStream(response.stream),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()



def is_safe_ip(ip_str: str) -> tuple[bool, str]:
    """Validate that an IP is a safe, routable public address (SSRF Defense)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, "Invalid IP address syntax"

    if ip.is_loopback:
        return False, "Loopback address (127.0.0.0/8, ::1) blocked"
    if ip.is_private:
        return False, "Private network address (RFC 1918 / ULA) blocked"
    if ip.is_link_local:
        return False, "Link-local address (169.254.0.0/16, fe80::/10) blocked"
    if ip.is_multicast:
        return False, "Multicast address blocked"
    if ip.is_reserved or ip.is_unspecified:
        return False, "Reserved or unspecified address blocked"
    if str(ip) == "169.254.169.254":
        return False, "Cloud instance metadata endpoint blocked"
    if not ip.is_global:
        return False, "Non-globally routable address (CGNAT, documentation, or reserved range) blocked"

    return True, "Public IP"


async def resolve_and_verify_all_ips(hostname: str, port: int = 443, resolver: Any = None) -> tuple[bool, list[str], str]:
    """Resolve hostname once and verify that all resolved IPs are public and safe (reject mixed answers)."""
    try:
        literal_ip = ipaddress.ip_address(hostname.strip().strip("[]"))
    except ValueError:
        literal_ip = None
    if literal_ip is not None:
        address = str(literal_ip)
        safe, reason = is_safe_ip(address)
        return safe, [address], f"Unsafe address '{address}': {reason}" if not safe else "All resolved addresses are public"
    normalized_host = hostname.strip().lower().rstrip(".")
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        return False, [], "Unsafe hostname: localhost names are blocked"

    if resolver is not None:
        budget_exhausted = False
        async def get_addresses(rdtype: str) -> list[str]:
            nonlocal budget_exhausted
            try:
                answer = await resolver.resolve(hostname, rdtype)
                return [str(item.address) for item in answer if hasattr(item, "address")]
            except ScanBudgetExhausted:
                budget_exhausted = True
                return []
            except Exception:
                return []
        answers = await asyncio.gather(get_addresses("A"), get_addresses("AAAA"))
        all_ips = list(dict.fromkeys(answers[0] + answers[1]))
        if budget_exhausted:
            return False, [], "DNS query budget exhausted; resolution is inconclusive."
        if not all_ips:
            return False, [], "Hostname did not resolve or query budget was unavailable"
    else:
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            if not addr_info:
                return False, [], "Hostname did not resolve to any addresses"
            all_ips = list(dict.fromkeys(info[4][0] for info in addr_info))
        except Exception:
            return False, [], "Resolution failed; result is inconclusive."

    for ip in all_ips:
        safe, reason = is_safe_ip(ip)
        if not safe:
            return False, all_ips, f"Unsafe address '{ip}': {reason}"

    return True, all_ips, "All resolved addresses are public"


def match_san_hostname(hostname: str, san_list: list[str]) -> bool:
    """Check if *hostname* matches any entry in *san_list* including wildcards (*.domain)."""
    norm_host = hostname.lower().rstrip(".")
    for pattern in san_list:
        norm_pat = pattern.lower().rstrip(".")
        if norm_pat.startswith("*."):
            # RFC 6125 wildcard matching: *.example.com matches sub.example.com, but not deep.sub.example.com
            suffix = norm_pat[2:]
            if norm_host.endswith(suffix):
                prefix = norm_host[:-len(suffix)]
                if prefix.endswith(".") and "." not in prefix[:-1]:
                    return True
        elif norm_host == norm_pat:
            return True
    return False


def parse_hsts(headers: list[str]) -> dict[str, Any]:
    """Parse HSTS conservatively; a header only activates with positive max-age."""
    if not headers:
        return {"status": "missing", "active": False, "max_age": None, "include_subdomains": False}
    max_age_values: list[str] = []
    include_subdomains = False
    malformed = False
    for header in headers:
        for raw_directive in header.split(";"):
            directive = raw_directive.strip()
            if not directive:
                continue
            name, separator, value = directive.partition("=")
            name = name.strip().lower()
            value = value.strip().strip('"')
            if name == "max-age":
                if not separator:
                    malformed = True
                max_age_values.append(value)
            elif name == "includesubdomains":
                if separator:
                    malformed = True
                include_subdomains = True
    if malformed or len(max_age_values) != 1 or not re.fullmatch(r"[0-9]+", max_age_values[0] if max_age_values else ""):
        return {"status": "invalid", "active": False, "max_age": None, "include_subdomains": include_subdomains}
    try:
        max_age = int(max_age_values[0])
    except ValueError:
        # Python limits conversion of very long integer strings. Treat such
        # headers as malformed instead of letting a remote header fail a scan.
        return {"status": "invalid", "active": False, "max_age": None, "include_subdomains": include_subdomains}
    if max_age == 0:
        return {"status": "disabled", "active": False, "max_age": 0, "include_subdomains": include_subdomains}
    return {"status": "active", "active": True, "max_age": max_age, "include_subdomains": include_subdomains}


def parse_security_txt(body: bytes, now: datetime | None = None) -> dict[str, Any]:
    """Validate required security.txt fields and expiration without retaining raw content."""
    text = body.decode("utf-8", errors="replace")
    fields: dict[str, list[str]] = {}
    malformed = "\ufffd" in text
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            malformed = True
            continue
        fields.setdefault(key.strip().lower(), []).append(value.strip())

    contacts = fields.get("contact", [])
    expires = fields.get("expires", [])
    if len(expires) != 1:
        malformed = True
    expiry = None
    if len(expires) == 1:
        raw_expiry = expires[0]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", raw_expiry):
            malformed = True
        else:
            try:
                normalized_expiry = raw_expiry[:-1] + "+00:00" if raw_expiry.endswith(("Z", "z")) else raw_expiry
                expiry = datetime.fromisoformat(normalized_expiry)
            except ValueError:
                malformed = True

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    expired = expiry is not None and expiry <= current.astimezone(expiry.tzinfo)
    status = "malformed" if malformed or not contacts else "expired" if expired else "valid"
    return {"status": status, "contact_count": len(contacts), "expires": expires[0] if len(expires) == 1 else None}


def review_csp(policy: str | None) -> list[str]:
    """Return concise risk notes for common CSP weaknesses; this is not a full CSP evaluator."""
    if not policy:
        return []
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = [token.lower() for token in tokens[1:]]
    risks: list[str] = []
    script_sources = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_sources:
        risks.append("script policy allows 'unsafe-inline'")
    if "'unsafe-eval'" in script_sources:
        risks.append("script policy allows 'unsafe-eval'")
    if "*" in script_sources:
        risks.append("script policy allows any source (*)")
    if "data:" in script_sources or "blob:" in script_sources:
        risks.append("script policy permits executable data: or blob: sources")
    object_sources = directives.get("object-src", directives.get("default-src"))
    if object_sources is None or "'none'" not in object_sources:
        risks.append("object-src is not restricted to 'none'")
    return risks


def _summarize_set_cookie(headers: httpx.Headers) -> list[dict[str, Any]]:
    """Keep cookie names and security flags only; never retain cookie values."""
    summaries: list[dict[str, Any]] = []
    for raw in headers.get_list("set-cookie")[:30]:
        parts = [part.strip() for part in raw.split(";")]
        first = parts[0].partition("=")[0].strip()
        attributes = {part.partition("=")[0].strip().lower(): part.partition("=")[2].strip() for part in parts[1:]}
        cookie = {
            "name": first[:100],
            "secure": "secure" in attributes,
            "http_only": "httponly" in attributes,
            "same_site": attributes.get("samesite", "").lower() or None,
        }
        cookie["missing"] = [
            name for name, present in (
                ("Secure", cookie["secure"]),
                ("HttpOnly", cookie["http_only"]),
                ("SameSite", bool(cookie["same_site"])),
            ) if not present
        ]
        summaries.append(cookie)
    return summaries


async def _probe_tls_protocols(host: str, address: str, port: int, timeout: float = 1.5) -> list[dict[str, Any]]:
    """Try one bounded handshake per protocol version to inventory server support."""
    versions = (
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    )

    async def probe(name: str, version: ssl.TLSVersion) -> dict[str, Any]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            try:
                context.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                return {"protocol": name, "status": "probe_unavailable", "cipher": None}
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port, ssl=context, server_hostname=host), timeout=timeout,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            cipher_info = ssl_object.cipher() if ssl_object else None
            cipher = cipher_info[0] if cipher_info else None
            weak = bool(cipher and re.search(r"(RC4|3DES|DES-CBC|NULL|EXPORT|MD5|ANON)", cipher, re.IGNORECASE))
            return {"protocol": name, "status": "supported", "cipher": cipher,
                    "weak_cipher_observed": weak}
        except asyncio.CancelledError:
            raise
        except Exception:
            return {"protocol": name, "status": "not_observed", "cipher": None}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    return await asyncio.gather(*(probe(name, version) for name, version in versions))


async def audit_tls_and_https(
    domain: str,
    port: int = 443,
    timeout: float = 3.5,
    resolver: Any = None,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Execute end-to-end TLS certificate and HTTPS posture verification with strict SSRF controls."""
    findings: list[Finding] = []
    budget = work_budget or ScanWorkBudget()
    norm_domain = domain.strip().lower().rstrip(".")

    result: dict[str, Any] = {
        "scanned": False,
        "status": "pending",
        "reason": None,
        "tls_version": None,
        "cipher": None,
        "certificate": None,
        "https_redirect": None,
        "security_headers": None,
        "score_impact": 0,
    }

    # 1. DNS pre-resolution and strict SSRF guard (resolve once, reject non-public IPs)
    safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(norm_domain, port, resolver=resolver)
    if not safe_all:
        if reason.startswith("DNS query budget exhausted"):
            result["status"] = "inconclusive"
            result["reason"] = reason
            findings.append(Finding(severity="info", record_type="TLS", message="TLS checks could not run because the DNS query budget was exhausted."))
            return result, findings
        result["status"] = "blocked"
        result["reason"] = reason
        findings.append(Finding(
            severity="error",
            record_type="TLS",
            message=f"SSRF Safety Guard: Target host '{norm_domain}' cannot be safely audited ({reason}). Scan halted.",
        ))
        return result, findings

    target_ip = resolved_ips[0]

    # 2. TLS Handshake & Certificate Extraction
    # Connect directly to the validated IP to prevent DNS rebinding, while passing server_hostname for SNI & verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    cert_dict: dict[str, Any] = {}
    tls_version: str | None = None
    cipher_name: str | None = None

    connection_errors: list[str] = []
    certificate_error: ssl.SSLCertVerificationError | None = None
    connected = False
    # Multi-homed hosts may publish IPv6 addresses that are not reachable from
    # this server. Try each already-validated public address before reporting N/A.
    per_ip_timeout = max(0.5, min(timeout, 2.0))
    for candidate_ip in resolved_ips:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=candidate_ip,
                    port=port,
                    ssl=ssl_context,
                    server_hostname=norm_domain,
                ),
                timeout=per_ip_timeout,
            )
            target_ip = candidate_ip
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                tls_version = ssl_obj.version()
                cipher_info = ssl_obj.cipher()
                cipher_name = cipher_info[0] if cipher_info else None
                raw_cert = ssl_obj.getpeercert()
                if raw_cert:
                    cert_dict = raw_cert
            writer.close()
            await writer.wait_closed()
            result["scanned"] = True
            result["status"] = "complete"
            connected = True
            certificate_error = None
            break
        except ssl.SSLCertVerificationError as exc:
            # Preserve a certificate error for the UI instead of disguising it
            # as an absent TLS scan.
            target_ip = candidate_ip
            certificate_error = exc
            logger.warning("TLS certificate verification failed for %s: %s", norm_domain, exc.verify_message)
            result["scanned"] = True
            result["status"] = "certificate_error"
            result["reason"] = "TLS certificate verification failed."
            continue
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            connection_errors.append(f"{candidate_ip}: connection failed")
        except Exception:
            logger.exception("TLS handshake failed")
            result["status"] = "error"
            result["reason"] = "TLS handshake failed; result is inconclusive."
            findings.append(Finding(
                severity="warning",
                record_type="TLS",
                message="TLS/HTTPS audit encountered an error; result is inconclusive.",
            ))
            return result, findings

    # A default TLS handshake reports only the best mutually negotiated version.
    # Probe each version separately to detect legacy protocol support.
    result["protocol_sweep"] = await _probe_tls_protocols(norm_domain, target_ip, port)
    old_protocols = [item["protocol"] for item in result["protocol_sweep"]
                     if item["status"] == "supported" and item["protocol"] in ("TLSv1", "TLSv1.1")]
    weak_ciphers = [item for item in result["protocol_sweep"] if item.get("weak_cipher_observed")]
    if old_protocols:
        findings.append(Finding(severity="warning", record_type="TLS", message=f"The protocol sweep observed deprecated TLS support: {', '.join(old_protocols)}."))
    if weak_ciphers:
        findings.append(Finding(severity="warning", record_type="TLS", message="The protocol sweep negotiated a weak TLS cipher in at least one protocol probe."))

    if certificate_error is not None:
        if not connected:
            result["status"] = "certificate_error"
        findings.append(Finding(
            severity="error",
            record_type="TLS",
            message=f"TLS certificate verification failed for '{norm_domain}'. Untrusted or self-signed certificate.",
        ))
    elif not connected:
        result["status"] = "unreachable"
        result["reason"] = (
            f"Could not connect to any of {len(resolved_ips)} validated public address(es) on port {port} "
            f"within {per_ip_timeout:g} seconds per address."
        )
        findings.append(Finding(
            severity="info",
            record_type="TLS",
            message=f"TLS/HTTPS audit was inconclusive: {result['reason']} Connection errors: {', '.join(connection_errors)}.",
        ))
        return result, findings

    # 3. Analyze Certificate Details
    if cert_dict:
        not_after_str = cert_dict.get("notAfter", "")
        not_before_str = cert_dict.get("notBefore", "")
        san_entries = [val for key, val in cert_dict.get("subjectAltName", []) if key.lower() in ("dns", "ip address")]
        
        issuer_parts = []
        for rdn in cert_dict.get("issuer", ()):
            for key, val in rdn:
                if key in ("commonName", "organizationName"):
                    issuer_parts.append(val)
        issuer_str = ", ".join(issuer_parts) if issuer_parts else "Public CA"

        days_remaining = -1
        is_expired = False
        if not_after_str:
            try:
                exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                days_remaining = (exp_dt - now_dt).days
                is_expired = days_remaining < 0
            except Exception:
                pass

        san_matched = match_san_hostname(norm_domain, san_entries)

        result["certificate"] = {
            "issuer": issuer_str,
            "subject": dict(x[0] for x in cert_dict.get("subject", ())),
            "san": san_entries[:15],
            "san_matched": san_matched,
            "valid_from": not_before_str,
            "valid_until": not_after_str,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
        }
        result["tls_version"] = tls_version
        result["cipher"] = cipher_name

        if is_expired:
            findings.append(Finding(
                severity="error",
                record_type="TLS",
                message=f"TLS certificate for '{norm_domain}' expired on {not_after_str}. Browsers will block connections.",
            ))
        elif days_remaining <= CERT_EXPIRY_WARNING_DAYS:
            findings.append(Finding(
                severity="warning",
                record_type="TLS",
                message=f"TLS certificate expires soon ({days_remaining} days remaining, {not_after_str}). Renew immediately.",
            ))
        else:
            findings.append(Finding(
                severity="info",
                record_type="TLS",
                message=f"TLS certificate is valid ({days_remaining} days remaining, expires {not_after_str}) issued by {issuer_str}.",
            ))

        if not san_matched:
            findings.append(Finding(
                severity="error",
                record_type="TLS",
                message=f"Certificate SAN mismatch: None of the {len(san_entries)} certificate SAN names cover '{norm_domain}'.",
            ))

        if tls_version in ("TLSv1.3", "TLSv1.2"):
            findings.append(Finding(
                severity="info",
                record_type="TLS",
                message=f"Modern encryption protocol negotiated: {tls_version} ({cipher_name}).",
            ))
        elif tls_version:
            findings.append(Finding(
                severity="warning",
                record_type="TLS",
                message=f"Legacy or deprecated TLS protocol negotiated: {tls_version}. Upgrade to TLS 1.2 or TLS 1.3.",
            ))

    # 4. Check HTTP (Port 80) -> HTTPS (Port 443) Redirection with strict redirect validation & pinned IP
    redirect_ok = False
    try:
        if not await budget.reserve_http("tls"):
            raise ScanBudgetExhausted("per-scan outbound request budget exhausted")
        http_transport = PinnedIPTransport(target_ip)
        async with httpx.AsyncClient(transport=http_transport, timeout=3.0, follow_redirects=False, headers=outbound_http_headers()) as client:
            async with client.stream("GET", f"http://{norm_domain}/") as resp_http:
                status_code = resp_http.status_code
                loc = resp_http.headers.get("location", "")
                if status_code in (301, 302, 307, 308):
                    parsed_loc = urlparse(loc)
                    redirect_host = parsed_loc.hostname or norm_domain
                    redir_safe, redir_ips, redir_reason = await resolve_and_verify_all_ips(redirect_host, parsed_loc.port or 443, resolver=resolver)
                    if not redir_safe:
                        findings.append(Finding(
                            severity="error",
                            record_type="HTTPS",
                            message=f"SSRF Alert: HTTP redirect points to blocked target '{redirect_host}' ({redir_reason}). Redirect halted.",
                        ))
                    elif loc.lower().startswith("https://"):
                        redirect_ok = True
                        result["https_redirect"] = {
                            "enforced": True,
                            "status_code": status_code,
                            "location": loc,
                        }
                        findings.append(Finding(
                            severity="info",
                            record_type="HTTPS",
                            message=f"Port 80 unencrypted HTTP automatically redirects to HTTPS ({status_code} -> {loc}).",
                        ))
                if not redirect_ok and not any(f.record_type == "HTTPS" and f.severity == "error" for f in findings):
                    result["https_redirect"] = {
                        "enforced": False,
                        "status_code": status_code,
                        "location": loc or None,
                    }
                    findings.append(Finding(
                        severity="warning",
                        record_type="HTTPS",
                        message=f"Port 80 HTTP does not redirect to HTTPS (HTTP {status_code}). Cleartext web traffic may be exposed to interception.",
                    ))
    except Exception:
        result["https_redirect"] = {"enforced": None, "status_code": None, "location": None, "status": "inconclusive"}
        findings.append(Finding(
            severity="info",
            record_type="HTTPS",
            message="Port 80 HTTP redirect check was inconclusive because the request could not be completed.",
        ))

    # 5. Check HTTPS Web Security Headers (Strict TLS verification, pinned IP, stream headers without body download)
    try:
        if not await budget.reserve_http("tls"):
            raise ScanBudgetExhausted("per-scan outbound request budget exhausted")
        https_transport = PinnedIPTransport(target_ip, verify=True)
        async with httpx.AsyncClient(transport=https_transport, timeout=3.0, follow_redirects=False, headers=outbound_http_headers()) as client:
            async with client.stream("GET", f"https://{norm_domain}/") as resp_https:
                h = resp_https.headers

                hsts_values = h.get_list("strict-transport-security")
                hsts = parse_hsts(hsts_values)
                csp = h.get("content-security-policy")
                xfo = h.get("x-frame-options")
                xcto = h.get("x-content-type-options")
                rp = h.get("referrer-policy")
                permissions_policy = h.get("permissions-policy")
                coop = h.get("cross-origin-opener-policy")
                corp = h.get("cross-origin-resource-policy")
                csp_risks = review_csp(csp)
                cookies = _summarize_set_cookie(h)

                sec_headers = {
                    "hsts": hsts["active"],
                    "hsts_status": hsts["status"],
                    "hsts_max_age": hsts["max_age"],
                    "hsts_include_subdomains": hsts["include_subdomains"],
                    "hsts_raw": "; ".join(hsts_values) or None,
                    "csp": bool(csp),
                    "csp_raw": csp[:4096] if csp else None,
                    "csp_risks": csp_risks,
                    "x_frame_options": xfo,
                    "x_content_type_options": xcto,
                    "referrer_policy": rp,
                    "permissions_policy": permissions_policy,
                    "cross_origin_opener_policy": coop,
                    "cross_origin_resource_policy": corp,
                    "cookies": cookies,
                }
                result["security_headers"] = sec_headers

                if hsts["status"] == "active":
                    subdomains_text = " and includeSubDomains" if hsts["include_subdomains"] else ""
                    findings.append(Finding(
                        severity="info",
                        record_type="HTTPS",
                        message=f"HSTS is active with max-age={hsts['max_age']} seconds{subdomains_text}.",
                    ))
                elif hsts["status"] == "disabled":
                    findings.append(Finding(
                        severity="warning",
                        record_type="HTTPS",
                        message="HSTS header is present but max-age is zero, which disables the policy.",
                    ))
                elif hsts["status"] == "invalid":
                    findings.append(Finding(
                        severity="warning",
                        record_type="HTTPS",
                        message="HSTS header has a missing, invalid, or duplicate max-age directive; policy activation could not be confirmed.",
                    ))
                else:
                    findings.append(Finding(
                        severity="warning",
                        record_type="HTTPS",
                        message="Strict-Transport-Security (HSTS) header is missing. Browsers may allow unencrypted downgrade attacks.",
                    ))

                if csp:
                    findings.append(Finding(
                        severity="warning" if csp_risks else "info",
                        record_type="CSP",
                        message=("Content-Security-Policy has common weaknesses: " + "; ".join(csp_risks) + ".") if csp_risks else "Content-Security-Policy is present; common script and object source directives look constrained.",
                    ))
                else:
                    findings.append(Finding(
                        severity="info",
                        record_type="HTTPS",
                        message="Content-Security-Policy (CSP) header is not published.",
                    ))

                missing_isolation = [name for name, value in (("Permissions-Policy", permissions_policy), ("COOP", coop), ("CORP", corp)) if not value]
                if missing_isolation:
                    findings.append(Finding(
                        severity="info",
                        record_type="HTTPS",
                        message=f"Additional browser isolation headers not observed: {', '.join(missing_isolation)}.",
                    ))
                cookies_with_gaps = [cookie for cookie in cookies if cookie["missing"]]
                if cookies_with_gaps:
                    findings.append(Finding(
                        severity="warning",
                        record_type="COOKIE",
                        message=f"{len(cookies_with_gaps)} of {len(cookies)} observed cookie(s) miss one or more Secure, HttpOnly, or SameSite attributes. Cookie values were not retained.",
                    ))
    except Exception:
        findings.append(Finding(
            severity="info",
            record_type="HTTPS",
            message="HTTPS web security header inspection was inconclusive because the request could not be completed.",
        ))

    # OPTIONS only reports the server's advertised methods; no write method is sent.
    try:
        if not await budget.reserve_http("tls"):
            raise ScanBudgetExhausted("per-scan outbound request budget exhausted")
        options_transport = PinnedIPTransport(target_ip, verify=True)
        async with httpx.AsyncClient(transport=options_transport, timeout=3.0, follow_redirects=False, headers=outbound_http_headers()) as client:
            async with client.stream("OPTIONS", f"https://{norm_domain}/") as response:
                allowed = [method.strip().upper() for method in response.headers.get("allow", "").split(",") if method.strip()]
                risky = sorted(set(allowed).intersection({"TRACE", "PUT", "DELETE", "CONNECT"}))
                result["http_methods"] = {
                    "status": "checked" if response.headers.get("allow") else "not_advertised",
                    "http_status": response.status_code,
                    "advertised": allowed,
                    "review_methods": risky,
                    "probe": "OPTIONS",
                }
                if risky:
                    findings.append(Finding(
                        severity="warning",
                        record_type="HTTP METHODS",
                        message=f"OPTIONS advertises potentially sensitive HTTP methods: {', '.join(risky)}. This is an advertisement, not proof that each method accepts requests; no write request was sent.",
                    ))
    except Exception:
        result["http_methods"] = {"status": "inconclusive", "http_status": None, "advertised": [], "review_methods": [], "probe": "OPTIONS", "reason": "HTTP method check could not be completed."}

    # RFC 9116 security.txt is a small, fixed-path request. Bound the response
    # body and validate the required Contact field without following redirects.
    security_txt: dict[str, Any] = {"status": "missing", "url": f"https://{norm_domain}/.well-known/security.txt"}
    try:
        if not await budget.reserve_http("tls"):
            raise ScanBudgetExhausted("request_budget_exhausted")
        security_transport = PinnedIPTransport(target_ip, verify=True)
        async with httpx.AsyncClient(transport=security_transport, timeout=3.0, follow_redirects=False, headers=outbound_http_headers()) as client:
            async with client.stream("GET", security_txt["url"]) as response:
                security_txt["http_status"] = response.status_code
                if response.status_code == 200:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk[: max(0, 16 * 1024 - len(body))])
                        if len(body) >= 16 * 1024:
                            break
                    if len(body) >= 16 * 1024:
                        security_txt.update({"status": "truncated", "reason": "Response exceeded the 16 KiB parsing limit."})
                    else:
                        security_txt.update(parse_security_txt(bytes(body)))
                elif 300 <= response.status_code < 400:
                    security_txt["status"] = "redirected"
                elif response.status_code in (404, 410):
                    security_txt["status"] = "missing"
                else:
                    security_txt["status"] = "unavailable"
    except Exception:
        security_txt.update({"status": "inconclusive", "reason": "Request could not be completed."})
    result["security_txt"] = security_txt
    if security_txt["status"] in ("missing", "malformed", "expired"):
        findings.append(Finding(
            severity="warning" if security_txt["status"] != "missing" else "info",
            record_type="SECURITY.TXT",
            message=f"security.txt is {security_txt['status']} at /.well-known/security.txt.",
        ))

    return result, findings
