"""Native Non-Blocking TLS & HTTPS Security Auditor.

Audits X.509 certificate validity, expiration, SAN wildcard coverage,
negotiated TLS protocol version, HTTP-to-HTTPS redirection, and essential
web security headers (HSTS, CSP, X-Frame-Options) without external binaries.
Hardened with strict SSRF controls, direct IP binding, and validated redirects.
"""

import asyncio
from datetime import datetime, timezone
import fnmatch
import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlparse
import httpcore
import httpx

from app.models import Finding


class PinnedIPBackend(httpcore.AnyIOBackend):
    """Network backend that pins TCP connections directly to a validated safe IP, eliminating DNS rebinding."""

    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        return await super().connect_tcp(
            self.target_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class PinnedIPTransport(httpx.AsyncHTTPTransport):
    """Transport that routes TCP traffic strictly to target_ip while preserving SNI and Host header."""

    def __init__(self, target_ip: str, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._pool._network_backend = PinnedIPBackend(target_ip)



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


async def resolve_and_verify_all_ips(hostname: str, port: int = 443) -> tuple[bool, list[str], str]:
    """Resolve hostname once and verify that all resolved IPs are public and safe (reject mixed answers)."""
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        if not addr_info:
            return False, [], "Hostname did not resolve to any addresses"
        all_ips = list(dict.fromkeys(info[4][0] for info in addr_info))
    except Exception as exc:
        return False, [], f"Resolution error: {exc}"

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
        elif fnmatch.fnmatch(norm_host, norm_pat):
            return True
    return False


async def audit_tls_and_https(
    domain: str,
    port: int = 443,
    timeout: float = 3.5,
) -> tuple[dict[str, Any], list[Finding]]:
    """Execute end-to-end TLS certificate and HTTPS posture verification with strict SSRF controls."""
    findings: list[Finding] = []
    norm_domain = domain.strip().lower().rstrip(".")

    result: dict[str, Any] = {
        "scanned": False,
        "tls_version": None,
        "cipher": None,
        "certificate": None,
        "https_redirect": None,
        "security_headers": None,
        "score_impact": 0,
    }

    # 1. DNS pre-resolution and strict SSRF guard (resolve once, reject non-public IPs)
    safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(norm_domain, port)
    if not safe_all:
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

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=target_ip,
                port=port,
                ssl=ssl_context,
                server_hostname=norm_domain,
            ),
            timeout=timeout,
        )
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
    except ssl.SSLCertVerificationError as exc:
        result["scanned"] = True
        findings.append(Finding(
            severity="error",
            record_type="TLS",
            message=f"TLS certificate verification failed for '{norm_domain}': {exc.verify_message}. Untrusted or self-signed certificate.",
        ))
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # Port 443 is unreachable or connection timed out
        result["scanned"] = False
        findings.append(Finding(
            severity="info",
            record_type="TLS",
            message=f"TLS/HTTPS audit on port {port} was inconclusive: target host was unreachable or timed out.",
        ))
        return result, findings
    except Exception:
        pass

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
        elif days_remaining <= 14:
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
        http_transport = PinnedIPTransport(target_ip)
        async with httpx.AsyncClient(transport=http_transport, timeout=3.0, follow_redirects=False) as client:
            resp_http = await client.get(f"http://{norm_domain}/")
            if resp_http.status_code in (301, 302, 307, 308):
                loc = resp_http.headers.get("location", "")
                parsed_loc = urlparse(loc)
                redirect_host = parsed_loc.hostname or norm_domain
                redir_safe, redir_ips, redir_reason = await resolve_and_verify_all_ips(redirect_host, parsed_loc.port or 443)
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
                        "status_code": resp_http.status_code,
                        "location": loc,
                    }
                    findings.append(Finding(
                        severity="info",
                        record_type="HTTPS",
                        message=f"Port 80 unencrypted HTTP automatically redirects to HTTPS ({resp_http.status_code} -> {loc}).",
                    ))
            if not redirect_ok and not any(f.record_type == "HTTPS" and f.severity == "error" for f in findings):
                result["https_redirect"] = {
                    "enforced": False,
                    "status_code": resp_http.status_code,
                    "location": resp_http.headers.get("location"),
                }
                findings.append(Finding(
                    severity="warning",
                    record_type="HTTPS",
                    message=f"Port 80 HTTP does not redirect to HTTPS (HTTP {resp_http.status_code}). Cleartext web traffic may be exposed to interception.",
                ))
    except Exception:
        result["https_redirect"] = {"enforced": False, "status_code": None, "location": None}

    # 5. Check HTTPS Web Security Headers (Strict TLS verification, pinned IP, no arbitrary redirects)
    try:
        https_transport = PinnedIPTransport(target_ip, verify=True)
        async with httpx.AsyncClient(transport=https_transport, timeout=3.0, follow_redirects=False) as client:
            resp_https = await client.get(f"https://{norm_domain}/")
            h = resp_https.headers


            hsts = h.get("strict-transport-security")
            csp = h.get("content-security-policy")
            xfo = h.get("x-frame-options")
            xcto = h.get("x-content-type-options")
            rp = h.get("referrer-policy")

            sec_headers = {
                "hsts": bool(hsts),
                "hsts_raw": hsts,
                "csp": bool(csp),
                "x_frame_options": xfo,
                "x_content_type_options": xcto,
                "referrer_policy": rp,
            }
            result["security_headers"] = sec_headers

            if hsts:
                findings.append(Finding(
                    severity="info",
                    record_type="HTTPS",
                    message=f"HTTP Strict Transport Security (HSTS) is active: `{hsts}`.",
                ))
            else:
                findings.append(Finding(
                    severity="warning",
                    record_type="HTTPS",
                    message="Strict-Transport-Security (HSTS) header is missing. Browsers may allow unencrypted downgrade attacks.",
                ))

            if csp:
                findings.append(Finding(
                    severity="info",
                    record_type="HTTPS",
                    message="Content-Security-Policy (CSP) is deployed to defend against XSS and clickjacking.",
                ))
            else:
                findings.append(Finding(
                    severity="info",
                    record_type="HTTPS",
                    message="Content-Security-Policy (CSP) header is not published.",
                ))
    except Exception:
        pass

    return result, findings
