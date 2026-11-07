"""Native Non-Blocking TLS & HTTPS Security Auditor.

Audits X.509 certificate validity, expiration, SAN wildcard coverage,
negotiated TLS protocol version, HTTP-to-HTTPS redirection, and essential
web security headers (HSTS, CSP, X-Frame-Options) without external binaries.
"""

import asyncio
from datetime import datetime, timezone
import fnmatch
import ipaddress
import socket
import ssl
from typing import Any
import httpx

from app.models import Finding


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

    return True, "Public IP"


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
    """Execute end-to-end TLS certificate and HTTPS posture verification."""
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

    # 1. DNS pre-resolution and SSRF guard
    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(norm_domain, port, type=socket.SOCK_STREAM)
        if not addr_info:
            return result, findings
        target_ip = addr_info[0][4][0]
    except Exception as exc:
        return result, findings

    safe, reason = is_safe_ip(target_ip)
    if not safe:
        findings.append(Finding(
            severity="error",
            record_type="TLS",
            message=f"SSRF Safety Guard: Target host '{norm_domain}' resolved to blocked address '{target_ip}' ({reason}). Scan halted.",
        ))
        return result, findings

    # 2. TLS Handshake & Certificate Extraction
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    cert_dict: dict[str, Any] = {}
    tls_version: str | None = None
    cipher_name: str | None = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(norm_domain, port, ssl=ssl_context, server_hostname=norm_domain),
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
        return result, findings
    except Exception:
        pass

    # 3. Analyze Certificate Details
    if cert_dict:
        not_after_str = cert_dict.get("notAfter", "")
        not_before_str = cert_dict.get("notBefore", "")
        san_entries = [val for key, val in cert_dict.get("subjectAltName", []) if key.lower() in ("dns", "ip address")]
        
        # Issuer CN or O
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
                # Format: 'May 10 12:00:00 2026 GMT'
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

        # Findings for Certificate
        if is_expired:
            findings.append(Finding(
                severity="error",
                record_type="TLS",
                message=f"CRITICAL: TLS certificate for '{norm_domain}' expired {abs(days_remaining)} days ago ({not_after_str}). Browsers will block access.",
            ))
        elif days_remaining <= 14:
            findings.append(Finding(
                severity="warning",
                record_type="TLS",
                message=f"TLS certificate for '{norm_domain}' will expire in {days_remaining} days ({not_after_str}). Immediate renewal required.",
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

    # 4. Check HTTP (Port 80) -> HTTPS (Port 443) Redirection
    redirect_ok = False
    try:
        async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
            resp_http = await client.get(f"http://{norm_domain}/")
            if resp_http.status_code in (301, 302, 307, 308):
                loc = resp_http.headers.get("location", "")
                if loc.lower().startswith("https://"):
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
            if not redirect_ok:
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
        # HTTP port 80 might be completely closed or filtered
        result["https_redirect"] = {"enforced": False, "status_code": None, "location": None}

    # 5. Check HTTPS Web Security Headers
    try:
        async with httpx.AsyncClient(timeout=3.0, verify=False, follow_redirects=True) as client:
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
    except Exception:
        pass

    return result, findings
