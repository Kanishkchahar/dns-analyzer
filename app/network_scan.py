"""Scoped Network Inventory & Port Service Verification.

Implements safe, SSRF-guarded List Scanning (scope resolution without port probes)
and opt-in Port & Service checks against explicitly approved public targets.
"""

import asyncio
import ipaddress
import hmac
import os
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
import dns.asyncresolver
import httpx

from app.models import Finding
from app.tls_check import PinnedIPTransport, is_safe_ip, resolve_and_verify_all_ips
from app.http_config import outbound_http_headers
from app.work_budget import ScanBudgetExhausted, ScanWorkBudget

# Curated, safe default ports for standard public infrastructure auditing
STANDARD_PORTS: dict[int, str] = {
    80: "HTTP (Web)",
    443: "HTTPS (Encrypted Web)",
    8443: "HTTPS-Alt (Admin/Web)",
    25: "SMTP (Mail Transfer)",
    587: "Submission (Mail Client)",
    465: "SMTPS (Secure Mail)",
    53: "DNS (Domain Name System)",
    22: "SSH (Secure Remote Administration)",
}

# Server-side controls: active scanning requires server-side policy authorization
MAX_PORTS_PER_SCAN = 10
GLOBAL_PORT_SCAN_SEMAPHORE = asyncio.Semaphore(4)
TARGET_SYNTAX_REGEX = re.compile(r"^[a-zA-Z0-9.\-_:\[\]]+$")

# Small fixed set of safe, public-facing discovery paths. This is deliberately
# not a wordlist or recursive crawler.
COMMON_WEB_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
    "/manifest.json",
    "/favicon.ico",
)
MAX_PUBLICATION_BODY_BYTES = 256 * 1024
MAX_ADVERTISED_PATHS = 200


def _same_origin_https_url(url: str, target_host: str) -> bool:
    """Accept only HTTPS URLs on the exact requested host and standard HTTPS port."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        expected = target_host.strip("[]").lower().rstrip(".")
        if ":" in expected:
            expected = ipaddress.ip_address(expected).compressed
            host = ipaddress.ip_address(host).compressed
        return (
            parsed.scheme.lower() == "https"
            and host == expected
            and parsed.port in (None, 443)
            and parsed.username is None
            and parsed.password is None
        )
    except (ValueError, TypeError):
        return False


def _publication_path(url: str, target_host: str) -> str | None:
    if not _same_origin_https_url(url, target_host):
        return None
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return path[:1000]


def _parse_robots(body: bytes, target_host: str) -> list[dict[str, str]]:
    found: dict[str, str] = {}
    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        directive = key.strip().lower()
        value = value.strip()
        if directive in ("allow", "disallow") and value.startswith("/") and len(value) <= 1000:
            found.setdefault(value, f"robots.txt {directive}")
        elif directive == "sitemap":
            path = _publication_path(value, target_host)
            if path:
                found.setdefault(path, "robots.txt sitemap directive")
    return [{"path": path, "source": source} for path, source in list(found.items())[:MAX_ADVERTISED_PATHS]]


def _parse_sitemap(body: bytes, target_host: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(body)
    except (ET.ParseError, ValueError, DefusedXmlException):
        return []
    found: dict[str, str] = {}
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "loc" or not element.text:
            continue
        path = _publication_path(element.text.strip(), target_host)
        if path:
            found.setdefault(path, "sitemap.xml")
        if len(found) >= MAX_ADVERTISED_PATHS:
            break
    return [{"path": path, "source": source} for path, source in found.items()]


def _classify_advertised_path(path: str) -> tuple[str, str | None]:
    """Flag names that merit human review without requesting them or asserting exposure."""
    normalized = path.lower().split("?", 1)[0]
    patterns = ("/.env", "/.git", "/admin", "/backup", "/config", "/debug", "/internal", "/private", "/staging")
    if any(normalized == pattern or normalized.startswith(pattern + "/") for pattern in patterns):
        return "review", "Path name may refer to administrative or internal content; no access was attempted."
    return "listed", None


def is_active_scan_allowed() -> bool:
    """Check if server configuration permits active port scanning (disabled by default)."""
    val = os.environ.get("ENABLE_ACTIVE_PORT_SCAN", "false").strip().lower()
    return val in ("true", "1", "yes", "enabled")


def verify_port_scan_authorization(
    auth_header: str | None = None,
    target: str = "",
) -> tuple[bool, str]:
    """Verify server-side authorization credentials and scope for active port probes."""
    expected_key = os.environ.get("PORT_SCAN_API_KEY", "").strip()
    allowed_targets_env = os.environ.get("PORT_SCAN_ALLOWED_DOMAINS", "").strip()

    # Explicit server-side policy requirement:
    # When active port scanning is enabled, the server must have an explicit policy configured.
    # If neither an API key nor an approved domain list is configured, probes are refused.
    if not expected_key and not allowed_targets_env:
        return (
            False,
            "Active port scanning requires an explicit server policy: configure PORT_SCAN_API_KEY and/or PORT_SCAN_ALLOWED_DOMAINS in the server environment.",
        )

    if expected_key:
        provided = ""
        if auth_header:
            if auth_header.lower().startswith("bearer "):
                provided = auth_header[7:].strip()
            else:
                provided = auth_header.strip()
        if not provided or not hmac.compare_digest(provided, expected_key):
            return (
                False,
                "Access denied: Valid server authorization token (PORT_SCAN_API_KEY) required to run active probes.",
            )

    if allowed_targets_env:
        allowed = [d.strip().lower() for d in allowed_targets_env.split(",") if d.strip()]
        clean_target = target.strip().lower().rstrip(".")
        if "*" not in allowed and not any(clean_target == a or clean_target.endswith(f".{a}") for a in allowed):
            return (
                False,
                f"Target '{clean_target}' is not in approved server scan scope ({', '.join(allowed)}).",
            )

    return True, "Authorized"



async def run_list_scan(
    targets: list[str],
    resolver: dns.asyncresolver.Resolver | None = None,
    work_budget: ScanWorkBudget | None = None,
) -> dict[str, Any]:
    """Resolve user-approved target scope without probing ports (bounded concurrency & input validation)."""
    clean_targets = [t.strip() for t in targets if t.strip()]
    budget = work_budget or ScanWorkBudget(profile="network_scan")
    resolver = resolver or budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
    list_semaphore = asyncio.Semaphore(10)

    async def _resolve_target(target: str) -> dict[str, Any]:
        target_info: dict[str, Any] = {
            "target": target,
            "resolved_ips": [],
            "in_scope_safe": False,
            "reasons": [],
        }

        # Validate input length and basic characters
        if len(target) > 253 or not TARGET_SYNTAX_REGEX.match(target):
            target_info["reasons"].append("Invalid target syntax or length exceeds 253 characters.")
            return target_info

        # Check if target is already an IP
        is_ip_direct, reason = is_safe_ip(target)
        if is_ip_direct:
            target_info["resolved_ips"].append({"ip": target, "safe": True, "reason": "Public IP"})
            target_info["in_scope_safe"] = True
            return target_info
        elif "Invalid IP" not in reason:
            # It was an IP, but unsafe
            target_info["resolved_ips"].append({"ip": target, "safe": False, "reason": reason})
            target_info["reasons"].append(reason)
            return target_info

        # Resolve A and AAAA records with bounded concurrency and timeout
        async with list_semaphore:
            try:
                async def query(rdtype: str) -> list[str]:
                    try:
                        answer = await asyncio.wait_for(resolver.resolve(target, rdtype), timeout=2.5)
                        return [str(record.address) for record in answer if hasattr(record, "address")]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        return []
                all_ips = list(dict.fromkeys([ip for kind in ("A", "AAAA") for ip in await query(kind)]))
                safe_count = 0
                for ip in all_ips:
                    safe, r = is_safe_ip(ip)
                    target_info["resolved_ips"].append({"ip": ip, "safe": safe, "reason": r})
                    if safe:
                        safe_count += 1
                    else:
                        target_info["reasons"].append(r)
                target_info["in_scope_safe"] = safe_count > 0 and len(target_info["reasons"]) == 0
            except asyncio.TimeoutError:
                target_info["reasons"].append("Resolution timed out after 2.5 seconds.")
            except ScanBudgetExhausted:
                target_info["status"] = "inconclusive"
                target_info["reasons"].append("DNS query budget exhausted; target resolution is inconclusive.")
            except Exception:
                target_info["status"] = "inconclusive"
                target_info["reasons"].append("Target resolution failed; result is inconclusive.")

        return target_info

    tasks = [_resolve_target(t) for t in clean_targets]
    results = await asyncio.gather(*tasks)

    total_safe = sum(1 for r in results if r["in_scope_safe"])
    return {
        "scan_mode": "List Scan (No port probes)",
        "total_targets": len(clean_targets),
        "in_scope_count": total_safe,
        "targets": results,
    }


async def run_common_path_scan(
    targets: list[str],
    timeout: float = 3.0,
    resolver: dns.asyncresolver.Resolver | None = None,
    work_budget: ScanWorkBudget | None = None,
) -> dict[str, Any]:
    """Check fixed public paths and parse same-origin robots/sitemap data, without crawling."""
    clean_targets = [target.strip() for target in targets if target.strip()]
    if not clean_targets or len(clean_targets) > 5:
        raise ValueError("Provide between 1 and 5 target hostnames or public IPs.")

    target_semaphore = asyncio.Semaphore(5)
    budget = work_budget or ScanWorkBudget(profile="network_scan")
    resolver = resolver or budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")

    async def _scan_target(target: str) -> dict[str, Any]:
        if len(target) > 253 or not TARGET_SYNTAX_REGEX.fullmatch(target):
            return {"target": target, "status": "invalid", "reason": "Invalid target syntax or length.", "paths": []}

        async with target_semaphore:
            safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(target, port=443, resolver=resolver)
            if not safe_all or not resolved_ips:
                exhausted = budget.dns_remaining <= 0
                return {"target": target, "status": "inconclusive" if exhausted else "blocked", "reason": "DNS query budget exhausted; target resolution is inconclusive." if exhausted else reason, "paths": []}

            path_semaphore = asyncio.Semaphore(7)
            url_host = target.strip("[]")
            try:
                if ipaddress.ip_address(url_host).version == 6:
                    url_host = f"[{url_host}]"
            except ValueError:
                pass
            origin = f"https://{url_host}"
            target_host = target.strip("[]")
            advertised: dict[str, dict[str, str | None]] = {}
            declared_sitemap_paths: set[str] = set()

            async def _read_limited(response: httpx.Response) -> bytes:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    remaining = MAX_PUBLICATION_BODY_BYTES - len(body)
                    if remaining <= 0:
                        break
                    body.extend(chunk[:remaining])
                    if len(body) >= MAX_PUBLICATION_BODY_BYTES:
                        break
                return bytes(body)

            async def _inspect_publication(path: str, body: bytes) -> None:
                discovered = _parse_robots(body, target_host) if path == "/robots.txt" else _parse_sitemap(body, target_host)
                for item in discovered:
                    item["review"], item["review_reason"] = _classify_advertised_path(item["path"])
                    advertised.setdefault(item["path"], {"source": item["source"], "review": item["review"], "review_reason": item["review_reason"]})
                    if item["source"] == "robots.txt sitemap directive":
                        declared_sitemap_paths.add(item["path"])

            async def _check_path(path: str) -> dict[str, Any]:
                async with path_semaphore:
                    errors: list[str] = []
                    for candidate_ip in resolved_ips:
                        try:
                            if not await budget.reserve_http("network_scan"):
                                return {"path": path, "status_code": None, "state": "inconclusive", "location": None, "error": "HTTP request budget exhausted."}
                            transport = PinnedIPTransport(candidate_ip, verify=True)
                            async with httpx.AsyncClient(
                                transport=transport,
                                timeout=timeout,
                                follow_redirects=False,
                                headers=outbound_http_headers(),
                            ) as client:
                                request_url = f"{origin}{path}"
                                async with client.stream("GET", request_url) as response:
                                    status_code = response.status_code
                                    location = response.headers.get("location") if status_code in (301, 302, 303, 307, 308) else None
                                    body = b""
                                    final_status = None
                                    redirect_error = None
                                    if location:
                                        redirect_url = urljoin(request_url, location)
                                        if _same_origin_https_url(redirect_url, target_host):
                                            try:
                                                if not await budget.reserve_http("network_scan"):
                                                    return {"path": path, "status_code": status_code, "state": "inconclusive", "location": location, "error": "HTTP request budget exhausted."}
                                                # Re-resolve and apply the same public-IP filter before one same-origin hop.
                                                redirect_safe, redirect_ips, redirect_reason = await resolve_and_verify_all_ips(target_host, port=443, resolver=resolver)
                                                if redirect_safe and redirect_ips:
                                                    redirect_transport = PinnedIPTransport(redirect_ips[0], verify=True)
                                                    async with httpx.AsyncClient(
                                                        transport=redirect_transport,
                                                        timeout=timeout,
                                                        follow_redirects=False,
                                                        headers=outbound_http_headers(),
                                                    ) as redirect_client:
                                                        async with redirect_client.stream("GET", redirect_url) as redirected:
                                                            final_status = redirected.status_code
                                                            if (path in ("/robots.txt", "/sitemap.xml") or path in declared_sitemap_paths) and 200 <= final_status < 300:
                                                                body = await _read_limited(redirected)
                                                else:
                                                    redirect_error = f"Same-host redirect blocked by SSRF policy: {redirect_reason}"
                                            except Exception:
                                                redirect_error = "Same-host redirect check failed; result is inconclusive."
                                    elif (path in ("/robots.txt", "/sitemap.xml") or path in declared_sitemap_paths) and 200 <= status_code < 300:
                                        body = await _read_limited(response)
                                    if body:
                                        await _inspect_publication(path, body)
                                    return {
                                        "path": path,
                                        "status_code": status_code,
                                        "state": "found" if 200 <= status_code < 300 else ("redirect" if location else ("restricted" if status_code in (401, 403) else ("not_found" if status_code == 404 else "response"))),
                                        "location": location,
                                        "redirect_status_code": final_status,
                                        "error": redirect_error,
                                    }
                        except Exception:
                            errors.append("Connection failed; result is inconclusive.")
                    return {"path": path, "status_code": None, "state": "inconclusive" if "budget exhausted" in ";".join(errors).lower() else "unavailable", "location": None, "error": "; ".join(errors)}

            path_results = await asyncio.gather(*(_check_path(path) for path in COMMON_WEB_PATHS))
            custom_sitemaps = [
                path for path in declared_sitemap_paths
                if path not in COMMON_WEB_PATHS
            ][:3]
            if custom_sitemaps:
                path_results.extend(await asyncio.gather(*(_check_path(path) for path in custom_sitemaps)))
            unavailable_count = sum(item["state"] == "unavailable" for item in path_results)
            redirect_failures = sum(bool(item.get("error")) for item in path_results)
            incomplete_count = max(unavailable_count, redirect_failures)
            return {
                "target": target,
                "status": "partial" if incomplete_count else "complete",
                "reason": f"{unavailable_count} path checks could not connect; {redirect_failures} same-host redirect checks were incomplete." if incomplete_count else None,
                "resolved_ips": resolved_ips,
                "paths": path_results,
                "advertised_paths": [
                    {"path": path, **details}
                    for path, details in list(advertised.items())[:MAX_ADVERTISED_PATHS]
                ],
            }

    results = await asyncio.gather(*(_scan_target(target) for target in clean_targets))
    return {
        "scan_mode": "Common Web Paths + Public Robots/Sitemap (No Crawling)",
        "path_count": len(COMMON_WEB_PATHS),
        "total_targets": len(clean_targets),
        "targets": results,
    }


async def run_port_scan(
    target: str,
    ports: list[int] | None = None,
    confirmed: bool = False,
    timeout: float = 1.5,
    auth_header: str | None = None,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> dict[str, Any]:
    """Execute scoped, opt-in port and service verification on approved target."""
    if not is_active_scan_allowed():
        return {
            "status": "disabled",
            "message": "Active port scanning is disabled by server deployment policy. Enable server-side authorization via ENABLE_ACTIVE_PORT_SCAN=true.",
        }

    auth_ok, auth_msg = verify_port_scan_authorization(auth_header, target)
    if not auth_ok:
        return {"status": "unauthorized", "message": auth_msg}


    target_ports = sorted(list(set(ports or list(STANDARD_PORTS.keys()))))

    # Validate port numbers and cap ports per request
    if len(target_ports) > MAX_PORTS_PER_SCAN:
        return {
            "status": "error",
            "message": f"Port count exceeds allowed limit: maximum {MAX_PORTS_PER_SCAN} ports allowed per scan request.",
        }

    for p in target_ports:
        if not isinstance(p, int) or p < 1 or p > 65535:
            return {
                "status": "error",
                "message": f"Invalid port number: {p}. Ports must be integers between 1 and 65535.",
            }

    if not confirmed:
        return {
            "status": "confirmation_required",
            "target": target,
            "requested_ports": target_ports,
            "port_services": {p: STANDARD_PORTS.get(p, "Custom") for p in target_ports},
            "message": "Explicit confirmation required before initiating active port probes. Set 'confirmed: true'.",
        }

    # Resolve target and enforce strict SSRF check across all resolved IPs
    clean_host = target.strip().lower().rstrip(".")
    safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(clean_host, port=target_ports[0], resolver=resolver)
    if not safe_all or not resolved_ips:
        return {
            "status": "inconclusive" if reason.startswith("DNS query budget exhausted") else "blocked",
            "message": f"SSRF Guard: Target '{clean_host}' cannot be probed ({reason}). Scanning aborted.",
        }

    target_ip = resolved_ips[0]

    async with GLOBAL_PORT_SCAN_SEMAPHORE:
        semaphore = asyncio.Semaphore(4)

        async def _probe_port(port: int) -> dict[str, Any]:
            svc_name = STANDARD_PORTS.get(port, "Unknown Service")
            async with semaphore:
                try:
                    conn = asyncio.open_connection(target_ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                    # Read banner if immediately available (bounded read)
                    banner: str | None = None
                    try:
                        raw = await asyncio.wait_for(reader.read(128), timeout=0.35)
                        if raw:
                            banner = raw.decode("utf-8", errors="replace").strip()[:80]
                    except Exception:
                        pass
                    writer.close()
                    await writer.wait_closed()
                    return {
                        "port": port,
                        "service": svc_name,
                        "state": "open",
                        "banner": banner,
                        "confidence": "confirmed",
                    }
                except (ConnectionRefusedError, OSError):
                    return {
                        "port": port,
                        "service": svc_name,
                        "state": "closed",
                        "banner": None,
                        "confidence": "confirmed",
                    }
                except asyncio.TimeoutError:
                    return {
                        "port": port,
                        "service": svc_name,
                        "state": "filtered",
                        "banner": None,
                        "confidence": "confirmed",
                    }

        tasks = [_probe_port(p) for p in target_ports]
        port_results = await asyncio.gather(*tasks)

    open_ports = [p for p in port_results if p["state"] == "open"]

    findings: list[dict[str, Any]] = []
    for op in open_ports:
        findings.append({
            "severity": "info",
            "category": "NETWORK",
            "target": f"{target_ip}:{op['port']}",
            "message": f"Port {op['port']} ({op['service']}) is open and responding. Banner: {op['banner'] or 'None'}",
            "evidence": f"TCP SYN/ACK connection confirmed to {target_ip}:{op['port']}",
            "confidence": "confirmed",
        })

    return {
        "status": "completed",
        "target": clean_host,
        "target_ip": target_ip,
        "probed_ports_count": len(target_ports),
        "open_ports_count": len(open_ports),
        "ports": port_results,
        "findings": findings,
    }
