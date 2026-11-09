"""Scoped Network Inventory & Port Service Verification.

Implements safe, SSRF-guarded List Scanning (scope resolution without port probes)
and opt-in Port & Service checks against explicitly approved public targets.
"""

import asyncio
from contextlib import suppress
import ipaddress
import hmac
import os
import re
import shutil
from typing import Any
from urllib.parse import urljoin, urlparse
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

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
MAX_NMAP_PORTS_PER_SCAN = 256
MAX_WIDE_PATHS = 64
COMMON_PATH_SCAN_HTTP_BUDGET = 20
WIDE_PATH_SCAN_HTTP_BUDGET = 160
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
WIDE_DIRECTORY_PATHS: tuple[str, ...] = tuple(
    "/" + path for path in (
        "admin/", "login", "dashboard/", "api/", "api/v1/", "docs/", "openapi.json",
        "swagger/", "graphql", "health", "status", "metrics", "debug/", "server-status",
        "backup/", "backups/", "old/", "archive/", "tmp/", "temp/", "test/", "staging/",
        "dev/", "config/", "settings/", ".env", ".git/HEAD", ".well-known/",
        "wp-login.php", "wp-admin/", "xmlrpc.php", "phpinfo.php", "composer.json",
        "package.json", "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
        "crossdomain.xml", "clientaccesspolicy.xml", "favicon.ico", "humans.txt", "ads.txt",
        "app/", "uploads/", "files/", "assets/", "static/", "media/", "images/",
        "cgi-bin/", "console/", "manage/", "oauth/", "auth/", "register", "search",
        "actuator/", "actuator/health", "actuator/env", ".DS_Store", "web.config",
        "error.log", "access.log", "dump.sql", "database.sql",
    )
)
WIDE_SCAN_PATHS: tuple[str, ...] = tuple(dict.fromkeys((*COMMON_WEB_PATHS, *WIDE_DIRECTORY_PATHS)))[:MAX_WIDE_PATHS]
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


def verify_wide_path_authorization(auth_header: str | None, target: str) -> tuple[bool, str]:
    """Apply server policy to the higher-volume fixed directory list."""
    if os.environ.get("ENABLE_WIDE_DIRECTORY_SCAN", "false").strip().lower() not in ("true", "1", "yes", "enabled"):
        return False, "Wide directory discovery is disabled by server policy. Set ENABLE_WIDE_DIRECTORY_SCAN=true and configure WIDE_PATH_SCAN_API_KEY and/or WIDE_PATH_SCAN_ALLOWED_DOMAINS, then restart the server."
    expected_key = os.environ.get("WIDE_PATH_SCAN_API_KEY", "").strip()
    allowed_env = os.environ.get("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "").strip()
    if not expected_key and not allowed_env:
        return False, "Wide directory discovery requires WIDE_PATH_SCAN_API_KEY and/or WIDE_PATH_SCAN_ALLOWED_DOMAINS in the server environment."
    if expected_key:
        provided = auth_header[7:].strip() if auth_header and auth_header.lower().startswith("bearer ") else (auth_header or "").strip()
        if not provided or not hmac.compare_digest(provided, expected_key):
            return False, "Authorization required for wide directory discovery."
    if allowed_env:
        allowed = [item.strip().lower().rstrip(".") for item in allowed_env.split(",") if item.strip()]
        normalized = target.strip().lower().rstrip(".")
        if not any(normalized == item or normalized.endswith(f".{item}") for item in allowed):
            return False, "Target is outside the server's approved wide directory scan scope."
    return True, "Authorized"


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
        if len(target) > 253 or not TARGET_SYNTAX_REGEX.fullmatch(target):
            target_info["reasons"].append("Invalid target syntax or length exceeds 253 characters.")
            target_info["status"] = "invalid"
            return target_info

        # Check if target is already an IP
        ip_candidate = target[1:-1] if target.startswith("[") and target.endswith("]") else target
        is_ip_direct, reason = is_safe_ip(ip_candidate)
        if is_ip_direct:
            target_info["resolved_ips"].append({"ip": ip_candidate, "safe": True, "reason": "Public IP"})
            target_info["in_scope_safe"] = True
            target_info["status"] = "in_scope"
            return target_info
        elif "Invalid IP" not in reason:
            # It was an IP, but unsafe
            target_info["resolved_ips"].append({"ip": ip_candidate, "safe": False, "reason": reason})
            target_info["reasons"].append(reason)
            target_info["status"] = "blocked"
            return target_info

        # Reject malformed DNS names before spending resolver budget. A trailing
        # dot is allowed because it denotes an absolute DNS name.
        hostname = target.rstrip(".")
        labels = hostname.split(".")
        if (
            not hostname
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
            or any(not re.fullmatch(r"[A-Za-z0-9-]+", label) for label in labels)
        ):
            target_info["reasons"].append("Invalid DNS hostname label syntax.")
            target_info["status"] = "invalid"
            return target_info

        # Resolve A and AAAA records with bounded concurrency and timeout
        async with list_semaphore:
            async def query(rdtype: str) -> tuple[list[str], str]:
                try:
                    answer = await asyncio.wait_for(resolver.resolve(target, rdtype), timeout=2.5)
                    records = [str(record.address) for record in answer if hasattr(record, "address")]
                    return records, "resolved" if records else "no_answer"
                except dns.resolver.NXDOMAIN:
                    return [], "nxdomain"
                except dns.resolver.NoAnswer:
                    return [], "no_answer"
                except ScanBudgetExhausted:
                    return [], "budget_exhausted"
                except (asyncio.TimeoutError, dns.exception.Timeout):
                    return [], "timeout"
                except Exception:
                    return [], "error"

            query_results = await asyncio.gather(query("A"), query("AAAA"))
            target_info["dns_status"] = {kind: state for kind, (_addresses, state) in zip(("A", "AAAA"), query_results)}
            all_ips = list(dict.fromkeys(ip for addresses, _state in query_results for ip in addresses))
            unresolved = any(state in ("budget_exhausted", "timeout", "error") for _addresses, state in query_results)
            unsafe = False
            for ip in all_ips:
                safe, ip_reason = is_safe_ip(ip)
                target_info["resolved_ips"].append({"ip": ip, "safe": safe, "reason": ip_reason})
                if not safe:
                    unsafe = True
                    target_info["reasons"].append(ip_reason)

            if unsafe:
                target_info["status"] = "blocked"
            elif unresolved:
                target_info["status"] = "inconclusive"
                states = set(target_info["dns_status"].values())
                if "budget_exhausted" in states:
                    target_info["reasons"].append("DNS query work budget exhausted for one or more address-family lookups.")
                else:
                    target_info["reasons"].append("One or more address-family lookups were inconclusive.")
            elif not all_ips:
                target_info["status"] = "unresolved"
                target_info["reasons"].append("No A or AAAA addresses were returned.")
            else:
                target_info["status"] = "in_scope"
                target_info["in_scope_safe"] = True

        return target_info

    tasks = [_resolve_target(t) for t in clean_targets]
    results = await asyncio.gather(*tasks)

    total_safe = sum(1 for r in results if r["in_scope_safe"])
    return {
        "scan_mode": "List Scan (No port probes)",
        "total_targets": len(clean_targets),
        "in_scope_count": total_safe,
        "inconclusive_count": sum(1 for item in results if item.get("status") == "inconclusive"),
        "unresolved_count": sum(1 for item in results if item.get("status") == "unresolved"),
        "targets": results,
    }


async def run_common_path_scan(
    targets: list[str],
    timeout: float = 3.0,
    resolver: dns.asyncresolver.Resolver | None = None,
    work_budget: ScanWorkBudget | None = None,
    wide: bool = False,
) -> dict[str, Any]:
    """Check fixed public paths and parse same-origin robots/sitemap data, without crawling."""
    clean_targets = [target.strip() for target in targets if target.strip()]
    if not clean_targets or len(clean_targets) > 5:
        raise ValueError("Provide between 1 and 5 target hostnames or public IPs.")
    if wide and len(clean_targets) > 2:
        raise ValueError("Wide directory search is limited to 2 targets per request.")

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

            paths_to_check = list(WIDE_SCAN_PATHS if wide else COMMON_WEB_PATHS)
            path_results = await asyncio.gather(*(_check_path(path) for path in paths_to_check))
            custom_sitemaps = [
                path for path in declared_sitemap_paths
                if path not in COMMON_WEB_PATHS
            ][:3]
            if custom_sitemaps:
                path_results.extend(await asyncio.gather(*(_check_path(path) for path in custom_sitemaps)))
            unavailable_count = sum(item["state"] == "unavailable" for item in path_results)
            inconclusive_count = sum(item["state"] == "inconclusive" for item in path_results)
            redirect_failures = sum(bool(item.get("error")) for item in path_results)
            incomplete_count = max(unavailable_count, inconclusive_count, redirect_failures)
            return {
                "target": target,
                "status": "partial" if incomplete_count else "complete",
                "reason": f"{unavailable_count} path checks could not connect; {inconclusive_count} exhausted their work budget; {redirect_failures} same-host redirect checks were incomplete." if incomplete_count else None,
                "resolved_ips": resolved_ips,
                "paths": path_results,
                "scan_mode": "wide_directory" if wide else "common_paths",
                "advertised_paths": [
                    {"path": path, **details}
                    for path, details in list(advertised.items())[:MAX_ADVERTISED_PATHS]
                ],
            }

    results = await asyncio.gather(*(_scan_target(target) for target in clean_targets))
    return {
        "path_count": len(WIDE_SCAN_PATHS) if wide else len(COMMON_WEB_PATHS),
        "scan_mode": "Wide HTTPS Directory Discovery (Bounded; No Recursion)" if wide else "Common Web Paths + Public Robots/Sitemap (No Crawling)",
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
    scanner: str = "connect",
) -> dict[str, Any]:
    """Execute scoped, opt-in port and service verification on approved target."""
    if not is_active_scan_allowed():
        return {
            "status": "disabled",
            "message": "Active port scanning is disabled by server deployment policy. Set ENABLE_ACTIVE_PORT_SCAN=true and configure PORT_SCAN_API_KEY and/or PORT_SCAN_ALLOWED_DOMAINS for approved targets, then restart the server.",
        }

    auth_ok, auth_msg = verify_port_scan_authorization(auth_header, target)
    if not auth_ok:
        return {"status": "unauthorized", "message": auth_msg}


    if scanner not in ("connect", "nmap"):
        return {"status": "error", "message": "Scanner must be 'connect' or 'nmap'."}
    target_ports = sorted(list(set(ports))) if ports else ([] if scanner == "nmap" else sorted(STANDARD_PORTS))

    # Validate port numbers and cap ports per request
    max_ports = MAX_NMAP_PORTS_PER_SCAN if scanner == "nmap" else MAX_PORTS_PER_SCAN
    if len(target_ports) > max_ports:
        return {
            "status": "error",
            "message": f"Port count exceeds allowed limit: maximum {max_ports} ports allowed for {scanner} scans.",
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
    safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(clean_host, port=target_ports[0] if target_ports else 443, resolver=resolver)
    if not safe_all or not resolved_ips:
        return {
            "status": "inconclusive" if reason.startswith("DNS query budget exhausted") else "blocked",
            "message": f"SSRF Guard: Target '{clean_host}' cannot be probed ({reason}). Scanning aborted.",
        }

    target_ip = resolved_ips[0]

    if scanner == "nmap":
        nmap = shutil.which("nmap")
        if not nmap:
            return {"status": "nmap_unavailable", "target": clean_host,
                    "message": "Nmap is not installed on this server. Install Nmap or select the basic TCP check."}
        port_arg = ",".join(str(port) for port in target_ports)
        args = [nmap, "-sT", "-sV", "--version-light", "-Pn", "--open", "-T3",
                "--max-retries", "1", "--host-timeout", "45s", "-oX", "-"]
        if port_arg:
            args.extend(["-p", port_arg])
        else:
            args.extend(["--top-ports", "100"])
        args.append(target_ip)
        async with GLOBAL_PORT_SCAN_SEMAPHORE:
            try:
                process = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(process.communicate(), timeout=55.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {"status": "timeout", "target": clean_host,
                        "message": "Nmap service identification exceeded the 55 second limit."}
            except asyncio.CancelledError:
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    with suppress(Exception):
                        await process.communicate()
                raise
            except OSError:
                return {"status": "nmap_unavailable", "target": clean_host,
                        "message": "Nmap could not be started on this server."}
        if process.returncode not in (0, 1):
            return {"status": "error", "target": clean_host,
                    "message": "Nmap did not complete successfully."}
        try:
            root = ET.fromstring(stdout)
            port_results = []
            for port_node in root.findall(".//port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                service = service_node.get("name", "unknown") if service_node is not None else "unknown"
                parts = [service_node.get(key, "") for key in ("product", "version", "extrainfo")] if service_node is not None else []
                banner = " ".join(part for part in parts if part).strip() or None
                port_results.append({"port": int(port_node.get("portid", "0")),
                                     "service": service, "state": "open", "banner": banner,
                                     "confidence": "nmap_version_probe"})
        except (ET.ParseError, ValueError):
            return {"status": "error", "target": clean_host,
                    "message": "Nmap returned unparseable results."}
        port_results.sort(key=lambda item: item["port"])
        findings = [{"severity": "info", "category": "NETWORK",
                     "target": f"{target_ip}:{item['port']}",
                     "message": f"Nmap identified {item['service']} on TCP/{item['port']}: {item['banner'] or 'version not identified'}.",
                     "evidence": item["banner"] or "TCP service probe response",
                     "confidence": item["confidence"]} for item in port_results]
        return {"status": "completed", "scanner": "nmap -sT -sV --version-light",
                "target": clean_host, "target_ip": target_ip,
                "probed_ports_count": len(target_ports) if target_ports else 100,
                "open_ports_count": len(port_results), "ports": port_results, "findings": findings}

    async with GLOBAL_PORT_SCAN_SEMAPHORE:
        semaphore = asyncio.Semaphore(4)

        async def _probe_port(port: int) -> dict[str, Any]:
            svc_name = STANDARD_PORTS.get(port, "Unknown Service")
            async with semaphore:
                writer = None
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
                    writer = None
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
                except asyncio.CancelledError:
                    if writer is not None:
                        writer.close()
                        with suppress(Exception):
                            await writer.wait_closed()
                    raise

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
