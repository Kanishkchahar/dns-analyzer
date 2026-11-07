"""Scoped Network Inventory & Port Service Verification.

Implements safe, SSRF-guarded List Scanning (scope resolution without port probes)
and opt-in Port & Service checks against explicitly approved public targets.
"""

import asyncio
import os
import re
import socket
from typing import Any
import dns.asyncresolver

from app.models import Finding
from app.tls_check import is_safe_ip, resolve_and_verify_all_ips

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


def is_active_scan_allowed() -> bool:
    """Check if server configuration permits active port scanning (disabled by default)."""
    val = os.environ.get("ENABLE_ACTIVE_PORT_SCAN", "false").strip().lower()
    return val in ("true", "1", "yes", "enabled")


def verify_port_scan_authorization(
    auth_token: str | None = None,
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
        provided = (auth_token or "").strip()
        if not provided and auth_header:
            if auth_header.lower().startswith("bearer "):
                provided = auth_header[7:].strip()
            else:
                provided = auth_header.strip()
        if not provided or provided != expected_key:
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
) -> dict[str, Any]:
    """Resolve user-approved target scope without probing ports (bounded concurrency & input validation)."""
    clean_targets = [t.strip() for t in targets if t.strip()]
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
            loop = asyncio.get_running_loop()
            try:
                addr_info = await asyncio.wait_for(
                    loop.getaddrinfo(target, None, type=socket.SOCK_STREAM),
                    timeout=2.5,
                )
                all_ips = list(dict.fromkeys(info[4][0] for info in addr_info))
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
            except Exception as exc:
                target_info["reasons"].append(f"Resolution failed: {exc}")

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


async def run_port_scan(
    target: str,
    ports: list[int] | None = None,
    confirmed: bool = False,
    timeout: float = 1.5,
    auth_token: str | None = None,
    auth_header: str | None = None,
) -> dict[str, Any]:
    """Execute scoped, opt-in port and service verification on approved target."""
    if not is_active_scan_allowed():
        return {
            "status": "disabled",
            "message": "Active port scanning is disabled by server deployment policy. Enable server-side authorization via ENABLE_ACTIVE_PORT_SCAN=true.",
        }

    auth_ok, auth_msg = verify_port_scan_authorization(auth_token, auth_header, target)
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
    safe_all, resolved_ips, reason = await resolve_and_verify_all_ips(clean_host, port=target_ports[0])
    if not safe_all or not resolved_ips:
        return {
            "status": "blocked",
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
