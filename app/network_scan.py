"""Scoped Network Inventory & Port Service Verification.

Implements safe, SSRF-guarded List Scanning (scope resolution without port probes)
and opt-in Port & Service checks against explicitly approved public targets.
"""

import asyncio
import socket
from typing import Any
import dns.asyncresolver

from app.models import Finding
from app.tls_check import is_safe_ip

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


async def run_list_scan(
    targets: list[str],
    resolver: dns.asyncresolver.Resolver | None = None,
) -> dict[str, Any]:
    """Resolve user-approved target scope without probing ports (Nmap List Scan equivalent)."""
    res = resolver or dns.asyncresolver.Resolver()
    results: list[dict[str, Any]] = []

    clean_targets = [t.strip() for t in targets if t.strip()]

    async def _resolve_target(target: str) -> dict[str, Any]:
        target_info: dict[str, Any] = {
            "target": target,
            "resolved_ips": [],
            "in_scope_safe": False,
            "reasons": [],
        }

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

        # Resolve A and AAAA records
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
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
) -> dict[str, Any]:
    """Execute scoped, opt-in port and service verification on approved target."""
    target_ports = sorted(list(set(ports or list(STANDARD_PORTS.keys()))))

    if not confirmed:
        return {
            "status": "confirmation_required",
            "target": target,
            "requested_ports": target_ports,
            "port_services": {p: STANDARD_PORTS.get(p, "Custom") for p in target_ports},
            "message": "Explicit confirmation required before initiating active port probes. Set 'confirmed: true'.",
        }

    # Resolve target and enforce SSRF check
    clean_host = target.strip().lower().rstrip(".")
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(clean_host, None, type=socket.SOCK_STREAM)
        if not addr_info:
            return {"status": "error", "message": f"Target '{clean_host}' does not resolve to an IP."}
        target_ip = addr_info[0][4][0]
    except Exception as exc:
        return {"status": "error", "message": f"Target resolution failed: {exc}"}

    safe, reason = is_safe_ip(target_ip)
    if not safe:
        return {
            "status": "blocked",
            "message": f"SSRF Guard: Target '{clean_host}' resolves to blocked IP '{target_ip}' ({reason}). Scanning aborted.",
        }

    semaphore = asyncio.Semaphore(8)

    async def _probe_port(port: int) -> dict[str, Any]:
        svc_name = STANDARD_PORTS.get(port, "Unknown Service")
        async with semaphore:
            try:
                conn = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                # Read banner if immediately available
                banner: str | None = None
                try:
                    raw = await asyncio.wait_for(reader.read(128), timeout=0.4)
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
