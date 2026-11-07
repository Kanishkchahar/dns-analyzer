"""Passive Subdomain Discovery & Inventory Engine.

Queries public Certificate Transparency (CT) logs to discover publicly known
subdomains without transmitting packets to target hosts. Resolves DNS footprint
and checks for dangling CNAME exposure.
"""

import asyncio
from datetime import datetime, timezone
import json
from typing import Any
import httpx
import dns.asyncresolver

from app.models import Finding
from app.resolver import _safe_query


async def discover_passive_subdomains(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    max_hosts: int = 40,
    timeout: float = 4.5,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query Certificate Transparency logs for *domain* and passively resolve records."""
    findings: list[Finding] = []
    norm_domain = domain.strip().lower().rstrip(".")

    result: dict[str, Any] = {
        "domain": norm_domain,
        "source": "Certificate Transparency (crt.sh)",
        "discovered_count": 0,
        "subdomains": [],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    discovered_names: set[str] = set()

    try:
        url = f"https://crt.sh/?q=%25.{norm_domain}&output=json"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; DNSAnalyzer/2.0)"}
        async with httpx.AsyncClient(timeout=timeout, verify=True) as client:
            async with client.stream("GET", url, headers=headers) as resp:
                if resp.status_code == 200:
                    chunks = []
                    bytes_read = 0
                    max_bytes = 512 * 1024  # Cap response body to 512 KB
                    async for chunk in resp.aiter_bytes():
                        bytes_read += len(chunk)
                        chunks.append(chunk)
                        if bytes_read >= max_bytes:
                            break
                    raw_text = b"".join(chunks).decode("utf-8", errors="replace")
                    raw_json: list[dict[str, Any]] | None = None
                    is_truncated = bytes_read >= max_bytes
                    try:
                        raw_json = json.loads(raw_text)
                    except json.JSONDecodeError:
                        # If stream was cut at 512 KB, repair array at last complete JSON object
                        last_brace = raw_text.rfind("}")
                        if last_brace != -1:
                            try:
                                repaired_text = raw_text[:last_brace + 1] + "]"
                                raw_json = json.loads(repaired_text)
                                is_truncated = True
                            except Exception:
                                raw_json = None

                    if raw_json and isinstance(raw_json, list):
                        for item in raw_json:
                            if isinstance(item, dict):
                                name_val = item.get("name_value", "")
                                for line in name_val.splitlines():
                                    clean_name = line.strip().lower().lstrip("*.")
                                    if clean_name.endswith(f".{norm_domain}") and clean_name != norm_domain:
                                        discovered_names.add(clean_name)
                        if is_truncated:
                            result["incomplete"] = True
                            findings.append(Finding(
                                severity="info",
                                record_type="Inventory",
                                message=f"Certificate Transparency log stream reached {max_bytes // 1024} KB limit. Partial inventory returned ({len(discovered_names)} subdomains discovered).",
                            ))
                    elif is_truncated:
                        result["incomplete"] = True
                        findings.append(Finding(
                            severity="info",
                            record_type="Inventory",
                            message=f"Certificate Transparency log response exceeded {max_bytes // 1024} KB limit and could not be parsed; inventory incomplete.",
                        ))
    except Exception:
        # crt.sh can occasionally be slow or rate-limited; gracefully continue with empty set
        pass

    # Cap to max_hosts for responsive performance
    sorted_hosts = sorted(list(discovered_names))[:max_hosts]
    result["discovered_count"] = len(sorted_hosts)

    if not sorted_hosts:
        return result, findings

    # Concurrently resolve each discovered host passively via DNS with bounded concurrency
    sub_semaphore = asyncio.Semaphore(10)

    async def _resolve_subdomain(sub: str) -> dict[str, Any]:
        async with sub_semaphore:
            a_task = _safe_query(resolver, sub, "A")
            cname_task = _safe_query(resolver, sub, "CNAME")
            a_res, cname_res = await asyncio.gather(a_task, cname_task)

            ips = a_res.get("records", []) if a_res.get("status") == "ok" else []
            cnames = cname_res.get("records", []) if cname_res.get("status") == "ok" else []
            cname_target = cnames[0] if cnames else None

            status = "resolving" if ips else ("dangling" if cname_target else "inactive")
            return {
                "subdomain": sub,
                "ips": ips,
                "cname": cname_target,
                "status": status,
            }

    sub_tasks = [_resolve_subdomain(h) for h in sorted_hosts]
    sub_results = await asyncio.gather(*sub_tasks)
    result["subdomains"] = sub_results

    dangling_count = sum(1 for s in sub_results if s["status"] == "dangling")
    if dangling_count > 0:
        findings.append(Finding(
            severity="warning",
            record_type="SUBDOMAINS",
            message=f"Discovered {dangling_count} subdomain(s) with dangling CNAME pointers via Certificate Transparency. Review for subdomain takeover risk.",
        ))

    return result, findings
