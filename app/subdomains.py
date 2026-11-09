"""Passive Subdomain Discovery & Inventory Engine.

Queries public Certificate Transparency (CT) logs to discover publicly known
subdomains without transmitting packets to target hosts. Resolves DNS footprint
and checks for dangling CNAME exposure.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any
from urllib.parse import urlencode
import httpx
import dns.asyncresolver

from app.models import Finding
from app.resolver import _safe_query
from app.takeover import check_subdomain_takeover
from app.work_budget import ScanBudgetExhausted, ScanWorkBudget
from app.http_config import outbound_http_headers

logger = logging.getLogger(__name__)
CT_MAX_ATTEMPTS = 2
CT_RETRY_DELAY_SECONDS = 0.1
CT_MAX_RESPONSE_BYTES = 512 * 1024


async def _fetch_ct_response(url: str, timeout: float, budget: ScanWorkBudget, module: str = "ct") -> tuple[int, str, bool, int]:
    """Fetch a bounded CT response with a small retry limit and budget accounting."""
    last_status = 0
    last_error: Exception | None = None
    for attempt in range(1, CT_MAX_ATTEMPTS + 1):
        if not await budget.reserve_http(module):
            error = ScanBudgetExhausted("outbound request budget exhausted")
            error.attempts = attempt - 1
            raise error
        try:
            api_key = os.environ.get("CERTSPOTTER_API_KEY", "").strip() if module == "ct_secondary" else ""
            async with httpx.AsyncClient(timeout=timeout, verify=True, headers=outbound_http_headers()) as client:
                request_headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
                async with client.stream("GET", url, headers=request_headers) as response:
                    last_status = response.status_code
                    if response.status_code == 200:
                        chunks = []
                        bytes_read = 0
                        async for chunk in response.aiter_bytes():
                            remaining = CT_MAX_RESPONSE_BYTES - bytes_read
                            chunks.append(chunk[:remaining])
                            bytes_read += min(len(chunk), remaining)
                            if bytes_read >= CT_MAX_RESPONSE_BYTES:
                                return response.status_code, b"".join(chunks).decode("utf-8", errors="replace"), True, attempt
                        return response.status_code, b"".join(chunks).decode("utf-8", errors="replace"), False, attempt
        except Exception as exc:
            last_error = exc
        if attempt < CT_MAX_ATTEMPTS:
            await asyncio.sleep(CT_RETRY_DELAY_SECONDS * attempt)
    if last_error is not None:
        raise last_error
    return last_status, "", False, CT_MAX_ATTEMPTS


async def discover_passive_subdomains(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    max_hosts: int = 40,
    timeout: float = 4.5,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query Certificate Transparency logs for *domain* and passively resolve records."""
    findings: list[Finding] = []
    norm_domain = domain.strip().lower().rstrip(".")

    result: dict[str, Any] = {
        "domain": norm_domain,
        "source": "Certificate Transparency (crt.sh + SSLMate Cert Spotter)",
        "status": "complete",
        "state": "SOURCE_UNAVAILABLE",
        "discovered_count": 0,
        "subdomains": [],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "attempts": 0,
    }

    discovered_names: dict[str, str | None] = {}
    sources_succeeded: list[str] = []
    sources_failed: list[str] = []
    budget = work_budget or ScanWorkBudget()

    try:
        url = f"https://crt.sh/?q=%25.{norm_domain}&output=json"
        status_code, raw_text, is_truncated, attempts = await _fetch_ct_response(url, timeout, budget)
        result["attempts"] = attempts
        if status_code == 200:
            raw_json: list[dict[str, Any]] | None = None
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

            valid_rows = (
                isinstance(raw_json, list)
                and (not raw_json or all(
                    isinstance(item, dict) and isinstance(item.get("name_value"), str)
                    for item in raw_json
                ))
            )
            if valid_rows:
                sources_succeeded.append("crt.sh")
                for item in raw_json:
                    if isinstance(item, dict):
                        name_val = item.get("name_value", "")
                        first_seen = str(item.get("entry_timestamp") or item.get("not_before") or "") or None
                        for line in name_val.splitlines():
                            clean_name = line.strip().lower().lstrip("*.")
                            if clean_name.endswith(f".{norm_domain}") and clean_name != norm_domain:
                                prior = discovered_names.get(clean_name)
                                if clean_name not in discovered_names or (first_seen and (not prior or first_seen < prior)):
                                    discovered_names[clean_name] = first_seen
                if is_truncated:
                    result["status"] = "partial"
                    result["state"] = "PARTIAL_RESULTS"
                    result["incomplete"] = True
                    findings.append(Finding(
                        severity="info",
                        record_type="Inventory",
                        message=f"Certificate Transparency log stream reached {CT_MAX_RESPONSE_BYTES // 1024} KB limit. Partial inventory returned ({len(discovered_names)} subdomains discovered).",
                    ))
                else:
                    result["state"] = "DISCOVERY_COMPLETED" if discovered_names else "NO_RESULTS"
            elif is_truncated:
                result["status"] = "unavailable"
                result["state"] = "SOURCE_UNAVAILABLE"
                result["reason"] = "Certificate Transparency response was truncated before valid JSON could be recovered."
                result["incomplete"] = True
                findings.append(Finding(
                    severity="info",
                    record_type="Inventory",
                    message=f"Certificate Transparency log response exceeded {CT_MAX_RESPONSE_BYTES // 1024} KB limit and could not be parsed; inventory incomplete.",
                ))
            else:
                result["status"] = "unavailable"
                result["state"] = "SOURCE_UNAVAILABLE"
                result["reason"] = "Certificate Transparency service returned an invalid response."
                findings.append(Finding(
                    severity="info",
                    record_type="Inventory",
                    message="Certificate Transparency results could not be parsed; subdomain inventory is unavailable.",
                ))
        else:
            sources_failed.append("crt.sh")
            result["status"] = "unavailable"
            result["state"] = "SOURCE_UNAVAILABLE"
            result["reason"] = f"Certificate Transparency service returned HTTP {status_code}."
            findings.append(Finding(
                severity="info",
                record_type="Inventory",
                message=f"Certificate Transparency lookup returned HTTP {status_code}; no subdomain inventory was produced.",
            ))
    except Exception as exc:
        sources_failed.append("crt.sh")
        result["status"] = "inconclusive" if isinstance(exc, ScanBudgetExhausted) else "unavailable"
        result["state"] = "SOURCE_UNAVAILABLE" if isinstance(exc, ScanBudgetExhausted) else "TIMEOUT" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else "SOURCE_UNAVAILABLE"
        result["attempts"] = getattr(exc, "attempts", CT_MAX_ATTEMPTS)
        logger.warning("Certificate Transparency lookup failed (%s)", type(exc).__name__)
        result["reason"] = "Certificate Transparency lookup failed"
        findings.append(Finding(
            severity="info",
            record_type="Inventory",
            message="Certificate Transparency lookup failed; subdomain inventory is unavailable.",
        ))

    # A second CT index improves coverage when a source is temporarily missing
    # an issuance. This remains passive: it sends no requests to found hosts.
    try:
        query = urlencode({"domain": norm_domain, "include_subdomains": "true", "expand": "dns_names"})
        status_code, raw_text, truncated, attempts = await _fetch_ct_response(
            f"https://api.certspotter.com/v1/issuances?{query}", timeout, budget, module="ct_secondary",
        )
        result["secondary_attempts"] = attempts
        issuance_rows = json.loads(raw_text) if status_code == 200 and not truncated else None
        if isinstance(issuance_rows, list):
            sources_succeeded.append("SSLMate Cert Spotter")
            for issuance in issuance_rows:
                if not isinstance(issuance, dict) or not isinstance(issuance.get("dns_names"), list):
                    continue
                first_seen = str(issuance.get("not_before") or "") or None
                for name in issuance["dns_names"]:
                    if not isinstance(name, str):
                        continue
                    clean_name = name.strip().lower().lstrip("*.").rstrip(".")
                    if clean_name.endswith(f".{norm_domain}") and clean_name != norm_domain:
                        prior = discovered_names.get(clean_name)
                        if clean_name not in discovered_names or (first_seen and (not prior or first_seen < prior)):
                            discovered_names[clean_name] = first_seen
        else:
            sources_failed.append("SSLMate Cert Spotter")
    except Exception as exc:
        sources_failed.append("SSLMate Cert Spotter")
        logger.info("Secondary CT source unavailable (%s)", type(exc).__name__)

    result["sources"] = sources_succeeded
    if sources_succeeded and sources_failed and result["status"] == "complete":
        result["status"] = "partial"
        result["state"] = "PARTIAL_RESULTS"
        result["incomplete"] = True
        result["reason"] = "One or more Certificate Transparency sources could not be queried."
    elif sources_succeeded and result["status"] == "unavailable":
        result["status"] = "partial"
        result["state"] = "PARTIAL_RESULTS"
        result["incomplete"] = True
        result["reason"] = "Only one Certificate Transparency source returned data."

    # Cap to max_hosts for responsive performance
    discovered_total = len(discovered_names)
    sorted_hosts = sorted(discovered_names)[:max_hosts]
    result["discovered_total"] = discovered_total
    result["discovered_count"] = len(sorted_hosts)
    if discovered_total > max_hosts and result["status"] == "complete":
        result["status"] = "partial"
        result["state"] = "PARTIAL_RESULTS"
        result["incomplete"] = True
        findings.append(Finding(
            severity="info",
            record_type="Inventory",
            message=f"Subdomain inventory was limited to {max_hosts} of {discovered_total} discovered names.",
        ))

    if not sorted_hosts:
        return result, findings

    # Concurrently resolve each discovered host passively via DNS with bounded concurrency
    sub_semaphore = asyncio.Semaphore(10)

    async def _resolve_subdomain(sub: str) -> dict[str, Any]:
        async with sub_semaphore:
            a_task = _safe_query(resolver, sub, "A")
            aaaa_task = _safe_query(resolver, sub, "AAAA")
            cname_task = _safe_query(resolver, sub, "CNAME")
            a_res, aaaa_res, cname_res = await asyncio.gather(a_task, aaaa_task, cname_task)

            ips = (a_res.get("records", []) if a_res.get("status") == "ok" else []) + (aaaa_res.get("records", []) if aaaa_res.get("status") == "ok" else [])
            cnames = cname_res.get("records", []) if cname_res.get("status") == "ok" else []
            cname_target = cnames[0] if cnames else None

            query_statuses = (a_res.get("status"), aaaa_res.get("status"), cname_res.get("status"))
            query_failed = any(s in ("timeout", "no_nameservers", "error") for s in query_statuses)
            status = "resolving" if ips else ("dangling" if cname_target else ("unverified" if query_failed else "inactive"))
            labels = set(sub.split("."))
            risk_tags = sorted(labels.intersection({"dev", "development", "staging", "stage", "test", "testing", "admin", "old", "legacy", "internal", "int", "qa", "uat", "backup"}))
            takeover_data = None
            if cname_target:
                takeover_data, _ = await check_subdomain_takeover(
                    sub,
                    {"CNAME": {"status": "ok", "records": cnames}},
                    budget.resolver_for(resolver, "takeover"),
                    budget=budget,
                )
            return {
                "subdomain": sub,
                "source": "Certificate Transparency",
                "ips": ips,
                "cname": cname_target,
                "cnames": cnames,
                "status": status,
                "first_seen": discovered_names.get(sub),
                "risk_tags": risk_tags,
                "takeover": takeover_data,
            }

    sub_tasks = [_resolve_subdomain(h) for h in sorted_hosts]
    sub_results = await asyncio.gather(*sub_tasks)
    risk_order = {"dangling": 0, "unverified": 1, "resolving": 2, "inactive": 3}
    for item in sub_results:
        tag_weight = 2 if item["risk_tags"] else 0
        takeover_weight = 5 if (item.get("takeover") or {}).get("vulnerable") else 0
        item["risk_score"] = takeover_weight + tag_weight + (1 if item["status"] == "dangling" else 0)
    sub_results.sort(key=lambda item: (-item["risk_score"], risk_order.get(item["status"], 4), item["subdomain"]))
    result["subdomains"] = sub_results

    unresolved_count = sum(1 for item in sub_results if item["status"] == "unverified")
    if unresolved_count:
        if result["status"] == "complete":
            result["status"] = "partial"
        result["state"] = "PARTIAL_RESULTS"
        result["incomplete"] = True
        findings.append(Finding(
            severity="info",
            record_type="Inventory",
            message=f"DNS resolution was inconclusive for {unresolved_count} discovered subdomain(s).",
        ))

    dangling_count = sum(1 for s in sub_results if s["status"] == "dangling")
    if dangling_count > 0:
        findings.append(Finding(
            severity="warning",
            record_type="SUBDOMAINS",
            message=f"Discovered {dangling_count} subdomain(s) with dangling CNAME pointers via Certificate Transparency. Review for subdomain takeover risk.",
        ))

    takeover_hosts = [item["subdomain"] for item in sub_results if (item.get("takeover") or {}).get("vulnerable")]
    if takeover_hosts:
        findings.append(Finding(
            severity="error",
            record_type="SUBDOMAIN TAKEOVER",
            message=f"The CT inventory found {len(takeover_hosts)} hostname(s) with a dangling CNAME matching a known provider signature: {', '.join(takeover_hosts[:8])}{'…' if len(takeover_hosts) > 8 else ''}. Verify ownership and reclaim or remove the DNS alias.",
        ))

    return result, findings
