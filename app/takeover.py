"""Bounded CNAME takeover fingerprint checks with explicit evidence levels."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.models import Finding
from app.tls_check import PinnedIPTransport
from app.work_budget import ScanWorkBudget

logger = logging.getLogger(__name__)
MAX_FINGERPRINT_BODY = 16 * 1024
TAKEOVER_DATA_PATH = Path(__file__).resolve().parent / "data" / "takeover_fingerprints.json"
with TAKEOVER_DATA_PATH.open(encoding="utf-8") as stream:
    _TAKEOVER_DATA = json.load(stream)
TAKEOVER_SIGNATURES: list[dict[str, Any]] = _TAKEOVER_DATA["services"]


def _match_provider(cname_target: str) -> dict[str, Any] | None:
    target = cname_target.lower().rstrip(".")
    for service in TAKEOVER_SIGNATURES:
        suffix_match = any(target == suffix or target.endswith("." + suffix) for suffix in service.get("cname_suffixes", []))
        contains_match = any(pattern in target for pattern in service.get("cname_contains", []))
        if suffix_match or contains_match:
            return service
    return None


async def _resolve_target_addresses(
    target: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], str]:
    addresses: list[str] = []
    states: list[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(target, rdtype)
            addresses.extend(str(record.address) for record in answer if hasattr(record, "address"))
            states.append("resolving")
        except dns.resolver.NXDOMAIN:
            states.append("nxdomain")
        except dns.resolver.NoAnswer:
            states.append("no_answer")
        except dns.exception.Timeout:
            states.append("timeout")
        except dns.resolver.NoNameservers:
            states.append("resolver_error")
        except Exception:
            states.append("resolver_error")
    unique = list(dict.fromkeys(addresses))
    if not unique:
        if "timeout" in states:
            return [], "timeout"
        if "resolver_error" in states:
            return [], "resolver_error"
        if "nxdomain" in states:
            return [], "nxdomain"
        return [], "no_answer"
    for address in unique:
        try:
            if not ipaddress.ip_address(address).is_global:
                return [], "unsafe_address"
        except ValueError:
            return [], "unsafe_address"
    return unique, "resolving"


async def _read_fingerprint_page(
    host: str,
    addresses: list[str],
    expected: str,
    budget: ScanWorkBudget,
) -> tuple[bool, str]:
    """Read a tiny HTTPS response over a validated, pinned public IP; never follow redirects."""
    for address in addresses[:2]:
        if not await budget.reserve_http():
            return False, "budget_exhausted"
        try:
            transport = PinnedIPTransport(address, verify=True)
            async with httpx.AsyncClient(transport=transport, timeout=2.0, follow_redirects=False) as client:
                async with client.stream("GET", f"https://{host}/") as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk[: max(0, MAX_FINGERPRINT_BODY - len(body))])
                        if len(body) >= MAX_FINGERPRINT_BODY:
                            break
                    page = bytes(body).decode("utf-8", errors="replace")
                    return expected.casefold() in page.casefold(), "page_checked"
        except Exception as exc:
            logger.info("Takeover fingerprint fetch failed for provider host (%s)", type(exc).__name__)
    return False, "fetch_failed"


def _candidate_result(
    domain: str,
    target: str,
    provider: dict[str, Any] | None,
    evidence: str,
    reason: str,
) -> tuple[dict[str, Any], list[Finding]]:
    service_name = provider["provider"] if provider else "Custom / Unknown"
    remediation = provider["remediation"] if provider else "Remove the obsolete CNAME or point it to an active, owned endpoint."
    message = (
        f"Potential dangling CNAME on `{domain}` points to `{target}` ({service_name}); "
        f"available evidence: {evidence}. Confirm resource ownership with the provider. {remediation}"
    )
    finding = Finding(severity="warning", record_type="TAKEOVER", message=message)
    return {
        "scanned": True,
        "has_cname": True,
        "cname_target": target,
        "provider": service_name,
        "vulnerable": False,
        "status": "candidate",
        "evidence_state": evidence,
        "details": reason,
        "remediation": remediation,
        "last_verified": provider.get("last_verified") if provider else None,
    }, [finding]


async def check_subdomain_takeover(
    domain: str,
    records: dict[str, Any],
    resolver: dns.asyncresolver.Resolver,
    budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Confirm only an exact service fingerprint; DNS-only evidence remains a candidate."""
    cname_entry = records.get("CNAME", {})
    raw_records = cname_entry.get("records", []) if cname_entry.get("status") == "ok" else []
    target = str(raw_records[0]).rstrip(".") if isinstance(raw_records, list) and raw_records else str(raw_records).rstrip(".") if isinstance(raw_records, str) else ""
    if not target:
        return {"scanned": True, "has_cname": False, "vulnerable": False, "status": "safe", "details": "No CNAME record at this hostname."}, []

    work_budget = budget or ScanWorkBudget()
    provider = _match_provider(target)
    addresses, evidence_state = await _resolve_target_addresses(target, resolver)
    if not addresses:
        if evidence_state in ("timeout", "resolver_error", "unsafe_address"):
            logger.info("Takeover DNS lookup inconclusive for %s (%s)", target, evidence_state)
            return {
                "scanned": True,
                "has_cname": True,
                "cname_target": target,
                "provider": provider["provider"] if provider else "Custom / Unknown",
                "vulnerable": False,
                "status": "could_not_verify",
                "evidence_state": evidence_state,
                "details": "The target could not be safely resolved for this check.",
                "last_verified": provider.get("last_verified") if provider else None,
            }, [Finding(severity="info", record_type="TAKEOVER", message=f"Takeover status for `{domain}` could not be verified; DNS lookup was inconclusive.")]
        return _candidate_result(domain, target, provider, evidence_state.upper(), "The target hostname did not resolve; DNS failure alone does not prove claimability.")

    if provider and provider.get("method") == "http_fingerprint" and provider.get("fingerprint"):
        matched, page_state = await _read_fingerprint_page(target, addresses, provider["fingerprint"], work_budget)
        if matched:
            message = (
                f"Confirmed takeover fingerprint for `{domain}` on {provider['provider']}: "
                f"the bounded HTTPS response matched the stored service fingerprint. {provider['remediation']}"
            )
            return {
                "scanned": True,
                "has_cname": True,
                "cname_target": target,
                "provider": provider["provider"],
                "vulnerable": True,
                "status": "confirmed_vulnerability",
                "evidence_state": "http_fingerprint",
                "fingerprint_matched": True,
                "last_verified": provider.get("last_verified"),
                "remediation": provider["remediation"],
            }, [Finding(severity="error", record_type="TAKEOVER", message=message)]
        if page_state == "budget_exhausted":
            return _candidate_result(domain, target, provider, "HTTP_CHECK_BUDGET_EXHAUSTED", "The target resolves, but the scan's outbound-request budget was exhausted.")
        return {
            "scanned": True,
            "has_cname": True,
            "cname_target": target,
            "provider": provider["provider"],
            "vulnerable": False,
            "status": "cloud_hosted",
            "evidence_state": page_state,
            "fingerprint_matched": False,
            "last_verified": provider.get("last_verified"),
            "details": "No stored unclaimed-service fingerprint was observed in the bounded HTTPS response.",
        }, []

    if provider and provider.get("method") == "dns_nxdomain":
        return {
            "scanned": True,
            "has_cname": True,
            "cname_target": target,
            "provider": provider["provider"],
            "vulnerable": False,
            "status": "cloud_hosted",
            "evidence_state": "resolving",
            "last_verified": provider.get("last_verified"),
            "details": "The provider target resolves; no dangling DNS evidence was observed.",
        }, []

    return {
        "scanned": True,
        "has_cname": True,
        "cname_target": target,
        "provider": provider["provider"] if provider else "Custom",
        "vulnerable": False,
        "status": "cloud_hosted" if provider else "safe",
        "evidence_state": "resolving",
        "last_verified": provider.get("last_verified") if provider else None,
        "details": "The CNAME target resolves; no matching takeover fingerprint was confirmed.",
    }, []
