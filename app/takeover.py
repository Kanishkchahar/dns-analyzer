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
from app.work_budget import ScanBudgetExhausted, ScanWorkBudget
from app.http_config import outbound_http_headers

logger = logging.getLogger(__name__)
MAX_FINGERPRINT_BODY = 16 * 1024
MAX_CNAME_DEPTH = 10
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


async def _read_fingerprint_page(
    host: str,
    addresses: list[str],
    expected: str,
    budget: ScanWorkBudget,
) -> tuple[bool, str]:
    """Try bounded HTTPS then HTTP requests over validated pinned public IPs."""
    for address in addresses[:2]:
        for scheme, verify in (("https", True), ("http", False)):
            if not await budget.reserve_http():
                return False, "budget_exhausted"
            try:
                transport = PinnedIPTransport(address, verify=verify)
                async with httpx.AsyncClient(transport=transport, timeout=2.0, follow_redirects=False, headers=outbound_http_headers()) as client:
                    async with client.stream("GET", f"{scheme}://{host}/") as response:
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk[: max(0, MAX_FINGERPRINT_BODY - len(body))])
                            if len(body) >= MAX_FINGERPRINT_BODY:
                                break
                        if expected.casefold() in bytes(body).decode("utf-8", errors="replace").casefold():
                            return True, f"{scheme}_body_match"
            except Exception as exc:
                logger.info("Takeover fingerprint fetch failed (%s)", type(exc).__name__)
    return False, "fetch_failed"


async def _resolve_addresses(
    host: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], list[str]]:
    addresses: list[str] = []
    states: list[str] = []
    for rdtype in ("A", "AAAA"):
        state = "resolver_error"
        saw_nxdomain = False
        for attempt in range(2):
            try:
                answer = await resolver.resolve(host, rdtype)
                query_addresses = [str(record.address) for record in answer if hasattr(record, "address")]
                addresses.extend(query_addresses)
                state = "resolved" if query_addresses else ("resolver_error" if saw_nxdomain else "no_answer")
                break
            except dns.resolver.NXDOMAIN:
                if attempt == 0:
                    saw_nxdomain = True
                    continue
                state = "nxdomain"
                break
            except dns.resolver.NoAnswer:
                state = "no_answer"
                break
            except ScanBudgetExhausted:
                state = "budget_exhausted"
                break
            except dns.exception.Timeout:
                state = "timeout"
                break
            except dns.resolver.NoNameservers:
                state = "resolver_error"
                break
            except Exception:
                state = "resolver_error"
                break
        states.append(state)

    unique = list(dict.fromkeys(addresses))
    for address in unique:
        try:
            if not ipaddress.ip_address(address).is_global:
                return [], ["unsafe_address"]
        except ValueError:
            return [], ["unsafe_address"]
    return unique, states


async def _resolve_cname_chain(
    seeds: list[str],
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], bool]:
    """Follow every observed alias in bounded chains; return whether a query failed."""
    targets: list[str] = []
    pending = [(str(seed).strip().lower().rstrip("."), 0, frozenset()) for seed in seeds if str(seed).strip()]
    seen: set[str] = set()
    inconclusive = False
    while pending:
        target, depth, ancestors = pending.pop(0)
        if not target:
            continue
        if target in ancestors:
            inconclusive = True
            continue
        if target in seen:
            continue
        seen.add(target)
        targets.append(target)
        if depth >= MAX_CNAME_DEPTH:
            inconclusive = True
            continue
        try:
            answer = await resolver.resolve(target, "CNAME")
            aliases = [str(record.target).rstrip(".").lower() for record in answer if hasattr(record, "target")]
            path = ancestors | {target}
            pending.extend((alias, depth + 1, path) for alias in aliases)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            # Address resolution below may still be definitive. Retain this as
            # incomplete chain evidence rather than turning it into a finding.
            inconclusive = True
    return targets, inconclusive


def _finding_result(
    domain: str,
    target: str,
    provider: dict[str, Any] | None,
    status: str,
    evidence: str,
    details: str,
) -> tuple[dict[str, Any], list[Finding]]:
    provider_name = provider["provider"] if provider else "Custom / Unknown"
    remediation = provider["remediation"] if provider else "Remove an obsolete CNAME or point it to an active resource you control."
    result = {
        "scanned": True,
        "has_cname": True,
        "cname_target": target,
        "provider": provider_name,
        "vulnerable": status == "confirmed",
        "status": status,
        "evidence_state": evidence,
        "details": details,
        "remediation": remediation,
        "last_verified": provider.get("last_verified") if provider else None,
        "verification": provider.get("verification", "unverified") if provider else "unverified",
        "nxdomain_confirms": bool(provider and provider.get("nxdomain_confirms") is True),
    }
    if status == "candidate":
        explanation = (
            "The page matches an unverified signature; this is only a candidate."
            if evidence == "unverified_page_match"
            else "DNS evidence is a candidate, not proof of claimability."
        )
        finding = Finding(
            severity="warning",
            record_type="TAKEOVER",
            message=(f"Potential dangling CNAME on `{domain}` points to `{target}` ({provider_name}); "
                     f"{explanation} {remediation}"),
        )
        return result, [finding]
    if status == "confirmed":
        finding = Finding(
            severity="warning",
            record_type="TAKEOVER",
            message=(f"Unclaimed-service response fingerprint matched for `{domain}` on {provider_name} "
                     f"at `{target}`. This match does not prove provider-side claimability. {remediation}"),
        )
        return result, [finding]
    if status == "inconclusive":
        return result, [Finding(
            severity="info",
            record_type="TAKEOVER",
            message=f"Takeover status for `{domain}` could not be verified ({evidence}); no positive result is claimed.",
        )]
    return result, []


async def check_subdomain_takeover(
    domain: str,
    records: dict[str, Any],
    resolver: dns.asyncresolver.Resolver,
    budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Inspect each CNAME in bounded chains; DNS-only evidence remains a candidate."""
    cname_entry = records.get("CNAME", {})
    raw_records = cname_entry.get("records", []) if cname_entry.get("status") == "ok" else []
    seeds = raw_records if isinstance(raw_records, list) else [raw_records]
    seeds = [str(target).rstrip(".") for target in seeds if str(target).strip()]
    if not seeds:
        return {"scanned": True, "has_cname": False, "vulnerable": False, "status": "safe", "details": "No CNAME record at this hostname."}, []

    work_budget = budget or ScanWorkBudget()
    targets, chain_inconclusive = await _resolve_cname_chain(seeds, resolver)
    candidates: list[tuple[str, dict[str, Any] | None, list[str], list[str]]] = []
    fingerprint_failure = False
    for target in targets:
        provider = _match_provider(target)
        addresses, states = await _resolve_addresses(target, resolver)
        if not addresses:
            if any(state in ("timeout", "budget_exhausted", "resolver_error", "unsafe_address") for state in states):
                fingerprint_failure = True
            candidates.append((target, provider, addresses, states))
            continue

        if provider and provider.get("detection_method") == "http_body":
            expected = provider.get("unclaimed_page_text")
            if not expected:
                fingerprint_failure = True
                continue
            matched, page_state = await _read_fingerprint_page(target, addresses, expected, work_budget)
            if matched:
                if provider.get("verification") == "verified":
                    return _finding_result(
                        domain, target, provider, "confirmed", page_state,
                        "The bounded HTTP response contained the verified stored provider text; claimability still requires provider confirmation.",
                    )
                return _finding_result(
                    domain, target, provider, "candidate", "unverified_page_match",
            "The page matches an unverified signature; provider behavior requires confirmation.",
                )
            if page_state in ("budget_exhausted", "fetch_failed"):
                fingerprint_failure = True

    if fingerprint_failure or chain_inconclusive:
        target, provider = next(((t, p) for t, p, _, _ in candidates), (targets[0], _match_provider(targets[0])))
        state = "budget_exhausted" if work_budget.http_remaining <= 0 else "lookup_or_fetch_failed"
        return _finding_result(domain, target, provider, "inconclusive", state, "One or more DNS-chain or bounded HTTP checks could not complete.")

    if candidates:
        target, provider, _, states = candidates[0]
        if any(state in ("timeout", "budget_exhausted", "resolver_error", "unsafe_address") for state in states):
            return _finding_result(domain, target, provider, "inconclusive", "lookup_or_fetch_failed", "DNS did not return a definitive result.")
        dns_state = "nxdomain" if "nxdomain" in states else "no_address_records"
        if (
            dns_state == "nxdomain"
            and provider
            and provider.get("detection_method") == "nxdomain"
            and provider.get("nxdomain_confirms") is True
            and provider.get("verification") == "verified"
        ):
            return _finding_result(
                domain, target, provider, "confirmed", "verified_nxdomain_rule",
                "The configured provider NXDOMAIN rule was re-queried and matched; provider-side claimability still requires confirmation.",
            )
        # NXDOMAIN is deliberately represented as a candidate: it is DNS-only
        # evidence and cannot establish that a provider resource is claimable.
        return _finding_result(
            domain, target, provider, "candidate", dns_state,
            "The CNAME target did not resolve; DNS failure alone does not prove claimability.",
        )

    return {
        "scanned": True,
        "has_cname": True,
        "cname_target": seeds[0],
        "provider": _match_provider(seeds[0])["provider"] if _match_provider(seeds[0]) else "Custom",
        "vulnerable": False,
        "status": "safe",
        "evidence_state": "resolving",
        "details": "CNAME targets resolved; no matching unclaimed-service fingerprint was observed.",
    }, []
