"""Direct-authority DNS checks with bounded public-address scope."""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
from typing import Any

import dns.asyncresolver
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from app.models import Finding
from app.work_budget import ScanWorkBudget


def _public_addresses(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global and value not in output:
            output.append(value)
    return output


async def _host_addresses(host: str, resolver: dns.asyncresolver.Resolver) -> list[str]:
    async def query(rdtype: str) -> list[str]:
        try:
            answer = await resolver.resolve(host, rdtype)
        except Exception:
            return []
        return [str(item.address) for item in answer if hasattr(item, "address")]

    answers = await asyncio.gather(query("A"), query("AAAA"))
    return _public_addresses(answers[0] + answers[1])


def _transfer_record_count(server_ip: str, zone_name: str, timeout: float) -> int:
    """Attempt TCP AXFR and return only a count; never construct or return zone data."""
    count = 0
    # xfr yields messages as they arrive. Do not retain the message or RDATA objects.
    for message in dns.query.xfr(
        server_ip,
        zone_name,
        timeout=timeout,
        lifetime=timeout,
        relativize=False,
        port=53,
    ):
        for rrset in message.answer:
            count += len(rrset)
    return count


async def _attempt_transfer_record_count(server_ip: str, zone_name: str, timeout: float) -> int:
    return await asyncio.wait_for(
        asyncio.to_thread(_transfer_record_count, server_ip, zone_name, timeout),
        timeout=timeout + 0.5,
    )


async def check_zone_transfers(
    zone: str,
    nameservers: list[str],
    resolver: dns.asyncresolver.Resolver,
    timeout: float = 3.0,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Check each listed authority for an unrestricted AXFR; expose counts only."""
    findings: list[Finding] = []
    budget = work_budget or ScanWorkBudget()
    results: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for raw_host in nameservers:
        host = str(raw_host).strip().lower().rstrip(".")
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        addresses = await _host_addresses(host, resolver)
        if not addresses:
            results.append({"nameserver": host, "status": "unresolved_or_non_public", "records_exposed": 0})
            continue
        server_result = {"nameserver": host, "status": "refused_or_unavailable", "records_exposed": 0}
        for address in addresses:
            try:
                if not await budget.reserve_dns():
                    server_result["status"] = "budget_exhausted"
                    break
                count = await _attempt_transfer_record_count(address, zone, timeout)
                if count > 0:
                    server_result = {"nameserver": host, "status": "transfer_allowed", "records_exposed": count}
                    findings.append(Finding(
                        severity="error",
                        record_type="AXFR",
                        message=f"Nameserver `{host}` allowed an unauthenticated zone transfer ({count} records). Restrict transfers to approved secondary-server IP addresses or require TSIG.",
                    ))
                    break
                server_result = {"nameserver": host, "status": "transfer_allowed_empty", "records_exposed": 0}
            except Exception:
                continue
        results.append(server_result)
    return {"zone": zone, "status": "complete", "nameservers_checked": len(results), "servers": results}, findings


async def check_wildcard_dns(
    zone: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[dict[str, Any], list[Finding]]:
    """Probe a high-entropy label for wildcard A/AAAA behavior."""
    label = f"dns-analyzer-{secrets.token_hex(16)}"
    probe = f"{label}.{zone.rstrip('.')}"
    answers: dict[str, list[str]] = {"A": [], "AAAA": []}
    lookup_errors: list[str] = []
    definitive_negative = 0
    for rdtype in ("A", "AAAA"):
        try:
            response = await resolver.resolve(probe, rdtype)
            answers[rdtype] = _public_addresses([
                str(item.address) for item in response if hasattr(item, "address")
            ])
            if not answers[rdtype]:
                definitive_negative += 1
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            definitive_negative += 1
        except Exception as exc:
            # A failed family lookup is not proof that wildcard DNS is absent.
            lookup_errors.append(type(exc).__name__)
    ips = sorted(set(answers["A"] + answers["AAAA"]))
    status = "detected" if ips else ("inconclusive" if not definitive_negative else "not_detected")
    findings: list[Finding] = []
    if ips:
        findings.append(Finding(
            severity="warning",
            record_type="WILDCARD DNS",
            message=f"A random hostname resolved through wildcard DNS to {', '.join(ips)}. CT names that resolve only to these addresses may be wildcard artifacts; review before treating them as real assets.",
        ))
    elif status == "inconclusive":
        findings.append(Finding(
            severity="info",
            record_type="WILDCARD DNS",
            message="Wildcard DNS could not be evaluated because both random-label address queries failed inconclusively.",
        ))
    return {
        "status": status,
        "probe_label": label,
        "addresses": ips,
        "records": answers,
        "reason": ", ".join(sorted(set(lookup_errors))) if lookup_errors and not ips else None,
    }, findings


def _query_direct(server_ip: str, zone: str, rdtype: str, timeout: float) -> dns.message.Message:
    query = dns.message.make_query(zone, rdtype)
    response = dns.query.udp(query, server_ip, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, server_ip, timeout=timeout)
    return response


def _extract_answer(response: dns.message.Message, rdtype: str) -> list[Any]:
    target_type = dns.rdatatype.from_text(rdtype)
    return [
        rdata
        for rrset in response.answer
        if rrset.rdtype == target_type
        for rdata in rrset
    ]


async def _direct_authority_observation(
    host: str,
    address: str,
    zone: str,
    timeout: float,
    budget: ScanWorkBudget,
) -> dict[str, Any]:
    async def query_type(rdtype: str) -> tuple[str, list[Any] | None, str | None]:
        if not await budget.reserve_dns():
            return rdtype, None, "budget_exhausted"
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(_query_direct, address, zone, rdtype, timeout),
                timeout=timeout + 0.25,
            )
            if response.rcode() != dns.rcode.NOERROR:
                return rdtype, None, dns.rcode.to_text(response.rcode())
            values = _extract_answer(response, rdtype)
            return rdtype, values if values else None, None if values else "missing_answer"
        except Exception as exc:
            return rdtype, None, type(exc).__name__

    soa_task = query_type("SOA")
    ns_task = query_type("NS")
    soa_result, ns_result = await asyncio.gather(soa_task, ns_task)
    _, soa_values, soa_error = soa_result
    _, ns_values, ns_error = ns_result
    return {
        "nameserver": host,
        "address": address,
        "soa_serial": int(soa_values[0].serial) if soa_values else None,
        "ns_records": sorted({str(item.target).rstrip(".").lower() for item in ns_values}) if ns_values else [],
        "errors": {key: value for key, value in (("SOA", soa_error), ("NS", ns_error)) if value},
    }


async def check_nameserver_consistency(
    zone: str,
    nameservers: list[str],
    resolver: dns.asyncresolver.Resolver,
    timeout: float = 2.5,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query each authoritative nameserver directly for SOA serial and NS set."""
    findings: list[Finding] = []
    budget = work_budget or ScanWorkBudget()
    observations: list[dict[str, Any]] = []
    for host in dict.fromkeys(str(item).strip().lower().rstrip(".") for item in nameservers):
        if not host:
            continue
        addresses = await _host_addresses(host, resolver)
        if not addresses:
            observations.append({"nameserver": host, "status": "unresolved_or_non_public", "errors": {"address": "no_public_address"}})
            continue
        host_observations = await asyncio.gather(*(
            _direct_authority_observation(host, address, zone, timeout, budget)
            for address in addresses[:2]
        ))
        observations.extend(host_observations)

    serials = {item["soa_serial"] for item in observations if item.get("soa_serial") is not None}
    ns_sets = {tuple(item["ns_records"]) for item in observations if item.get("ns_records")}
    broken = [item for item in observations if item.get("errors") or not item.get("soa_serial") or not item.get("ns_records")]
    if broken:
        names = sorted({item["nameserver"] for item in broken})
        findings.append(Finding(
            severity="warning",
            record_type="NS CONSISTENCY",
            message=f"Could not obtain both SOA and NS answers directly from {len(names)} listed nameserver(s): {', '.join(names)}. Check delegation and authoritative service.",
        ))
    if len(serials) > 1:
        findings.append(Finding(
            severity="warning",
            record_type="NS CONSISTENCY",
            message="Authoritative nameservers returned different SOA serial numbers. Zone data may be out of sync.",
        ))
    if len(ns_sets) > 1:
        findings.append(Finding(
            severity="warning",
            record_type="NS CONSISTENCY",
            message="Authoritative nameservers returned different NS record sets.",
        ))
    return {
        "status": "partial" if broken else "complete",
        "observations": observations,
        "serials_match": len(serials) <= 1,
        "ns_sets_match": len(ns_sets) <= 1,
    }, findings
