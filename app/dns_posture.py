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


def _cymru_query_name(address: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        reversed_ip = ".".join(reversed(str(ip).split(".")))
        return f"{reversed_ip}.origin.asn.cymru.com."
    reversed_nibbles = ".".join(reversed(ip.exploded.replace(":", "")))
    return f"{reversed_nibbles}.origin6.asn.cymru.com."


def _parse_cymru_origins(records: list[Any]) -> list[tuple[str, str]]:
    origins: set[tuple[str, str]] = set()
    for record in records:
        chunks = getattr(record, "strings", ())
        if chunks:
            value = "".join(
                part.decode("ascii", errors="replace") if isinstance(part, bytes) else str(part)
                for part in chunks
            )
        else:
            value = str(record).strip('"')
        fields = [field.strip() for field in value.strip('"').split("|")]
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        try:
            prefix = str(ipaddress.ip_network(fields[1], strict=False))
        except ValueError:
            continue
        origins.add((fields[0], prefix))
    return sorted(origins)


async def check_nameserver_asn_diversity(
    nameservers: list[str],
    resolver: dns.asyncresolver.Resolver,
    timeout: float = 2.5,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Compare public authoritative nameserver IPs using Team Cymru's DNS origin service.

    An ASN finding is emitted only when every observed public address for at least
    two distinct nameservers returned a valid origin and all origins match.
    """
    budget = work_budget or ScanWorkBudget()
    budgeted_resolver = budget.resolver_for(resolver, "dns_posture")
    hosts = list(dict.fromkeys(str(item).strip().lower().rstrip(".") for item in nameservers if str(item).strip()))
    if not hosts:
        return {"status": "inconclusive", "nameservers": [], "asns": [], "single_asn": None}, []

    results: list[dict[str, Any]] = []
    for host in hosts:
        addresses = await _host_addresses(host, budgeted_resolver)
        if not addresses:
            results.append({"nameserver": host, "status": "inconclusive", "reason": "No public address lookup completed.", "addresses": []})
            continue
        host_result: dict[str, Any] = {"nameserver": host, "status": "complete", "addresses": []}
        for address in addresses[:16]:
            try:
                query_name = _cymru_query_name(address)
                answer = await asyncio.wait_for(budgeted_resolver.resolve(query_name, "TXT"), timeout=timeout)
                origins = _parse_cymru_origins(list(answer))
                if not origins:
                    host_result["addresses"].append({"ip": address, "status": "no_origin"})
                    host_result["status"] = "partial"
                else:
                    host_result["addresses"].append({
                        "ip": address,
                        "status": "complete",
                        "asns": sorted({asn for asn, _prefix in origins}),
                        "prefixes": sorted({prefix for _asn, prefix in origins}),
                    })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                host_result["addresses"].append({"ip": address, "status": "no_origin"})
                host_result["status"] = "partial"
            except Exception:
                host_result["addresses"].append({"ip": address, "status": "inconclusive"})
                host_result["status"] = "partial"
        results.append(host_result)

    address_results = [
        item
        for host in results
        for item in host.get("addresses", [])
    ]
    observed_asns = sorted({
        asn
        for item in address_results
        for asn in item.get("asns", [])
    })
    complete = (
        len(hosts) >= 2
        and len(results) == len(hosts)
        and all(host.get("status") == "complete" for host in results)
        and len(address_results) > 0
        and all(item.get("status") == "complete" for item in address_results)
    )
    same_asn = len(observed_asns) == 1 if complete else None
    findings: list[Finding] = []
    if complete and same_asn:
        findings.append(Finding(
            severity="warning",
            record_type="NS DIVERSITY",
            message=(
                f"All public addresses for {len(hosts)} authoritative nameservers map to "
                f"origin ASN {observed_asns[0]}. They share one routed network origin; "
                "ASN data does not prove that the servers share a physical site."
            ),
        ))

    status = "complete" if complete else "inconclusive"
    return {
        "status": status,
        "nameservers": results,
        "asns": observed_asns,
        "single_asn": same_asn,
        "source": "Team Cymru IP-to-ASN DNS service",
    }, findings


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
                if not await budget.reserve_dns("dns_posture"):
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
        except Exception:
            # A failed family lookup is not proof that wildcard DNS is absent.
            lookup_errors.append("DNS lookup failed")
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


def _query_direct(server_ip: str, zone: str, rdtype: str, timeout: float, *, tcp: bool = False) -> dns.message.Message:
    query = dns.message.make_query(zone, rdtype)
    query.flags &= ~dns.flags.RD
    return dns.query.tcp(query, server_ip, timeout=timeout) if tcp else dns.query.udp(query, server_ip, timeout=timeout)


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
    async def query_type(rdtype: str) -> tuple[str, list[Any] | None, str | None, bool | None, str | None]:
        if not await budget.reserve_dns("dns_posture"):
            return rdtype, None, "budget_exhausted", None, None
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(_query_direct, address, zone, rdtype, timeout),
                timeout=timeout + 0.25,
            )
            if response.flags & dns.flags.TC:
                if not await budget.reserve_dns("dns_posture"):
                    return rdtype, None, "budget_exhausted_before_tcp_fallback", None, None
                response = await asyncio.wait_for(
                    asyncio.to_thread(_query_direct, address, zone, rdtype, timeout, tcp=True),
                    timeout=timeout + 0.25,
                )
                if response.flags & dns.flags.TC:
                    return rdtype, None, "truncated_tcp_response", bool(response.flags & dns.flags.AA), dns.rcode.to_text(response.rcode())
            if response.rcode() != dns.rcode.NOERROR:
                return rdtype, None, dns.rcode.to_text(response.rcode()), bool(response.flags & dns.flags.AA), dns.rcode.to_text(response.rcode())
            values = _extract_answer(response, rdtype)
            return rdtype, values if values else None, None if values else "missing_answer", bool(response.flags & dns.flags.AA), "NOERROR"
        except Exception:
            return rdtype, None, "DNS lookup failed", None, None

    soa_task = query_type("SOA")
    ns_task = query_type("NS")
    soa_result, ns_result = await asyncio.gather(soa_task, ns_task)
    _, soa_values, soa_error, soa_aa, soa_rcode = soa_result
    _, ns_values, ns_error, ns_aa, ns_rcode = ns_result
    return {
        "nameserver": host,
        "address": address,
        "soa_serial": int(soa_values[0].serial) if soa_values else None,
        "soa_authoritative": soa_aa,
        "soa_rcode": soa_rcode,
        "ns_authoritative": ns_aa,
        "ns_rcode": ns_rcode,
        "soa_fields": ({
            "mname": str(soa_values[0].mname).rstrip(".").lower(),
            "rname": str(soa_values[0].rname).rstrip(".").lower(),
            "refresh": int(soa_values[0].refresh),
            "retry": int(soa_values[0].retry),
            "expire": int(soa_values[0].expire),
            "minimum": int(soa_values[0].minimum),
        } if soa_values else None),
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
    soa_fields = {tuple(sorted(item["soa_fields"].items())) for item in observations if item.get("soa_fields")}
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
    if len(soa_fields) > 1:
        findings.append(Finding(
            severity="warning",
            record_type="NS CONSISTENCY",
            message="Authoritative nameservers disagree on SOA MNAME, RNAME, or timer values (refresh, retry, expire, minimum). Check zone propagation and secondary configuration.",
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
        "soa_fields_match": len(soa_fields) <= 1,
        "ns_sets_match": len(ns_sets) <= 1,
    }, findings


def _parent_referral(server_ip: str, child_zone: str, timeout: float, *, tcp: bool = False) -> dict[str, Any]:
    query = dns.message.make_query(child_zone, "NS")
    query.flags &= ~dns.flags.RD
    response = dns.query.tcp(query, server_ip, timeout=timeout) if tcp else dns.query.udp(query, server_ip, timeout=timeout)
    if response.flags & dns.flags.TC and not tcp:
        return {"server_ip": server_ip, "status": "truncated", "rcode": dns.rcode.to_text(response.rcode()), "nameservers": [], "glue": {}}
    if response.flags & dns.flags.TC:
        return {"server_ip": server_ip, "status": "inconclusive", "reason": "truncated_tcp_response", "nameservers": [], "glue": {}}
    child_name = dns.name.from_text(child_zone)
    ns_hosts = sorted({
        str(item.target).rstrip(".").lower()
        for section in (response.answer, response.authority)
        for rrset in section
        if rrset.name == child_name and rrset.rdtype == dns.rdatatype.NS
        for item in rrset
    })
    glue: dict[str, list[str]] = {host: [] for host in ns_hosts}
    for rrset in response.additional:
        if rrset.rdtype not in (dns.rdatatype.A, dns.rdatatype.AAAA):
            continue
        owner = str(rrset.name).rstrip(".").lower()
        if owner in glue:
            glue[owner].extend(str(item.address) for item in rrset)
    return {
        "server_ip": server_ip,
        "rcode": dns.rcode.to_text(response.rcode()),
        "authoritative": bool(response.flags & dns.flags.AA),
        "nameservers": ns_hosts,
        "glue": {host: sorted(set(values)) for host, values in glue.items()},
    }


async def _query_parent_referral(
    server_ip: str, child_zone: str, timeout: float, budget: ScanWorkBudget,
) -> dict[str, Any]:
    if not await budget.reserve_dns("dns_posture"):
        return {"server_ip": server_ip, "status": "inconclusive", "reason": "budget_exhausted", "nameservers": [], "glue": {}}
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_parent_referral, server_ip, child_zone, timeout),
            timeout=timeout + 0.5,
        )
        if result.get("status") == "truncated":
            if not await budget.reserve_dns("dns_posture"):
                return {"server_ip": server_ip, "status": "inconclusive", "reason": "budget_exhausted_before_tcp_fallback", "nameservers": [], "glue": {}}
            result = await asyncio.wait_for(
                asyncio.to_thread(_parent_referral, server_ip, child_zone, timeout, tcp=True),
                timeout=timeout + 0.5,
            )
        result["status"] = "complete" if result["rcode"] == "NOERROR" and result["nameservers"] else "inconclusive"
        return result
    except Exception:
        return {"server_ip": server_ip, "status": "inconclusive", "reason": "parent_query_failed", "nameservers": [], "glue": {}}


async def check_parent_child_delegation(
    zone: str,
    resolver: dns.asyncresolver.Resolver,
    child_observations: list[dict[str, Any]],
    timeout: float = 2.5,
    work_budget: ScanWorkBudget | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Compare a parent referral and its in-bailiwick glue with direct child answers."""
    budget = work_budget or ScanWorkBudget()
    parent_resolver = budget.resolver_for(resolver, "dns_posture")
    child_name = dns.name.from_text(zone.rstrip(".").lower())
    parent_name = child_name.parent()
    child_text = child_name.to_text(omit_final_dot=True)
    parent_text = parent_name.to_text(omit_final_dot=True) or "."
    result: dict[str, Any] = {
        "status": "inconclusive", "zone": child_text, "parent_zone": parent_text,
        "parent_observations": [], "parent_nameservers": [], "child_nameservers": [],
        "glue": [], "delegation_matches": None, "lame_nameservers": [],
    }
    findings: list[Finding] = []
    try:
        answer = await parent_resolver.resolve(parent_name.to_text(), "NS", lifetime=timeout, search=False)
        parent_hosts = sorted({str(item.target).rstrip(".").lower() for item in answer})
    except Exception:
        result["reason"] = "parent_nameserver_lookup_inconclusive"
        return result, findings
    if not parent_hosts:
        result["reason"] = "parent_nameservers_unavailable"
        return result, findings

    # Query two independent parent authorities when available. A single response
    # is useful evidence, but not enough to declare a delegation mismatch.
    parent_observations = []
    queried_parent_ips: set[str] = set()
    for host in parent_hosts[:4]:
        addresses = await _host_addresses(host, parent_resolver)
        if not addresses:
            continue
        for address in addresses[:2]:
            if address in queried_parent_ips:
                continue
            queried_parent_ips.add(address)
            observation = await _query_parent_referral(address, child_text, timeout, budget)
            observation["nameserver"] = host
            parent_observations.append(observation)
            if observation.get("status") == "complete":
                break
    result["parent_observations"] = parent_observations
    complete_parent = [item for item in parent_observations if item.get("status") == "complete"]
    parent_sets = {tuple(item.get("nameservers", [])) for item in complete_parent}
    if len(complete_parent) < 2 or len(parent_sets) != 1:
        result["reason"] = "parent_responses_incomplete_or_disagree"
        return result, findings

    parent_ns = list(next(iter(parent_sets)))
    child_sets = {
        tuple(sorted(set(item.get("ns_records", []))))
        for item in child_observations
        if item.get("ns_records") and item.get("soa_serial") is not None
        and item.get("soa_authoritative") is True
    }
    child_complete = bool(child_observations) and all(
        item.get("soa_serial") is not None and item.get("ns_records")
        and item.get("soa_authoritative") is True and item.get("ns_authoritative") is True
        and not item.get("errors")
        for item in child_observations
    )
    result["parent_nameservers"] = parent_ns
    result["child_nameservers"] = sorted({host for values in child_sets for host in values})
    lame_hosts = sorted({
        str(item.get("nameserver", "")).rstrip(".").lower()
        for item in child_observations
        if str(item.get("nameserver", "")).rstrip(".").lower() in parent_ns
        and ((item.get("soa_rcode") == "NOERROR" and item.get("soa_authoritative") is False)
             or (item.get("soa_rcode") == "NXDOMAIN" and item.get("soa_authoritative") is True))
    })
    result["lame_nameservers"] = lame_hosts
    if lame_hosts:
        findings.append(Finding(
            severity="warning", record_type="NS DELEGATION",
            message=f"Parent delegation includes nameserver(s) that did not serve the child zone authoritatively: {', '.join(lame_hosts)}. Verify the zone is loaded and the delegation points to the intended service.",
        ))
    if child_complete and len(child_sets) == 1:
        child_ns = list(next(iter(child_sets)))
        result["delegation_matches"] = set(parent_ns) == set(child_ns)
        if not result["delegation_matches"]:
            findings.append(Finding(
                severity="warning", record_type="NS DELEGATION",
                message="Parent and child nameserver sets differ. Confirm the registrar delegation and authoritative zone NS records are synchronized.",
            ))
    else:
        result["reason"] = "child_authority_answers_incomplete_or_disagree"
        return result, findings

    glue_results = []
    for host in parent_ns:
        ns_name = dns.name.from_text(host)
        in_bailiwick = ns_name.is_subdomain(child_name)
        parent_glue = [
            {"server_ip": parent_item["server_ip"], "addresses": parent_item.get("glue", {}).get(host, [])}
            for parent_item in complete_parent
        ]
        observed_glue = sorted({address for item in parent_glue for address in item["addresses"]})
        if not in_bailiwick:
            glue_results.append({"nameserver": host, "required": False, "status": "not_required", "addresses": observed_glue, "parent_observations": parent_glue})
            continue
        parent_glue_sets = {tuple(sorted(set(item["addresses"]))) for item in parent_glue}
        status = "missing" if not observed_glue else "inconsistent" if len(parent_glue_sets) > 1 else "present"
        glue_results.append({"nameserver": host, "required": True, "status": status, "addresses": observed_glue, "parent_observations": parent_glue})
        if status == "missing":
            findings.append(Finding(
                severity="warning", record_type="NS DELEGATION",
                message=f"In-bailiwick nameserver {host} is missing glue in the parent referral. Publish valid glue at the registrar or parent DNS provider.",
            ))
        elif status == "inconsistent":
            findings.append(Finding(
                severity="warning", record_type="NS DELEGATION",
                message=f"Parent authorities disagree on glue for in-bailiwick nameserver {host}. Synchronize glue at the registrar or parent DNS provider.",
            ))
    result["glue"] = glue_results
    result["status"] = "complete"
    result.pop("reason", None)
    return result, findings
