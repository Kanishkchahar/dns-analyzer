"""Async DNS resolution layer using dnspython."""

import asyncio
import logging
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
from app.work_budget import ScanBudgetExhausted

logger = logging.getLogger(__name__)


async def _safe_query(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str) -> dict[str, Any]:
    """Run a single DNS query and return a structured result, catching all expected errors."""
    try:
        answer = await resolver.resolve(domain, rtype)
        ttl: int = answer.rrset.ttl if answer.rrset else 0
        records: Any = []

        if rtype == "A":
            records = [rr.address for rr in answer]
        elif rtype == "AAAA":
            records = [rr.address for rr in answer]
        elif rtype == "MX":
            records = [
                {"priority": rr.preference, "host": str(rr.exchange).rstrip(".")}
                for rr in answer
            ]
        elif rtype == "NS":
            records = [str(rr.target).rstrip(".") for rr in answer]
        elif rtype == "TXT":
            records = [b"".join(rr.strings).decode("utf-8", errors="replace") for rr in answer]
        elif rtype == "CNAME":
            records = [str(rr.target).rstrip(".") for rr in answer]
        elif rtype == "SOA":
            rr = answer[0]
            records = {
                "mname": str(rr.mname).rstrip("."),
                "rname": str(rr.rname).rstrip("."),
                "serial": rr.serial,
                "refresh": rr.refresh,
                "retry": rr.retry,
                "expire": rr.expire,
                "minimum": rr.minimum,
            }
        elif rtype == "CAA":
            records = [
                {
                    "flags": rr.flags,
                    "tag": rr.tag.decode("ascii", errors="replace") if isinstance(rr.tag, bytes) else str(rr.tag),
                    "value": rr.value.decode("utf-8", errors="replace") if isinstance(rr.value, bytes) else str(rr.value),
                }
                for rr in answer
            ]

        return {"status": "ok", "records": records, "ttl": ttl}

    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "records": [], "ttl": 0, "reason": "Non-existent domain (NXDOMAIN)"}
    except dns.resolver.NoAnswer:
        return {"status": "no_answer", "records": [], "ttl": 0, "reason": "No record of the requested type"}
    except dns.resolver.NoNameservers:
        return {"status": "no_nameservers", "records": [], "ttl": 0, "reason": "DNS nameserver lookup failed"}
    except ScanBudgetExhausted:
        return {"status": "budget_exhausted", "records": [], "ttl": 0, "reason": "Per-scan DNS query budget exhausted"}
    except dns.exception.Timeout:
        return {"status": "timeout", "records": [], "ttl": 0, "reason": "Query timed out"}
    except Exception as exc:
        logger.warning("DNS %s query failed for requested name (%s)", rtype, type(exc).__name__)
        return {"status": "error", "records": [], "ttl": 0, "reason": "DNS lookup failed"}



async def _resolve_host_addresses(resolver: dns.asyncresolver.Resolver, host: str) -> dict[str, Any]:
    """Check both address families without treating lookup failures as absence."""
    async def query(rtype: str) -> tuple[str, str]:
        try:
            answer = await resolver.resolve(host, rtype)
            return rtype, "present" if len(answer) else "absent"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return rtype, "absent"
        except Exception:
            # Timeout, SERVFAIL, budget exhaustion, and resolver errors do not
            # prove that the hostname has no address records.
            return rtype, "inconclusive"

    outcomes = dict(await asyncio.gather(query("A"), query("AAAA")))
    families = [rtype for rtype, status in outcomes.items() if status == "present"]
    if families:
        return {"resolves": True, "resolution_status": "resolved", "address_families": families}
    if all(status == "absent" for status in outcomes.values()):
        return {"resolves": False, "resolution_status": "unresolved", "address_families": []}
    return {"resolves": False, "resolution_status": "inconclusive", "address_families": []}


async def _resolve_host_to_a(resolver: dns.asyncresolver.Resolver, host: str) -> bool:
    """Backward-compatible predicate: true when A or AAAA resolves."""
    return (await _resolve_host_addresses(resolver, host))["resolves"]


async def discover_zone_apex(domain: str, resolver: dns.asyncresolver.Resolver) -> str:
    """
    Discover the authoritative zone apex for a submitted hostname by ascending domain labels.
    RFC 1034/1035: Every authoritative zone cut has an SOA record at its apex.
    e.g. 'api.staging.example.com' -> discovers 'example.com' as authoritative zone apex.
    """
    norm = domain.rstrip(".").lower()
    labels = norm.split(".")
    # If already a 2-label domain (or single label), return as is
    if len(labels) <= 2:
        return norm

    # Ascend labels from current hostname up to domain.tld
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        try:
            ans = await resolver.resolve(candidate, "SOA")
            if ans and len(ans) > 0:
                return candidate
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue

    return norm


async def resolve_domain(domain: str, resolver: dns.asyncresolver.Resolver | None = None) -> dict[str, Any]:
    """
    Query all required record types concurrently and return a structured dict.
    Discovers authoritative zone apex for subdomains to prevent false missing-NS/SOA alerts.
    Also performs secondary A and AAAA lookups for each NS and MX host.
    """
    resolver = resolver or dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 6.0
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    norm_domain = domain.rstrip(".").lower()

    # Discover zone apex concurrently with primary hostname lookups
    apex_task = discover_zone_apex(norm_domain, resolver)
    query_tasks = [_safe_query(resolver, norm_domain, rtype) for rtype in record_types]

    zone_apex, *results_list = await asyncio.gather(apex_task, *query_tasks)
    data: dict[str, Any] = dict(zip(record_types, results_list))

    is_subdomain = (zone_apex != norm_domain)
    data["zone_metadata"] = {
        "zone_apex": zone_apex,
        "is_subdomain": is_subdomain,
        "queried_domain": norm_domain,
        "heuristic_notice": "Discovered candidate zone apex via SOA label traversal. This is heuristic metadata and does not guarantee authoritative ownership scope for complex delegated topologies.",
    }

    # If subdomain has no dedicated NS/SOA delegation, inherit from discovered authoritative zone apex
    if is_subdomain:
        if data["NS"]["status"] != "ok" or not data["NS"]["records"]:
            apex_ns = await _safe_query(resolver, zone_apex, "NS")
            if apex_ns["status"] == "ok" and apex_ns["records"]:
                data["NS"] = {
                    **apex_ns,
                    "inherited_from": zone_apex,
                }
        if data["SOA"]["status"] != "ok" or not data["SOA"]["records"]:
            apex_soa = await _safe_query(resolver, zone_apex, "SOA")
            if apex_soa["status"] == "ok" and apex_soa["records"]:
                data["SOA"] = {
                    **apex_soa,
                    "inherited_from": zone_apex,
                }
        if data["CAA"]["status"] == "no_answer":
            labels = norm_domain.split(".")
            apex_labels = zone_apex.split(".")
            for offset in range(1, max(1, len(labels) - len(apex_labels) + 1)):
                candidate = ".".join(labels[offset:])
                if candidate == norm_domain:
                    continue
                parent_caa = await _safe_query(resolver, candidate, "CAA")
                if parent_caa["status"] == "ok" and parent_caa["records"]:
                    data["CAA"] = {**parent_caa, "inherited_from": candidate}
                    break

    # Secondary: resolve each NS host
    if data["NS"]["status"] == "ok":
        ns_hosts: list[str] = data["NS"]["records"]
        resolve_tasks = [_resolve_host_addresses(resolver, h) for h in ns_hosts]
        resolve_results = await asyncio.gather(*resolve_tasks)
        data["NS"]["records"] = [
            {"host": h, **r}
            for h, r in zip(ns_hosts, resolve_results)
        ]

    # Secondary: resolve each MX host
    if data["MX"]["status"] == "ok":
        mx_entries = data["MX"]["records"]
        resolve_tasks = [_resolve_host_addresses(resolver, e["host"]) for e in mx_entries]
        resolve_results = await asyncio.gather(*resolve_tasks)
        data["MX"]["records"] = [
            {**entry, **res}
            for entry, res in zip(mx_entries, resolve_results)
        ]

    return data
