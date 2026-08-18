"""Async DNS resolution layer using dnspython."""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype


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

        return {"status": "ok", "records": records, "ttl": ttl}

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return {"status": "not_found", "records": [], "ttl": 0}
    except dns.exception.Timeout:
        return {"status": "timeout", "records": [], "ttl": 0}
    except Exception as exc:
        return {"status": "error", "records": [], "ttl": 0, "error": str(exc)}


async def _resolve_host_to_a(resolver: dns.asyncresolver.Resolver, host: str) -> bool:
    """Check whether a hostname resolves to at least one A record."""
    try:
        await resolver.resolve(host, "A")
        return True
    except Exception:
        return False


async def resolve_domain(domain: str) -> dict[str, Any]:
    """
    Query all required record types concurrently and return a structured dict.
    Also performs secondary A-record lookups for each NS and MX host.
    """
    resolver = dns.asyncresolver.Resolver()
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    # Run all primary lookups concurrently
    tasks = [_safe_query(resolver, domain, rtype) for rtype in record_types]
    results_list = await asyncio.gather(*tasks)
    data: dict[str, Any] = dict(zip(record_types, results_list))

    # Secondary: resolve each NS host
    if data["NS"]["status"] == "ok":
        ns_hosts: list[str] = data["NS"]["records"]
        resolve_tasks = [_resolve_host_to_a(resolver, h) for h in ns_hosts]
        resolve_results = await asyncio.gather(*resolve_tasks)
        data["NS"]["records"] = [
            {"host": h, "resolves": r}
            for h, r in zip(ns_hosts, resolve_results)
        ]

    # Secondary: resolve each MX host
    if data["MX"]["status"] == "ok":
        mx_entries = data["MX"]["records"]
        resolve_tasks = [_resolve_host_to_a(resolver, e["host"]) for e in mx_entries]
        resolve_results = await asyncio.gather(*resolve_tasks)
        data["MX"]["records"] = [
            {**entry, "resolves": res}
            for entry, res in zip(mx_entries, resolve_results)
        ]

    return data
