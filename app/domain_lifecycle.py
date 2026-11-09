"""RDAP domain registration and expiry check, registered as an optional plugin."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from app.http_config import outbound_http_headers
from app.models import Finding
from app.tls_check import PinnedIPTransport, resolve_and_verify_all_ips

logger = logging.getLogger(__name__)
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_bootstrap_cache: tuple[float, dict[str, str]] | None = None
_BOOTSTRAP_TTL_SECONDS = 24 * 60 * 60


async def _rdap_base(domain: str, resolver: Any, budget: Any) -> str | None:
    global _bootstrap_cache
    now = asyncio.get_running_loop().time()
    if _bootstrap_cache and now - _bootstrap_cache[0] < _BOOTSTRAP_TTL_SECONDS:
        mapping = _bootstrap_cache[1]
    else:
        safe, addresses, _ = await resolve_and_verify_all_ips("data.iana.org", resolver=resolver)
        if not safe or not addresses or not await budget.reserve_http("rdap"):
            return None
        try:
            transport = PinnedIPTransport(addresses[0], verify=True)
            async with httpx.AsyncClient(transport=transport, timeout=4.0, headers=outbound_http_headers()) as client:
                response = await client.get(BOOTSTRAP_URL)
            response.raise_for_status()
            bootstrap = response.json()
            mapping: dict[str, str] = {}
            for service in bootstrap.get("services", []):
                if not isinstance(service, list) or len(service) != 2:
                    continue
                suffixes, urls = service
                if not isinstance(suffixes, list) or not isinstance(urls, list):
                    continue
                base = next((item.rstrip("/") for item in urls if isinstance(item, str) and item.startswith("https://")), None)
                if base:
                    for suffix in suffixes:
                        if isinstance(suffix, str):
                            mapping[suffix.lower()] = base
            if not mapping:
                return None
            _bootstrap_cache = (now, mapping)
        except Exception as exc:
            logger.info("IANA RDAP bootstrap unavailable (%s)", type(exc).__name__)
            return None

    tld = domain.rsplit(".", 1)[-1].lower()
    return mapping.get(tld)


async def check_domain_lifecycle(domain: str, resolver: Any, budget: Any, _records: dict[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
    resolver = budget.resolver_for(resolver, "shared")
    base = await _rdap_base(domain, resolver, budget)
    if not base:
        return {"status": "inconclusive", "source": "RDAP"}, [Finding(
            severity="inconclusive", record_type="RDAP", message="Domain registration expiry could not be checked because RDAP discovery was unavailable.",
        )]
    host = urlparse(base).hostname
    if not host:
        return {"status": "inconclusive", "source": "RDAP"}, []
    safe, addresses, _ = await resolve_and_verify_all_ips(host, resolver=resolver)
    if not safe or not addresses or not await budget.reserve_http("rdap"):
        return {"status": "inconclusive", "source": "RDAP", "registry": host}, [Finding(
            severity="inconclusive", record_type="RDAP", message="Domain registration expiry could not be checked because the RDAP registry was unreachable or outside the scan budget.",
        )]

    try:
        transport = PinnedIPTransport(addresses[0], verify=True)
        async with httpx.AsyncClient(transport=transport, timeout=5.0, headers=outbound_http_headers()) as client:
            response = await client.get(f"{base}/domain/{quote(domain, safe='.-')}")
        if response.status_code == 404:
            return {"status": "not_found", "source": "RDAP", "registry": host}, []
        response.raise_for_status()
        payload = response.json()
        expiry_value = next((event.get("eventDate") for event in payload.get("events", [])
                             if str(event.get("eventAction", "")).lower() in ("expiration", "expiry")), None)
        if not expiry_value:
            return {"status": "unavailable", "source": "RDAP", "registry": host}, []
        expires = datetime.fromisoformat(str(expiry_value).replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        days_remaining = (expires - datetime.now(timezone.utc)).days
        data = {"status": "complete", "source": "RDAP", "registry": host,
                "expires": expires.astimezone(timezone.utc).isoformat(), "days_remaining": days_remaining}
        if days_remaining < 0:
            severity, message = "error", f"Domain registration appears to have expired ({days_remaining} days relative to RDAP expiry). Verify at the registrar immediately."
        elif days_remaining <= 30:
            severity, message = "error", f"Domain registration expires in {days_remaining} days. Renew it promptly."
        elif days_remaining <= 90:
            severity, message = "warning", f"Domain registration expires in {days_remaining} days. Confirm auto-renewal and payment details."
        else:
            severity, message = "info", f"RDAP reports domain registration expiry in {days_remaining} days."
        return data, [Finding(severity=severity, record_type="RDAP", message=message)]
    except Exception as exc:
        logger.info("RDAP lookup failed for %s (%s)", domain, type(exc).__name__)
        return {"status": "inconclusive", "source": "RDAP", "registry": host}, [Finding(
            severity="inconclusive", record_type="RDAP", message="Domain registration expiry could not be verified from RDAP.",
        )]


def register(register: Any) -> None:
    register("domain_lifecycle", check_domain_lifecycle,
             "RDAP domain registration and expiry check")


