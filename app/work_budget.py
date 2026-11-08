"""Shared per-scan DNS and outbound HTTP budgets with module reservations."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.exception

DEFAULT_DNS_QUERY_BUDGET = 500
DEFAULT_HTTP_REQUEST_BUDGET = 25

# Each allocation is protected from other modules. Sums equal the defaults.
DNS_MODULE_SHARES = {
    "records": 60, "spf": 70, "dkim": 45, "dmarc": 15, "bimi": 5,
    "dnssec": 70, "subdomains": 120, "takeover": 20, "tls": 25,
    "mail_transport": 15, "dns_posture": 25, "network_scan": 10, "shared": 20,
}
HTTP_MODULE_SHARES = {
    "ct": 2, "takeover": 15, "tls": 4, "mail_transport": 1,
    "network_scan": 2, "shared": 1,
}


class ScanBudgetExhausted(dns.exception.Timeout):
    """A per-scan work budget was exhausted before an outbound request."""


class ScanWorkBudget:
    def __init__(
        self,
        dns_queries: int = DEFAULT_DNS_QUERY_BUDGET,
        http_requests: int = DEFAULT_HTTP_REQUEST_BUDGET,
        *,
        profile: str = "full_scan",
        dns_shares: dict[str, int] | None = None,
        http_shares: dict[str, int] | None = None,
    ):
        self.dns_remaining = dns_queries
        self.http_remaining = http_requests
        if profile == "network_scan":
            dns_shares = {"network_scan": dns_queries}
            http_shares = {"network_scan": http_requests}
        elif profile != "full_scan":
            raise ValueError("Unknown scan budget profile")
        self.dns_module_remaining = self._scale_shares(dns_queries, dns_shares or DNS_MODULE_SHARES)
        self.http_module_remaining = self._scale_shares(http_requests, http_shares or HTTP_MODULE_SHARES)
        self._dns_lock = asyncio.Lock()
        self._http_lock = asyncio.Lock()

    @staticmethod
    def _scale_shares(total: int, shares: dict[str, int]) -> dict[str, int]:
        if total < 0 or any(value < 0 for value in shares.values()):
            raise ValueError("Budget and module shares must be non-negative")
        share_total = sum(shares.values())
        if not share_total:
            return {name: 0 for name in shares}
        exact = {name: total * value / share_total for name, value in shares.items()}
        scaled = {name: int(value) for name, value in exact.items()}
        remainder = total - sum(scaled.values())
        order = sorted(shares, key=lambda name: (exact[name] - scaled[name], shares[name]), reverse=True)
        for name in order[:remainder]:
            scaled[name] += 1
        return scaled

    def resolver_for(self, resolver: Any, module: str) -> "BudgetedResolver":
        """Wrap the underlying resolver with this scan's module allocation."""
        while isinstance(resolver, BudgetedResolver):
            resolver = resolver._resolver
        return BudgetedResolver(resolver, self, module=module)

    async def reserve_dns(self, module: str = "shared") -> bool:
        async with self._dns_lock:
            remaining = self.dns_module_remaining.get(module, 0)
            if self.dns_remaining <= 0 or remaining <= 0:
                return False
            self.dns_module_remaining[module] = remaining - 1
            self.dns_remaining -= 1
            return True

    async def reserve_http(self, module: str = "shared") -> bool:
        async with self._http_lock:
            remaining = self.http_module_remaining.get(module, 0)
            if self.http_remaining <= 0 or remaining <= 0:
                return False
            self.http_module_remaining[module] = remaining - 1
            self.http_remaining -= 1
            return True


class BudgetedResolver:
    """Resolver proxy that accounts for each DNS query in a module share."""

    def __init__(self, resolver: Any, budget: ScanWorkBudget, module: str = "shared"):
        object.__setattr__(self, "_resolver", resolver)
        object.__setattr__(self, "budget", budget)
        object.__setattr__(self, "module", module)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_resolver", "budget", "module"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._resolver, name, value)

    async def resolve(self, *args: Any, **kwargs: Any) -> Any:
        if not await self.budget.reserve_dns(self.module):
            raise ScanBudgetExhausted(f"{self.module} DNS query budget exhausted")
        return await self._resolver.resolve(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolver, name)
