"""Shared per-scan budgets for DNS queries and outbound HTTP requests."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.exception

DEFAULT_DNS_QUERY_BUDGET = 500
DEFAULT_HTTP_REQUEST_BUDGET = 25


class ScanBudgetExhausted(dns.exception.Timeout):
    """A per-scan work budget was exhausted before an outbound request."""


class ScanWorkBudget:
    def __init__(self, dns_queries: int = DEFAULT_DNS_QUERY_BUDGET, http_requests: int = DEFAULT_HTTP_REQUEST_BUDGET):
        self.dns_remaining = dns_queries
        self.http_remaining = http_requests
        self._dns_lock = asyncio.Lock()
        self._http_lock = asyncio.Lock()

    async def reserve_dns(self) -> bool:
        async with self._dns_lock:
            if self.dns_remaining <= 0:
                return False
            self.dns_remaining -= 1
            return True

    def dnssec_resolver(self, resolver: Any, reserved_queries: int = 100) -> "BudgetedResolver":
        """Return a DNSSEC-scoped resolver backed by the scan's shared DNS budget.

        DNSSEC may consume at most the reserved share (and the shared balance if
        its caller supplies a larger allocation in a future configuration).
        The reservation is carved out atomically when this wrapper is created.
        """
        reserved = min(max(0, reserved_queries), self.dns_remaining)
        self.dns_remaining -= reserved
        return BudgetedResolver(resolver, self, module="dnssec", allowance=reserved)

    async def reserve_http(self) -> bool:
        async with self._http_lock:
            if self.http_remaining <= 0:
                return False
            self.http_remaining -= 1
            return True


class BudgetedResolver:
    """Resolver proxy that accounts for each DNS query before sending it."""

    def __init__(self, resolver: Any, budget: ScanWorkBudget, module: str = "shared", allowance: int | None = None):
        object.__setattr__(self, "_resolver", resolver)
        object.__setattr__(self, "budget", budget)
        object.__setattr__(self, "module", module)
        object.__setattr__(self, "allowance", allowance)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_resolver", "budget", "module", "allowance"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._resolver, name, value)

    async def resolve(self, *args: Any, **kwargs: Any) -> Any:
        if self.allowance is not None:
            if self.allowance <= 0:
                raise ScanBudgetExhausted(f"{self.module} DNS query budget exhausted")
            object.__setattr__(self, "allowance", self.allowance - 1)
            return await self._resolver.resolve(*args, **kwargs)
        if not await self.budget.reserve_dns():
            raise ScanBudgetExhausted("Per-scan DNS query budget exhausted")
        return await self._resolver.resolve(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolver, name)
