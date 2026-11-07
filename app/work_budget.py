"""Shared per-scan budgets for DNS queries and outbound HTTP requests."""

from __future__ import annotations

import asyncio
from typing import Any

import dns.exception


class ScanWorkBudget:
    def __init__(self, dns_queries: int = 500, http_requests: int = 25):
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

    async def reserve_http(self) -> bool:
        async with self._http_lock:
            if self.http_remaining <= 0:
                return False
            self.http_remaining -= 1
            return True


class BudgetedResolver:
    """Resolver proxy that accounts for each DNS query before sending it."""

    def __init__(self, resolver: Any, budget: ScanWorkBudget):
        object.__setattr__(self, "_resolver", resolver)
        object.__setattr__(self, "budget", budget)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_resolver", "budget"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._resolver, name, value)

    async def resolve(self, *args: Any, **kwargs: Any) -> Any:
        if not await self.budget.reserve_dns():
            raise dns.exception.Timeout("Per-scan DNS query budget exhausted")
        return await self._resolver.resolve(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolver, name)
