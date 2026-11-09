"""Entry-point based registry for independent scan checks.

Plugins return ``(data, findings)`` and receive the same DNS and outbound-work
budgets as the core pipeline. Third-party code is loaded only from installed
``dns_analyzer.checks`` entry points.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.metadata import entry_points
from importlib import import_module
import logging
from pkgutil import iter_modules
from typing import Any, Callable, Awaitable

from app.models import Finding

logger = logging.getLogger(__name__)

CheckRunner = Callable[..., Awaitable[tuple[dict[str, Any], list[Finding]]]]


@dataclass(frozen=True)
class ScanCheck:
    name: str
    run: CheckRunner
    description: str


_CHECKS: dict[str, ScanCheck] = {}
_ENTRY_POINTS_LOADED = False


def register_check(name: str, run: CheckRunner, description: str) -> None:
    """Register or replace an independent scan check by stable name."""
    if not name or not name.replace("_", "").isalnum():
        raise ValueError("Check names must contain only letters, numbers, and underscores")
    _CHECKS[name] = ScanCheck(name=name, run=run, description=description)


def _load_entry_points() -> None:
    global _ENTRY_POINTS_LOADED
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    # Built-ins are discovered from app.checks so a new check needs no main.py
    # or registry edits. Installed third-party checks use Python entry points.
    try:
        package = import_module("app.checks")
        for module_info in iter_modules(package.__path__, package.__name__ + "."):
            module = import_module(module_info.name)
            registrar = getattr(module, "register", None)
            if callable(registrar):
                registrar(register_check)
    except Exception:
        logger.exception("Could not discover built-in scan checks")
    try:
        points = entry_points().select(group="dns_analyzer.checks")
    except Exception:
        logger.exception("Could not enumerate scan check plugins")
        return
    for point in points:
        try:
            registrar = point.load()
            registrar(register_check)
        except Exception:
            logger.exception("Could not load scan check plugin %s", point.name)


async def run_registered_checks(
    domain: str,
    resolver: Any,
    work_budget: Any,
    records: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[Finding]]:
    """Run registered checks concurrently; isolate failures and preserve scan results."""
    _load_entry_points()
    plugins = tuple(_CHECKS.values())
    if not plugins:
        return {}, []

    async def run_one(plugin: ScanCheck) -> tuple[str, dict[str, Any], list[Finding]]:
        try:
            data, findings = await asyncio.wait_for(
                plugin.run(domain, resolver, work_budget, records), timeout=12.0,
            )
            return plugin.name, data, findings
        except Exception as exc:
            logger.warning("Scan check plugin %s failed (%s)", plugin.name, type(exc).__name__)
            return plugin.name, {"status": "inconclusive", "reason": "Check could not complete."}, [
                Finding(
                    severity="inconclusive",
                    record_type=plugin.name.upper(),
                    message=f"{plugin.description} could not complete.",
                ),
            ]

    outcomes = await asyncio.gather(*(run_one(plugin) for plugin in plugins))
    return (
        {name: data for name, data, _ in outcomes},
        [finding for _, _, findings in outcomes for finding in findings],
    )
