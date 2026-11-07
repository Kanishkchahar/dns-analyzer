"""Tests for Scoped Network Inventory & Port Service Verification (app/network_scan.py)."""

import pytest
from app.network_scan import run_list_scan, run_port_scan


@pytest.mark.asyncio
class TestNetworkScan:
    async def test_list_scan_resolves_and_identifies_public_scope(self):
        # Input mixed with public and private IPs
        targets = ["93.184.216.34", "127.0.0.1", "10.0.0.5"]
        res = await run_list_scan(targets)

        assert res["total_targets"] == 3
        assert res["in_scope_count"] == 1
        t_pub = next(t for t in res["targets"] if t["target"] == "93.184.216.34")
        assert t_pub["in_scope_safe"] is True

        t_loop = next(t for t in res["targets"] if t["target"] == "127.0.0.1")
        assert t_loop["in_scope_safe"] is False
        assert any("Loopback" in r for r in t_loop["reasons"])

    async def test_port_scan_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ENABLE_ACTIVE_PORT_SCAN", raising=False)
        res = await run_port_scan("93.184.216.34", ports=[80], confirmed=True)
        assert res["status"] == "disabled"
        assert "disabled by server deployment policy" in res["message"]

    async def test_port_scan_requires_explicit_confirmation(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        res = await run_port_scan("93.184.216.34", ports=[80, 443], confirmed=False)
        assert res["status"] == "confirmation_required"
        assert "Explicit confirmation required" in res["message"]

    async def test_port_scan_ssrf_blocks_private_target(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        res = await run_port_scan("127.0.0.1", ports=[80], confirmed=True)
        assert res["status"] == "blocked"
        assert "SSRF Guard" in res["message"]

    async def test_port_scan_port_limit_and_validation(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        # Exceeds max 10 ports
        many_ports = list(range(1, 15))
        res = await run_port_scan("93.184.216.34", ports=many_ports, confirmed=True)
        assert res["status"] == "error"
        assert "Port count exceeds allowed limit" in res["message"]

        # Invalid port number
        res_invalid = await run_port_scan("93.184.216.34", ports=[0, 80], confirmed=True)
        assert res_invalid["status"] == "error"
        assert "Invalid port number" in res_invalid["message"]

