"""Tests for Scoped Network Inventory & Port Service Verification (app/network_scan.py)."""

import pytest
from app.network_scan import (
    COMMON_WEB_PATHS,
    _parse_robots,
    _parse_sitemap,
    _same_origin_https_url,
    run_common_path_scan,
    run_list_scan,
    run_port_scan,
)


@pytest.mark.asyncio
class TestNetworkScan:
    def test_robots_and_sitemap_extract_same_host_paths_only(self):
        robots = b"Disallow: /private/\nSitemap: https://example.com/custom-map.xml\nSitemap: https://other.example/map.xml"
        sitemap = b"<urlset><url><loc>https://example.com/docs/start</loc></url><url><loc>https://other.example/private</loc></url></urlset>"

        assert _parse_robots(robots, "example.com") == [
            {"path": "/private/", "source": "robots.txt disallow"},
            {"path": "/custom-map.xml", "source": "robots.txt sitemap directive"},
        ]
        assert _parse_sitemap(sitemap, "example.com") == [
            {"path": "/docs/start", "source": "sitemap.xml"},
        ]
        assert _same_origin_https_url("https://example.com/next", "example.com")
        assert not _same_origin_https_url("https://other.example/next", "example.com")

    async def test_common_path_scan_uses_fixed_paths_and_blocks_private_targets(self, monkeypatch):
        async def reject_private(target, port=443):
            return False, ["127.0.0.1"], "Unsafe address '127.0.0.1': Loopback blocked"

        monkeypatch.setattr("app.network_scan.resolve_and_verify_all_ips", reject_private)
        result = await run_common_path_scan(["example.com"])

        assert result["path_count"] == len(COMMON_WEB_PATHS) == 7
        assert result["targets"][0]["status"] == "blocked"
        assert result["targets"][0]["paths"] == []

    async def test_common_path_scan_limits_targets(self):
        with pytest.raises(ValueError, match="between 1 and 5"):
            await run_common_path_scan(["example.com"] * 6)

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
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        res = await run_port_scan("93.184.216.34", ports=[80, 443], confirmed=False)
        assert res["status"] == "confirmation_required"
        assert "Explicit confirmation required" in res["message"]

    async def test_port_scan_ssrf_blocks_private_target(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        res = await run_port_scan("127.0.0.1", ports=[80], confirmed=True)
        assert res["status"] == "blocked"
        assert "SSRF Guard" in res["message"]

    async def test_port_scan_port_limit_and_validation(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        # Exceeds max 10 ports
        many_ports = list(range(1, 15))
        res = await run_port_scan("93.184.216.34", ports=many_ports, confirmed=True)
        assert res["status"] == "error"
        assert "Port count exceeds allowed limit" in res["message"]

        # Invalid port number
        res_invalid = await run_port_scan("93.184.216.34", ports=[0, 80], confirmed=True)
        assert res_invalid["status"] == "error"
        assert "Invalid port number" in res_invalid["message"]

    async def test_port_scan_requires_explicit_server_policy(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.delenv("PORT_SCAN_API_KEY", raising=False)
        monkeypatch.delenv("PORT_SCAN_ALLOWED_DOMAINS", raising=False)
        res = await run_port_scan("93.184.216.34", ports=[80], confirmed=True)
        assert res["status"] == "unauthorized"
        assert "requires an explicit server policy" in res["message"]

    async def test_port_scan_authorization_and_domain_scope(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "secret-token-123")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "example.com, target.org")

        # Missing token
        res = await run_port_scan("example.com", ports=[80], confirmed=True)
        assert res["status"] == "unauthorized"
        assert "API_KEY" in res["message"]

        # Invalid token
        res_bad_tok = await run_port_scan("example.com", ports=[80], confirmed=True, auth_token="wrong-token")
        assert res_bad_tok["status"] == "unauthorized"

        # Disallowed target scope even with valid token
        res_bad_scope = await run_port_scan("malicious.com", ports=[80], confirmed=True, auth_token="secret-token-123")
        assert res_bad_scope["status"] == "unauthorized"
        assert "not in approved server scan scope" in res_bad_scope["message"]

