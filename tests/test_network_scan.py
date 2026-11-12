"""Tests for Scoped Network Inventory & Port Service Verification (app/network_scan.py)."""

import json

import pytest
import dns.exception
from app.network_scan import (
    COMMON_WEB_PATHS,
    MAX_WIDE_PORTS_PER_SCAN,
    STANDARD_PORTS,
    WIDE_PORTS,
    WIDE_SCAN_PATHS,
    _parse_robots,
    _parse_sitemap,
    _same_origin_https_url,
    run_common_path_scan,
    run_list_scan,
    run_port_scan,
    scan_capabilities,
)


@pytest.mark.asyncio
class TestNetworkScan:
    async def test_port_scan_token_uses_constant_time_comparison(self, monkeypatch):
        import hmac
        from unittest.mock import patch
        from app.network_scan import verify_port_scan_authorization

        monkeypatch.setenv("PORT_SCAN_API_KEY", "expected-token")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "example.com")
        with patch("app.network_scan.hmac.compare_digest", wraps=hmac.compare_digest) as compare:
            allowed, _ = verify_port_scan_authorization("Bearer expected-token", "example.com")
        assert allowed is True
        compare.assert_called_once_with("expected-token", "expected-token")

    def test_sitemap_parser_rejects_entity_expansion_payloads(self):
        payload = b'<!DOCTYPE foo [<!ENTITY x "expanded">]><urlset><url><loc>https://example.com/&x;</loc></url></urlset>'
        assert _parse_sitemap(payload, "example.com") == []

    def test_sitemap_parser_rejects_external_entity_payloads(self):
        payload = b'<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><urlset><url><loc>&x;</loc></url></urlset>'
        assert _parse_sitemap(payload, "example.com") == []

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
        async def reject_private(target, port=443, resolver=None):
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

    async def test_list_scan_dns_budget_exhaustion_is_inconclusive(self):
        from app.work_budget import BudgetedResolver, ScanWorkBudget
        budget = ScanWorkBudget(dns_queries=0, http_requests=0)
        result = await run_list_scan(["example.com"], resolver=BudgetedResolver(object(), budget), work_budget=budget)
        assert result["targets"][0]["status"] == "inconclusive"
        assert any("budget exhausted" in reason.lower() for reason in result["targets"][0]["reasons"])

    async def test_list_scan_marks_malformed_hostname_invalid_without_dns(self):
        from tests.conftest import MockResolver

        resolver = MockResolver()
        result = await run_list_scan(["bad..example.com"], resolver=resolver)
        assert result["targets"][0]["status"] == "invalid"
        assert resolver.responses == {}

    async def test_list_scan_reports_empty_answers_as_unresolved(self):
        from tests.conftest import MockResolver

        result = await run_list_scan(["missing.example"], resolver=MockResolver())
        target = result["targets"][0]
        assert target["status"] == "unresolved"
        assert target["dns_status"] == {"A": "nxdomain", "AAAA": "nxdomain"}
        assert result["unresolved_count"] == 1

    async def test_list_scan_keeps_partial_dns_timeout_inconclusive(self):
        from tests.conftest import MockAnswer, MockResolver, MockRR

        resolver = MockResolver({
            ("example.com", "A"): MockAnswer([MockRR(address="93.184.216.34")]),
            ("example.com", "AAAA"): dns.exception.Timeout(),
        })
        result = await run_list_scan(["example.com"], resolver=resolver)
        target = result["targets"][0]
        assert target["status"] == "inconclusive"
        assert target["in_scope_safe"] is False
        assert target["dns_status"]["A"] == "resolved"
        assert target["dns_status"]["AAAA"] == "timeout"
        assert result["inconclusive_count"] == 1

    async def test_list_scan_accepts_bracketed_public_ipv6_literal(self):
        result = await run_list_scan(["[2606:2800:220:1:248:1893:25c8:1946]"])
        target = result["targets"][0]
        assert target["status"] == "in_scope"
        assert target["in_scope_safe"] is True

    async def test_path_scan_http_budget_exhaustion_is_inconclusive_without_fetch(self):
        from app.work_budget import ScanWorkBudget
        budget = ScanWorkBudget(dns_queries=500, http_requests=0)
        result = await run_common_path_scan(["93.184.216.34"], work_budget=budget)
        target = result["targets"][0]
        assert target["status"] == "partial"
        assert all(path["state"] == "inconclusive" for path in target["paths"])
        assert all("budget exhausted" in path["error"].lower() for path in target["paths"])

    async def test_common_path_scan_completes_with_budget_for_all_seven_paths(self, monkeypatch):
        from app import network_scan
        from app.work_budget import ScanWorkBudget

        class Response:
            status_code = 404
            headers = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            def stream(self, *_args, **_kwargs):
                return Response()

        async def safe_public_target(*_args, **_kwargs):
            return True, ["93.184.216.34"], "Public IP"

        monkeypatch.setattr(network_scan, "resolve_and_verify_all_ips", safe_public_target)
        monkeypatch.setattr(network_scan, "PinnedIPTransport", lambda *_args, **_kwargs: object())
        monkeypatch.setattr(network_scan.httpx, "AsyncClient", lambda **_kwargs: Client())

        budget = ScanWorkBudget(
            profile="network_scan",
            dns_queries=500,
            http_requests=len(COMMON_WEB_PATHS),
        )
        result = await run_common_path_scan(["example.com"], work_budget=budget)

        target = result["targets"][0]
        assert target["status"] == "complete"
        assert len(target["paths"]) == len(COMMON_WEB_PATHS) == 7
        assert all(path["state"] == "not_found" for path in target["paths"])
        assert budget.http_remaining == 0

    async def test_port_scan_disabled_by_default(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "test-key")
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

    async def test_wide_port_profile_is_bounded_and_respects_port_gates(self, monkeypatch):
        assert 8 < len(WIDE_PORTS) <= MAX_WIDE_PORTS_PER_SCAN
        assert len(set(WIDE_PORTS)) == len(WIDE_PORTS)
        assert all(1 <= port <= 65535 for port in WIDE_PORTS)
        assert set(STANDARD_PORTS).issubset(set(WIDE_PORTS))

        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        confirmation = await run_port_scan("93.184.216.34", confirmed=False, wide=True)
        assert confirmation["status"] == "confirmation_required"
        assert confirmation["wide"] is True
        assert sorted(confirmation["requested_ports"]) == sorted(WIDE_PORTS)

        # The explicit-ports cap still applies to wide runs, just at the higher bound.
        res = await run_port_scan("93.184.216.34", ports=list(range(1, 102)), confirmed=True, wide=True)
        assert res["status"] == "error"
        assert "maximum 100 ports" in res["message"]

    async def test_scan_capabilities_reports_policy_without_secrets(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "test-key")
        monkeypatch.delenv("ENABLE_ACTIVE_PORT_SCAN", raising=False)
        monkeypatch.delenv("ENABLE_WIDE_DIRECTORY_SCAN", raising=False)
        monkeypatch.delenv("PORT_SCAN_API_KEY", raising=False)
        monkeypatch.delenv("PORT_SCAN_ALLOWED_DOMAINS", raising=False)
        monkeypatch.delenv("WIDE_PATH_SCAN_API_KEY", raising=False)
        monkeypatch.delenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", raising=False)
        defaults = scan_capabilities()
        assert defaults["active_port_scan"]["enabled"] is False
        assert defaults["active_port_scan"]["authorized"] is False
        assert defaults["wide_directory_scan"]["enabled"] is False
        assert defaults["wide_directory_scan"]["path_count"] == len(WIDE_SCAN_PATHS) == 64

        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "secret-token-123")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "example.com, target.org")
        monkeypatch.setenv("ENABLE_WIDE_DIRECTORY_SCAN", "true")
        monkeypatch.setenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "example.com")
        enabled = scan_capabilities()
        assert enabled["active_port_scan"]["enabled"] is True
        assert enabled["active_port_scan"]["authorized"] is True
        assert enabled["active_port_scan"]["requires_api_key"] is True
        assert enabled["active_port_scan"]["allowed_domain_count"] == 2
        assert enabled["wide_directory_scan"]["enabled"] is True
        assert enabled["wide_directory_scan"]["authorized"] is True
        assert enabled["wide_directory_scan"]["scope_restricted"] is True
        serialized = json.dumps(enabled)
        assert "secret-token-123" not in serialized
        assert "example.com" not in serialized

    async def test_port_scan_requires_explicit_server_policy(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "test-key")
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
        res_bad_tok = await run_port_scan("example.com", ports=[80], confirmed=True, auth_header="Bearer wrong-token")
        assert res_bad_tok["status"] == "unauthorized"

        # Disallowed target scope even with valid token
        res_bad_scope = await run_port_scan("malicious.com", ports=[80], confirmed=True, auth_header="Bearer secret-token-123")
        assert res_bad_scope["status"] == "unauthorized"
        assert "not in approved server scan scope" in res_bad_scope["message"]

    async def test_nmap_xml_maps_ssl_tunnel_to_https(self, monkeypatch):
        from unittest.mock import AsyncMock, patch

        nmap_xml = b"""<?xml version="1.0"?>
        <nmaprun scanner="nmap" version="7.99">
          <host>
            <status state="up"/>
            <address addr="103.196.215.223" addrtype="ipv4"/>
            <ports>
              <extraports state="filtered" count="98"/>
              <port protocol="tcp" portid="443">
                <state state="open"/>
                <service name="http" product="nginx" version="1.27.2" tunnel="ssl">
                  <cpe>cpe:/a:igor_sysoev:nginx:1.27.2</cpe>
                </service>
              </port>
              <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http" product="nginx" version="1.27.2"/>
              </port>
            </ports>
          </host>
        </nmaprun>"""

        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (nmap_xml, b"")
        mock_proc.returncode = 0

        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")

        with patch("shutil.which", return_value="/usr/bin/nmap"):
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                res = await run_port_scan("103.196.215.223", ports=[443, 80], confirmed=True, scanner="nmap")

        assert res["status"] == "completed"
        assert res["extraports_summary"]["filtered"] == 98
        ports = {p["port"]: p for p in res["ports"]}
        assert ports[443]["service"] == "https"
        assert ports[443]["banner"] == "nginx 1.27.2"
        assert ports[443]["cpe"] == "cpe:/a:igor_sysoev:nginx:1.27.2"
        assert ports[80]["service"] == "http"

    def test_normalize_network_target(self):
        from app.network_scan import _normalize_network_target

        assert _normalize_network_target("example.com") == ("example.com", None)
        assert _normalize_network_target("EXAMPLE.COM.") == ("example.com", None)
        assert _normalize_network_target("https://example.com/test") == ("example.com", None)
        assert _normalize_network_target("http://example.com:8080/test") == ("example.com", 8080)
        assert _normalize_network_target("example.com:443") == ("example.com", 443)
        assert _normalize_network_target("93.184.216.34:80") == ("93.184.216.34", 80)
        assert _normalize_network_target("2001:db8::1") == ("2001:db8::1", None)
        assert _normalize_network_target("[2001:db8::1]:9000") == ("2001:db8::1", 9000)
        assert _normalize_network_target("https://[2001:db8::1]:8443/api") == ("2001:db8::1", 8443)
        assert _normalize_network_target("") == ("", None)

    def test_authorization_with_normalized_targets(self, monkeypatch):
        from app.network_scan import verify_port_scan_authorization, verify_wide_path_authorization

        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "global-key")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "port-secret")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "example.com")
        monkeypatch.setenv("ENABLE_WIDE_DIRECTORY_SCAN", "true")
        monkeypatch.setenv("WIDE_PATH_SCAN_API_KEY", "wide-secret")
        monkeypatch.setenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "example.com")

        # URL and host:port with allowed domain should pass scope check
        ok, _ = verify_port_scan_authorization("Bearer port-secret", "https://sub.example.com:8443/path")
        assert ok is True

        ok, _ = verify_wide_path_authorization("Bearer wide-secret", "https://example.com:443/")
        assert ok is True

        # Target not matching scope should fail
        not_ok, msg = verify_port_scan_authorization("Bearer port-secret", "https://other.org:8080")
        assert not_ok is False
        assert "not in approved server scan scope" in msg


