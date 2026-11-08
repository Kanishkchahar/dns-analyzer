"""Integration tests for FastAPI endpoints (app/main.py)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
import base64
from pathlib import Path
import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import (
    _CLIENT_REQUESTS,
    _CUSTOM_DKIM_CACHE,
    _MAX_TRACKED_IPS,
    _enforce_rate_limit,
    _get_cached_custom_dkim,
    _store_custom_dkim,
    app,
)
from tests.conftest import MockAnswer, MockResolver, MockRR


def test_dashboard_displays_incomplete_grade_marker():
    source = (Path(__file__).parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert 'data.domain_score?.grade?.endsWith("(incomplete)")' in source
    assert "Grade is provisional (incomplete)" in source


@pytest.mark.asyncio
async def test_custom_dkim_cache_is_keyed_by_normalized_domain_and_selector_set(monkeypatch):
    _CUSTOM_DKIM_CACHE.clear()
    _store_custom_dkim("Example.COM.", ["SelectorB", "selectorA", "selectorB"], {
        "selectors_found": [{"selector": "selectorA"}], "has_dkim": True,
    })
    assert ("example.com", ("selectora", "selectorb")) in _CUSTOM_DKIM_CACHE
    cached = _get_cached_custom_dkim("EXAMPLE.com.")
    assert cached["selectors_found"] == [{"selector": "selectorA"}]

    monkeypatch.setattr("app.main._CUSTOM_DKIM_CACHE_TTL", 0)
    assert _get_cached_custom_dkim("example.com") is None
    _CUSTOM_DKIM_CACHE.clear()


@pytest.mark.asyncio
async def test_rate_limiter_stays_within_client_record_bound(monkeypatch):
    _CLIENT_REQUESTS.clear()
    monkeypatch.setenv("TESTING", "false")
    now = asyncio.get_running_loop().time()
    _CLIENT_REQUESTS.update({f"client-{index}": [now] for index in range(_MAX_TRACKED_IPS)})
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="new-client"))
    _enforce_rate_limit(request)
    assert len(_CLIENT_REQUESTS) == _MAX_TRACKED_IPS
    assert "new-client" in _CLIENT_REQUESTS
    _CLIENT_REQUESTS.clear()


@pytest.fixture
def mock_dns_system():
    """Sets up a comprehensive mock DNS environment for the entire application."""
    a_rr = MockRR(address="93.184.216.34")
    aaaa_rr = MockRR(address="2606:2800:220:1:248:1893:25c8:1946")
    mx_rr = MockRR(preference=10, exchange="mail.example.com.")
    ns_rr = MockRR(target="ns1.example.com.")
    ns2_rr = MockRR(target="ns2.example.com.")
    txt_spf = MockRR(strings=[b"v=spf1 -all"])
    dmarc_rr = MockRR(strings=[b"v=DMARC1; p=reject; pct=100; rua=mailto:rep@example.com"])
    bimi_rr = MockRR(strings=[b"v=BIMI1; l=https://example.com/logo.svg; a="])
    dkim_rr = MockRR(strings=[b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"])
    dnskey_rr = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        f"257 3 13 {base64.b64encode(bytes(range(64))).decode()}",
    )
    ds_rr = dns.dnssec.make_ds(dns.name.from_text("example.com"), dnskey_rr, "SHA256")
    soa_rr = MockRR(
        mname="ns1.example.com.",
        rname="admin.example.com.",
        serial=2026110701,
        refresh=7200,
        retry=3600,
        expire=1209600,
        minimum=3600,
    )

    responses = {
        ("example.com", "A"): MockAnswer([a_rr]),
        ("example.com", "AAAA"): MockAnswer([aaaa_rr]),
        ("example.com", "MX"): MockAnswer([mx_rr]),
        ("example.com", "NS"): MockAnswer([ns_rr, ns2_rr]),
        ("example.com", "TXT"): MockAnswer([txt_spf]),
        ("example.com", "SOA"): MockAnswer([soa_rr]),
        ("example.com", "DNSKEY"): MockAnswer([dnskey_rr]),
        ("example.com", "DS"): MockAnswer([ds_rr]),
        ("_dmarc.example.com", "TXT"): MockAnswer([dmarc_rr]),
        ("default._bimi.example.com", "TXT"): MockAnswer([bimi_rr]),
        ("google._domainkey.example.com", "TXT"): MockAnswer([dkim_rr]),
        ("ns1.example.com", "A"): MockAnswer([a_rr]),
        ("ns2.example.com", "A"): MockAnswer([a_rr]),
        ("mail.example.com", "A"): MockAnswer([a_rr]),
    }
    return MockResolver(responses)


@pytest.fixture(autouse=True)
def mock_external_network_calls():
    """Mock external passive CT logs and TLS probes so unit tests execute deterministically in milliseconds."""
    mock_tls = ({"scanned": True, "tls_version": "TLSv1.3", "certificate": {"is_expired": False, "days_remaining": 90}}, [])
    mock_sub = ({"discovered_count": 0, "subdomains": []}, [])
    mock_axfr = ({"zone": "example.com", "status": "complete", "nameservers_checked": 0, "servers": []}, [])
    mock_wildcard = ({"status": "not_detected", "addresses": [], "records": {"A": [], "AAAA": []}}, [])
    mock_ns_consistency = ({"status": "complete", "observations": [], "serials_match": True, "ns_sets_match": True}, [])
    with patch("app.main.audit_tls_and_https", return_value=mock_tls), \
         patch("app.main.discover_passive_subdomains", return_value=mock_sub), \
         patch("app.main.check_zone_transfers", return_value=mock_axfr), \
         patch("app.main.check_wildcard_dns", return_value=mock_wildcard), \
         patch("app.main.check_nameserver_consistency", return_value=mock_ns_consistency):
        yield


@pytest.mark.asyncio
class TestAPIEndpoints:
    @pytest.mark.parametrize(
        ("method", "path", "payload", "patch_target"),
        [
            ("post", "/api/analyze", {"domain": "example.com"}, "app.main.run_full_scan"),
            ("get", "/api/subdomains/example.com", None, "app.main.discover_passive_subdomains"),
            ("post", "/api/email/dkim-selectors", {"domain": "example.com", "selectors": ["custom"]}, "app.main.check_dkim_selectors"),
            ("get", "/api/report/example.com", None, "app.main.run_full_scan"),
            ("post", "/api/network/list-scan", {"targets": ["example.com"]}, "app.main.run_list_scan"),
            ("post", "/api/network/path-scan", {"targets": ["example.com"]}, "app.main.run_common_path_scan"),
            ("post", "/api/network/port-scan", {"target": "example.com"}, "app.main.run_port_scan"),
            ("get", "/api/badge/example.com", None, "app.main._get_cached_scan"),
        ],
    )
    async def test_endpoint_errors_do_not_expose_exception_details(
        self, method, path, payload, patch_target, monkeypatch,
    ):
        error_text = "ENDPOINT_ERROR_SECRET_SENTINEL"
        mock = Mock(side_effect=RuntimeError(error_text)) if patch_target.endswith("_get_cached_scan") else AsyncMock(side_effect=RuntimeError(error_text))
        monkeypatch.setattr(patch_target, mock)
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await getattr(client, method)(path, json=payload) if payload is not None else await getattr(client, method)(path)
        assert response.status_code == 500
        assert error_text not in response.text
        assert response.json().get("detail")

    async def test_port_scan_validation_does_not_echo_or_log_auth_token(self, caplog):
        token = "AUTH_TOKEN_VALIDATION_SENTINEL"
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/network/port-scan",
                json={"target": "example.com", "auth_token": [token]},
            )
        assert response.status_code == 422
        assert token not in response.text
        assert token not in caplog.text

    async def test_network_path_scan_endpoint(self):
        result = {"scan_mode": "Common Web Paths + Public Robots/Sitemap (No Crawling)", "path_count": 7, "targets": []}
        with patch("app.main.run_common_path_scan", return_value=result) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/network/path-scan", json={"targets": ["example.com"]})

        assert resp.status_code == 200
        assert resp.json()["path_count"] == 7
        assert mocked.await_count == 1
        assert mocked.await_args.args == (["example.com"],)
        assert set(mocked.await_args.kwargs) == {"resolver", "work_budget"}

    async def test_network_path_scan_rejects_more_than_five_targets(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/path-scan", json={"targets": ["example.com"] * 6})

        assert resp.status_code == 400

    async def test_root_serves_html(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "DNS Analyzer" in resp.text
            assert resp.headers["x-content-type-options"] == "nosniff"
            assert resp.headers["x-frame-options"] == "DENY"
            assert "default-src 'self'" in resp.headers["content-security-policy"]

    async def test_health_probes_report_live_and_ready(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            live = await client.get("/health/live")
            ready = await client.get("/health/ready")
        assert live.status_code == 200
        assert live.json() == {"status": "alive"}
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}

    async def test_readiness_probe_fails_when_required_frontend_asset_is_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("app.main.STATIC_DIR", tmp_path)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "not_ready",
            "missing_assets": ["index.html", "app.js", "style.css"],
        }

    async def test_grade_badge_requires_a_recent_scan_and_serves_svg_after_scan(self):
        from app.main import _SCAN_CACHE, _SCAN_CACHE_TTL, _store_cached_scan, run_full_scan

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            missing = await client.get("/api/badge/example.com")
        assert missing.status_code == 404

        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            scan = await run_full_scan("example.com")
        scan.domain_score = scan.domain_score.model_copy(update={"grade": "B (incomplete)"})
        _store_cached_scan("example.com", scan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/badge/example.com")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/svg+xml")
        assert 0 <= int(response.headers["cache-control"].split("=")[-1]) <= int(_SCAN_CACHE_TTL)
        assert "example.com" in response.text
        assert "B (incomplete)" in response.text

        cached_at, cached_scan = _SCAN_CACHE["example.com"]
        _SCAN_CACHE["example.com"] = (cached_at - _SCAN_CACHE_TTL - 1, cached_scan)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            expired = await client.get("/api/badge/example.com")
        assert expired.status_code == 404

    async def test_txt_timeout_does_not_report_spf_missing_or_complete_email_score(self, mock_dns_system):
        from app.main import run_full_scan

        mock_dns_system.responses[("example.com", "TXT")] = dns.exception.Timeout()
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            scan = await run_full_scan("example.com")

        assert scan.email_auth.spf["status"] == "inconclusive"
        spf_failures = [finding for finding in scan.findings if finding.record_type == "SPF"]
        assert spf_failures
        assert all(finding.severity == "inconclusive" for finding in spf_failures)
        assert "(incomplete)" in scan.email_auth.score.grade

    async def test_post_analyze_valid_domain(self, mock_dns_system):
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/analyze", json={"domain": "example.com"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "example.com"
        assert "records" in data
        assert "findings" in data
        assert "summary" in data
        assert "email_auth" in data
        assert "security" in data
        assert "remediation" in data
        assert "bind_zone_snippet" in data
        assert "domain_score" in data
        assert data["summary"]["inconclusive"] == data["domain_score"]["inconclusive_count"]
        assert data["domain_score"]["grade"].split(" ", 1)[0] in ("A+", "A", "B")
        assert data["domain_score"]["scope"].startswith("DNS, email authentication")
        assert "score_breakdown" in data
        assert "caps_applied" in data["score_breakdown"]
        assert "infrastructure" in data["domain_score"]["factors"]
        assert data["email_auth"]["score"]["grade"] in ("A+", "A")
        assert data["security"]["dnssec"]["status"] in ("secured", "delegation_match_verified")

    async def test_post_analyze_sanitized_error_handling(self):
        with patch("app.main.run_full_scan", side_effect=RuntimeError("Secret database connection failed")):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/analyze", json={"domain": "example.com"})

        assert resp.status_code == 500
        data = resp.json()
        assert "Secret database connection failed" not in data["detail"]
        assert "An error occurred during DNS analysis" in data["detail"]

    async def test_post_analyze_url_auto_extract(self, mock_dns_system):
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/analyze",
                    json={"domain": "https://example.com/some/path?param=1"},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"] == "example.com"

    async def test_post_analyze_invalid_domain(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/analyze", json={"domain": "invalid..domain"})

        assert resp.status_code == 422

    async def test_get_report_valid_domain(self, mock_dns_system):
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/report/example.com")

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert 'filename="dns-report-example.com.html"' in resp.headers["content-disposition"]
        assert "TLS &amp; HTTPS Posture" in resp.text
        assert "Passive Subdomain Inventory" in resp.text
        assert "<!DOCTYPE html>" in resp.text
        assert "example.com" in resp.text

    async def test_get_report_invalid_domain_returns_400(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/report/invalid..domain")

        assert resp.status_code == 400

    async def test_post_network_list_scan_api(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/list-scan", json={"targets": ["93.184.216.34", "127.0.0.1"]})

        assert resp.status_code == 200
        data = resp.json()
        assert data["total_targets"] == 2
        assert data["in_scope_count"] == 1

    async def test_post_network_port_scan_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ENABLE_ACTIVE_PORT_SCAN", raising=False)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/port-scan", json={"target": "93.184.216.34", "confirmed": False})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "disabled"

    async def test_post_network_port_scan_confirmation_required(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/port-scan", json={"target": "93.184.216.34", "confirmed": False})

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "confirmation_required"

    async def test_post_network_port_scan_body_token_is_deprecated_and_header_works(self, monkeypatch, caplog):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "super-secret-token")
        transport = ASGITransport(app=app)

        # 1. Without credentials -> 200 with unauthorized status
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/port-scan", json={"target": "93.184.216.34", "confirmed": False})
        assert resp.json()["status"] == "unauthorized"

        # One-release compatibility: JSON authorizes, with a warning that never includes the token.
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/port-scan", json={"target": "93.184.216.34", "confirmed": False, "auth_token": "super-secret-token"})
        assert resp.json()["status"] == "confirmation_required"
        assert "Deprecated port-scan auth_token body field" in caplog.text
        assert "super-secret-token" not in caplog.text

        # 3. With Authorization: Bearer <token> header -> authorized
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/network/port-scan",
                json={"target": "93.184.216.34", "confirmed": False},
                headers={"Authorization": "Bearer super-secret-token"},
            )
        assert resp.json()["status"] == "confirmation_required"

    async def test_analysis_api_does_not_expose_resolver_exception_text(self):
        transport = ASGITransport(app=app)
        with patch("app.main.run_full_scan", side_effect=RuntimeError("RESOLVER_SECRET_SENTINEL")):
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post("/api/analyze", json={"domain": "example.com"})
        assert response.status_code == 500
        assert "RESOLVER_SECRET_SENTINEL" not in response.text
        assert "An error occurred during DNS analysis" in response.text

    async def test_get_report_reuses_cached_scan(self, mock_dns_system):
        from app.main import _store_cached_scan, run_full_scan
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            scan_obj = await run_full_scan("example.com")
            _store_cached_scan("example.com", scan_obj)

        with patch("app.main.run_full_scan") as mock_full_scan:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/report/example.com")
            assert resp.status_code == 200
            assert mock_full_scan.call_count == 0  # Reused cache!

    async def test_api_subdomains_endpoint(self):
        with patch("app.main.discover_passive_subdomains", return_value=({"domain": "example.com", "subdomains": []}, [])):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/subdomains/example.com")
            assert resp.status_code == 200
            assert resp.json()["domain"] == "example.com"

    def test_extract_client_ip_proxy_trust(self, monkeypatch):
        from app.main import _extract_client_ip
        from starlette.requests import Request

        # Case 1: Proxy trust disabled (default)
        monkeypatch.delenv("TRUST_REVERSE_PROXY", raising=False)
        req_scope = {
            "type": "http",
            "client": ("192.168.1.50", 12345),
            "headers": [(b"x-forwarded-for", b"203.0.113.195, 10.0.0.1")],
        }
        req = Request(req_scope)
        assert _extract_client_ip(req) == "192.168.1.50"

        # Case 2: Proxy trust enabled
        monkeypatch.setenv("TRUST_REVERSE_PROXY", "true")
        assert _extract_client_ip(req) == "203.0.113.195"

    async def test_force_refresh_bypasses_cache(self, mock_dns_system):
        from app.main import _store_cached_scan, run_full_scan
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            scan_obj = await run_full_scan("example.com")
            _store_cached_scan("example.com", scan_obj)

        with patch("app.main.run_full_scan", return_value=scan_obj) as mock_full_scan:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # With force_refresh=True, run_full_scan must be called despite cache
                resp = await client.post("/api/analyze", json={"domain": "example.com", "force_refresh": True})
            assert resp.status_code == 200
            assert mock_full_scan.call_count == 1

    async def test_api_analyze_reuses_cached_scan(self, mock_dns_system):
        from app.main import _store_cached_scan, run_full_scan
        with patch("dns.asyncresolver.Resolver", return_value=mock_dns_system):
            scan_obj = await run_full_scan("example.com")
            _store_cached_scan("example.com", scan_obj)

        with patch("app.main.run_full_scan") as mock_full_scan:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/analyze", json={"domain": "example.com"})
            assert resp.status_code == 200
            assert mock_full_scan.call_count == 0  # Reused cache!

    async def test_semaphore_wait_timeout_returns_503(self):
        from app.main import SCAN_SEMAPHORE
        import asyncio

        # Acquire all permits so next request times out waiting on semaphore
        permits = []
        for _ in range(8):
            await SCAN_SEMAPHORE.acquire()
            permits.append(None)

        try:
            with patch("app.main.SEMAPHORE_WAIT_TIMEOUT", 0.05):
                transport = ASGITransport(app=app)
                async with AsyncClient(transport=transport, base_url="http://test") as client:
                    resp_analyze = await client.post("/api/analyze", json={"domain": "example.com"})
                    assert resp_analyze.status_code == 503
                    assert "high scan volume" in resp_analyze.json()["detail"]

                    resp_report = await client.get("/api/report/example.com")
                    assert resp_report.status_code == 503
                    assert "high scan volume" in resp_report.json()["detail"]
        finally:
            for _ in permits:
                SCAN_SEMAPHORE.release()


