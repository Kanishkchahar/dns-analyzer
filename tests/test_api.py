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
    _TARGET_LAST_SCAN,
    _enforce_target_cooldown,
    _enforce_rate_limit,
    _await_scan_or_disconnect,
    _get_cached_custom_dkim,
    _store_custom_dkim,
    app,
)
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
async def test_scan_work_is_cancelled_when_client_disconnects():
    class DisconnectedRequest:
        async def is_disconnected(self):
            return True

    cancelled = asyncio.Event()

    async def long_running_scan():
        try:
            await asyncio.sleep(10)
        finally:
            cancelled.set()

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await _await_scan_or_disconnect(DisconnectedRequest(), long_running_scan())
    assert exc.value.status_code == 499
    assert cancelled.is_set()


def test_optional_api_key_auth_and_rejection(monkeypatch):
    from starlette.requests import Request
    from fastapi import HTTPException
    from app.auth import require_api_key

    scope = {"type": "http", "headers": []}
    request = Request(scope)
    monkeypatch.delenv("DNS_ANALYZER_API_KEYS", raising=False)
    require_api_key(request)

    monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "first-secret, second-secret")
    with pytest.raises(HTTPException) as missing:
        require_api_key(request)
    assert missing.value.status_code == 401

    request = Request({"type": "http", "headers": [(b"authorization", b"Bearer second-secret")]})
    require_api_key(request)
    request = Request({"type": "http", "headers": [(b"authorization", b"Bearer wrong-secret")]})
    with pytest.raises(HTTPException) as invalid:
        require_api_key(request)
    assert invalid.value.status_code == 401


def test_local_hostname_lookups_are_cached_but_configured_names_stay_dynamic(monkeypatch):
    from app import auth

    auth._local_hostnames.cache_clear()
    hostname = Mock(return_value="scanner")
    fqdn = Mock(return_value="scanner.example.net")
    monkeypatch.setattr(auth.socket, "gethostname", hostname)
    monkeypatch.setattr(auth.socket, "getfqdn", fqdn)
    try:
        first = auth.blocked_target_names()
        monkeypatch.setenv("DNS_ANALYZER_BLOCKED_TARGETS", "extra.example.org")
        second = auth.blocked_target_names()
        assert first == {"localhost", "localhost.localdomain", "scanner", "scanner.example.net"}
        assert second == first | {"extra.example.org"}
        hostname.assert_called_once_with()
        fqdn.assert_called_once_with()
    finally:
        auth._local_hostnames.cache_clear()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("post", "/api/analyze", {"domain": "example.com"}),
        ("get", "/api/report/example.com", None),
        ("post", "/api/network/list-scan", {"targets": ["example.com"]}),
    ],
)
async def test_scan_api_returns_401_when_api_keys_are_configured(monkeypatch, method, path, payload):
    monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "configured-secret")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.request(method, path, json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_expensive_rate_limit_returns_429():
    from fastapi import HTTPException

    _CLIENT_REQUESTS.clear()
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="198.51.100.19"))
    _enforce_rate_limit(request, limit=1)
    with pytest.raises(HTTPException) as limited:
        _enforce_rate_limit(request, limit=1)
    assert limited.value.status_code == 429
    _CLIENT_REQUESTS.clear()


@pytest.mark.asyncio
async def test_target_cooldown_returns_429(monkeypatch):
    from fastapi import HTTPException

    _TARGET_LAST_SCAN.clear()
    monkeypatch.setenv("DNS_ANALYZER_TARGET_COOLDOWN_SECONDS", "30")
    _enforce_target_cooldown("Example.COM.")
    _enforce_target_cooldown("example.com", "paths")
    with pytest.raises(HTTPException) as limited:
        _enforce_target_cooldown("example.com")
    assert limited.value.status_code == 429
    _TARGET_LAST_SCAN.clear()


def test_dashboard_displays_incomplete_grade_marker():
    source = (Path(__file__).parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert 'data.domain_score?.grade?.endsWith("(incomplete)")' in source
    assert "Grade is provisional (incomplete)" in source


def test_dashboard_uses_canonical_inconclusive_check_count():
    source = (Path(__file__).parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert "Number.isInteger(data.summary.inconclusive)" in source
    assert 'currentFindings.filter((finding) => finding.severity === "inconclusive")' not in source


def test_dashboard_scope_panel_reports_and_respects_server_policy():
    root = Path(__file__).parents[1] / "static"
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")

    assert 'id="scope-readiness"' in html
    assert "ENABLE_WIDE_DIRECTORY_SCAN=true" in html
    assert "ENABLE_ACTIVE_PORT_SCAN=true" in html
    assert '<option value="connect-wide">' in html

    assert 'apiFetch("/api/network/capabilities")' in js
    assert "renderScanCapabilities" in js
    assert "widePathConfirm.disabled = !wide.enabled" in js
    assert "portScanConfirm.disabled = !port.enabled" in js
    assert "wide: widePorts" in js


def test_dashboard_deep_links_report_sections_in_url_hash():
    source = (Path(__file__).parents[1] / "static" / "app.js").read_text(encoding="utf-8")
    assert "SEGMENT_HASH_ALIASES" in source
    assert 'window.addEventListener("hashchange"' in source
    assert "segmentTabFromHash() || activeSegmentTabId" in source
    assert "syncSegmentHash(targetTabId)" in source


def test_dashboard_exposes_tab_scoped_api_key_for_protected_deployments():
    root = Path(__file__).parents[1]
    html = (root / "static" / "index.html").read_text(encoding="utf-8")
    script = (root / "static" / "app.js").read_text(encoding="utf-8")
    assert 'id="dashboard-api-key"' in html
    assert "sessionStorage.setItem(API_KEY_STORAGE_KEY, value)" in script
    assert 'apiFetch("/api/analyze"' in script


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
    mock_ns_asn = ({"status": "inconclusive", "nameservers": [], "asns": [], "single_asn": None}, [])
    mock_parent_child = ({"status": "inconclusive", "parent_observations": [], "parent_nameservers": [], "child_nameservers": [], "glue": [], "delegation_matches": None}, [])
    with patch("app.main.audit_tls_and_https", return_value=mock_tls), \
         patch("app.main.discover_passive_subdomains", return_value=mock_sub), \
         patch("app.main.check_zone_transfers", return_value=mock_axfr), \
         patch("app.main.check_wildcard_dns", return_value=mock_wildcard), \
         patch("app.main.check_nameserver_consistency", return_value=mock_ns_consistency), \
         patch("app.main.check_nameserver_asn_diversity", return_value=mock_ns_asn), \
         patch("app.main.check_parent_child_delegation", return_value=mock_parent_child):
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
        from app.network_scan import COMMON_PATH_SCAN_HTTP_BUDGET, COMMON_WEB_PATHS
        result = {"scan_mode": "Common Web Paths + Public Robots/Sitemap (No Crawling)", "path_count": 7, "targets": []}
        with patch("app.main.run_common_path_scan", return_value=result) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/network/path-scan", json={"targets": ["example.com"]})

        assert resp.status_code == 200
        assert resp.json()["path_count"] == 7
        assert mocked.await_count == 1
        assert mocked.await_args.args == (["example.com"],)
        assert set(mocked.await_args.kwargs) == {"resolver", "work_budget", "wide"}
        assert mocked.await_args.kwargs["wide"] is False
        budget = mocked.await_args.kwargs["work_budget"].http_remaining
        assert budget == COMMON_PATH_SCAN_HTTP_BUDGET
        assert budget >= 2 * len(COMMON_WEB_PATHS)

    async def test_wide_path_scan_gets_bounded_budget_for_paths_and_redirects(self, monkeypatch):
        from app.network_scan import MAX_WIDE_PATHS, WIDE_PATH_SCAN_HTTP_BUDGET
        monkeypatch.setenv("ENABLE_WIDE_DIRECTORY_SCAN", "true")
        monkeypatch.setenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "example.com")
        result = {"scan_mode": "wide", "path_count": 64, "targets": []}
        with patch("app.main.run_common_path_scan", return_value=result) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/network/path-scan",
                    json={"targets": ["example.com"], "wide": True, "confirmed": True},
                )

        assert response.status_code == 200
        assert mocked.await_args.kwargs["wide"] is True
        budget = mocked.await_args.kwargs["work_budget"].http_remaining
        assert budget == WIDE_PATH_SCAN_HTTP_BUDGET
        assert budget >= 2 * (MAX_WIDE_PATHS + 3)

    async def test_wide_path_scan_accepts_separate_token_with_dashboard_auth(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "dashboard-key")
        monkeypatch.setenv("ENABLE_WIDE_DIRECTORY_SCAN", "true")
        monkeypatch.setenv("WIDE_PATH_SCAN_API_KEY", "wide-key")
        monkeypatch.setenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "example.com")
        with patch("app.main.run_common_path_scan", return_value={"targets": [], "path_count": 64}) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/network/path-scan",
                    headers={
                        "Authorization": "Bearer dashboard-key",
                        "X-Wide-Path-Token": "wide-key",
                    },
                    json={"targets": ["example.com"], "wide": True, "confirmed": True},
                )
        assert response.status_code == 200
        assert mocked.await_args.kwargs["wide"] is True

    async def test_port_scan_accepts_separate_token_with_dashboard_auth(self, monkeypatch):
        monkeypatch.setenv("DNS_ANALYZER_API_KEYS", "dashboard-key")
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "port-key")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "example.com")
        with patch("app.main.run_port_scan", return_value={"status": "completed"}) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/network/port-scan",
                    headers={
                        "Authorization": "Bearer dashboard-key",
                        "X-Port-Scan-Token": "port-key",
                    },
                    json={"target": "example.com", "confirmed": True},
                )
        assert response.status_code == 200
        assert mocked.await_args.kwargs["auth_header"] == "Bearer port-key"

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
        assert data["summary"]["inconclusive"] >= data["domain_score"]["inconclusive_count"]
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

    async def test_network_capabilities_endpoint_reports_policy_without_secrets(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_API_KEY", "capabilities-secret-sentinel")
        monkeypatch.setenv("ENABLE_WIDE_DIRECTORY_SCAN", "true")
        monkeypatch.setenv("WIDE_PATH_SCAN_ALLOWED_DOMAINS", "example.com")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/network/capabilities")

        assert resp.status_code == 200
        data = resp.json()
        assert data["active_port_scan"]["enabled"] is True
        assert data["active_port_scan"]["authorized"] is True
        assert data["active_port_scan"]["max_wide_ports"] == 100
        assert data["wide_directory_scan"]["path_count"] == 64
        assert "capabilities-secret-sentinel" not in resp.text
        assert "example.com" not in resp.text

    async def test_post_network_port_scan_forwards_wide_flag(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "true")
        monkeypatch.setenv("PORT_SCAN_ALLOWED_DOMAINS", "*")
        result = {"status": "completed", "scanner": "wide_connect", "target": "example.com", "ports": []}
        with patch("app.main.run_port_scan", new=AsyncMock(return_value=result)) as mocked:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/network/port-scan",
                    json={"target": "example.com", "confirmed": True, "scanner": "connect", "wide": True},
                )

        assert resp.status_code == 200
        assert mocked.await_args.kwargs["wide"] is True
        assert mocked.await_args.kwargs["scanner"] == "connect"

    async def test_post_network_port_scan_disabled_by_default(self, monkeypatch):
        monkeypatch.setenv("ENABLE_ACTIVE_PORT_SCAN", "false")
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

        # Case 2: Trust one proxy hop (rightmost valid entry).
        monkeypatch.setenv("TRUST_REVERSE_PROXY", "true")
        monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)
        assert _extract_client_ip(req) == "10.0.0.1"

        # Two trusted hops selects the second valid address from the right.
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
        assert _extract_client_ip(req) == "203.0.113.195"

        # Too few valid entries fall back to the socket peer.
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "3")
        assert _extract_client_ip(req) == "192.168.1.50"

        # Malformed values are ignored; a malformed hop does not become a bucket key.
        req_scope["headers"] = [(b"x-forwarded-for", b"203.0.113.195, garbage, 10.0.0.1")]
        req = Request(req_scope)
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "2")
        assert _extract_client_ip(req) == "203.0.113.195"

        # IPv6 addresses are accepted and canonicalized.
        req_scope["headers"] = [(b"x-forwarded-for", b"2001:db8::1, 2001:0db8::2")]
        req = Request(req_scope)
        monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
        assert _extract_client_ip(req) == "2001:db8::2"

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


