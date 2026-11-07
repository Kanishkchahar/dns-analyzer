"""Integration tests for FastAPI endpoints (app/main.py)."""

from unittest.mock import patch
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from tests.conftest import MockAnswer, MockResolver, MockRR


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
    dnskey_rr = MockRR(flags=257, protocol=3, algorithm=13)
    ds_rr = MockRR(key_tag=12345, algorithm=13, digest_type=2)
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
    with patch("app.main.audit_tls_and_https", return_value=mock_tls), \
         patch("app.main.discover_passive_subdomains", return_value=mock_sub):
        yield


@pytest.mark.asyncio
class TestAPIEndpoints:
    async def test_root_serves_html(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/")
            assert resp.status_code == 200
            assert "text/html" in resp.headers["content-type"]
            assert "DNS Analyzer" in resp.text

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
        assert data["domain_score"]["grade"] in ("A+", "A")
        assert "infrastructure" in data["domain_score"]["factors"]
        assert data["email_auth"]["score"]["grade"] in ("A+", "A")
        assert data["security"]["dnssec"]["status"] == "secured"

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
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/network/port-scan", json={"target": "93.184.216.34", "confirmed": False})

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "confirmation_required"

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


