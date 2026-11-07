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
        ("example.com", "NS"): MockAnswer([ns_rr]),
        ("example.com", "TXT"): MockAnswer([txt_spf]),
        ("example.com", "CNAME"): MockAnswer([]),
        ("example.com", "SOA"): MockAnswer([soa_rr]),
        ("example.com", "DNSKEY"): MockAnswer([dnskey_rr]),
        ("example.com", "DS"): MockAnswer([ds_rr]),
        ("_dmarc.example.com", "TXT"): MockAnswer([dmarc_rr]),
        ("default._bimi.example.com", "TXT"): MockAnswer([bimi_rr]),
        ("google._domainkey.example.com", "TXT"): MockAnswer([dkim_rr]),
        ("ns1.example.com", "A"): MockAnswer([a_rr]),
        ("mail.example.com", "A"): MockAnswer([a_rr]),
    }
    return MockResolver(responses)


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
        assert data["email_auth"]["score"]["grade"] in ("A+", "A")
        assert data["security"]["dnssec"]["status"] == "secured"

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
