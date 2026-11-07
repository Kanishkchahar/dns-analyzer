"""Tests for DNS resolver layer (app/resolver.py)."""

from unittest.mock import AsyncMock, patch
import dns.exception
import dns.resolver
import pytest

from app.resolver import _resolve_host_to_a, _safe_query, resolve_domain
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestResolverLayer:
    async def test_safe_query_a_records(self):
        answer = MockAnswer([MockRR(address="93.184.216.34")], ttl=300)
        resolver = MockResolver({("example.com", "A"): answer})

        res = await _safe_query(resolver, "example.com", "A")
        assert res["status"] == "ok"
        assert res["records"] == ["93.184.216.34"]
        assert res["ttl"] == 300

    async def test_safe_query_mx_records(self):
        answer = MockAnswer([MockRR(preference=10, exchange="mail.example.com.")], ttl=600)
        resolver = MockResolver({("example.com", "MX"): answer})

        res = await _safe_query(resolver, "example.com", "MX")
        assert res["status"] == "ok"
        assert res["records"] == [{"priority": 10, "host": "mail.example.com"}]

    async def test_safe_query_soa_records(self):
        soa_rr = MockRR(
            mname="ns1.example.com.",
            rname="admin.example.com.",
            serial=2026110701,
            refresh=7200,
            retry=3600,
            expire=1209600,
            minimum=300,
        )
        answer = MockAnswer([soa_rr], ttl=3600)
        resolver = MockResolver({("example.com", "SOA"): answer})

        res = await _safe_query(resolver, "example.com", "SOA")
        assert res["status"] == "ok"
        assert res["records"]["serial"] == 2026110701
        assert res["records"]["mname"] == "ns1.example.com"

    async def test_safe_query_nxdomain(self):
        resolver = MockResolver({("nonexistent.xyz", "A"): dns.resolver.NXDOMAIN()})
        res = await _safe_query(resolver, "nonexistent.xyz", "A")
        assert res["status"] in ("nxdomain", "not_found")
        assert res["records"] == []

    async def test_safe_query_timeout(self):
        resolver = MockResolver({("slow.xyz", "A"): dns.exception.Timeout()})
        res = await _safe_query(resolver, "slow.xyz", "A")
        assert res["status"] == "timeout"
        assert res["records"] == []

    async def test_safe_query_hides_resolver_exception_details(self):
        resolver = MockResolver({("example.com", "A"): RuntimeError("nameserver 10.0.0.7 refused")})
        res = await _safe_query(resolver, "example.com", "A")
        assert res["reason"] == "DNS lookup failed"
        assert "10.0.0.7" not in str(res)

    async def test_resolve_host_to_a(self):
        answer = MockAnswer([MockRR(address="1.1.1.1")])
        resolver = MockResolver({("ns1.example.com", "A"): answer})

        resolves = await _resolve_host_to_a(resolver, "ns1.example.com")
        assert resolves is True

        fails = await _resolve_host_to_a(resolver, "broken.host.com")
        assert fails is False

    async def test_resolve_domain_all_types(self):
        a_ans = MockAnswer([MockRR(address="1.2.3.4")])
        aaaa_ans = MockAnswer([MockRR(address="2001:db8::1")])
        mx_ans = MockAnswer([MockRR(preference=10, exchange="mx.example.com.")])
        ns_ans = MockAnswer([MockRR(target="ns1.example.com.")])
        txt_ans = MockAnswer([MockRR(strings=[b"v=spf1 -all"])])
        soa_rr = MockRR(
            mname="ns1.example.com.",
            rname="hostmaster.example.com.",
            serial=1,
            refresh=3600,
            retry=600,
            expire=86400,
            minimum=300,
        )
        soa_ans = MockAnswer([soa_rr])

        responses = {
            ("example.com", "A"): a_ans,
            ("example.com", "AAAA"): aaaa_ans,
            ("example.com", "MX"): mx_ans,
            ("example.com", "NS"): ns_ans,
            ("example.com", "TXT"): txt_ans,
            ("example.com", "CNAME"): dns.resolver.NXDOMAIN(),
            ("example.com", "SOA"): soa_ans,
            ("ns1.example.com", "A"): a_ans,
            ("mx.example.com", "A"): a_ans,
        }
        mock_resolver = MockResolver(responses)

        with patch("dns.asyncresolver.Resolver", return_value=mock_resolver):
            data = await resolve_domain("example.com")

        assert "A" in data
        assert "AAAA" in data
        assert "MX" in data
        assert "NS" in data
        assert "TXT" in data
        assert "CNAME" in data
        assert "SOA" in data
        assert data["NS"]["records"][0]["resolves"] is True
        assert data["MX"]["records"][0]["resolves"] is True
