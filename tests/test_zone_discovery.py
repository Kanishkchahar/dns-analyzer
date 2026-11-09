"""Tests for Authoritative Zone Apex Discovery and Subdomain Delegation."""

import pytest
from app.resolver import discover_zone_apex
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestZoneApexDiscovery:
    async def test_discover_apex_on_subdomain(self):
        # blog.corp.example.com -> SOA exists at example.com
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
            ("example.com", "SOA"): MockAnswer([soa_rr]),
        }
        resolver = MockResolver(responses)

        apex = await discover_zone_apex("blog.corp.example.com", resolver)
        assert apex == "example.com"

    async def test_discover_apex_when_subdomain_has_delegated_soa(self):
        # sub.example.com has its own SOA delegation
        sub_soa = MockRR(mname="ns1.sub.example.com.", rname="admin.sub.example.com.", serial=1, refresh=7200, retry=3600, expire=1209600, minimum=3600)
        parent_soa = MockRR(mname="ns1.example.com.", rname="admin.example.com.", serial=2, refresh=7200, retry=3600, expire=1209600, minimum=3600)

        responses = {
            ("sub.example.com", "SOA"): MockAnswer([sub_soa]),
            ("example.com", "SOA"): MockAnswer([parent_soa]),
        }
        resolver = MockResolver(responses)

        apex = await discover_zone_apex("sub.example.com", resolver)
        assert apex == "sub.example.com"

    async def test_discover_apex_root_domain_direct(self):
        resolver = MockResolver({})
        apex = await discover_zone_apex("example.com", resolver)
        assert apex == "example.com"


@pytest.mark.asyncio
class TestSubdomainDiscovery:
    async def test_ct_stream_truncation_repairs_json(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from app.subdomains import discover_passive_subdomains
        import json

        # Simulate a CT log response cut off mid-JSON at 512KB boundary
        # Full list would have item1 and item2, but item2 is cut in half
        items = [{"name_value": "api.example.com\nadmin.example.com"}]
        valid_part = json.dumps(items)[:-1] # cut off trailing ']'
        truncated_payload = (valid_part + ', {"name_value": "cut-off.examp').encode("utf-8")

        mock_stream = AsyncMock()
        mock_stream.status_code = 200
        mock_stream.aiter_bytes = MagicMock(return_value=_async_iter([truncated_payload]))

        mock_client = MagicMock()
        mock_client.stream.return_value.__aenter__.return_value = mock_stream

        with patch("httpx.AsyncClient") as mock_http_client:
            mock_http_client.return_value.__aenter__.return_value = mock_client
            resolver = MockResolver({})
            data, findings = await discover_passive_subdomains("example.com", resolver)

        # Repaired JSON must salvage the complete items before the cut
        assert "api.example.com" in [s["subdomain"] for s in data["subdomains"]]
        assert "admin.example.com" in [s["subdomain"] for s in data["subdomains"]]


async def _async_iter(items):
    for item in items:
        yield item
