"""Tests for Authoritative Zone Apex Discovery and Subdomain Delegation."""

import pytest
from app.resolver import discover_zone_apex, resolve_domain
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
