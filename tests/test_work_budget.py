"""Module reservation tests use in-memory DNS answers and no outbound requests."""

import pytest
import dns.rdatatype

from app.dnssec import check_dnssec
from app.email_auth import fetch_dmarc
from app.tls_check import resolve_and_verify_all_ips
from app.work_budget import (
    DEFAULT_DNS_QUERY_BUDGET,
    DEFAULT_HTTP_REQUEST_BUDGET,
    DNS_MODULE_SHARES,
    HTTP_MODULE_SHARES,
    BudgetedResolver,
    ScanWorkBudget,
)
from tests.conftest import MockAnswer, MockResolver, MockRR
from tests.dnssec_fixtures import ZONE, make_signed_hierarchy


def test_default_module_reservations_match_global_caps():
    assert sum(DNS_MODULE_SHARES.values()) == DEFAULT_DNS_QUERY_BUDGET == 500
    assert sum(HTTP_MODULE_SHARES.values()) == DEFAULT_HTTP_REQUEST_BUDGET == 25
    budget = ScanWorkBudget()
    assert sum(budget.dns_module_remaining.values()) == 500
    assert sum(budget.http_module_remaining.values()) == 25


@pytest.mark.asyncio
async def test_one_module_cannot_consume_another_modules_dns_or_http_share():
    budget = ScanWorkBudget(
        dns_queries=3,
        http_requests=3,
        dns_shares={"ct": 1, "takeover": 1, "tls": 1},
        http_shares={"ct": 1, "takeover": 1, "tls": 1},
    )
    assert await budget.reserve_dns("ct")
    assert not await budget.reserve_dns("ct")
    assert await budget.reserve_dns("takeover")
    assert await budget.reserve_dns("tls")
    assert await budget.reserve_http("ct")
    assert not await budget.reserve_http("ct")
    assert await budget.reserve_http("takeover")
    assert await budget.reserve_http("tls")


@pytest.mark.asyncio
async def test_ct_and_takeover_exhaustion_leaves_tls_dnssec_and_email_checks_available(monkeypatch):
    fixture = make_signed_hierarchy()
    key = fixture["dnskeys"][ZONE]
    ds = fixture["hierarchy"][(ZONE, dns.rdatatype.DS)][0][0]
    resolver = MockResolver({
        ("example.test", "DNSKEY"): MockAnswer([key]),
        ("example.test", "DS"): MockAnswer([ds]),
        ("example.test", "A"): MockAnswer([MockRR(address="93.184.216.34")]),
        ("example.test", "AAAA"): MockAnswer([]),
        ("www.example.test", "A"): MockAnswer([MockRR(address="93.184.216.34")]),
        ("www.example.test", "AAAA"): MockAnswer([]),
        ("www.example.test", "CNAME"): MockAnswer([MockRR(target="myorg.github.io.")]),
        ("myorg.github.io", "CNAME"): MockAnswer([]),
        ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
        ("myorg.github.io", "AAAA"): MockAnswer([]),
        ("_dmarc.example.test", "TXT"): MockAnswer([MockRR(strings=[b"v=DMARC1; p=reject"])])
    })

    class CTResponse:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def aiter_bytes(self):
            yield b'[{"name_value":"www.example.test"}]'

    class CTClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def stream(self, *_args, **_kwargs):
            return CTResponse()

    async def fake_page_fetch(_host, _addresses, _expected, budget):
        if not await budget.reserve_http("takeover"):
            return False, "budget_exhausted"
        return False, "fetch_failed"

    monkeypatch.setattr("app.subdomains.httpx.AsyncClient", lambda **_kwargs: CTClient())
    monkeypatch.setattr("app.takeover._read_fingerprint_page", fake_page_fetch)
    budget = ScanWorkBudget(
        dns_queries=11,
        http_requests=4,
        dns_shares={"dnssec": 2, "dmarc": 1, "tls": 2, "subdomains": 3, "takeover": 3},
        http_shares={"ct": 1, "takeover": 1, "tls": 1, "mail_transport": 1},
    )

    from app.subdomains import discover_passive_subdomains
    subdomains, _ = await discover_passive_subdomains(
        "example.test", budget.resolver_for(resolver, "subdomains"), work_budget=budget,
    )
    assert subdomains["discovered_count"] == 1
    assert subdomains["subdomains"][0]["takeover"]["status"] == "inconclusive"
    assert not await budget.reserve_http("takeover")
    assert await budget.reserve_http("tls")
    assert await budget.reserve_http("mail_transport")

    dnssec_data, _ = await check_dnssec("example.test", budget.resolver_for(resolver, "dnssec"))
    dmarc_data = await fetch_dmarc("example.test", budget.resolver_for(resolver, "dmarc"))
    tls_ok, tls_addresses, _ = await resolve_and_verify_all_ips(
        "example.test", resolver=budget.resolver_for(resolver, "tls"),
    )
    assert dnssec_data["status"] == "delegation_match_verified"
    assert dmarc_data is not None
    assert tls_ok and tls_addresses == ["93.184.216.34"]


def test_network_scan_profile_gets_the_full_standalone_cap():
    budget = ScanWorkBudget(profile="network_scan")
    assert budget.dns_module_remaining == {"network_scan": 500}
    assert budget.http_module_remaining == {"network_scan": 25}
