"""CT inventory tests use a fake HTTP response and fake DNS resolver only."""

import dns.resolver
import httpx
import pytest

from app.subdomains import discover_passive_subdomains
from app.work_budget import ScanWorkBudget
from tests.conftest import MockAnswer, MockResolver, MockRR


class _CTResponse:
    status_code = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def aiter_bytes(self):
        yield b'[{"name_value":"one.example.com\\ntwo.example.com"}]'


class _CTClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, *_args, **_kwargs):
        return _CTResponse()


@pytest.mark.asyncio
async def test_ct_discovered_takeover_fetches_share_scan_http_budget(monkeypatch):
    monkeypatch.setattr("app.subdomains.httpx.AsyncClient", lambda **_kwargs: _CTClient())
    reserved = 0

    async def fake_page_fetch(_host, _addresses, _expected, budget):
        nonlocal reserved
        if await budget.reserve_http("takeover"):
            reserved += 1
            return False, "fetch_failed"
        return False, "budget_exhausted"

    monkeypatch.setattr("app.takeover._read_fingerprint_page", fake_page_fetch)

    class CTResolver(MockResolver):
        async def resolve(self, qname, rdtype, *args, **kwargs):
            host = qname.rstrip(".").lower()
            kind = rdtype.upper()
            if host in ("one.example.com", "two.example.com") and kind == "CNAME":
                return MockAnswer([MockRR(target="claimed.github.io.")])
            if host in ("one.example.com", "two.example.com") and kind == "A":
                return MockAnswer([MockRR(address="192.0.2.8")])
            if host in ("one.example.com", "two.example.com") and kind == "AAAA":
                return MockAnswer([])
            if host == "claimed.github.io" and kind == "A":
                return MockAnswer([MockRR(address="185.199.108.153")])
            if host == "claimed.github.io" and kind == "AAAA":
                return MockAnswer([])
            raise dns.resolver.NXDOMAIN()

    budget = ScanWorkBudget(
        http_requests=2,
        http_shares={"ct": 1, "takeover": 1},
    )  # one CT request plus one fingerprint fetch
    data, _ = await discover_passive_subdomains("example.com", CTResolver(), work_budget=budget)

    assert data["discovered_count"] == 2
    assert reserved == 1
    assert budget.http_remaining == 0
    assert all(item["takeover"]["status"] == "inconclusive" for item in data["subdomains"])


@pytest.mark.asyncio
async def test_ct_successful_empty_response_is_distinct_from_source_failure(monkeypatch):
    class EmptyResponse(_CTResponse):
        async def aiter_bytes(self):
            yield b"[]"

    class EmptyClient(_CTClient):
        def stream(self, *_args, **_kwargs):
            return EmptyResponse()

    monkeypatch.setattr("app.subdomains.httpx.AsyncClient", lambda **_kwargs: EmptyClient())
    data, _ = await discover_passive_subdomains("example.com", MockResolver())

    assert data["status"] == "complete"
    assert data["state"] == "NO_RESULTS"
    assert data["attempts"] == 1


@pytest.mark.asyncio
async def test_ct_retries_provider_error_and_preserves_per_host_source(monkeypatch):
    responses = iter([
        (503, b"unavailable"),
        (200, b'[{"name_value":"one.example.com"}]'),
    ])
    attempts = 0

    class SequenceResponse(_CTResponse):
        def __init__(self, status_code, body):
            self.status_code = status_code
            self.body = body

        async def aiter_bytes(self):
            yield self.body

    class SequenceClient(_CTClient):
        def stream(self, *_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            return SequenceResponse(*next(responses))

    monkeypatch.setattr("app.subdomains.httpx.AsyncClient", lambda **_kwargs: SequenceClient())
    budget = ScanWorkBudget(http_requests=2, http_shares={"ct": 2})
    data, _ = await discover_passive_subdomains("example.com", MockResolver(), work_budget=budget)

    assert attempts == data["attempts"] == 2
    # crt.sh succeeded, but the separately reserved secondary-source budget
    # was not configured in this test, so the combined result is partial.
    assert data["state"] == "PARTIAL_RESULTS"
    assert data["subdomains"][0]["source"] == "Certificate Transparency"


@pytest.mark.asyncio
async def test_ct_timeout_is_reported_as_timeout_after_bounded_retries(monkeypatch):
    attempts = 0

    class TimeoutClient(_CTClient):
        def stream(self, *_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("app.subdomains.httpx.AsyncClient", lambda **_kwargs: TimeoutClient())
    budget = ScanWorkBudget(http_requests=2, http_shares={"ct": 2})
    data, _ = await discover_passive_subdomains("example.com", MockResolver(), work_budget=budget)

    assert attempts == data["attempts"] == 2
    assert data["status"] == "unavailable"
    assert data["state"] == "TIMEOUT"
