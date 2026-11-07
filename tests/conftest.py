"""Shared fixtures and mock helpers for DNS Analyzer tests."""

from typing import Any
import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from app.main import app


class MockRR:
    """Mock dnspython Resource Record."""

    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockRRSet:
    """Mock dnspython RRSet."""

    def __init__(self, ttl: int = 3600):
        self.ttl = ttl


class MockAnswer:
    """Mock dnspython answer collection."""

    def __init__(self, rrs: list[Any], ttl: int = 3600):
        self._rrs = rrs
        self.rrset = MockRRSet(ttl=ttl)

    def __iter__(self):
        return iter(self._rrs)

    def __len__(self):
        return len(self._rrs)

    def __getitem__(self, index: int):
        return self._rrs[index]


class MockResolver:
    """A flexible async resolver stub for testing DNS queries without hitting network."""

    def __init__(self, responses: dict[tuple[str, str], Any] | None = None):
        # Map of (qname, rdatatype) -> list of record objects or Exception
        self.responses: dict[tuple[str, str], Any] = responses or {}

    async def resolve(self, qname: str, rtype: str, *args, **kwargs):
        # Normalize trailing dots
        key = (qname.rstrip(".").lower(), rtype.upper())
        if key in self.responses:
            val = self.responses[key]
            if isinstance(val, Exception):
                raise val
            return val
        # Also check wildcard / fallback for qname
        for (pattern_name, pattern_type), val in self.responses.items():
            if pattern_name == "*" and pattern_type.upper() == rtype.upper():
                if isinstance(val, Exception):
                    raise val
                return val
        import dns.resolver
        raise dns.resolver.NXDOMAIN()


@pytest.fixture
def client():
    """Synchronous test client for FastAPI."""
    return TestClient(app)


@pytest.fixture
async def async_client():
    """Asynchronous httpx test client for FastAPI."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture
def sample_resolver_data() -> dict[str, Any]:
    """Sample raw resolver output dictionary with standard healthy records."""
    return {
        "A": {
            "status": "ok",
            "records": ["93.184.216.34"],
            "ttl": 3600,
        },
        "AAAA": {
            "status": "ok",
            "records": ["2606:2800:220:1:248:1893:25c8:1946"],
            "ttl": 3600,
        },
        "MX": {
            "status": "ok",
            "records": [
                {"priority": 10, "host": "mail.example.com", "resolves": True}
            ],
            "ttl": 3600,
        },
        "NS": {
            "status": "ok",
            "records": [
                {"host": "ns1.example.com", "resolves": True},
                {"host": "ns2.example.com", "resolves": True},
            ],
            "ttl": 86400,
        },
        "TXT": {
            "status": "ok",
            "records": ["v=spf1 -all"],
            "ttl": 3600,
        },
        "CNAME": {
            "status": "not_found",
            "records": [],
            "ttl": 0,
        },
        "SOA": {
            "status": "ok",
            "records": {
                "mname": "ns1.example.com",
                "rname": "admin.example.com",
                "serial": 2026110701,
                "refresh": 7200,
                "retry": 3600,
                "expire": 1209600,
                "minimum": 3600,
            },
            "ttl": 3600,
        },
    }
