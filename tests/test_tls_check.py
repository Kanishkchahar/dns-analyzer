"""Tests for Native TLS & HTTPS Security Auditor (app/tls_check.py)."""

from datetime import datetime, timezone

import pytest
from app.tls_check import (
    PinnedIPBackend,
    PinnedIPTransport,
    audit_tls_and_https,
    is_safe_ip,
    match_san_hostname,
    parse_hsts,
    parse_security_txt,
    resolve_and_verify_all_ips,
)


class TestTLSUtilities:
    def test_http_transport_versions_and_pinned_backend_are_explicit(self):
        import httpcore
        import httpx

        assert httpx.__version__ == "0.28.1"
        assert httpcore.__version__ == "1.0.9"
        transport = PinnedIPTransport("1.1.1.1", verify=True)
        backend = transport._pool._network_backend
        assert isinstance(backend, PinnedIPBackend)
        assert backend.target_ip == "1.1.1.1"

    def test_pinned_transport_private_pool_api_change_has_clear_failure(self):
        transport = PinnedIPTransport("1.1.1.1", verify=True)
        try:
            pool = transport._pool
            ssl_context = pool._ssl_context
            backend = pool._network_backend
        except AttributeError as exc:
            pytest.fail(
                "PinnedIPTransport depends on httpcore's private AsyncConnectionPool "
                "._ssl_context and ._network_backend API; update the pinned transport "
                f"for this httpcore version ({exc})."
            )
        assert ssl_context is not None
        assert isinstance(backend, PinnedIPBackend)

    async def test_resolve_and_verify_all_ips_blocks_loopback(self):
        safe, ips, reason = await resolve_and_verify_all_ips("127.0.0.1", 80)
        assert safe is False
        assert "Unsafe address" in reason

    async def test_resolve_and_verify_budget_exhaustion_is_inconclusive(self):
        from app.work_budget import BudgetedResolver, ScanWorkBudget
        budget = ScanWorkBudget(dns_queries=0, http_requests=25)
        resolver = BudgetedResolver(object(), budget)
        safe, addresses, reason = await resolve_and_verify_all_ips("example.com", resolver=resolver)
        assert safe is False
        assert addresses == []
        assert "DNS query budget exhausted" in reason

    def test_ssrf_safety_blocks_private_and_loopback_ips(self):
        # Loopback
        safe, reason = is_safe_ip("127.0.0.1")
        assert safe is False
        assert "Loopback" in reason

        safe, _ = is_safe_ip("::1")
        assert safe is False

        # RFC 1918 Private
        safe, _ = is_safe_ip("10.0.0.1")
        assert safe is False

        safe, _ = is_safe_ip("192.168.1.1")
        assert safe is False

        safe, _ = is_safe_ip("172.16.5.10")
        assert safe is False

        # Cloud metadata
        safe, _ = is_safe_ip("169.254.169.254")
        assert safe is False

        # Non-global / CGNAT / documentation IPs
        safe, reason = is_safe_ip("100.64.0.1")
        assert safe is False
        assert "Non-globally routable" in reason

        safe, _ = is_safe_ip("192.0.2.1")
        assert safe is False

        # Public IPs are approved
        safe, _ = is_safe_ip("93.184.216.34")
        assert safe is True

        safe, _ = is_safe_ip("2606:2800:220:1:248:1893:25c8:1946")
        assert safe is True

    def test_san_hostname_wildcard_matching(self):
        san_list = ["*.example.com", "example.com", "mycorp.net"]

        assert match_san_hostname("example.com", san_list) is True
        assert match_san_hostname("sub.example.com", san_list) is True
        assert match_san_hostname("api.example.com", san_list) is True
        # Multi-level subdomain should not match standard single wildcard per RFC 6125
        assert match_san_hostname("deep.sub.example.com", san_list) is False
        assert match_san_hostname("other.com", san_list) is False
        assert match_san_hostname("foobar.example.com", ["foo*.example.com"]) is False

    def test_hsts_requires_a_single_positive_max_age(self):
        active = parse_hsts(["max-age=31536000; includeSubDomains"])
        assert active == {
            "status": "active", "active": True, "max_age": 31536000,
            "include_subdomains": True,
        }
        assert parse_hsts(["max-age=0"]) ["status"] == "disabled"
        assert parse_hsts(["includeSubDomains"]) ["status"] == "invalid"
        assert parse_hsts(["max-age=10", "max-age=20"]) ["status"] == "invalid"
        assert parse_hsts(["max-age=abc"]) ["status"] == "invalid"
        assert parse_hsts(["max-age=" + "9" * 5000])["status"] == "invalid"
        assert parse_hsts([])["status"] == "missing"

    def test_security_txt_requires_contact_and_one_valid_future_expiry(self):
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        valid = b"Contact: mailto:security@example.com\nExpires: 2027-11-08T00:00:00z\n"
        assert parse_security_txt(valid, now)["status"] == "valid"
        assert parse_security_txt(b"Contact: mailto:security@example.com\n", now)["status"] == "malformed"
        assert parse_security_txt(
            b"Contact: mailto:security@example.com\nExpires: 2026-11-07T00:00:00Z\n", now,
        )["status"] == "expired"
        assert parse_security_txt(
            b"Contact: mailto:security@example.com\nExpires: 2027-11-08T00:00:00Z\nExpires: 2028-11-08T00:00:00Z\n", now,
        )["status"] == "malformed"


@pytest.mark.asyncio
class TestTLSAuditor:
    async def test_audit_tls_ssrf_protection_aborts(self):
        # Localhost target triggers SSRF guard
        data, findings = await audit_tls_and_https("localhost")
        assert any("SSRF Safety Guard" in f.message for f in findings)
        assert data["scanned"] is False
