"""Tests for Native TLS & HTTPS Security Auditor (app/tls_check.py)."""

from datetime import datetime, timezone

import pytest
import httpx
from app.tls_check import (
    PinnedIPTransport,
    audit_tls_and_https,
    is_safe_ip,
    match_san_hostname,
    parse_hsts,
    parse_security_txt,
    resolve_and_verify_all_ips,
)


class TestTLSUtilities:
    def test_pinned_transport_exposes_configured_target_ip(self):
        transport = PinnedIPTransport("1.1.1.1", verify=True)
        assert transport.target_ip == "1.1.1.1"

    async def test_pinned_transport_uses_ip_and_preserves_tls_and_http_host(self, monkeypatch):
        import httpcore

        class MemoryStream(httpcore.AsyncNetworkStream):
            def __init__(self):
                self.request_bytes = bytearray()
                self.response_bytes = bytearray(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
                self.server_hostname = None

            async def read(self, max_bytes, timeout=None):
                chunk = bytes(self.response_bytes[:max_bytes])
                del self.response_bytes[:max_bytes]
                return chunk

            async def write(self, buffer, timeout=None):
                self.request_bytes.extend(buffer)

            async def aclose(self):
                return None

            async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
                self.server_hostname = server_hostname
                return self

            def get_extra_info(self, info):
                return None

        class RecordingBackend:
            def __init__(self):
                self.target = None
                self.port = None
                self.stream = MemoryStream()

            async def connect_tcp(self, host, port, **_kwargs):
                self.target = host
                self.port = port
                return self.stream

            async def connect_unix_socket(self, *_args, **_kwargs):
                raise AssertionError("Pinned transport must use TCP")

            async def sleep(self, _seconds):
                return None

        backend = RecordingBackend()
        monkeypatch.setattr("app.tls_check.httpcore.AnyIOBackend", lambda: backend)
        transport = PinnedIPTransport("1.1.1.1", verify=False)
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            response = await client.get("https://example.test:8443/pinned")

        assert response.status_code == 200
        assert backend.target == "1.1.1.1"
        assert backend.port == 8443
        assert backend.stream.server_hostname == "example.test"
        assert b"Host: example.test:8443" in backend.stream.request_bytes

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
