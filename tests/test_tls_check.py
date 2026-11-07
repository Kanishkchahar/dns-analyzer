"""Tests for Native TLS & HTTPS Security Auditor (app/tls_check.py)."""

import pytest
from app.tls_check import is_safe_ip, match_san_hostname, audit_tls_and_https, resolve_and_verify_all_ips


class TestTLSUtilities:
    async def test_resolve_and_verify_all_ips_blocks_loopback(self):
        safe, ips, reason = await resolve_and_verify_all_ips("127.0.0.1", 80)
        assert safe is False
        assert "Unsafe address" in reason

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


@pytest.mark.asyncio
class TestTLSAuditor:
    async def test_audit_tls_ssrf_protection_aborts(self):
        # Localhost target triggers SSRF guard
        data, findings = await audit_tls_and_https("localhost")
        assert any("SSRF Safety Guard" in f.message for f in findings)
        assert data["scanned"] is False
