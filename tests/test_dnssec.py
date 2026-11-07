"""Tests for DNSSEC Cryptographic Chain Validator (app/dnssec.py)."""

import pytest

from app.dnssec import check_dnssec
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestDNSSEC:
    async def test_dnssec_delegation_match_status(self):
        # KSK flag = 257 (bit 15 set: 257 & 1 == 1)
        dnskey_rr = MockRR(flags=257, protocol=3, algorithm=13)
        ds_rr = MockRR(key_tag=12345, algorithm=13, digest_type=2)

        resolver = MockResolver({
            ("example.com", "DNSKEY"): MockAnswer([dnskey_rr]),
            ("example.com", "DS"): MockAnswer([ds_rr]),
        })

        data, findings = await check_dnssec("example.com", resolver)
        assert data["status"] == "delegation_match_verified"
        assert data["delegation_verified"] is True
        assert data["enabled"] is True
        assert data["dnskey_count"] == 1
        assert data["ds_count"] == 1
        assert data["keys"][0]["algorithm"] == "ECDSA Curve P-256 with SHA-256"
        assert any(
            f.severity == "info" and "DS-to-DNSKEY delegation link verified" in f.message for f in findings
        )

    async def test_dnssec_incomplete_chain(self):
        dnskey_rr = MockRR(flags=256, protocol=3, algorithm=8)
        resolver = MockResolver({
            ("example.com", "DNSKEY"): MockAnswer([dnskey_rr]),
        })

        data, findings = await check_dnssec("example.com", resolver)
        assert data["status"] == "incomplete_chain"
        assert data["enabled"] is False
        assert any(
            f.severity == "warning" and "no DS delegation" in f.message
            for f in findings
        )

    async def test_dnssec_bogus_status(self):
        ds_rr = MockRR(key_tag=9999, algorithm=8, digest_type=1)
        resolver = MockResolver({
            ("example.com", "DS"): MockAnswer([ds_rr]),
        })

        data, findings = await check_dnssec("example.com", resolver)
        assert data["status"] == "bogus"
        assert data["enabled"] is False
        assert any(
            f.severity == "error" and "SERVFAIL" in f.message for f in findings
        )

    async def test_dnssec_unsigned_domain(self):
        resolver = MockResolver({})
        data, findings = await check_dnssec("example.com", resolver)
        assert data["status"] == "unsigned"
        assert data["enabled"] is False
        assert any(
            f.severity == "info" and "not enabled" in f.message for f in findings
        )

    def test_safe_key_tag_and_verify_ds_matches_dnskey(self):
        from app.dnssec import _safe_key_tag, verify_ds_matches_dnskey
        import dns.name

        mock_key = MockRR(key_tag=54321)
        assert _safe_key_tag(mock_key) == 54321

        domain_name = dns.name.from_text("example.com")
        ds_match = MockRR(key_tag=54321)
        ds_mismatch = MockRR(key_tag=11111)

        matched, tag = verify_ds_matches_dnskey(domain_name, [mock_key], [ds_match])
        assert matched is True
        assert tag == 54321

        unmatched, tag2 = verify_ds_matches_dnskey(domain_name, [mock_key], [ds_mismatch])
        assert unmatched is False
        assert tag2 == 0

