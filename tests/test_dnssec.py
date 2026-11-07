"""Tests for DNSSEC Cryptographic Chain Validator (app/dnssec.py)."""

import pytest
import base64
import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from app.dnssec import check_dnssec
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestDNSSEC:
    async def test_dnssec_delegation_match_status(self):
        dnskey_rr = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            f"257 3 13 {base64.b64encode(bytes(range(64))).decode()}",
        )
        ds_rr = dns.dnssec.make_ds(dns.name.from_text("example.com"), dnskey_rr, "SHA256")

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

        domain_name = dns.name.from_text("example.com")
        key = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            f"257 3 13 {base64.b64encode(bytes(range(64))).decode()}",
        )
        ds_match = dns.dnssec.make_ds(domain_name, key, "SHA256")
        other_key = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            f"257 3 13 {base64.b64encode(bytes(reversed(range(64)))).decode()}",
        )
        ds_mismatch = dns.dnssec.make_ds(domain_name, other_key, "SHA256")

        assert _safe_key_tag(key) == dns.dnssec.key_id(key)
        matched, tag = verify_ds_matches_dnskey(domain_name, [key], [ds_match])
        assert matched is True
        assert tag == dns.dnssec.key_id(key)

        unmatched, tag2 = verify_ds_matches_dnskey(domain_name, [key], [ds_mismatch])
        assert unmatched is False
        assert tag2 == 0

        fake_key = MockRR(flags=257, protocol=3, algorithm=13, key_tag=12345)
        fake_ds = MockRR(key_tag=12345, algorithm=13, digest_type=2)
        assert verify_ds_matches_dnskey(domain_name, [fake_key], [fake_ds]) == (False, 0)

