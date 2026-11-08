"""DNSSEC trust anchor loader and validation-state tests; no external DNS is used."""
from datetime import datetime, timezone
import json

import dns.exception
import dns.dnssec
import dns.rdatatype
import dns.resolver
import pytest

from app.dnssec import AnchorFileError, _legacy_delegation_check, check_dnssec, load_root_trust_anchors, validate_dnssec_chain
from tests.conftest import MockAnswer, MockResolver, MockRR
from tests.dnssec_fixtures import ZONE, make_signed_hierarchy


def anchor(tag, start="2020-01-01T00:00:00+00:00", until=None, revoked=False):
    return {"key_tag": tag, "algorithm": 8, "digest_type": 2, "digest": "AB" * 32,
            "validFrom": start, "validUntil": until, "revoked": revoked}


def write_anchor_file(tmp_path, entries):
    path = tmp_path / "anchors.json"
    path.write_text(json.dumps({"anchors": entries}), encoding="utf-8")
    return path


def _legacy_resolver(mode="match"):
    fixture = make_signed_hierarchy()
    key = fixture["dnskeys"][ZONE]
    ds = dns.dnssec.make_ds(ZONE, key, "SHA256")
    if mode == "mismatch":
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        private = ec.generate_private_key(ec.SECP256R1())
        other = dns.dnssec.make_dnskey(private.public_key(), 13, flags=257)
        ds = dns.dnssec.make_ds(ZONE, other, "SHA256")
    if mode == "missing_digest":
        ds = MockRR(key_tag=dns.dnssec.key_id(key), algorithm=key.algorithm, digest_type=2)
    if mode == "unsupported_digest":
        ds = MockRR(key_tag=dns.dnssec.key_id(key), algorithm=key.algorithm, digest_type=250, digest="ABCD")
    if mode == "unsupported_algorithm":
        ds = MockRR(key_tag=dns.dnssec.key_id(key), algorithm=250, digest_type=2, digest="AB" * 32)
    replies = {("example.test", "DNSKEY"): MockAnswer([key]), ("example.test", "DS"): MockAnswer([ds])}
    if mode == "missing_ds":
        replies.pop(("example.test", "DS"))
    if mode == "lookup_failure":
        replies[("example.test", "DNSKEY")] = dns.resolver.NoNameservers()
    class NameAwareResolver:
        async def resolve(self, qname, rtype):
            name = qname.to_text(omit_final_dot=True) if hasattr(qname, "to_text") else str(qname).rstrip(".")
            return await MockResolver(replies).resolve(name, rtype)
    return NameAwareResolver()


@pytest.mark.asyncio
async def test_dnssec_delegation_match_status():
    result, _ = await _legacy_delegation_check("example.test", _legacy_resolver(), None)
    assert result["status"] == "delegation_match_verified"
    assert result["validator"] == "legacy"
    assert result["delegation_verified"] is True


@pytest.mark.asyncio
async def test_dnssec_incomplete_chain():
    result, _ = await _legacy_delegation_check("example.test", _legacy_resolver("missing_ds"), None)
    assert result["status"] == "incomplete_chain"


@pytest.mark.asyncio
async def test_dnssec_bogus_status():
    result, findings = await _legacy_delegation_check("example.test", _legacy_resolver("mismatch"), None)
    assert result["status"] == "bogus"
    assert any(f.severity == "error" for f in findings)


@pytest.mark.asyncio
async def test_dnssec_ds_without_digest_is_inconclusive():
    result, _ = await _legacy_delegation_check("example.test", _legacy_resolver("missing_digest"), None)
    assert result["status"] == "inconclusive"


@pytest.mark.parametrize("mode", ["unsupported_digest", "unsupported_algorithm"])
@pytest.mark.asyncio
async def test_dnssec_uncomparable_ds_is_inconclusive(mode):
    result, _ = await _legacy_delegation_check("example.test", _legacy_resolver(mode), None)
    assert result["status"] == "inconclusive"


@pytest.mark.asyncio
async def test_dnssec_query_error_is_inconclusive_not_unsigned():
    result, _ = await _legacy_delegation_check("example.test", _legacy_resolver("lookup_failure"), None)
    assert result["status"] == "inconclusive"


@pytest.mark.asyncio
async def test_dnssec_unsigned_domain():
    class UnsignedResolver:
        async def resolve(self, name, rdtype):
            raise dns.resolver.NoAnswer()
    result, _ = await _legacy_delegation_check("example.test", UnsignedResolver(), None)
    assert result["status"] == "unsigned"


def test_safe_key_tag_and_verify_ds_matches_dnskey():
    fixture = make_signed_hierarchy()
    key = fixture["dnskeys"][ZONE]
    ds = dns.dnssec.make_ds(ZONE, key, "SHA256")
    assert dns.dnssec.key_id(key) == ds.key_tag
    assert dns.dnssec.make_ds(ZONE, key, ds.digest_type).digest == ds.digest


@pytest.mark.asyncio
async def test_unset_chain_validation_flag_uses_legacy_and_never_calls_chain(monkeypatch):
    monkeypatch.delenv("ENABLE_DNSSEC_CHAIN_VALIDATION", raising=False)
    resolver = _legacy_resolver()
    monkeypatch.setattr("app.dnssec.validate_dnssec_chain", pytest.fail)
    result, _ = await check_dnssec("example.test", resolver)
    assert result["validator"] == "legacy"


@pytest.mark.asyncio
async def test_enabled_chain_result_keeps_legacy_score_input(monkeypatch):
    monkeypatch.setenv("ENABLE_DNSSEC_CHAIN_VALIDATION", "true")

    async def fake_chain(domain, resolver, apex):
        return ({"status": "bogus", "validator": "chain", "cryptographically_verified": False}, [])

    monkeypatch.setattr("app.dnssec.validate_dnssec_chain", fake_chain)
    result, _ = await check_dnssec("example.test", _legacy_resolver())
    assert result["status"] == "delegation_match_verified"
    assert result["chain_status"] == "bogus"
    assert result["validator"] == "chain"
    assert result["legacy_score_status"] == "delegation_match_verified"



def test_anchor_loader_accepts_multiple_current_anchors(tmp_path):
    path = write_anchor_file(tmp_path, [anchor(1), anchor(2)])
    assert [a["key_tag"] for a in load_root_trust_anchors(path, datetime(2026, 1, 1, tzinfo=timezone.utc))] == [1, 2]


def test_anchor_loader_ignores_expired_anchor(tmp_path):
    path = write_anchor_file(tmp_path, [anchor(1, until="2021-01-01T00:00:00+00:00"), anchor(2)])
    assert [a["key_tag"] for a in load_root_trust_anchors(path, datetime(2026, 1, 1, tzinfo=timezone.utc))] == [2]


def test_anchor_loader_fails_when_no_current_anchor_remains(tmp_path):
    path = write_anchor_file(tmp_path, [anchor(1, until="2021-01-01T00:00:00+00:00")])
    with pytest.raises(AnchorFileError, match="No currently valid"):
        load_root_trust_anchors(path, datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_anchor_loader_fails_clearly_on_malformed_file(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(AnchorFileError, match="Malformed DNSSEC root trust anchor file"):
        load_root_trust_anchors(path)


@pytest.mark.asyncio
async def test_dnssec_network_failure_is_inconclusive():
    class FailedResolver:
        async def resolve(self, name, rdtype, **kwargs):
            raise dns.exception.Timeout
    result, _ = await check_dnssec("example.test", FailedResolver())
    assert result["status"] == "inconclusive"
    assert result["cryptographically_verified"] is False

