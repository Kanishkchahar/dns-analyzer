"""DNSSEC trust anchor loader and validation-state tests; no external DNS is used."""
from datetime import datetime, timezone
import json
from pathlib import Path

import dns.exception
import dns.dnssec
import dns.rdatatype
import dns.resolver
import pytest

from app.dnssec import AnchorFileError, _VALIDATED_RRSET_CACHE, _legacy_delegation_check, _resolve, check_dnssec, load_root_trust_anchors, reload_root_trust_anchors, validate_dnssec_chain
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


def _anchor_data(fixture):
    ds = fixture["trust_anchor"]
    return [{"key_tag": ds.key_tag, "algorithm": ds.algorithm, "digest_type": ds.digest_type,
             "digest": ds.digest.hex().upper(), "validFrom": "2020-01-01T00:00:00+00:00", "validUntil": None}]


@pytest.mark.asyncio
async def test_chain_validation_accepts_injected_anchor_and_clock_and_sets_do_cd():
    fixture = make_signed_hierarchy()
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain(
        "example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"],
    )
    assert result["status"] == "secure"
    assert result["cryptographically_verified"] is True
    assert all(call[3] & dns.flags.DO and call[4] & dns.flags.CD for call in fixture["resolver"].calls)
    queried = [(name, kind) for name, kind, *_ in fixture["resolver"].calls]
    assert queried.index((ZONE, dns.rdatatype.DS)) < queried.index((ZONE, dns.rdatatype.DNSKEY))


@pytest.mark.parametrize("algorithm", [8, 13, 15], ids=["rsa-sha256", "ecdsa-p256", "ed25519"])
@pytest.mark.asyncio
async def test_chain_validation_verifies_supported_algorithm_hierarchies(algorithm):
    fixture = make_signed_hierarchy(algorithm=algorithm)
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain(
        "example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"],
    )
    assert result["status"] == "secure"


@pytest.mark.parametrize("mode,expected,reason", [
    ("expired", "bogus", "signature_expired"),
    ("not_yet_valid", "bogus", "signature_not_yet_valid"),
    ("bad_signature", "bogus", "signature_validation_failed"),
    ("ds_mismatch", "bogus", "ds_dnskey_mismatch"),
    ("dnskey_stripped", "bogus", "dnskey_missing_for_validated_ds"),
    ("ds_bad_signature", "bogus", "signature_validation_failed"),
    ("ds_no_signature", "inconclusive", "missing_rrsig"),
    ("missing_ds", "inconclusive", "ds_absent_denial_not_validated"),
    ("missing_ds_tld", "inconclusive", "ds_absent_denial_not_validated"),
    ("unsupported_algorithm", "inconclusive", "unsupported_algorithm"),
    ("truncated_unrecoverable", "inconclusive", "dns_response_unavailable"),
    ("timeout", "inconclusive", "dns_response_unavailable"),
    ("budget_exhaustion", "inconclusive", "budget_exhausted"),
])
@pytest.mark.asyncio
async def test_chain_validation_state_matrix(mode, expected, reason):
    fixture = make_signed_hierarchy(mode=mode)
    _VALIDATED_RRSET_CACHE.clear()
    result, findings = await validate_dnssec_chain(
        "example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"],
    )
    assert result["status"] == expected
    assert any(node["reason_code"] == reason for node in result["chain"])
    assert result["cryptographically_verified"] is (expected == "secure")


@pytest.mark.asyncio
async def test_checking_disabled_flag_prevents_resolver_servfail():
    fixture = make_signed_hierarchy(mode="servfail_without_cd")
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
    assert result["status"] == "secure"
    assert fixture["resolver"].calls
    assert all(call[3] & dns.flags.DO and call[4] & dns.flags.CD for call in fixture["resolver"].calls)


@pytest.mark.asyncio
async def test_signed_but_unvalidated_parent_ds_is_inconclusive():
    fixture = make_signed_hierarchy(mode="ds_no_signature")
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
    assert result["status"] == "inconclusive"
    assert result["chain"][-1]["reason_code"] == "missing_rrsig"
    # Child DNSKEY must not be requested once the parent's DS proof fails.
    assert not any(name == ZONE and kind == dns.rdatatype.DNSKEY for name, kind, *_ in fixture["resolver"].calls)


@pytest.mark.asyncio
async def test_deprecated_algorithm_and_sha1_ds_have_findings():
    fixture = make_signed_hierarchy(mode="deprecated_algorithm")
    _VALIDATED_RRSET_CACHE.clear()
    result, findings = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
    assert result["status"] == "secure"
    assert {finding.code for finding in findings} >= {"DNSSEC-009", "DNSSEC-010"}


@pytest.mark.asyncio
async def test_signature_expiring_soon_has_warning_finding():
    fixture = make_signed_hierarchy(mode="expires_soon")
    _VALIDATED_RRSET_CACHE.clear()
    result, findings = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
    assert result["status"] == "secure"
    assert any(f.code == "DNSSEC-011" and f.severity == "warning" for f in findings)


@pytest.mark.asyncio
async def test_nsec3_opt_out_is_reported_and_nonzero_iterations_are_inconclusive():
    fixture = make_signed_hierarchy(mode="nsec3_opt_out")
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
    assert result["nsec"]["type"] == "NSEC3"
    assert result["nsec"]["nsec3_opt_out"] is True
    assert result["status"] == "secure"
    over_limit = make_signed_hierarchy(mode="nsec3_over_limit")
    _VALIDATED_RRSET_CACHE.clear()
    result, _ = await validate_dnssec_chain("example.test", over_limit["resolver"], trust_anchors=_anchor_data(over_limit), now=over_limit["now"])
    assert result["status"] == "inconclusive"
    assert result["nsec"]["iteration_limit"] == 0


@pytest.mark.asyncio
async def test_cached_rrset_is_not_reused_after_signature_expiry():
    fixture = make_signed_hierarchy()
    _VALIDATED_RRSET_CACHE.clear()
    anchor_data = _anchor_data(fixture)
    result, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=anchor_data, now=fixture["now"])
    assert result["status"] == "secure"
    prior_calls = len(fixture["resolver"].calls)
    later = fixture["now"] + __import__("datetime").timedelta(days=31)
    result, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=anchor_data, now=later)
    assert len(fixture["resolver"].calls) > prior_calls
    assert result["status"] == "bogus"


@pytest.mark.asyncio
async def test_validated_rrsets_are_reused_until_ttl_or_signature_expiry():
    fixture = make_signed_hierarchy()
    _VALIDATED_RRSET_CACHE.clear()
    anchors = _anchor_data(fixture)
    first, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=anchors, now=fixture["now"])
    calls_after_first = len(fixture["resolver"].calls)
    second, _ = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=anchors, now=fixture["now"])
    assert first["status"] == second["status"] == "secure"
    assert len(fixture["resolver"].calls) == calls_after_first + 1  # uncached informational NSEC3PARAM query only
    assert len(_VALIDATED_RRSET_CACHE) >= 6


@pytest.mark.asyncio
async def test_expired_and_not_yet_valid_signatures_have_distinct_error_codes():
    for mode, code in (("expired", "DNSSEC-012"), ("not_yet_valid", "DNSSEC-013")):
        fixture = make_signed_hierarchy(mode=mode)
        _VALIDATED_RRSET_CACHE.clear()
        _, findings = await validate_dnssec_chain("example.test", fixture["resolver"], trust_anchors=_anchor_data(fixture), now=fixture["now"])
        assert any(finding.code == code and finding.severity == "error" for finding in findings)


@pytest.mark.asyncio
async def test_truncated_dnssec_udp_and_tcp_attempts_both_consume_shared_dns_budget():
    from app.work_budget import ScanWorkBudget
    fixture = make_signed_hierarchy(mode="truncated_response")
    fixture["resolver"].use_edns(ednsflags=dns.flags.DO)
    fixture["resolver"].flags |= dns.flags.CD
    budget = ScanWorkBudget(dns_queries=2, http_requests=0, dns_shares={"dnssec": 2}, http_shares={"shared": 0})
    wrapped = budget.resolver_for(fixture["resolver"], "dnssec")
    answer = await _resolve(wrapped, ZONE, "DNSKEY")
    assert answer.rrset == fixture["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0]
    assert budget.dns_remaining == 0
    assert budget.dns_module_remaining["dnssec"] == 0


@pytest.mark.asyncio
async def test_configured_recursive_resolver_tcp_retry_is_budgeted_and_sets_do_cd(monkeypatch):
    import dns.asyncquery
    import dns.asyncresolver
    import dns.message
    from app.work_budget import ScanWorkBudget

    fixture = make_signed_hierarchy()
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    udp_calls, tcp_calls = [], []
    key_rrset, key_signature = fixture["hierarchy"][(dns.name.root, dns.rdatatype.DNSKEY)]

    async def fake_udp(request, where, **kwargs):
        udp_calls.append((request, where))
        response = dns.message.make_response(request)
        response.flags |= dns.flags.TC
        return response

    async def fake_tcp(request, where, **kwargs):
        tcp_calls.append((request, where))
        response = dns.message.make_response(request)
        signature_set = dns.rrset.from_rdata(dns.name.root, 300, key_signature)
        response.answer.extend([key_rrset, signature_set])
        return response

    monkeypatch.setattr(dns.asyncquery, "udp", fake_udp)
    monkeypatch.setattr(dns.asyncquery, "tcp", fake_tcp)
    budget = ScanWorkBudget(dns_queries=2, http_requests=0, dns_shares={"dnssec": 2}, http_shares={"shared": 0})
    wrapped = budget.resolver_for(resolver, "dnssec")
    answer = await _resolve(wrapped, dns.name.root, "DNSKEY")
    assert answer.rrset == key_rrset
    assert len(udp_calls) == len(tcp_calls) == 1
    assert all(request.ednsflags & dns.flags.DO and request.flags & dns.flags.CD for request, _ in udp_calls + tcp_calls)
    assert budget.dns_remaining == budget.dns_module_remaining["dnssec"] == 0


def test_reloading_trust_anchors_clears_validated_rrset_cache(tmp_path):
    _VALIDATED_RRSET_CACHE[(1, "example.test.", dns.rdatatype.DNSKEY, "anchor")] = (9999999999, object())
    path = write_anchor_file(tmp_path, [anchor(1)])
    reload_root_trust_anchors(path, datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert _VALIDATED_RRSET_CACHE == {}


def test_checked_in_anchor_file_records_verified_iana_provenance():
    path = Path(__file__).parents[1] / "app" / "data" / "root_trust_anchors.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["signature_verification"]["verified"] is True
    assert data["signature_verification"]["signature_url"].endswith("root-anchors.p7s")
    assert data["signature_verification"]["certificate_bundle_url"].endswith("icannbundle.pem")
    assert data["xml_sha256"] == "3ccaab38830025ee0a0f6c1f25769427544f81ea2865aa860468f3ef5278b908"

