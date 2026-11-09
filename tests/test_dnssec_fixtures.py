"""Self-tests for the local signed DNSSEC hierarchy fixtures."""

import dns.dnssec
import dns.flags
import dns.rrset
import dns.rdatatype
import pytest

from tests.dnssec_fixtures import ROOT, TLD, ZONE, make_signed_hierarchy


def validate_set(zone, kind, fixture, keys=None, now=None, signer=None):
    rrset, signature = fixture["hierarchy"][(zone, dns.rdatatype.from_text(kind))]
    if not rrset or not signature:
        raise KeyError(f"Missing {kind} for {zone}")
    sigset = dns.rrset.from_rdata(zone, 300, signature)
    validation_keys = keys if keys is not None else fixture["hierarchy"][(zone, dns.rdatatype.DNSKEY)][0]
    dns.dnssec.validate(rrset, sigset, {signer or zone: validation_keys}, now=(now or fixture["now"]).timestamp())


def test_generated_root_tld_zone_hierarchy_validates_with_dnspython():
    fixture = make_signed_hierarchy()
    for zone in (ROOT, TLD, ZONE):
        validate_set(zone, "DNSKEY", fixture)
        validate_set(zone, "SOA", fixture)
    for child, parent in ((TLD, ROOT), (ZONE, TLD)):
        validate_set(child, "DS", fixture, fixture["hierarchy"][(parent, dns.rdatatype.DNSKEY)][0], signer=parent)
        ds = fixture["hierarchy"][(child, dns.rdatatype.DS)][0][0]
        assert dns.dnssec.make_ds(child, fixture["dnskeys"][child], ds.digest_type).digest == ds.digest


@pytest.mark.parametrize("algorithm", [8, 13, 15], ids=["rsa-sha256", "ecdsa-p256", "ed25519"])
def test_fixture_generates_supported_throwaway_key_algorithms(algorithm):
    fixture = make_signed_hierarchy(algorithm=algorithm)
    for zone in (ROOT, TLD, ZONE):
        validate_set(zone, "DNSKEY", fixture)
        validate_set(zone, "SOA", fixture)
        assert fixture["dnskeys"][zone].algorithm == algorithm
    for child, parent in ((TLD, ROOT), (ZONE, TLD)):
        validate_set(child, "DS", fixture, fixture["hierarchy"][(parent, dns.rdatatype.DNSKEY)][0], signer=parent)


@pytest.mark.parametrize("mode", ["expired", "not_yet_valid", "bad_signature"])
def test_signature_tampering_breaks_validation(mode):
    clean = make_signed_hierarchy()
    fixture = make_signed_hierarchy(mode=mode)
    assert fixture["hierarchy"][(ZONE, dns.rdatatype.SOA)] != clean["hierarchy"][(ZONE, dns.rdatatype.SOA)]
    with pytest.raises(dns.dnssec.ValidationFailure):
        validate_set(ZONE, "SOA", fixture)


def test_ds_mismatch_is_signed_but_does_not_match_key():
    clean = make_signed_hierarchy()
    fixture = make_signed_hierarchy(mode="ds_mismatch")
    assert fixture["hierarchy"][(ZONE, dns.rdatatype.DS)][0] != clean["hierarchy"][(ZONE, dns.rdatatype.DS)][0]
    validate_set(ZONE, "DS", fixture, fixture["hierarchy"][(TLD, dns.rdatatype.DNSKEY)][0], signer=TLD)
    ds = fixture["hierarchy"][(ZONE, dns.rdatatype.DS)][0][0]
    assert dns.dnssec.key_id(fixture["dnskeys"][ZONE]) != ds.key_tag


def test_missing_ds_and_stripped_dnskey_modes_remove_records():
    clean = make_signed_hierarchy()
    missing = make_signed_hierarchy(mode="missing_ds")
    stripped = make_signed_hierarchy(mode="dnskey_stripped")
    assert missing["hierarchy"].get((ZONE, dns.rdatatype.DS)) is None
    assert (ZONE, dns.rdatatype.DS) in clean["hierarchy"]
    assert stripped["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)] == (None, None)
    assert clean["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0] is not None


def test_unsupported_and_deprecated_algorithm_modes_are_visible():
    clean = make_signed_hierarchy()
    unsupported = make_signed_hierarchy(mode="unsupported_algorithm")
    assert any(key.algorithm == 253 for key in unsupported["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0])
    assert unsupported["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0] != clean["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0]
    deprecated = make_signed_hierarchy(mode="deprecated_algorithm")
    assert deprecated["hierarchy"][(ZONE, dns.rdatatype.DS)][0][0].digest_type == 1
    assert deprecated["dnskeys"][ZONE].algorithm == 5
    assert deprecated["hierarchy"][(ZONE, dns.rdatatype.DS)][0] != clean["hierarchy"][(ZONE, dns.rdatatype.DS)][0]


@pytest.mark.asyncio
async def test_fake_resolver_udp_truncation_retries_tcp_and_preserves_do_cd():
    fixture = make_signed_hierarchy(mode="truncated_response")
    resolver = fixture["resolver"]
    resolver.use_edns(ednsflags=dns.flags.DO)
    resolver.flags |= dns.flags.CD
    udp = await resolver.resolve(ZONE, "DNSKEY", tcp=False)
    assert udp.response.flags & dns.flags.TC
    tcp = await resolver.resolve(ZONE, "DNSKEY", tcp=True)
    assert any(call[2] is False for call in resolver.calls)
    assert any(call[2] is True for call in resolver.calls)
    assert all(call[3] & dns.flags.DO for call in resolver.calls)
    assert all(call[4] & dns.flags.CD for call in resolver.calls)
    assert tcp.rrset == fixture["hierarchy"][(ZONE, dns.rdatatype.DNSKEY)][0]


@pytest.mark.asyncio
async def test_fake_resolver_only_serves_signatures_when_do_is_set():
    fixture = make_signed_hierarchy()
    without_do = await fixture["resolver"].resolve(ZONE, "DNSKEY")
    assert all(entry.rdtype != dns.rdatatype.RRSIG for entry in without_do.response.answer)
    resolver = make_signed_hierarchy()["resolver"]
    resolver.use_edns(ednsflags=dns.flags.DO)
    with_do = await resolver.resolve(ZONE, "DNSKEY")
    assert any(entry.rdtype == dns.rdatatype.RRSIG for entry in with_do.response.answer)


@pytest.mark.asyncio
async def test_fake_resolver_timeout_servfail_cd_and_budget_modes():
    import dns.exception
    import dns.resolver
    from app.work_budget import ScanBudgetExhausted
    from tests.dnssec_fixtures import FakeDNSSECResolver

    with pytest.raises(dns.exception.Timeout):
        await FakeDNSSECResolver({}, "timeout").resolve(ZONE, "SOA")
    servfail = FakeDNSSECResolver({}, "servfail_without_cd")
    with pytest.raises(dns.resolver.NoNameservers):
        await servfail.resolve(ZONE, "SOA")
    servfail.flags |= dns.flags.CD
    await servfail.resolve(ZONE, "SOA")
    limited = FakeDNSSECResolver(make_signed_hierarchy()["hierarchy"], "budget_exhaustion")
    await limited.resolve(ZONE, "SOA")
    await limited.resolve(ZONE, "SOA")
    with pytest.raises(ScanBudgetExhausted):
        await limited.resolve(ZONE, "SOA")
