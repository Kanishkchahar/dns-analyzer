from types import SimpleNamespace
from unittest.mock import AsyncMock
from datetime import datetime, timedelta, timezone
import hashlib

import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.extended_checks import _dnsbl_check, _dnsbl_query_name, _tlsa_check, _tlsa_match
from app.work_budget import ScanWorkBudget


def _make_test_certificate() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_tlsa_match_supports_dane_ee_certificate_and_spki_hashes():
    cert_der = _make_test_certificate()
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    for selector, selected in ((0, cert_der), (1, spki)):
        assert _tlsa_match(cert_der, {
            "usage": 3, "selector": selector, "matching_type": 1,
            "association_data": hashlib.sha256(selected).hexdigest(),
        }) is True
    assert _tlsa_match(cert_der, {
        "usage": 3, "selector": 0, "matching_type": 2,
        "association_data": hashlib.sha512(cert_der).hexdigest(),
    }) is True
    assert _tlsa_match(cert_der, {
        "usage": 3, "selector": 0, "matching_type": 1,
        "association_data": "00" * 32,
    }) is False
    assert _tlsa_match(cert_der, {
        "usage": 2, "selector": 0, "matching_type": 1,
        "association_data": "00" * 32,
    }) is None


@pytest.mark.asyncio
async def test_tlsa_check_reports_matching_evidence_without_claiming_dnssec(monkeypatch):
    cert_der = _make_test_certificate()
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[SimpleNamespace(
        usage=3, selector=0, mtype=1, cert=hashlib.sha256(cert_der).digest(),
    )]))
    monkeypatch.setattr("app.extended_checks.resolve_and_verify_all_ips", AsyncMock(return_value=(True, ["8.8.8.8"], None)))
    monkeypatch.setattr("app.extended_checks._https_leaf_certificate", AsyncMock(return_value=cert_der))
    budget = ScanWorkBudget(dns_queries=1, http_requests=1, dns_shares={"shared": 1}, http_shares={"tlsa_probe": 1})

    result, findings = await _tlsa_check("example.test", budget.resolver_for(resolver, "shared"), {"MX": {"records": []}}, budget)

    assert result["status"] == "matched_unvalidated"
    assert result["dnssec_validation"] == "not_performed"
    assert result["observations"][0]["addresses"][0]["matches"][0]["matched"] is True
    assert findings[0].code == "MAIL-DANE-001"


@pytest.mark.asyncio
async def test_tlsa_network_failure_is_inconclusive_and_does_not_probe(monkeypatch):
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[SimpleNamespace(
        usage=3, selector=0, mtype=1, cert=b"\x00" * 32,
    )]))
    monkeypatch.setattr("app.extended_checks.resolve_and_verify_all_ips", AsyncMock(return_value=(False, [], "unsafe address")))
    cert_probe = AsyncMock()
    monkeypatch.setattr("app.extended_checks._https_leaf_certificate", cert_probe)
    budget = ScanWorkBudget(dns_queries=1, http_requests=1, dns_shares={"shared": 1}, http_shares={"tlsa_probe": 1})

    result, findings = await _tlsa_check("example.test", budget.resolver_for(resolver, "shared"), {"MX": {"records": []}}, budget)

    assert result["status"] == "partial"
    assert findings[0].severity == "inconclusive"
    cert_probe.assert_not_awaited()


def test_dnsbl_query_reverses_only_public_ipv4_addresses():
    assert _dnsbl_query_name("8.8.8.8", "zen.spamhaus.org") == "8.8.8.8.zen.spamhaus.org."
    with pytest.raises(ValueError):
        _dnsbl_query_name("192.168.1.2", "zen.spamhaus.org")


@pytest.mark.asyncio
async def test_dnsbl_reports_only_source_specific_positive_return_codes():
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="8.8.8.8")],
        [SimpleNamespace(address="127.0.0.2")],
        dns.resolver.NXDOMAIN(),
        dns.resolver.NXDOMAIN(),
    ]))
    budget = ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dnsbl": 4})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "listed"
    assert result["observations"][0]["lists"][0]["status"] == "listed"
    assert len(findings) == 1
    assert findings[0].code == "MAIL-DNSBL-001"


@pytest.mark.asyncio
async def test_spamhaus_pbl_is_a_warning_not_a_malicious_listing_error():
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="8.8.8.8")],
        [SimpleNamespace(address="127.0.0.10")],
        dns.resolver.NXDOMAIN(),
        dns.resolver.NXDOMAIN(),
    ]))
    budget = ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dnsbl": 4})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "listed"
    assert findings[0].severity == "warning"
    assert "policy listing" in findings[0].message
    assert "127.0.0.10" in findings[0].message


@pytest.mark.asyncio
async def test_dnsbl_spamhaus_access_limit_is_inconclusive_not_listed():
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="8.8.8.8")],
        [SimpleNamespace(address="127.255.255.254")],
        dns.resolver.NXDOMAIN(),
        dns.resolver.NXDOMAIN(),
    ]))
    budget = ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dnsbl": 4})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "inconclusive"
    assert result["observations"][0]["lists"][0]["status"] == "inconclusive"
    assert all(finding.severity == "inconclusive" for finding in findings)
    assert not any("listed by" in finding.message for finding in findings)


@pytest.mark.asyncio
async def test_dnsbl_unknown_loopback_response_is_inconclusive():
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="8.8.8.8")],
        [SimpleNamespace(address="127.0.0.99")],
        dns.resolver.NXDOMAIN(),
        dns.resolver.NXDOMAIN(),
    ]))
    budget = ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dnsbl": 4})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "inconclusive"
    assert findings[0].severity == "inconclusive"


@pytest.mark.asyncio
async def test_dnsbl_budget_exhaustion_remains_inconclusive():
    resolver = SimpleNamespace(resolve=AsyncMock())
    budget = ScanWorkBudget(dns_queries=0, http_requests=0, dns_shares={"dnsbl": 1})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "inconclusive"
    assert findings[0].severity == "inconclusive"
    assert resolver.resolve.await_count == 0


@pytest.mark.asyncio
async def test_dnsbl_nxdomain_for_all_lists_is_a_completed_clear_result():
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="8.8.8.8")],
        dns.resolver.NXDOMAIN(), dns.resolver.NXDOMAIN(), dns.resolver.NXDOMAIN(),
    ]))
    budget = ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dnsbl": 4})

    result, findings = await _dnsbl_check(
        {"MX": {"records": [{"host": "mx.example.test"}]}},
        budget.resolver_for(resolver, "dnsbl"),
    )

    assert result["status"] == "clear"
    assert findings == []
