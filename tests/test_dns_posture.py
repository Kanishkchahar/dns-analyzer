from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import ipaddress

import pytest

from app import dns_posture


def test_cymru_query_names_reverse_ipv4_octets_and_ipv6_nibbles():
    assert dns_posture._cymru_query_name("8.8.8.8") == "8.8.8.8.origin.asn.cymru.com."
    ip6 = ipaddress.ip_address("2001:4860:b002::68").exploded
    expected = ".".join(reversed(ip6.replace(":", ""))) + ".origin6.asn.cymru.com."
    assert dns_posture._cymru_query_name("2001:4860:b002::68") == expected


@pytest.mark.asyncio
async def test_nameserver_asn_diversity_warns_only_for_complete_shared_origin(monkeypatch):
    from app.work_budget import ScanWorkBudget

    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[
        ["8.8.8.8"], ["8.8.4.4"],
    ]))
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(strings=[b"15169 | 8.8.0.0/16 | US | arin | 2000-01-01"]),
    ]))
    result, findings = await dns_posture.check_nameserver_asn_diversity(
        ["ns1.example.net", "ns2.example.net"],
        resolver,
        work_budget=ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dns_posture": 4}),
    )

    assert result["status"] == "complete"
    assert result["asns"] == ["15169"]
    assert result["single_asn"] is True
    assert len(findings) == 1
    assert findings[0].code == "DNS-NS-ASN-001"


@pytest.mark.asyncio
async def test_nameserver_asn_diversity_does_not_warn_when_asns_differ(monkeypatch):
    from app.work_budget import ScanWorkBudget

    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[
        ["8.8.8.8"], ["1.1.1.1"],
    ]))
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(strings=[b"15169 | 8.8.0.0/16 | US | arin | 2000-01-01"])],
        [SimpleNamespace(strings=[b"13335 | 1.1.1.0/24 | AU | apnic | 2011-01-01"])],
    ]))
    result, findings = await dns_posture.check_nameserver_asn_diversity(
        ["ns1.example.net", "ns2.example.net"],
        resolver,
        work_budget=ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dns_posture": 4}),
    )

    assert result["status"] == "complete"
    assert result["single_asn"] is False
    assert result["asns"] == ["13335", "15169"]
    assert findings == []


@pytest.mark.asyncio
async def test_nameserver_asn_diversity_keeps_multi_origin_answers_distinct(monkeypatch):
    from app.work_budget import ScanWorkBudget

    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[
        ["8.8.8.8"], ["8.8.4.4"],
    ]))
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(strings=[b"15169 | 8.8.0.0/16 | US | arin | 2000-01-01"]),
        SimpleNamespace(strings=[b"13335 | 8.8.0.0/16 | US | arin | 2000-01-01"]),
    ]))
    result, findings = await dns_posture.check_nameserver_asn_diversity(
        ["ns1.example.net", "ns2.example.net"],
        resolver,
        work_budget=ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dns_posture": 4}),
    )

    assert result["status"] == "complete"
    assert result["asns"] == ["13335", "15169"]
    assert result["single_asn"] is False
    assert findings == []


@pytest.mark.asyncio
async def test_nameserver_asn_diversity_keeps_lookup_failure_inconclusive(monkeypatch):
    import dns.resolver
    from app.work_budget import ScanWorkBudget

    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[
        ["8.8.8.8"], ["1.1.1.1"],
    ]))
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(strings=[b"15169 | 8.8.0.0/16 | US | arin | 2000-01-01"])],
        dns.resolver.Timeout(),
    ]))
    result, findings = await dns_posture.check_nameserver_asn_diversity(
        ["ns1.example.net", "ns2.example.net"],
        resolver,
        work_budget=ScanWorkBudget(dns_queries=4, http_requests=0, dns_shares={"dns_posture": 4}),
    )

    assert result["status"] == "inconclusive"
    assert result["single_asn"] is None
    assert findings == []


@pytest.mark.asyncio
async def test_nameserver_asn_diversity_budget_exhaustion_is_inconclusive(monkeypatch):
    from app.work_budget import ScanWorkBudget

    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(return_value=["8.8.8.8"]))
    resolver = SimpleNamespace(resolve=AsyncMock())
    result, findings = await dns_posture.check_nameserver_asn_diversity(
        ["ns1.example.net", "ns2.example.net"],
        resolver,
        work_budget=ScanWorkBudget(dns_queries=0, http_requests=0, dns_shares={"dns_posture": 0}),
    )

    assert result["status"] == "inconclusive"
    assert result["single_asn"] is None
    assert resolver.resolve.await_count == 0
    assert findings == []


@pytest.mark.asyncio
async def test_wildcard_probe_returns_only_public_addresses(monkeypatch):
    resolver = SimpleNamespace(resolve=AsyncMock(side_effect=[
        [SimpleNamespace(address="203.0.113.8")],
        [SimpleNamespace(address="2606:4700:4700::1111")],
    ]))

    result, findings = await dns_posture.check_wildcard_dns("example.com", resolver)

    assert result["status"] == "detected"
    assert result["addresses"] == ["2606:4700:4700::1111"]
    assert len(findings) == 1
    assert "203.0.113.8" not in findings[0].message


@pytest.mark.asyncio
async def test_zone_transfer_finding_contains_count_but_no_zone_contents(monkeypatch):
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(return_value=["8.8.8.8"]))
    monkeypatch.setattr(dns_posture, "_attempt_transfer_record_count", AsyncMock(return_value=12))
    resolver = SimpleNamespace()

    result, findings = await dns_posture.check_zone_transfers("example.com", ["ns1.example.net"], resolver)

    assert result["servers"] == [{
        "nameserver": "ns1.example.net",
        "status": "transfer_allowed",
        "records_exposed": 12,
    }]
    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert "12 records" in findings[0].message
    assert "secret.example.com" not in str(result)


@pytest.mark.asyncio
async def test_zone_transfer_refusal_is_not_reported_as_exposure(monkeypatch):
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(return_value=["8.8.8.8"]))

    async def denied(*_):
        raise OSError("transfer refused")

    monkeypatch.setattr(dns_posture, "_attempt_transfer_record_count", denied)
    result, findings = await dns_posture.check_zone_transfers("example.com", ["ns1.example.net"], SimpleNamespace())

    assert result["servers"][0]["status"] == "refused_or_unavailable"
    assert result["servers"][0]["records_exposed"] == 0
    assert findings == []


@pytest.mark.asyncio
async def test_nameserver_consistency_reports_serial_and_ns_drift(monkeypatch):
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_direct_authority_observation", AsyncMock(side_effect=[
        {"nameserver": "ns1.example.net", "address": "8.8.8.8", "soa_serial": 10, "ns_records": ["ns1.example.net"]},
        {"nameserver": "ns2.example.net", "address": "1.1.1.1", "soa_serial": 11, "ns_records": ["ns2.example.net"]},
    ]))

    result, findings = await dns_posture.check_nameserver_consistency(
        "example.com", ["ns1.example.net", "ns2.example.net"], SimpleNamespace()
    )

    assert result["serials_match"] is False
    assert result["ns_sets_match"] is False
    assert len(findings) == 2
    assert all(item.severity == "warning" for item in findings)


def _parent_observation(server_ip, ns_hosts, glue):
    return {
        "server_ip": server_ip, "status": "complete", "rcode": "NOERROR",
        "authoritative": False, "nameservers": ns_hosts, "glue": glue,
    }


def test_parent_referral_extracts_child_ns_and_only_referral_glue(monkeypatch):
    import dns.flags
    import dns.message
    import dns.rrset

    response_holder = {}

    def fake_udp(query, _address, timeout):
        response_holder["query"] = query
        response = dns.message.make_response(query)
        response.authority.append(dns.rrset.from_text(
            "example.com.", 300, "IN", "NS", "ns1.example.com.", "ns2.provider.net.",
        ))
        response.additional.append(dns.rrset.from_text("ns1.example.com.", 300, "IN", "A", "192.0.2.10"))
        return response

    monkeypatch.setattr(dns_posture.dns.query, "udp", fake_udp)
    result = dns_posture._parent_referral("8.8.8.8", "example.com", 1.0)

    assert not (response_holder["query"].flags & dns.flags.RD)
    assert result["nameservers"] == ["ns1.example.com", "ns2.provider.net"]
    assert result["glue"]["ns1.example.com"] == ["192.0.2.10"]
    assert result["glue"]["ns2.provider.net"] == []


@pytest.mark.asyncio
async def test_parent_referral_tcp_fallback_uses_a_second_dns_budget_unit(monkeypatch):
    import dns.flags
    import dns.message
    import dns.rrset
    from app.work_budget import ScanWorkBudget

    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(dns_posture.asyncio, "to_thread", run_inline)

    calls = []

    def fake_udp(query, _address, timeout):
        calls.append("udp")
        response = dns.message.make_response(query)
        response.flags |= dns.flags.TC
        return response

    def fake_tcp(query, _address, timeout):
        calls.append("tcp")
        response = dns.message.make_response(query)
        response.authority.append(dns.rrset.from_text("example.com.", 300, "IN", "NS", "ns1.example.com."))
        return response

    monkeypatch.setattr(dns_posture.dns.query, "udp", fake_udp)
    monkeypatch.setattr(dns_posture.dns.query, "tcp", fake_tcp)
    budget = ScanWorkBudget(dns_queries=2, http_requests=0, dns_shares={"dns_posture": 2})
    result = await dns_posture._query_parent_referral("8.8.8.8", "example.com", 1.0, budget)
    assert result["status"] == "complete"
    assert calls == ["udp", "tcp"]
    assert budget.dns_remaining == 0


@pytest.mark.asyncio
async def test_parent_referral_does_not_retry_tcp_after_budget_exhaustion(monkeypatch):
    import dns.flags
    import dns.message
    from app.work_budget import ScanWorkBudget

    async def run_inline(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(dns_posture.asyncio, "to_thread", run_inline)

    tcp = Mock()

    def fake_udp(query, _address, timeout):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.TC
        return response

    monkeypatch.setattr(dns_posture.dns.query, "udp", fake_udp)
    monkeypatch.setattr(dns_posture.dns.query, "tcp", tcp)
    budget = ScanWorkBudget(dns_queries=1, http_requests=0, dns_shares={"dns_posture": 1})
    result = await dns_posture._query_parent_referral("8.8.8.8", "example.com", 1.0, budget)
    assert result["status"] == "inconclusive"
    assert result["reason"] == "budget_exhausted_before_tcp_fallback"
    tcp.assert_not_called()


@pytest.mark.asyncio
async def test_parent_child_delegation_matches_and_checks_only_required_glue(monkeypatch):
    from app.work_budget import ScanWorkBudget

    parent_ns = ["ns1.example.com", "ns2.provider.net"]
    parent_resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(target="ns1.parent.net."), SimpleNamespace(target="ns2.parent.net."),
    ]))
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_query_parent_referral", AsyncMock(side_effect=[
        _parent_observation("8.8.8.8", parent_ns, {"ns1.example.com": ["192.0.2.10"], "ns2.provider.net": []}),
        _parent_observation("1.1.1.1", parent_ns, {"ns1.example.com": ["192.0.2.10"], "ns2.provider.net": []}),
    ]))
    children = [
        {"nameserver": "ns1.example.com", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": parent_ns, "errors": {}},
        {"nameserver": "ns2.provider.net", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": parent_ns, "errors": {}},
    ]
    budget = ScanWorkBudget(dns_queries=10, http_requests=0, dns_shares={"dns_posture": 10})

    result, findings = await dns_posture.check_parent_child_delegation(
        "example.com", parent_resolver, children, work_budget=budget,
    )

    assert result["status"] == "complete"
    assert result["delegation_matches"] is True
    assert [item["status"] for item in result["glue"]] == ["present", "not_required"]
    assert findings == []


@pytest.mark.asyncio
async def test_parent_child_delegation_flags_mismatch_and_missing_glue(monkeypatch):
    from app.work_budget import ScanWorkBudget

    parent_ns = ["ns1.example.com", "ns2.provider.net"]
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(target="ns1.parent.net."), SimpleNamespace(target="ns2.parent.net."),
    ]))
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_query_parent_referral", AsyncMock(return_value=_parent_observation(
        "8.8.8.8", parent_ns, {"ns1.example.com": [], "ns2.provider.net": []},
    )))
    children = [
        {"nameserver": "ns1.example.com", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ["ns1.example.com", "ns3.provider.net"], "errors": {}},
        {"nameserver": "ns3.provider.net", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ["ns1.example.com", "ns3.provider.net"], "errors": {}},
    ]
    budget = ScanWorkBudget(dns_queries=10, http_requests=0, dns_shares={"dns_posture": 10})

    result, findings = await dns_posture.check_parent_child_delegation(
        "example.com", resolver, children, work_budget=budget,
    )

    assert result["delegation_matches"] is False
    assert result["glue"][0]["status"] == "missing"
    assert {finding.code for finding in findings} == {"DNS-NS-DELEGATION-002", "DNS-NS-DELEGATION-003"}


@pytest.mark.asyncio
async def test_disagreeing_parent_authorities_do_not_create_a_mismatch_finding(monkeypatch):
    from app.work_budget import ScanWorkBudget

    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(target="ns1.parent.net."), SimpleNamespace(target="ns2.parent.net."),
    ]))
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_query_parent_referral", AsyncMock(side_effect=[
        _parent_observation("8.8.8.8", ["ns1.example.com", "ns2.example.com"], {}),
        _parent_observation("1.1.1.1", ["ns1.example.com", "ns3.example.com"], {}),
    ]))
    children = [
        {"nameserver": "ns1.example.com", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ["ns1.example.com", "ns2.example.com"], "errors": {}},
        {"nameserver": "ns2.example.com", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ["ns1.example.com", "ns2.example.com"], "errors": {}},
    ]
    budget = ScanWorkBudget(dns_queries=10, http_requests=0, dns_shares={"dns_posture": 10})

    result, findings = await dns_posture.check_parent_child_delegation("example.com", resolver, children, work_budget=budget)

    assert result["status"] == "inconclusive"
    assert result["delegation_matches"] is None
    assert findings == []


@pytest.mark.asyncio
async def test_parent_authorities_disagreeing_on_glue_get_a_separate_finding(monkeypatch):
    from app.work_budget import ScanWorkBudget

    ns_set = ["ns1.example.com", "ns2.example.com"]
    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(target="ns1.parent.net."), SimpleNamespace(target="ns2.parent.net."),
    ]))
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_query_parent_referral", AsyncMock(side_effect=[
        _parent_observation("8.8.8.8", ns_set, {"ns1.example.com": ["192.0.2.10"], "ns2.example.com": ["192.0.2.11"]}),
        _parent_observation("1.1.1.1", ns_set, {"ns1.example.com": ["192.0.2.12"], "ns2.example.com": ["192.0.2.11"]}),
    ]))
    children = [
        {"nameserver": host, "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ns_set, "errors": {}}
        for host in ns_set
    ]
    budget = ScanWorkBudget(dns_queries=10, http_requests=0, dns_shares={"dns_posture": 10})

    result, findings = await dns_posture.check_parent_child_delegation("example.com", resolver, children, work_budget=budget)

    assert result["status"] == "complete"
    assert result["glue"][0]["status"] == "inconsistent"
    assert any(finding.code == "DNS-NS-DELEGATION-005" for finding in findings)


@pytest.mark.asyncio
async def test_lame_child_authority_is_reported_but_parent_failure_is_inconclusive(monkeypatch):
    from app.work_budget import ScanWorkBudget

    resolver = SimpleNamespace(resolve=AsyncMock(return_value=[
        SimpleNamespace(target="ns1.parent.net."), SimpleNamespace(target="ns2.parent.net."),
    ]))
    monkeypatch.setattr(dns_posture, "_host_addresses", AsyncMock(side_effect=[["8.8.8.8"], ["1.1.1.1"]]))
    monkeypatch.setattr(dns_posture, "_query_parent_referral", AsyncMock(return_value=_parent_observation(
        "8.8.8.8", ["ns1.example.com", "ns2.example.com"],
        {"ns1.example.com": ["192.0.2.1"], "ns2.example.com": ["192.0.2.2"]},
    )))
    children = [
        {"nameserver": "ns1.example.com", "soa_authoritative": False, "soa_rcode": "NOERROR", "ns_records": [], "errors": {"SOA": "missing_answer"}},
        {"nameserver": "ns2.example.com", "soa_serial": 10, "soa_authoritative": True, "soa_rcode": "NOERROR", "ns_authoritative": True, "ns_records": ["ns1.example.com", "ns2.example.com"], "errors": {}},
    ]
    budget = ScanWorkBudget(dns_queries=10, http_requests=0, dns_shares={"dns_posture": 10})

    result, findings = await dns_posture.check_parent_child_delegation("example.com", resolver, children, work_budget=budget)

    assert result["status"] == "inconclusive"
    assert result["lame_nameservers"] == ["ns1.example.com"]
    assert any(finding.code == "DNS-NS-DELEGATION-004" for finding in findings)


@pytest.mark.asyncio
async def test_parent_delegation_dns_budget_exhaustion_is_inconclusive():
    from app.work_budget import ScanWorkBudget

    resolver = SimpleNamespace(resolve=AsyncMock())
    budget = ScanWorkBudget(dns_queries=0, http_requests=0, dns_shares={"dns_posture": 0})
    result, findings = await dns_posture.check_parent_child_delegation("example.com", resolver, [], work_budget=budget)
    assert result["status"] == "inconclusive"
    assert findings == []
    assert resolver.resolve.await_count == 0
