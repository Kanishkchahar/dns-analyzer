from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app import dns_posture


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
