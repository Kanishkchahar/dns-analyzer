"""Tests for BIMI (Brand Indicators for Message Identification) Analyzer (app/bimi.py)."""

import pytest

from app.bimi import check_bimi
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestBIMI:
    async def test_bimi_not_configured_dmarc_eligible(self):
        resolver = MockResolver({})
        dmarc_data = {"policy": "reject", "pct": 100}

        data, findings = await check_bimi("example.com", dmarc_data, resolver)
        assert data["has_bimi"] is False
        assert data["status"] == "not_configured"
        assert data["dmarc_eligible"] is True
        assert any(
            f.severity == "info" and "eligible to publish a BIMI record" in f.message
            for f in findings
        )

    async def test_bimi_not_configured_dmarc_ineligible(self):
        resolver = MockResolver({})
        dmarc_data = {"policy": "none", "pct": 100}

        data, findings = await check_bimi("example.com", dmarc_data, resolver)
        assert data["has_bimi"] is False
        assert data["dmarc_eligible"] is False
        assert len(findings) == 0

    async def test_bimi_found_dmarc_ineligible_warning(self):
        bimi_rr = MockRR(strings=[b"v=BIMI1; l=https://example.com/logo.svg; a="])
        resolver = MockResolver({
            ("default._bimi.example.com", "TXT"): MockAnswer([bimi_rr]),
        })
        dmarc_data = {"policy": "none", "pct": 100}

        data, findings = await check_bimi("example.com", dmarc_data, resolver)
        assert data["has_bimi"] is True
        assert data["status"] == "dmarc_ineligible"
        assert any(
            f.severity == "warning" and "will NOT display your logo" in f.message
            for f in findings
        )

    async def test_bimi_missing_logo_tag_warning(self):
        bimi_rr = MockRR(strings=[b"v=BIMI1; a=https://example.com/cert.pem"])
        resolver = MockResolver({
            ("default._bimi.example.com", "TXT"): MockAnswer([bimi_rr]),
        })
        dmarc_data = {"policy": "reject", "pct": 100}

        data, findings = await check_bimi("example.com", dmarc_data, resolver)
        assert data["has_bimi"] is True
        assert data["status"] == "missing_logo"
        assert any(
            f.severity == "warning" and "missing the required SVG logo" in f.message
            for f in findings
        )

    async def test_bimi_active_with_vmc(self):
        bimi_rr = MockRR(strings=[b"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem"])
        resolver = MockResolver({
            ("default._bimi.example.com", "TXT"): MockAnswer([bimi_rr]),
        })
        dmarc_data = {"policy": "quarantine", "pct": 100}

        data, findings = await check_bimi("example.com", dmarc_data, resolver)
        assert data["has_bimi"] is True
        assert data["status"] == "active"
        assert data["logo_url"] == "https://example.com/logo.svg"
        assert data["vmc_url"] == "https://example.com/cert.pem"
        assert any(
            f.severity == "info" and "BIMI is active" in f.message for f in findings
        )
