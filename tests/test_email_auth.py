"""Tests for DMARC, DKIM, and Email Health Scoring (app/email_auth.py)."""

import pytest

from app.email_auth import (
    _parse_tags,
    analyze_dkim,
    analyze_dmarc,
    check_dkim_selectors,
    compute_email_score,
    fetch_dmarc,
)
from app.models import Finding
from tests.conftest import MockAnswer, MockResolver, MockRR


class TestDMARCParsing:
    def test_parse_tags(self):
        raw = "v=DMARC1; p=reject; pct=100; rua=mailto:reports@example.com; ; "
        tags = _parse_tags(raw)
        assert tags["v"] == "DMARC1"
        assert tags["p"] == "reject"
        assert tags["pct"] == "100"
        assert tags["rua"] == "mailto:reports@example.com"

    @pytest.mark.asyncio
    async def test_fetch_dmarc_success(self):
        dmarc_rr = MockRR(strings=[b"v=DMARC1; p=quarantine; pct=100; rua=mailto:rep@example.com"])
        resolver = MockResolver({
            ("_dmarc.example.com", "TXT"): MockAnswer([dmarc_rr]),
        })

        res = await fetch_dmarc("example.com", resolver)
        assert res is not None
        assert res["version"] == "DMARC1"
        assert res["policy"] == "quarantine"
        assert res["pct"] == 100
        assert res["rua"] == "mailto:rep@example.com"

    @pytest.mark.asyncio
    async def test_fetch_dmarc_none_when_missing(self):
        resolver = MockResolver({})
        res = await fetch_dmarc("example.com", resolver)
        assert res is None


class TestDMARCAnalyzer:
    def test_analyze_dmarc_missing(self):
        findings = analyze_dmarc(None)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "no DMARC policy" in findings[0].message

    def test_analyze_dmarc_policy_none_warning(self):
        data = {
            "raw": "v=DMARC1; p=none",
            "policy": "none",
            "pct": 100,
            "rua": None,
            "ruf": None,
        }
        findings = analyze_dmarc(data)
        assert any(
            f.severity == "warning" and "p=none" in f.message or "set to 'none'" in f.message for f in findings
        )

    def test_analyze_dmarc_partial_percentage(self):
        data = {
            "raw": "v=DMARC1; p=reject; pct=50",
            "policy": "reject",
            "pct": 50,
            "rua": "mailto:rep@example.com",
            "ruf": None,
        }
        findings = analyze_dmarc(data)
        assert any(
            f.severity == "warning" and "50%" in f.message for f in findings
        )

    def test_analyze_dmarc_strict_reject(self):
        data = {
            "raw": "v=DMARC1; p=reject; pct=100; rua=mailto:r@example.com",
            "policy": "reject",
            "pct": 100,
            "rua": "mailto:r@example.com",
            "ruf": None,
        }
        findings = analyze_dmarc(data)
        assert any(
            f.severity == "info" and "reject" in f.message for f in findings
        )


class TestDKIM:
    @pytest.mark.asyncio
    async def test_check_dkim_selectors(self):
        dkim_rr = MockRR(strings=[b"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD"])
        resolver = MockResolver({
            ("google._domainkey.example.com", "TXT"): MockAnswer([dkim_rr]),
        })

        res = await check_dkim_selectors("example.com", resolver)
        assert res["has_dkim"] is True
        assert len(res["selectors_found"]) == 1
        assert res["selectors_found"][0]["selector"] == "google"
        assert res["selectors_found"][0]["has_key"] is True

    def test_analyze_dkim_found_vs_missing(self):
        # Missing DKIM
        f_missing = analyze_dkim({"has_dkim": False, "selectors_found": []})
        assert len(f_missing) == 1
        assert f_missing[0].severity == "warning"

        # Found DKIM
        sel = {
            "selector": "google",
            "has_key": True,
            "flags": None,
            "key_type": "rsa",
            "public_key": "MIGf...",
        }
        f_found = analyze_dkim({"has_dkim": True, "selectors_found": [sel]})
        assert len(f_found) == 1
        assert f_found[0].severity == "info"
        assert "google" in f_found[0].message


class TestEmailScore:
    def test_email_score_high_grade(self):
        spf_findings = [Finding(severity="info", record_type="SPF", message="OK")]
        dmarc_findings = [
            Finding(severity="info", record_type="DMARC", message="policy is 'reject'"),
            Finding(severity="info", record_type="DMARC", message="reporting rua configured"),
        ]
        dkim_findings = [Finding(severity="info", record_type="DKIM", message="DKIM selector active")]

        score = compute_email_score(spf_findings, dmarc_findings, dkim_findings)
        assert score["score"] >= 90
        assert score["grade"] in ("A+", "A")

    def test_email_score_poor_grade_when_all_missing(self):
        spf_findings = [
            Finding(severity="error", record_type="SPF", message="No SPF record found"),
            Finding(severity="error", record_type="SPF", message="Second SPF error"),
        ]
        dmarc_findings = [
            Finding(severity="error", record_type="DMARC", message="No DMARC policy found"),
            Finding(severity="error", record_type="DMARC", message="Second DMARC error"),
        ]
        dkim_findings = [
            Finding(severity="warning", record_type="DKIM", message="No DKIM found"),
            Finding(severity="warning", record_type="DKIM", message="Second DKIM warning"),
        ]

        score = compute_email_score(spf_findings, dmarc_findings, dkim_findings)
        assert score["score"] < 50
        assert score["grade"] in ("D", "F")
