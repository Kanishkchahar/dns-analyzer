"""Tests for Pydantic data models and input validation."""

import pytest
from pydantic import ValidationError

from app.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    EmailAuth,
    EmailScore,
    Finding,
    RemediationFix,
    SecurityAudit,
    Summary,
)


class TestAnalyzeRequest:
    @pytest.mark.parametrize(
        "raw_input,expected_domain",
        [
            ("example.com", "example.com"),
            ("EXAMPLE.COM", "example.com"),
            ("  google.com  ", "google.com"),
            ("sub.domain.co.uk", "sub.domain.co.uk"),
            ("cloudflare123.com", "cloudflare123.com"),
            ("my-domain-test.org", "my-domain-test.org"),
            ("https://example.com", "example.com"),
            ("http://sub.domain.org/dashboard/users", "sub.domain.org"),
            ("https://github.com/org/repo?tab=stars#readme", "github.com"),
            ("http://example.com:8080/test", "example.com"),
            ("example.com.", "example.com"),
            ("münchen.de", "xn--mnchen-3ya.de"),
            ("https://MÜNCHEN.de", "xn--mnchen-3ya.de"),
        ],
    )
    def test_valid_domain_inputs(self, raw_input: str, expected_domain: str):
        req = AnalyzeRequest(domain=raw_input)
        assert req.domain == expected_domain

    @pytest.mark.parametrize(
        "invalid_input",
        [
            "",
            "   ",
            "notadomain",
            "invalid..domain.com",
            "-leadingdash.com",
            "trailingdash-.com",
            "https://",
            "http:///",
            "@special!char.com",
            "domain with spaces.com",
            "example.c",  # TLD must be >= 2 characters
        ],
    )
    def test_invalid_domain_inputs(self, invalid_input: str):
        with pytest.raises(ValidationError):
            AnalyzeRequest(domain=invalid_input)


class TestDataSchemas:
    def test_finding_schema(self):
        f = Finding(severity="error", record_type="A", message="Test error message")
        assert f.severity == "error"
        assert f.record_type == "A"
        assert f.message == "Test error message"

    def test_finding_gets_stable_catalog_code_and_plain_language_guidance(self):
        finding = Finding(severity="error", record_type="AXFR", message="Zone transfer was allowed.")

        assert finding.code == "DNS-AXFR-001"
        assert finding.explanation["fix"]
        assert "never record contents" in finding.explanation["technical"]

    def test_summary_schema(self):
        s = Summary(errors=1, warnings=2, info=3)
        assert s.errors == 1
        assert s.warnings == 2
        assert s.info == 3

    def test_email_score_schema(self):
        score = EmailScore(score=95, grade="A+", label="Exceptional")
        assert score.score == 95
        assert score.grade == "A+"
        assert score.label == "Exceptional"

    def test_remediation_fix_schema(self):
        fix = RemediationFix(
            title="Add SPF",
            record_type="TXT",
            host="@",
            value="v=spf1 -all",
            ttl=3600,
            provider_guides={"Cloudflare": "Add TXT @"},
        )
        assert fix.title == "Add SPF"
        assert fix.record_type == "TXT"
        assert fix.ttl == 3600
        assert "Cloudflare" in fix.provider_guides

    def test_analyze_response_schema(self):
        resp = AnalyzeResponse(
            domain="example.com",
            scan_timestamp="2026-11-07 10:00:00 UTC",
            records={"A": {"status": "ok", "records": ["1.2.3.4"], "ttl": 300}},
            findings=[Finding(severity="info", record_type="A", message="OK")],
            summary=Summary(errors=0, warnings=0, info=1),
            email_auth=EmailAuth(
                score=EmailScore(score=100, grade="A+", label="Perfect")
            ),
            security=SecurityAudit(),
            remediation=[],
            bind_zone_snippet="$ORIGIN example.com.\n",
        )
        assert resp.domain == "example.com"
        assert resp.summary.info == 1
        assert resp.email_auth.score.grade == "A+"
