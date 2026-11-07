"""Tests for standalone HTML report generation (app/report.py)."""

from app.models import (
    EmailAuth,
    EmailScore,
    Finding,
    RemediationFix,
    SecurityAudit,
    Summary,
)
from app.report import build_report


class TestReportBuilder:
    def test_build_report_renders_full_html(self, sample_resolver_data):
        findings = [
            Finding(severity="info", record_type="A", message="Domain resolves cleanly."),
            Finding(severity="warning", record_type="SPF", message="SPF uses ?all."),
        ]
        summary = Summary(errors=0, warnings=1, info=1)
        score = EmailScore(score=85, grade="B", label="Good")
        email_auth = EmailAuth(
            spf={"raw": "v=spf1 ?all", "all_mechanism": "?all", "mechanisms": []},
            dmarc={"raw": "v=DMARC1; p=quarantine", "policy": "quarantine", "pct": 100},
            score=score,
        )
        security = SecurityAudit(
            dnssec={"enabled": True, "status": "secured", "algorithm": "ECDSA", "records_count": {"dnskey": 1, "ds": 1}},
            takeover={"status": "safe", "vulnerable": False},
            bimi={"has_bimi": False, "status": "not_configured"},
        )
        fixes = [
            RemediationFix(
                title="Upgrade SPF",
                record_type="TXT",
                host="@",
                value="v=spf1 -all",
                ttl=3600,
            )
        ]

        html = build_report(
            domain="example.com",
            scan_timestamp="2026-11-07 10:00:00 UTC",
            records=sample_resolver_data,
            findings=findings,
            summary=summary,
            email_auth=email_auth,
            security=security,
            remediation=fixes,
        )

        assert "<!DOCTYPE html>" in html
        assert "<title>DNS Report — example.com</title>" in html
        assert "example.com" in html
        assert "Domain resolves cleanly." in html
        assert "SPF uses ?all." in html
        assert "v=spf1 ?all" in html
        assert "quarantine" in html
        assert "93.184.216.34" in html
