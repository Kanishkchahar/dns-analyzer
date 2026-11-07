"""Tests for DNS infrastructure analyzer rules (app/analyzer.py)."""

from typing import Any
import pytest

from app.analyzer import (
    analyze,
    check_cname_conflict,
    check_domain_resolves,
    check_mx_exists,
    check_mx_resolves,
    check_ns_exists,
    check_ns_redundancy,
    check_ns_resolves,
    check_soa_sanity,
    check_ttl_sanity,
    summarize,
)
from app.models import Finding


class TestAnalyzerChecks:
    def test_check_domain_resolves_when_a_or_aaaa_present(self, sample_resolver_data):
        assert check_domain_resolves(sample_resolver_data) == []

        # Only AAAA
        data_aaaa = {"A": {"status": "not_found"}, "AAAA": {"status": "ok"}}
        assert check_domain_resolves(data_aaaa) == []

    def test_check_domain_resolves_fails_when_no_ip(self):
        data = {"A": {"status": "not_found"}, "AAAA": {"status": "not_found"}}
        findings = check_domain_resolves(data)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "does not resolve to any IP address" in findings[0].message

    def test_check_ns_exists_success_and_failure(self):
        ok_data = {"NS": {"status": "ok", "records": [{"host": "ns1.example.com", "resolves": True}]}}
        assert check_ns_exists(ok_data) == []

        missing_data = {"NS": {"status": "not_found"}}
        findings = check_ns_exists(missing_data)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert findings[0].record_type == "NS"

    def test_check_ns_redundancy(self):
        # Multiple NS - good
        multi_ns = {"NS": {"status": "ok", "records": [{"host": "ns1.com"}, {"host": "ns2.com"}]}}
        assert check_ns_redundancy(multi_ns) == []

        # Single NS - warning
        single_ns = {"NS": {"status": "ok", "records": [{"host": "ns1.com"}]}}
        findings = check_ns_redundancy(single_ns)
        assert len(findings) == 1
        assert findings[0].severity == "warning"
        assert "redundancy" in findings[0].message.lower()

    def test_check_ns_resolves(self):
        data_good = {
            "NS": {
                "status": "ok",
                "records": [
                    {"host": "ns1.example.com", "resolves": True},
                    {"host": "ns2.example.com", "resolves": True},
                ],
            }
        }
        assert check_ns_resolves(data_good) == []

        data_bad = {
            "NS": {
                "status": "ok",
                "records": [
                    {"host": "ns1.example.com", "resolves": True},
                    {"host": "ns2.dead.com", "resolves": False},
                ],
            }
        }
        findings = check_ns_resolves(data_bad)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "ns2.dead.com" in findings[0].message

    def test_check_mx_exists(self):
        data_ok = {"MX": {"status": "ok", "records": [{"priority": 10, "host": "mail.com"}]}}
        assert check_mx_exists(data_ok) == []

        data_missing = {"MX": {"status": "not_found"}}
        findings = check_mx_exists(data_missing)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "No MX records found" in findings[0].message

    def test_check_mx_resolves(self):
        data_bad = {
            "MX": {
                "status": "ok",
                "records": [
                    {"priority": 10, "host": "mx1.broken.net", "resolves": False}
                ],
            }
        }
        findings = check_mx_resolves(data_bad)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "mx1.broken.net" in findings[0].message

    def test_check_cname_conflict(self):
        # CNAME alone is fine
        cname_alone = {
            "CNAME": {"status": "ok", "records": ["target.com"]},
            "A": {"status": "not_found"},
            "MX": {"status": "not_found"},
        }
        assert check_cname_conflict(cname_alone) == []

        # CNAME coexisting with A is an RFC 1034 violation
        cname_conflict = {
            "CNAME": {"status": "ok", "records": ["target.com"]},
            "A": {"status": "ok", "records": ["1.2.3.4"]},
        }
        findings = check_cname_conflict(cname_conflict)
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "RFC 1034" in findings[0].message

    def test_check_soa_sanity(self):
        # Missing SOA
        findings = check_soa_sanity({"SOA": {"status": "not_found"}})
        assert len(findings) == 1
        assert findings[0].severity == "error"

        # Healthy SOA
        healthy = {
            "SOA": {
                "status": "ok",
                "records": {"refresh": 7200, "retry": 3600, "expire": 1209600},
            }
        }
        assert check_soa_sanity(healthy) == []

        # Unusual SOA: refresh < retry
        unusual_refresh = {
            "SOA": {
                "status": "ok",
                "records": {"refresh": 1800, "retry": 3600, "expire": 1209600},
            }
        }
        f1 = check_soa_sanity(unusual_refresh)
        assert any(f.severity == "warning" and "smaller than retry" in f.message for f in f1)

        # Low expire (< 2 days / 172800s)
        low_expire = {
            "SOA": {
                "status": "ok",
                "records": {"refresh": 7200, "retry": 3600, "expire": 86400},
            }
        }
        f2 = check_soa_sanity(low_expire)
        assert any(f.severity == "warning" and "less than 2 days" in f.message for f in f2)

    def test_check_ttl_sanity(self):
        # TTL = 0 triggers warning
        data_zero = {"A": {"status": "ok", "ttl": 0}}
        f_zero = check_ttl_sanity(data_zero)
        assert len(f_zero) == 1
        assert f_zero[0].severity == "warning"
        assert "TTL of 0" in f_zero[0].message

        # TTL > 7 days (604800) triggers info
        data_high = {"A": {"status": "ok", "ttl": 800000}}
        f_high = check_ttl_sanity(data_high)
        assert len(f_high) == 1
        assert f_high[0].severity == "info"
        assert "unusually high" in f_high[0].message

        # Normal TTL
        data_normal = {"A": {"status": "ok", "ttl": 3600}}
        assert check_ttl_sanity(data_normal) == []


class TestAnalyzeAndSummarize:
    def test_full_analyze_and_summarize(self, sample_resolver_data):
        findings = analyze("example.com", sample_resolver_data)
        summary = summarize(findings)

        assert isinstance(findings, list)
        assert "errors" in summary
        assert "warnings" in summary
        assert "info" in summary
        assert summary["errors"] == 0
        assert summary["warnings"] == 0
