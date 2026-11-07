"""Tests for SPF parser, lookup counter, flattener, and analyzer (app/spf.py)."""

import pytest

from app.spf import (
    _parse_term,
    analyze_spf,
    count_spf_lookups,
    flatten_spf,
    parse_spf,
)
from tests.conftest import MockAnswer, MockResolver, MockRR


class TestSPFParser:
    def test_parse_term_various_mechanisms(self):
        t1 = _parse_term("+ip4:192.168.1.0/24")
        assert t1 == {"qualifier": "+", "type": "ip4", "value": "192.168.1.0/24"}

        t2 = _parse_term("include:_spf.google.com")
        assert t2 == {"qualifier": "+", "type": "include", "value": "_spf.google.com"}

        t3 = _parse_term("~all")
        assert t3 == {"qualifier": "~", "type": "all", "value": None}

        t4 = _parse_term("-all")
        assert t4 == {"qualifier": "-", "type": "all", "value": None}

        t5 = _parse_term("?all")
        assert t5 == {"qualifier": "?", "type": "all", "value": None}

        t6 = _parse_term("redirect=_spf.example.org")
        assert t6 == {"qualifier": "+", "type": "redirect", "value": "_spf.example.org"}

        t7 = _parse_term("exp=explain.example.org")
        assert t7 == {"qualifier": "+", "type": "exp", "value": "explain.example.org"}

    def test_parse_spf_finds_record(self):
        txts = [
            "google-site-verification=abcdef",
            "v=spf1 ip4:1.2.3.4 include:_spf.google.com -all",
        ]
        parsed = parse_spf(txts)
        assert parsed is not None
        assert parsed["raw"] == "v=spf1 ip4:1.2.3.4 include:_spf.google.com -all"
        assert parsed["version"] == "spf1"
        assert parsed["all_mechanism"] == "-all"
        assert parsed["includes"] == ["_spf.google.com"]
        assert len(parsed["mechanisms"]) == 3

    def test_parse_spf_none_found(self):
        assert parse_spf([]) is None
        assert parse_spf(["some-txt-record"]) is None


class TestSPFAnalyzer:
    def test_analyze_spf_missing(self):
        findings = analyze_spf(None, None, txt_records=[])
        assert len(findings) == 1
        assert findings[0].severity == "error"
        assert "No SPF record found" in findings[0].message

    def test_analyze_spf_multiple_records(self):
        txt_records = [
            "v=spf1 include:_spf.google.com ~all",
            "v=spf1 ip4:10.0.0.1 -all",
        ]
        spf_data = parse_spf(txt_records)
        findings = analyze_spf(spf_data, None, txt_records=txt_records)
        assert any(
            f.severity == "error" and "Multiple SPF records" in f.message
            for f in findings
        )

    def test_analyze_spf_plus_all_critical(self):
        txt = ["v=spf1 +all"]
        spf_data = parse_spf(txt)
        findings = analyze_spf(spf_data, None, txt_records=txt)
        assert any(
            f.severity == "error" and "+all" in f.message for f in findings
        )

    def test_analyze_spf_neutral_all_warning(self):
        txt = ["v=spf1 ?all"]
        spf_data = parse_spf(txt)
        findings = analyze_spf(spf_data, None, txt_records=txt)
        assert any(
            f.severity == "warning" and "?all" in f.message for f in findings
        )

    def test_analyze_spf_deprecated_ptr(self):
        txt = ["v=spf1 ptr -all"]
        spf_data = parse_spf(txt)
        findings = analyze_spf(spf_data, None, txt_records=txt)
        assert any(
            f.severity == "warning" and "ptr" in f.message for f in findings
        )

    def test_analyze_spf_lookup_limit_exceeded(self):
        txt = ["v=spf1 include:a.com include:b.com -all"]
        spf_data = parse_spf(txt)
        lookup_data = {"total_lookups": 11, "limit": 10, "over_limit": True, "tree": []}
        findings = analyze_spf(spf_data, lookup_data, txt_records=txt)
        assert any(
            f.severity == "error" and "exceeding" in f.message for f in findings
        )

    def test_analyze_spf_oversized(self):
        long_spf = "v=spf1 " + " ".join(f"ip4:192.0.2.{i}" for i in range(100)) + " -all"
        txt = [long_spf]
        spf_data = parse_spf(txt)
        findings = analyze_spf(spf_data, None, txt_records=txt)
        assert any(
            f.severity == "warning" and "exceeding" in f.message for f in findings
        )


@pytest.mark.asyncio
class TestSPFAsyncOperations:
    async def test_count_spf_lookups_tree(self):
        # Mock root domain pointing to include:child.com
        root_txt = MockRR(strings=[b"v=spf1 include:child.com -all"])
        child_txt = MockRR(strings=[b"v=spf1 ip4:1.1.1.1 -all"])

        responses = {
            ("example.com", "TXT"): MockAnswer([root_txt]),
            ("child.com", "TXT"): MockAnswer([child_txt]),
        }
        resolver = MockResolver(responses)

        res = await count_spf_lookups("example.com", resolver)
        assert res["total_lookups"] == 1
        assert res["limit"] == 10
        assert res["over_limit"] is False
        assert len(res["lookup_tree"]) == 1

    async def test_flatten_spf(self):
        root_txt = MockRR(strings=[b"v=spf1 include:child.com ip4:10.0.0.1 -all"])
        child_txt = MockRR(strings=[b"v=spf1 ip4:10.0.0.2 -all"])

        responses = {
            ("example.com", "TXT"): MockAnswer([root_txt]),
            ("child.com", "TXT"): MockAnswer([child_txt]),
        }
        resolver = MockResolver(responses)

        res = await flatten_spf("example.com", resolver)
        assert "v=spf1" in res["flattened_record"]
        assert "10.0.0.1" in res["ip4_ranges"]
        assert "10.0.0.2" in res["ip4_ranges"]
        assert res["flattened_lookups"] == 0
