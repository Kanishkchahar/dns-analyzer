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
        assert res["can_flatten"] is True
        assert "v=spf1" in res["flattened_record"]
        assert res["flattened_record"].endswith("-all")
        assert "10.0.0.1" in res["ip4_ranges"]
        assert "10.0.0.2" in res["ip4_ranges"]
        assert res["flattened_lookups"] == 0

    async def test_flatten_spf_preserves_softfail_all_qualifier(self):
        root_txt = MockRR(strings=[b"v=spf1 ip4:192.168.1.1 ~all"])
        responses = {("example.com", "TXT"): MockAnswer([root_txt])}
        resolver = MockResolver(responses)

        res = await flatten_spf("example.com", resolver)
        assert res["can_flatten"] is True
        assert res["flattened_record"] == "v=spf1 ip4:192.168.1.1 ~all"
        assert res["flattened_record"].endswith("~all")

    async def test_flatten_spf_refuses_unsafe_records(self):
        # 1. Missing explicit 'all' mechanism
        no_all_rr = MockRR(strings=[b"v=spf1 ip4:192.168.1.1"])
        res1 = await flatten_spf("example.com", MockResolver({("example.com", "TXT"): MockAnswer([no_all_rr])}))
        assert res1["can_flatten"] is False
        assert res1["flattened_record"] is None
        assert "lacks an explicit 'all'" in res1["reason"]

        # 2. Unsupported mechanism: ptr
        ptr_rr = MockRR(strings=[b"v=spf1 ptr:isp.com -all"])
        res2 = await flatten_spf("example.com", MockResolver({("example.com", "TXT"): MockAnswer([ptr_rr])}))
        assert res2["can_flatten"] is False
        assert res2["flattened_record"] is None
        assert "unsupported dynamic mechanism 'ptr'" in res2["reason"]

        # 3. Non-positive mechanism qualifier: -ip4
        neg_rr = MockRR(strings=[b"v=spf1 -ip4:10.0.0.1 ip4:10.0.0.2 -all"])
        res3 = await flatten_spf("example.com", MockResolver({("example.com", "TXT"): MockAnswer([neg_rr])}))
        assert res3["can_flatten"] is False
        assert res3["flattened_record"] is None
        assert "uses qualifier '-'" in res3["reason"]

        # 4. Included record with +all
        root_inc_rr = MockRR(strings=[b"v=spf1 include:partner.com -all"])
        partner_all_rr = MockRR(strings=[b"v=spf1 ip4:1.2.3.4 +all"])
        res4 = await flatten_spf("example.com", MockResolver({
            ("example.com", "TXT"): MockAnswer([root_inc_rr]),
            ("partner.com", "TXT"): MockAnswer([partner_all_rr]),
        }))
        assert res4["can_flatten"] is False
        assert res4["flattened_record"] is None
        assert "+all" in res4["reason"]

        # 5. Failed A resolution
        root_a_rr = MockRR(strings=[b"v=spf1 a:missing.example.com -all"])
        res5 = await flatten_spf("example.com", MockResolver({("example.com", "TXT"): MockAnswer([root_a_rr])}))
        assert res5["can_flatten"] is False
        assert res5["flattened_record"] is None
        assert "failed to resolve A/AAAA IP addresses" in res5["reason"]

        # 6. Failed MX resolution
        root_mx_rr = MockRR(strings=[b"v=spf1 mx:missing.example.com -all"])
        res6 = await flatten_spf("example.com", MockResolver({("example.com", "TXT"): MockAnswer([root_mx_rr])}))
        assert res6["can_flatten"] is False
        assert res6["flattened_record"] is None
        assert "failed to resolve MX" in res6["reason"]

    async def test_count_spf_lookups_shared_includes_evaluated(self):
        # Branch 1 and Branch 2 both include shared.com
        root_txt = MockRR(strings=[b"v=spf1 include:branch1.com include:branch2.com -all"])
        b1_txt = MockRR(strings=[b"v=spf1 include:shared.com -all"])
        b2_txt = MockRR(strings=[b"v=spf1 include:shared.com -all"])
        shared_txt = MockRR(strings=[b"v=spf1 a -all"])

        responses = {
            ("example.com", "TXT"): MockAnswer([root_txt]),
            ("branch1.com", "TXT"): MockAnswer([b1_txt]),
            ("branch2.com", "TXT"): MockAnswer([b2_txt]),
            ("shared.com", "TXT"): MockAnswer([shared_txt]),
        }
        resolver = MockResolver(responses)

        res = await count_spf_lookups("example.com", resolver)
        # Root includes: branch1 (1) + shared (1) + 'a' in shared (1) = 3 lookups on branch 1
        # branch2 (1) + shared (1) + 'a' in shared (1) = 3 lookups on branch 2
        # Total = 6 lookups
        assert res["total_lookups"] == 6

    async def test_count_spf_lookups_cycle_terminates(self):
        # A includes B, B includes A
        a_txt = MockRR(strings=[b"v=spf1 include:b.com -all"])
        b_txt = MockRR(strings=[b"v=spf1 include:a.com -all"])

        responses = {
            ("a.com", "TXT"): MockAnswer([a_txt]),
            ("b.com", "TXT"): MockAnswer([b_txt]),
        }
        resolver = MockResolver(responses)

        res = await count_spf_lookups("a.com", resolver)
        # Should not hang in infinite recursion; terminates gracefully
        assert res["total_lookups"] == 2
