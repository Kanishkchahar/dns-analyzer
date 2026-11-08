"""Tests for DMARC, DKIM, and Email Health Scoring (app/email_auth.py)."""

import pytest

from app.email_auth import (
    _parse_tags,
    analyze_dkim,
    analyze_dmarc,
    check_dkim_selectors,
    compute_domain_score,
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
        # Missing / unchecked DKIM labeled as info (not found among checked selectors)
        f_missing = analyze_dkim({"has_dkim": False, "selectors_found": []})
        assert len(f_missing) == 1
        assert f_missing[0].severity == "info"
        assert "no dkim records detected" in f_missing[0].message.lower()

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

    def test_compute_domain_score_comprehensive(self):
        records = {
            "A": {"status": "ok", "records": ["93.184.216.34"]},
            "AAAA": {"status": "ok", "records": ["2606:2800:220:1:248:1893:25c8:1946"]},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": ["ns1.example.com admin.example.com 1 7200 3600 1209600 3600"]},
        }
        dns_findings = [Finding(severity="info", record_type="A", message="IPv4 resolves")]
        email_score = {"score": 100, "grade": "A+", "label": "Excellent"}
        dnssec_data = {"status": "delegation_match_verified", "enabled": True}
        takeover_data = {"vulnerable": False, "status": "safe"}

        domain_score = compute_domain_score(records, dns_findings, email_score, dnssec_data, takeover_data)
        assert 0 <= domain_score["score"] <= 100
        assert "infrastructure" in domain_score["factors"]
        assert "email_auth" in domain_score["factors"]
        assert "dnssec" in domain_score["factors"]
        assert "threats" in domain_score["factors"]
        assert domain_score["factors"]["infrastructure"]["max_score"] == 20
        assert domain_score["factors"]["email_auth"]["max_score"] == 25
        assert domain_score["factors"]["dnssec"]["max_score"] == 20
        assert domain_score["factors"]["threats"]["max_score"] == 15
        assert "A and AAAA records present" in domain_score["factors"]["infrastructure"]["summary"]

    def test_compute_domain_score_threat_deduction(self):
        records = {"A": {"status": "ok", "records": ["93.184.216.34"]}, "CNAME": {"status": "ok", "records": ["app.github.io"]}}
        dns_findings = []
        email_score = {"score": 80, "grade": "B", "label": "Fair"}
        dnssec_data = {"status": "unsigned", "enabled": False}
        takeover_data = {"vulnerable": True, "status": "confirmed", "has_cname": True, "provider": "GitHub Pages"}

        domain_score = compute_domain_score(records, dns_findings, email_score, dnssec_data, takeover_data)
        assert domain_score["factors"]["threats"]["score"] == 0
        assert domain_score["factors"]["threats"]["score"] == 0
        assert domain_score["score"] < 60

    def test_compute_domain_score_dnssec_delegation_match_scored_separately(self):
        records = {"A": {"status": "ok", "records": ["93.184.216.34"]}}
        email_score = {"score": 100, "grade": "A+", "label": "Excellent"}
        dnssec_data = {"status": "delegation_match_verified", "enabled": False}
        takeover_data = {"vulnerable": False, "status": "safe"}

        domain_score = compute_domain_score(records, [], email_score, dnssec_data, takeover_data)
        assert domain_score["factors"]["dnssec"]["score"] == 20
        assert domain_score["factors"]["dnssec"]["status"] == "inconclusive"
        assert domain_score["factors"]["dnssec"]["checks_completed"] == 1

    def test_compute_domain_score_inconclusive_dnssec_gets_no_dnssec_points(self):
        result = compute_domain_score(
            {}, [], {"score": 100}, {"status": "inconclusive"}, {"status": "safe"}
        )
        assert result["factors"]["dnssec"]["score"] is None
        assert result["factors"]["dnssec"]["status"] == "inconclusive"
        assert result["factors"]["dnssec"]["checks"][0]["points_earned"] is None

    def test_compute_domain_score_axfr_caps_grade(self):
        result = compute_domain_score(
            {"A": {"status": "ok", "records": ["8.8.8.8"]}}, [], {"score": 100},
            {"status": "unsigned"}, {"status": "safe"},
            dns_posture_data={"axfr": {"servers": [{"status": "transfer_allowed", "records_exposed": 4}]}},
        )
        assert result["score"] == 54
        assert result["grade"].startswith("D")
        assert result["score_breakdown"]["caps_applied"][0]["code"] == "AXFR_EXPOSURE"

    def test_not_applicable_factors_are_excluded_and_weights_normalize(self):
        records = {
            "A": {"status": "no_answer", "records": []},
            "AAAA": {"status": "no_answer", "records": []},
            "MX": {"status": "no_answer", "records": []},
            "NS": {"status": "ok", "records": ["ns1.example.com"]},
            "SOA": {"status": "ok", "records": {"serial": 1}},
            "CNAME": {"status": "no_answer", "records": []},
        }
        result = compute_domain_score(
            records, [], {"score": 100}, {"status": "unsigned"},
            {"status": "safe", "has_cname": False},
            tls_data={"scanned": False},
            dns_posture_data={"axfr": {}, "wildcard": {"status": "not_detected"}, "nameserver_consistency": {"status": "complete", "serials_match": True, "ns_sets_match": True, "soa_fields_match": True}},
            mail_transport_data={},
            email_data={"dmarc_status": "complete", "dkim_status": "complete"},
        )
        factors = result["factors"]
        assert factors["threats"]["status"] == "not_applicable"
        assert factors["tls_web"]["status"] == "not_applicable"
        assert factors["mail_transport"]["status"] == "not_applicable"
        assert result["score_breakdown"]["applicable_weight"] == 70
        assert result["score"] == round(sum(f["score"] for f in factors.values() if f["status"] != "not_applicable") / 70 * 100)

    def test_inconclusive_factor_is_marked_and_does_not_assign_unknown_checks_points(self):
        result = compute_domain_score(
            {"A": {"status": "ok", "records": ["192.0.2.10"]}}, [], {"score": 100},
            {"status": "inconclusive"}, {"status": "safe", "has_cname": False},
        )
        dnssec = result["factors"]["dnssec"]
        assert dnssec["status"] == "inconclusive"
        assert dnssec["checks"][0]["points_earned"] is None
        assert dnssec["checks"][1]["points_earned"] is None
        assert dnssec["score"] is None
        assert {item["category"] for item in result["score_breakdown"]["excluded_factors"]} >= {"DNSSEC"}
        assert "based on" in result["label"]
        assert "factors" in result["label"]

    def test_provisional_grade_when_excluded_weight_exceeds_thirty_percent(self):
        records = {
            "A": {"status": "ok", "records": ["192.0.2.10"]},
            "AAAA": {"status": "ok", "records": ["2001:db8::1"]},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": ["ns1.example.com host.example.com 1 3600 1800 604800 300"]},
            "MX": {"status": "no_answer", "records": []},
            "CNAME": {"status": "no_answer", "records": []},
            "TXT": {"status": "ok", "records": ["v=spf1 -all"]},
        }
        result = compute_domain_score(
            records, [], {"score": 100}, {"status": "delegation_match_verified"},
            {"status": "safe", "has_cname": False},
            tls_data=None,
            dns_posture_data={"status": "inconclusive"},
            mail_transport_data={"mta_sts": {"status": "inconclusive"}, "tls_rpt": {"status": "inconclusive"}},
            email_data={"dmarc_status": "complete", "dkim_status": "complete"},
        )
        assert result["score_breakdown"]["excluded_weight"] > 30
        assert result["score_breakdown"]["provisional"] is True
        assert result["grade"].endswith("(incomplete)")
        assert "based on" in result["label"] and "factors" in result["label"]

        exact_threshold = compute_domain_score(
            records, [], {"score": 100}, {"status": "delegation_match_verified"},
            {"status": "safe", "has_cname": False},
            dns_posture_data={
                "axfr": {"servers": [{"status": "refused_or_unavailable", "records_exposed": 0}]},
                "wildcard": {"status": "not_detected"},
                "nameserver_consistency": {"status": "complete", "serials_match": True, "ns_sets_match": True, "soa_fields_match": True},
            },
            mail_transport_data={"mta_sts": {"status": "not_configured"}, "tls_rpt": {"status": "not_configured"}},
            email_data={"dmarc_status": "complete", "dkim_status": "complete"},
        )
        assert exact_threshold["score_breakdown"]["excluded_weight"] == 30
        assert exact_threshold["score_breakdown"]["provisional"] is False

    def test_all_factors_excluded_has_no_scored_factors(self):
        records = {
            key: {"status": "timeout", "records": []}
            for key in ("A", "AAAA", "NS", "SOA", "MX", "CNAME", "TXT")
        }
        result = compute_domain_score(
            records, [], {"score": 100}, {"status": "inconclusive"},
            {"status": "inconclusive", "has_cname": False},
            mail_transport_data={
                "mta_sts": {"status": "inconclusive"}, "tls_rpt": {"status": "inconclusive"},
            },
            email_data={"dmarc_status": "inconclusive", "dkim_status": "inconclusive"},
        )
        assert result["score_breakdown"]["included_factor_count"] == 0
        assert result["score_breakdown"]["excluded_weight"] == 100
        assert all(factor["status"] == "inconclusive" for factor in result["score_breakdown"]["factors"].values())
        assert result["grade"] == "F (incomplete)"
        assert "based on 0 of 7 factors" in result["label"]

    def test_axfr_cap_can_apply_with_provisional_grade(self):
        records = {
            "A": {"status": "ok", "records": ["192.0.2.10"]},
            "AAAA": {"status": "ok", "records": ["2001:db8::1"]},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": ["ns1.example.com host.example.com 1 3600 1800 604800 300"]},
            "MX": {"status": "timeout", "records": []},
            "CNAME": {"status": "ok", "records": ["service.example.net"]},
            "TXT": {"status": "timeout", "records": []},
        }
        result = compute_domain_score(
            records, [], {"score": 100}, {"status": "inconclusive"},
            {"status": "confirmed", "has_cname": True},
            dns_posture_data={"axfr": {"servers": [{"status": "transfer_allowed", "records_exposed": 2}]}},
            mail_transport_data={
                "mta_sts": {"status": "inconclusive"}, "tls_rpt": {"status": "inconclusive"},
            },
            email_data={"dmarc_status": "inconclusive", "dkim_status": "inconclusive"},
        )
        assert result["score_breakdown"]["provisional"] is True
        assert result["grade"].endswith("(incomplete)")
        assert {cap["code"] for cap in result["score_breakdown"]["caps_applied"]} >= {
            "AXFR_EXPOSURE", "CONFIRMED_TAKEOVER",
        }
        assert result["score"] <= 39

    def test_takeover_states_have_explicit_deductions_and_no_candidate_cap(self):
        records = {
            "A": {"status": "ok", "records": ["192.0.2.10"]},
            "AAAA": {"status": "ok", "records": ["2001:db8::1"]},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": ["ns1.example.com host.example.com 1 3600 1800 604800 300"]},
            "CNAME": {"status": "ok", "records": ["service.example.net"]},
            "MX": {"status": "no_answer", "records": []},
            "TXT": {"status": "ok", "records": []},
        }
        expected = {"safe": (15, 0), "candidate": (6.75, 8.25), "confirmed": (0, 15)}
        for state, (earned, deducted) in expected.items():
            result = compute_domain_score(
                records, [], {"score": 100}, {"status": "unsigned"},
                {"status": state, "has_cname": True},
            )
            factor = result["score_breakdown"]["factors"]["takeover"]
            assert factor["points_earned"] == earned
            assert factor["points_deducted"] == deducted
            if state == "candidate":
                assert result["score_breakdown"]["caps_applied"] == []
            if state == "confirmed":
                assert result["score"] <= 39

        inconclusive = compute_domain_score(
            records, [], {"score": 100}, {"status": "unsigned"},
            {"status": "inconclusive", "has_cname": True},
        )
        factor = inconclusive["score_breakdown"]["factors"]["takeover"]
        assert factor["status"] == "inconclusive" and factor["points_earned"] is None
        assert "Takeover Risk" in [item["category"] for item in inconclusive["score_breakdown"]["excluded_factors"]]

    def test_confirmed_takeover_and_bogus_dnssec_apply_independent_caps(self):
        records = {
            "A": {"status": "ok", "records": ["192.0.2.10"]},
            "AAAA": {"status": "ok", "records": ["2001:db8::1"]},
            "MX": {"status": "ok", "records": [{"host": "mail.example.com"}]},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": {"serial": 1}},
            "TXT": {"status": "ok", "records": ["v=spf1 -all"]},
            "CNAME": {"status": "ok", "records": ["app.github.io"]},
        }
        kwargs = {
            "tls_data": {"scanned": True, "status": "complete", "certificate": {"is_expired": False}, "https_redirect": {"enforced": True}, "security_headers": {}},
            "dns_posture_data": {"axfr": {"servers": [{"status": "refused_or_unavailable", "records_exposed": 0}]}, "wildcard": {"status": "not_detected"}, "nameserver_consistency": {"status": "complete", "serials_match": True, "ns_sets_match": True, "soa_fields_match": True}},
            "mail_transport_data": {"mta_sts": {"status": "configured", "policy_status": "valid"}, "tls_rpt": {"status": "configured"}},
            "email_data": {"dmarc_status": "complete", "dkim_status": "complete"},
        }
        takeover = compute_domain_score(
            records, [], {"score": 100}, {"status": "unsigned"},
            {"status": "confirmed", "has_cname": True, "vulnerable": True}, **kwargs,
        )
        assert takeover["score"] == 39
        assert "CONFIRMED_TAKEOVER" in [cap["code"] for cap in takeover["score_breakdown"]["caps_applied"]]

        bogus = compute_domain_score(
            records, [], {"score": 100}, {"status": "bogus"},
            {"status": "safe", "has_cname": True}, **kwargs,
        )
        assert bogus["score"] == 39
        assert "BOGUS_DNSSEC" in [cap["code"] for cap in bogus["score_breakdown"]["caps_applied"]]

    def test_chain_dnssec_states_are_informational_for_score_and_caps(self):
        records = {"A": {"status": "ok", "records": ["192.0.2.10"]}, "NS": {"status": "ok", "records": ["ns.example.com"]}}
        baseline = compute_domain_score(
            records, [], {"score": 90}, {"status": "unsigned", "validator": "legacy"},
            {"status": "safe", "has_cname": False},
        )
        chain_states = ("secure", "insecure", "bogus", "inconclusive")
        for state in chain_states:
            candidate = compute_domain_score(
                records, [], {"score": 90}, {"status": state, "validator": "chain", "legacy_score_status": "unsigned"},
                {"status": "safe", "has_cname": False},
            )
            factor = candidate["score_breakdown"]["factors"]["dnssec"]
            assert factor["status"] == "inconclusive"
            assert factor["score"] == baseline["score_breakdown"]["factors"]["dnssec"]["score"]
            assert factor["checks_completed"] == 1
            assert "informational" in factor["summary"]
            assert candidate["score"] == baseline["score"]
            assert candidate["grade"] == baseline["grade"]
            assert candidate["score_breakdown"]["caps_applied"] == baseline["score_breakdown"]["caps_applied"]
            assert "BOGUS_DNSSEC" not in [cap["code"] for cap in candidate["score_breakdown"]["caps_applied"]]

    def test_every_dnssec_engine_state_has_the_expected_scoring_treatment(self):
        records = {"A": {"status": "ok", "records": ["192.0.2.10"]}, "NS": {"status": "ok", "records": ["ns.example.com"]}}
        takeover = {"status": "safe", "has_cname": False}
        email_score = {"score": 90}
        legacy_states = {
            "delegation_match_verified": "scored",
            "incomplete_chain": "scored",
            "unsigned": "scored",
            "inconclusive": "excluded",
            "bogus": "capped",
        }
        chain_states = {"secure", "insecure", "bogus", "inconclusive"}
        for status, treatment in legacy_states.items():
            result = compute_domain_score(records, [], email_score, {"status": status, "validator": "legacy"}, takeover)
            dnssec_factor = result["score_breakdown"]["factors"]["dnssec"]
            if treatment == "scored":
                assert dnssec_factor["checks_completed"] == 1
                assert dnssec_factor["score"] is not None
            elif treatment == "excluded":
                assert dnssec_factor["checks_completed"] == 0
                assert dnssec_factor["score"] is None
            else:
                assert "BOGUS_DNSSEC" in [cap["code"] for cap in result["score_breakdown"]["caps_applied"]]
        for status in chain_states:
            result = compute_domain_score(records, [], email_score, {"status": status, "validator": "chain", "legacy_score_status": "inconclusive"}, takeover)
            dnssec_factor = result["score_breakdown"]["factors"]["dnssec"]
            assert dnssec_factor["checks_completed"] == 0
            assert dnssec_factor["score"] is None
            assert not result["score_breakdown"]["caps_applied"]

    def test_breakdown_has_points_status_checks_codes_and_cap_reason(self):
        from app.models import Finding

        result = compute_domain_score(
            {"A": {"status": "ok", "records": ["192.0.2.10"]}, "NS": {"status": "ok", "records": ["ns.example.com"]}},
            [Finding(severity="warning", record_type="NS", message="Only one nameserver found — no redundancy.")],
            {"score": 80}, {"status": "bogus"}, {"status": "candidate", "has_cname": True},
        )
        breakdown = result["score_breakdown"]
        infra = breakdown["factors"]["infrastructure"]
        assert breakdown["factors"]["takeover"]["maximum"] == 15
        assert set(("points_earned", "maximum", "status", "finding_codes_costing_points")) <= infra.keys()
        assert "DNS-NS-003" in infra["finding_codes_costing_points"]
        assert breakdown["caps_applied"][0]["reason"]
