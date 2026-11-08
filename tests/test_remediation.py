"""Tests for 1-Click Remediation & BIND Zone File Generator (app/remediation.py)."""

from app.models import EmailAuth, RemediationFix, SecurityAudit
from app.remediation import generate_bind_zone_file, generate_remediation_fixes


class TestRemediation:
    def test_remediation_for_missing_spf_and_dmarc(self):
        email_auth = EmailAuth(spf=None, dmarc=None)
        security = SecurityAudit(
            dnssec={"enabled": False},
            bimi={"dmarc_eligible": False, "has_bimi": False},
        )

        fixes = generate_remediation_fixes("example.com", [], email_auth, security)
        titles = [f.title for f in fixes]

        assert any("Confirm mail use and authorized senders" in t for t in titles)
        assert any("Anti-Spoofing DMARC Policy" in t for t in titles)
        assert any("Enable DNSSEC" in t for t in titles)

    def test_missing_spf_asks_for_sender_confirmation_without_guessing_a_provider(self):
        email_auth = EmailAuth(spf=None, dmarc={"policy": "reject"})
        security = SecurityAudit(dnssec={"enabled": True})
        records = {
            "TXT": {"status": "ok", "records": []},
            "MX": {"status": "ok", "records": ["aspmx.l.google.com"]},
        }

        fixes = generate_remediation_fixes("example.com", [], email_auth, security, records)
        spf = next(fix for fix in fixes if fix.record_type == "SPF")

        assert spf.guidance_only is True
        assert spf.value == ""
        assert "authorized to send" in spf.guidance
        assert not spf.provider_guides
        assert "Google" not in " ".join(spf.prerequisites)
        assert generate_bind_zone_file("example.com", fixes).count('"v=spf1') == 0

    def test_missing_spf_is_not_reported_as_missing_when_txt_lookup_failed(self):
        email_auth = EmailAuth(spf=None, dmarc={"policy": "reject"})
        security = SecurityAudit(dnssec={"enabled": True})
        fixes = generate_remediation_fixes(
            "example.com", [], email_auth, security,
            records={"TXT": {"status": "timeout", "records": []}},
        )

        assert not any(fix.record_type == "SPF" for fix in fixes)

    def test_remediation_for_spf_over_limit_flattening(self):
        email_auth = EmailAuth(
            spf={"raw": "v=spf1 ..."},
            spf_lookups={"over_limit": True, "total_lookups": 12},
            spf_flattened={"flattened_record": "v=spf1 ip4:1.2.3.4 -all"},
            dmarc={"policy": "reject"},
        )
        security = SecurityAudit(dnssec={"enabled": True})

        fixes = generate_remediation_fixes("example.com", [], email_auth, security)
        flat_fixes = [f for f in fixes if "Flattened Record" in f.title]

        assert len(flat_fixes) == 1
        assert flat_fixes[0].value == "v=spf1 ip4:1.2.3.4 -all"

    def test_remediation_upgrade_dmarc_none_policy(self):
        email_auth = EmailAuth(
            spf={"raw": "v=spf1 -all"},
            dmarc={"policy": "none"},
        )
        security = SecurityAudit(dnssec={"enabled": True})

        fixes = generate_remediation_fixes("example.com", [], email_auth, security)
        dmarc_fixes = [f for f in fixes if "Upgrade DMARC Policy" in f.title]

        assert len(dmarc_fixes) == 1
        assert "p=reject" in dmarc_fixes[0].value

    def test_remediation_bimi_when_eligible(self):
        email_auth = EmailAuth(
            spf={"raw": "v=spf1 -all"},
            dmarc={"policy": "reject", "pct": 100},
        )
        security = SecurityAudit(
            dnssec={"enabled": True},
            bimi={"dmarc_eligible": True, "has_bimi": False},
        )

        fixes = generate_remediation_fixes("example.com", [], email_auth, security)
        bimi_fixes = [f for f in fixes if "Enable BIMI" in f.title]

        assert len(bimi_fixes) == 1
        assert bimi_fixes[0].host == "default._bimi"
        assert "v=BIMI1" in bimi_fixes[0].value

    def test_generate_bind_zone_file(self):
        fixes = [
            RemediationFix(
                title="SPF Fix",
                record_type="TXT",
                host="@",
                value="v=spf1 -all",
                ttl=3600,
            ),
            RemediationFix(
                title="DMARC Fix",
                record_type="TXT",
                host="_dmarc",
                value="v=DMARC1; p=reject",
                ttl=3600,
            ),
        ]

        zone_text = generate_bind_zone_file("example.com", fixes)
        assert "$ORIGIN example.com." in zone_text
        assert "$TTL 3600" in zone_text
        assert '@\tIN\tTXT\t"v=spf1 -all"' in zone_text
        assert '_dmarc\tIN\tTXT\t"v=DMARC1; p=reject"' in zone_text

    def test_bind_zone_splits_long_txt_into_rfc_sized_strings(self):
        fix = RemediationFix(title="Long TXT", record_type="TXT", host="_dmarc", value="x" * 300)
        snippet = generate_bind_zone_file("example.com", [fix])

        assert '"' + ("x" * 255) + '" "' + ("x" * 45) + '"' in snippet

    def test_bind_zone_does_not_quote_address_rdata(self):
        fix = RemediationFix(title="IPv4", record_type="A", host="www", value="203.0.113.15")
        snippet = generate_bind_zone_file("example.com", [fix])

        assert "www\tIN\tA\t203.0.113.15" in snippet
