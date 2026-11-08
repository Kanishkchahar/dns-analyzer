"""Tests for Subdomain Takeover & Dangling CNAME Detector (app/takeover.py)."""

import pytest

from app.takeover import check_subdomain_takeover
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestSubdomainTakeover:
    def test_fingerprint_confirmation_requires_recent_verification_date(self):
        from datetime import datetime, timedelta, timezone

        from app.takeover import _fingerprint_is_currently_verified

        recent = (datetime.now(timezone.utc).date() - timedelta(days=30)).isoformat()
        stale = (datetime.now(timezone.utc).date() - timedelta(days=366)).isoformat()
        tomorrow = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
        assert _fingerprint_is_currently_verified({"verification": "verified", "last_verified": recent})
        assert not _fingerprint_is_currently_verified({"verification": "verified", "last_verified": stale})
        assert not _fingerprint_is_currently_verified({"verification": "verified", "last_verified": tomorrow})
        assert not _fingerprint_is_currently_verified({"verification": "verified", "last_verified": None})

    def test_catalog_entries_have_required_fields_and_dns_confirmation_defaults_off(self):
        from app.takeover import TAKEOVER_SIGNATURES

        assert TAKEOVER_SIGNATURES
        for provider in TAKEOVER_SIGNATURES:
            assert provider["provider"]
            assert provider["detection_method"] in ("nxdomain", "http_body")
            assert provider["remediation"]
            assert "last_verified" in provider
            assert provider["nxdomain_confirms"] is False
            if provider["detection_method"] == "http_body":
                assert provider["unclaimed_page_text"]

    async def test_no_cname_is_safe(self):
        records = {"CNAME": {"status": "not_found", "records": []}}
        resolver = MockResolver({})

        data, findings = await check_subdomain_takeover("example.com", records, resolver)
        assert data["has_cname"] is False
        assert data["vulnerable"] is False
        assert data["status"] == "safe"
        assert len(findings) == 0

    async def test_active_custom_cname_is_safe(self):
        records = {"CNAME": {"status": "ok", "records": ["target.mycorp.internal."]}}
        # target resolves
        resolver = MockResolver({
            ("target.mycorp.internal", "A"): MockAnswer([MockRR(address="8.8.8.8")]),
        })

        data, findings = await check_subdomain_takeover("sub.example.com", records, resolver)
        assert data["has_cname"] is True
        assert data["vulnerable"] is False
        assert data["status"] == "safe"
        assert data["provider"] == "Custom"

    async def test_active_cloud_provider_without_fingerprint_is_not_a_finding(self, monkeypatch):
        async def no_match(*args, **kwargs):
            return False, "page_checked"
        monkeypatch.setattr("app.takeover._read_fingerprint_page", no_match)
        records = {"CNAME": {"status": "ok", "records": ["myorg.github.io."]}}
        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
            ("myorg.github.io", "AAAA"): MockAnswer([]),
        })

        data, findings = await check_subdomain_takeover("blog.example.com", records, resolver)
        assert data["has_cname"] is True
        assert data["vulnerable"] is False
        assert data["status"] == "safe"
        assert data["provider"] == "GitHub Pages"
        assert findings == []

    async def test_resolving_known_provider_with_normal_content_scores_safe(self, monkeypatch):
        from app.email_auth import compute_domain_score

        async def normal_content(*_args, **_kwargs):
            return False, "page_checked_no_fingerprint"

        monkeypatch.setattr("app.takeover._read_fingerprint_page", normal_content)
        records = {
            "A": {"status": "ok", "records": ["192.0.2.10"]},
            "AAAA": {"status": "no_answer", "records": []},
            "NS": {"status": "ok", "records": ["ns1.example.com", "ns2.example.com"]},
            "SOA": {"status": "ok", "records": ["ns1.example.com host.example.com 1 3600 1800 604800 300"]},
            "CNAME": {"status": "ok", "records": ["myorg.github.io"]},
            "MX": {"status": "no_answer", "records": []},
            "TXT": {"status": "no_answer", "records": []},
        }
        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
            ("myorg.github.io", "AAAA"): MockAnswer([]),
        })
        takeover, _ = await check_subdomain_takeover("www.example.com", records, resolver)
        assert takeover["status"] == "safe"

        score = compute_domain_score(
            records, [], {"score": 100}, {"status": "unsigned"}, takeover,
        )
        factor = score["score_breakdown"]["factors"]["takeover"]
        assert factor["status"] == "scored"
        assert factor["points_earned"] == 15
        assert factor["points_deducted"] == 0

    async def test_dns_only_dangling_cname_is_candidate_not_confirmed(self):
        # CNAME points to github.io but target does not resolve (NXDOMAIN)
        records = {"CNAME": {"status": "ok", "records": ["abandoned-subdomain.github.io"]}}
        resolver = MockResolver({})  # will raise NXDOMAIN

        data, findings = await check_subdomain_takeover("docs.example.com", records, resolver)
        assert data["has_cname"] is True
        assert data["vulnerable"] is False
        assert data["status"] == "candidate"
        assert data["provider"] == "GitHub Pages"
        assert "GitHub Pages" in data["remediation"]
        assert any(
            f.severity == "warning" and "Potential dangling CNAME" in f.message
            for f in findings
        )

    async def test_s3_dns_failure_alone_is_only_a_candidate(self):
        records = {"CNAME": {"status": "ok", "records": ["mybucket.s3.amazonaws.com"]}}
        resolver = MockResolver({})

        data, findings = await check_subdomain_takeover("assets.example.com", records, resolver)
        assert data["vulnerable"] is False
        assert data["status"] == "candidate"
        assert data["provider"] == "Amazon S3"
        assert any(
            f.severity == "warning" and "Amazon S3" in f.message for f in findings
        )

    async def test_dangling_custom_cname_is_warning_not_critical(self):
        records = {"CNAME": {"status": "ok", "records": ["dead-internal-alias.customcorp.net"]}}
        resolver = MockResolver({})  # target does not resolve

        data, findings = await check_subdomain_takeover("service.example.com", records, resolver)
        assert data["vulnerable"] is False
        assert data["status"] == "candidate"
        assert data["provider"] == "Custom / Unknown"
        assert any(
            f.severity == "warning" and "Potential dangling CNAME" in f.message for f in findings
        )

    async def test_takeover_resolver_timeout_does_not_false_positive(self):
        import dns.exception
        records = {"CNAME": {"status": "ok", "records": ["abandoned.github.io"]}}

        class TimeoutResolver:
            async def resolve(self, domain, rdtype):
                raise dns.exception.Timeout()

        data, findings = await check_subdomain_takeover("docs.example.com", records, TimeoutResolver())
        assert data["vulnerable"] is False
        assert data["status"] == "inconclusive"
        assert data["evidence_state"] == "lookup_or_fetch_failed"
        assert any("could not be verified" in f.message for f in findings)

    async def test_unverified_http_fingerprint_is_candidate(self, monkeypatch):
        async def match(*args, **kwargs):
            return True, "page_checked"
        monkeypatch.setattr("app.takeover._read_fingerprint_page", match)
        records = {"CNAME": {"status": "ok", "records": ["myorg.github.io"]}}
        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
            ("myorg.github.io", "AAAA"): MockAnswer([]),
        })
        data, findings = await check_subdomain_takeover("docs.example.com", records, resolver)
        assert data["status"] == "candidate"
        assert data["vulnerable"] is False
        assert data["evidence_state"] == "unverified_page_match"
        assert "unverified signature" in data["details"]
        assert len(findings) == 1 and findings[0].severity == "warning"

    async def test_verified_http_fingerprint_can_confirm(self, monkeypatch):
        from datetime import datetime, timezone
        from app.takeover import TAKEOVER_SIGNATURES

        provider = next(item for item in TAKEOVER_SIGNATURES if item["provider"] == "GitHub Pages")
        monkeypatch.setitem(provider, "verification", "verified")
        monkeypatch.setitem(provider, "last_verified", datetime.now(timezone.utc).date().isoformat())

        async def match(*args, **kwargs):
            return True, "https_body_match"

        monkeypatch.setattr("app.takeover._read_fingerprint_page", match)
        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
            ("myorg.github.io", "AAAA"): MockAnswer([]),
        })
        data, _ = await check_subdomain_takeover(
            "docs.example.com", {"CNAME": {"status": "ok", "records": ["myorg.github.io"]}}, resolver,
        )
        assert data["status"] == "confirmed"
        assert data["vulnerable"] is True

    async def test_cname_chain_is_followed_to_provider_target(self, monkeypatch):
        async def match(host, addresses, expected, budget):
            assert host == "unclaimed.github.io"
            return True, "https_body_match"

        monkeypatch.setattr("app.takeover._read_fingerprint_page", match)
        resolver = MockResolver({
            ("alias.custom.example", "CNAME"): MockAnswer([MockRR(target="unclaimed.github.io.")]),
            ("unclaimed.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
        })
        data, findings = await check_subdomain_takeover(
            "docs.example.com",
            {"CNAME": {"status": "ok", "records": ["alias.custom.example"]}},
            resolver,
        )
        assert data["status"] == "candidate"
        assert data["evidence_state"] == "unverified_page_match"
        assert data["cname_target"] == "unclaimed.github.io"
        assert findings[0].severity == "warning"
        assert "current verification date" in findings[0].message

    async def test_verified_nxdomain_rule_requires_two_real_nxdomain_answers(self, monkeypatch):
        from datetime import datetime, timezone
        import dns.resolver
        from app.takeover import TAKEOVER_SIGNATURES

        provider = next(item for item in TAKEOVER_SIGNATURES if item["provider"] == "Microsoft Azure App Service")
        monkeypatch.setitem(provider, "verification", "verified")
        monkeypatch.setitem(provider, "last_verified", datetime.now(timezone.utc).date().isoformat())
        monkeypatch.setitem(provider, "nxdomain_confirms", True)

        class CountingResolver(MockResolver):
            def __init__(self):
                super().__init__()
                self.address_queries = 0

            async def resolve(self, qname, rdtype, *args, **kwargs):
                if rdtype.upper() in ("A", "AAAA"):
                    self.address_queries += 1
                return await super().resolve(qname, rdtype, *args, **kwargs)

        resolver = CountingResolver()
        data, _ = await check_subdomain_takeover(
            "app.example.com", {"CNAME": {"status": "ok", "records": ["abandoned.azurewebsites.net"]}}, resolver,
        )
        assert data["status"] == "confirmed"
        assert resolver.address_queries == 4  # A and AAAA were each re-queried once.

        class FailingResolver(MockResolver):
            async def resolve(self, qname, rdtype, *args, **kwargs):
                if rdtype.upper() in ("A", "AAAA"):
                    raise dns.resolver.NoNameservers()
                raise dns.resolver.NXDOMAIN()

        failed, _ = await check_subdomain_takeover(
            "app.example.com", {"CNAME": {"status": "ok", "records": ["abandoned.azurewebsites.net"]}}, FailingResolver(),
        )
        assert failed["status"] == "inconclusive"

    async def test_nxdomain_candidate_requires_verified_opt_in(self):
        resolver = MockResolver()
        data, _ = await check_subdomain_takeover(
            "app.example.com", {"CNAME": {"status": "ok", "records": ["abandoned.azurewebsites.net"]}}, resolver,
        )
        assert data["status"] == "candidate"
        assert data["nxdomain_confirms"] is False

    async def test_cname_depth_cap_returns_inconclusive(self):
        import dns.resolver
        from app.takeover import MAX_CNAME_DEPTH

        class LongChainResolver(MockResolver):
            async def resolve(self, qname, rdtype, *args, **kwargs):
                if rdtype.upper() == "CNAME":
                    depth = int(qname.split("node", 1)[1].split(".", 1)[0]) if qname.startswith("node") else 0
                    return MockAnswer([MockRR(target=f"node{depth + 1}.chain.example")])
                raise dns.resolver.NXDOMAIN()

        data, findings = await check_subdomain_takeover(
            "chain.example.com",
            {"CNAME": {"status": "ok", "records": ["node0.chain.example"]}},
            LongChainResolver(),
        )
        assert MAX_CNAME_DEPTH == 10
        assert data["status"] == "inconclusive"
        assert findings[0].severity == "info"

    async def test_cname_loop_is_inconclusive_and_depth_is_capped(self):
        resolver = MockResolver({
            ("a.example.net", "CNAME"): MockAnswer([MockRR(target="b.example.net.")]),
            ("b.example.net", "CNAME"): MockAnswer([MockRR(target="a.example.net.")]),
        })
        data, findings = await check_subdomain_takeover(
            "loop.example.com", {"CNAME": {"status": "ok", "records": ["a.example.net"]}}, resolver,
        )
        assert data["status"] == "inconclusive"
        assert findings[0].severity == "info"

    async def test_fetch_budget_exhaustion_is_inconclusive(self):
        from app.work_budget import ScanWorkBudget

        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
        })
        data, findings = await check_subdomain_takeover(
            "docs.example.com",
            {"CNAME": {"status": "ok", "records": ["myorg.github.io"]}},
            resolver,
            budget=ScanWorkBudget(http_requests=0),
        )
        assert data["status"] == "inconclusive"
        assert data["evidence_state"] == "budget_exhausted"
        assert findings[0].severity == "info"

    async def test_cname_chain_timeout_is_inconclusive(self):
        import dns.exception

        class TimeoutCnameResolver(MockResolver):
            async def resolve(self, qname, rdtype, *args, **kwargs):
                if rdtype.upper() == "CNAME":
                    raise dns.exception.Timeout()
                return await super().resolve(qname, rdtype, *args, **kwargs)

        resolver = TimeoutCnameResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
        })
        data, findings = await check_subdomain_takeover(
            "docs.example.com",
            {"CNAME": {"status": "ok", "records": ["myorg.github.io"]}},
            resolver,
        )
        assert data["status"] == "inconclusive"
        assert findings[0].severity == "info"

