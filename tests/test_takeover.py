"""Tests for Subdomain Takeover & Dangling CNAME Detector (app/takeover.py)."""

import pytest

from app.takeover import check_subdomain_takeover
from tests.conftest import MockAnswer, MockResolver, MockRR


@pytest.mark.asyncio
class TestSubdomainTakeover:
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
        assert data["status"] == "cloud_hosted"
        assert data["provider"] == "GitHub Pages"
        assert findings == []

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
        assert data["status"] == "could_not_verify"
        assert data["evidence_state"] == "timeout"
        assert any("could not be verified" in f.message for f in findings)

    async def test_exact_http_fingerprint_confirms_takeover(self, monkeypatch):
        async def match(*args, **kwargs):
            return True, "page_checked"
        monkeypatch.setattr("app.takeover._read_fingerprint_page", match)
        records = {"CNAME": {"status": "ok", "records": ["myorg.github.io"]}}
        resolver = MockResolver({
            ("myorg.github.io", "A"): MockAnswer([MockRR(address="185.199.108.153")]),
            ("myorg.github.io", "AAAA"): MockAnswer([]),
        })
        data, findings = await check_subdomain_takeover("docs.example.com", records, resolver)
        assert data["status"] == "confirmed_vulnerability"
        assert data["vulnerable"] is True
        assert len(findings) == 1 and findings[0].severity == "error"

