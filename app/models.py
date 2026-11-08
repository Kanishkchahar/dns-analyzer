"""Pydantic request/response schemas for the DNS Analyzer API."""

import re
import logging
import os
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.finding_catalog import get_finding_guidance, known_finding_codes, legacy_codes_for

_finding_logger = logging.getLogger(__name__)


DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    # IDNA encodes internationalized TLDs as xn--... labels. The IDNA codec
    # validates the Unicode input; allow its ASCII encoding here.
    r"(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,57}[a-zA-Z0-9])?)$",
    re.IGNORECASE,
)


class AnalyzeRequest(BaseModel):
    domain: str
    force_refresh: bool = False

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not v:
            raise ValueError("Domain must not be empty.")
        # Strip scheme (http://, https://)
        v = re.sub(r"^https?://", "", v, flags=re.IGNORECASE)
        # Strip path, query, and fragment
        v = re.sub(r"[/\\?#].*$", "", v)
        # Strip trailing port if present
        v = re.sub(r":\d+$", "", v)
        v = v.strip(".")

        if not v:
            raise ValueError("Domain must not be empty.")

        # Normalize Internationalized Domain Names (IDN) to punycode ASCII
        try:
            v_ascii = v.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"'{v}' contains invalid internationalized domain characters.")

        if not DOMAIN_RE.match(v_ascii):
            raise ValueError(
                f"'{v}' does not look like a valid domain name. "
                "Expected format: example.com"
            )
        return v_ascii



class Finding(BaseModel):
    severity: str  # "error" | "warning" | "info" | "inconclusive"
    record_type: str
    message: str
    code: str = "GEN-001"
    legacy_codes: list[str] = Field(default_factory=list)
    explanation: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def attach_catalog_entry(cls, value: Any) -> Any:
        if isinstance(value, dict):
            value = dict(value)
            record_type = value.get("record_type", "")
            guidance = get_finding_guidance(record_type, value.get("message", ""))
            value.setdefault("code", guidance["code"])
            if value["code"] not in known_finding_codes():
                unknown_code = value["code"]
                _finding_logger.error("Finding code %r is missing from catalog; using GEN-001", unknown_code)
                if os.environ.get("PYTEST_CURRENT_TEST"):
                    raise ValueError(f"Finding code {unknown_code!r} is missing from the finding catalog.")
                value["code"] = "GEN-001"
                guidance = get_finding_guidance("UNKNOWN", "")
                value["legacy_codes"] = []
                value["explanation"] = guidance
            value.setdefault("legacy_codes", legacy_codes_for(guidance, record_type))
            value.setdefault("explanation", guidance)
        return value


class Summary(BaseModel):
    errors: int
    warnings: int
    info: int
    inconclusive: int = 0


class EmailScore(BaseModel):
    score: int
    grade: str
    label: str
    inconclusive_count: int = 0


class EmailAuth(BaseModel):
    spf: dict[str, Any] | None = None
    spf_lookups: dict[str, Any] | None = None
    spf_flattened: dict[str, Any] | None = None
    dmarc: dict[str, Any] | None = None
    dkim: dict[str, Any] | None = None
    mta_sts: dict[str, Any] | None = None
    tls_rpt: dict[str, Any] | None = None
    score: EmailScore | None = None


class SecurityAudit(BaseModel):
    dnssec: dict[str, Any] | None = None
    takeover: dict[str, Any] | None = None
    bimi: dict[str, Any] | None = None


class RemediationFix(BaseModel):
    title: str
    record_type: str
    host: str
    value: str
    guidance: str | None = None
    guidance_only: bool = False
    ttl: int = 3600
    provider_guides: dict[str, str] = Field(default_factory=dict)
    provider_commands: dict[str, str] = Field(default_factory=dict)
    is_draft: bool = True
    impact_warning: str | None = None
    prerequisites: list[str] = Field(default_factory=list)



class DomainFactorScore(BaseModel):
    category: str
    weight: int
    score: float | None
    max_score: int
    status: str
    summary: str


class DomainScore(BaseModel):
    score: int
    grade: str
    label: str
    scope: str = "DNS and email posture"
    inconclusive_count: int = 0
    inconclusive_checks: list[str] = Field(default_factory=list)
    factors: dict[str, DomainFactorScore]


class AnalyzeResponse(BaseModel):
    domain: str
    scan_timestamp: str
    records: dict[str, Any]
    findings: list[Finding]
    summary: Summary
    zone_metadata: dict[str, Any] | None = None
    domain_score: DomainScore | None = None
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    email_auth: EmailAuth | None = None
    security: SecurityAudit | None = None
    tls: dict[str, Any] | None = None
    subdomains: dict[str, Any] | None = None
    dns_posture: dict[str, Any] = Field(default_factory=dict)
    coverage: list[dict[str, Any]] = Field(default_factory=list)
    remediation: list[RemediationFix] | None = None
    bind_zone_snippet: str | None = None


class ListScanRequest(BaseModel):
    targets: list[str]


class PathScanRequest(BaseModel):
    targets: list[str]


class DkimSelectorRequest(BaseModel):
    domain: str
    selectors: list[str] = Field(min_length=1, max_length=20)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return AnalyzeRequest(domain=value).domain

    @field_validator("selectors")
    @classmethod
    def validate_selectors(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not normalized or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", value) for value in normalized):
            raise ValueError("Selectors must contain 1–63 letters, numbers, underscores, or hyphens.")
        if len(normalized) > 20:
            raise ValueError("Check no more than 20 selectors at a time.")
        return normalized


class PortScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    confirmed: bool = False
    auth_token: str | None = None
