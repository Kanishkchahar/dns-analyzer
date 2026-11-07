"""Pydantic request/response schemas for the DNS Analyzer API."""

import re
from typing import Any

from pydantic import BaseModel, field_validator


DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"[a-zA-Z]{2,}$"
)


class AnalyzeRequest(BaseModel):
    domain: str

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
        if not DOMAIN_RE.match(v):
            raise ValueError(
                f"'{v}' does not look like a valid domain name. "
                "Expected format: example.com"
            )
        return v


class Finding(BaseModel):
    severity: str  # "error" | "warning" | "info"
    record_type: str
    message: str


class Summary(BaseModel):
    errors: int
    warnings: int
    info: int


class EmailScore(BaseModel):
    score: int
    grade: str
    label: str


class EmailAuth(BaseModel):
    spf: dict[str, Any] | None = None
    spf_lookups: dict[str, Any] | None = None
    spf_flattened: dict[str, Any] | None = None
    dmarc: dict[str, Any] | None = None
    dkim: dict[str, Any] | None = None
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
    ttl: int = 3600
    provider_guides: dict[str, str] = {}
    is_draft: bool = True
    impact_warning: str | None = None
    prerequisites: list[str] = []


class DomainFactorScore(BaseModel):
    category: str
    weight: int
    score: int
    max_score: int
    status: str
    summary: str


class DomainScore(BaseModel):
    score: int
    grade: str
    label: str
    factors: dict[str, DomainFactorScore]


class AnalyzeResponse(BaseModel):
    domain: str
    scan_timestamp: str
    records: dict[str, Any]
    findings: list[Finding]
    summary: Summary
    zone_metadata: dict[str, Any] | None = None
    domain_score: DomainScore | None = None
    email_auth: EmailAuth | None = None
    security: SecurityAudit | None = None
    tls: dict[str, Any] | None = None
    subdomains: dict[str, Any] | None = None
    remediation: list[RemediationFix] | None = None
    bind_zone_snippet: str | None = None


class ListScanRequest(BaseModel):
    targets: list[str]


class PortScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    confirmed: bool = False
