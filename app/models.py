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


class AnalyzeResponse(BaseModel):
    domain: str
    scan_timestamp: str
    records: dict[str, Any]
    findings: list[Finding]
    summary: Summary
    email_auth: EmailAuth | None = None
