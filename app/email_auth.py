"""DMARC and DKIM email authentication analysis.

This module provides async DNS-based checks for DMARC policies and DKIM
selectors, along with analysis functions that return actionable findings
and an overall email health score.
"""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception

from app.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(severity: str, record_type: str, message: str) -> Finding:
    """Shorthand for creating a Finding instance."""
    return Finding(severity=severity, record_type=record_type, message=message)


def _parse_tags(raw: str) -> dict[str, str]:
    """Parse a semicolon-delimited tag=value string into a dict.

    Handles whitespace around tags and values, and skips empty segments.
    """
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip()] = value.strip()
    return tags


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

async def fetch_dmarc(domain: str, resolver: dns.asyncresolver.Resolver) -> dict[str, Any] | None:
    """Fetch and parse the DMARC record for *domain*.

    Queries ``_dmarc.{domain}`` for TXT records and extracts the first
    record that starts with ``v=DMARC1``.  All standard DMARC tags are
    parsed into a structured dict.

    Returns:
        A dict with parsed DMARC data, or ``None`` if no DMARC record is
        found or a DNS error occurs.
    """
    qname = f"_dmarc.{domain}"
    try:
        answer = await resolver.resolve(qname, "TXT")
        txt_records = [
            b"".join(rr.strings).decode("utf-8", errors="replace")
            for rr in answer
        ]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except dns.exception.Timeout:
        return None
    except Exception:
        return None

    # Find the DMARC record among TXT results
    dmarc_raw: str | None = None
    for txt in txt_records:
        if txt.strip().startswith("v=DMARC1"):
            dmarc_raw = txt.strip()
            break

    if dmarc_raw is None:
        return None

    tags = _parse_tags(dmarc_raw)

    pct_raw = tags.get("pct", "100")
    try:
        pct = int(pct_raw)
    except ValueError:
        pct = 100

    return {
        "raw": dmarc_raw,
        "version": tags.get("v", "DMARC1"),
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "pct": pct,
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "adkim": tags.get("adkim", "r"),
        "aspf": tags.get("aspf", "r"),
        "fo": tags.get("fo", "0"),
    }


def analyze_dmarc(dmarc_data: dict[str, Any] | None) -> list[Finding]:
    """Analyze parsed DMARC data and return a list of findings.

    Checks for missing records, weak policies, reporting gaps, and
    partial enforcement.
    """
    findings: list[Finding] = []

    if dmarc_data is None:
        findings.append(_finding(
            "error", "DMARC",
            "Your domain has no DMARC policy. Any server can spoof emails from your domain.",
        ))
        return findings

    # -- Policy strength --
    policy = dmarc_data.get("policy")
    if policy == "none":
        findings.append(_finding(
            "warning", "DMARC",
            "DMARC policy is set to 'none' — emails are monitored but not blocked. "
            "Consider upgrading to 'quarantine' or 'reject'.",
        ))
    elif policy == "quarantine":
        findings.append(_finding(
            "info", "DMARC",
            "DMARC policy is 'quarantine' — suspicious emails are sent to spam. "
            "Consider upgrading to 'reject' for maximum protection.",
        ))
    elif policy == "reject":
        findings.append(_finding(
            "info", "DMARC",
            "DMARC policy is 'reject' — unauthorized emails are blocked. "
            "This is the strongest protection.",
        ))

    # -- Aggregate reporting --
    if not dmarc_data.get("rua"):
        findings.append(_finding(
            "warning", "DMARC",
            "No aggregate report address (rua) configured — you won't receive DMARC compliance reports.",
        ))

    # -- Partial enforcement --
    pct = dmarc_data.get("pct", 100)
    if pct < 100:
        findings.append(_finding(
            "warning", "DMARC",
            f"DMARC policy applies to only {pct}% of emails — set pct=100 for full enforcement.",
        ))

    # -- Subdomain policy --
    if dmarc_data.get("subdomain_policy") is None:
        findings.append(_finding(
            "info", "DMARC",
            "No subdomain policy (sp=) set — subdomains inherit the main domain policy.",
        ))

    return findings


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

# Common selectors used by major email providers and services
_COMMON_SELECTORS: list[str] = [
    "google", "default", "selector1", "selector2",
    "s1", "s2", "dkim", "mail",
    "k1", "k2", "k3",
    "mandrill", "zendesk", "amazonses", "cm",
]


async def _check_single_selector(
    domain: str,
    selector: str,
    resolver: dns.asyncresolver.Resolver,
) -> dict[str, Any] | None:
    """Query a single DKIM selector and parse the result.

    Returns a parsed dict on success, or ``None`` if the selector does
    not exist.
    """
    qname = f"{selector}._domainkey.{domain}"
    try:
        answer = await resolver.resolve(qname, "TXT")
        raw = b"".join(answer[0].strings).decode("utf-8", errors="replace")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except dns.exception.Timeout:
        return None
    except Exception:
        return None

    tags = _parse_tags(raw)
    public_key = tags.get("p", "")
    display_key = (public_key[:40] + "...") if len(public_key) > 40 else public_key

    return {
        "selector": selector,
        "raw": raw,
        "version": tags.get("v", "DKIM1"),
        "key_type": tags.get("k", "rsa"),
        "public_key": display_key,
        "flags": tags.get("t"),
        "has_key": bool(public_key),
    }


async def check_dkim_selectors(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> dict[str, Any]:
    """Check common DKIM selectors for *domain*.

    Queries all selectors concurrently and returns a summary dict with
    found selectors, the full list of selectors checked, and a boolean
    indicating whether any DKIM record was discovered.
    """
    tasks = [
        _check_single_selector(domain, sel, resolver)
        for sel in _COMMON_SELECTORS
    ]
    results = await asyncio.gather(*tasks)

    selectors_found: list[dict[str, Any]] = [
        r for r in results if r is not None
    ]

    return {
        "selectors_found": selectors_found,
        "selectors_checked": list(_COMMON_SELECTORS),
        "has_dkim": len(selectors_found) > 0,
    }


def analyze_dkim(dkim_data: dict[str, Any]) -> list[Finding]:
    """Analyze DKIM selector data and return a list of findings.

    Flags missing selectors, empty public keys, testing-mode selectors,
    and valid configurations.
    """
    findings: list[Finding] = []

    if not dkim_data.get("has_dkim"):
        findings.append(_finding(
            "warning", "DKIM",
            "No DKIM records found for common selectors. DKIM signing helps prevent email spoofing. "
            "Note: custom selectors may exist but were not checked.",
        ))
        return findings

    for sel in dkim_data.get("selectors_found", []):
        selector_name = sel["selector"]

        if not sel.get("has_key"):
            findings.append(_finding(
                "error", "DKIM",
                f"DKIM selector '{selector_name}' has an empty public key — DKIM verification will fail.",
            ))
            continue

        if sel.get("flags") == "y":
            findings.append(_finding(
                "info", "DKIM",
                f"DKIM selector '{selector_name}' is in testing mode.",
            ))

        findings.append(_finding(
            "info", "DKIM",
            f"DKIM is configured for selector '{selector_name}'.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Email health score
# ---------------------------------------------------------------------------

_GRADE_THRESHOLDS: list[tuple[int, str, str]] = [
    (95, "A+", "Excellent"),
    (85, "A",  "Good"),
    (70, "B",  "Fair"),
    (55, "C",  "Poor"),
    (40, "D",  "Critical"),
    (0,  "F",  "Failing"),
]


def compute_email_score(
    spf_findings: list[Finding],
    dmarc_findings: list[Finding],
    dkim_findings: list[Finding],
) -> dict[str, Any]:
    """Compute an overall email health score from SPF, DMARC, and DKIM findings.

    Scoring:
        - Start at **100** points.
        - Each *error* finding: **−15** points.
        - Each *warning* finding: **−8** points.
        - Each *info* finding: **0** points.
        - The final score is clamped to the **0–100** range.

    Returns:
        A dict containing ``score`` (int), ``grade`` (str), and ``label`` (str).
    """
    score = 100
    all_findings = [*spf_findings, *dmarc_findings, *dkim_findings]

    for f in all_findings:
        if f.severity == "error":
            score -= 15
        elif f.severity == "warning":
            score -= 8

    score = max(0, min(100, score))

    grade = "F"
    label = "Failing"
    for threshold, g, lbl in _GRADE_THRESHOLDS:
        if score >= threshold:
            grade = g
            label = lbl
            break

    return {
        "score": score,
        "grade": grade,
        "label": label,
    }
