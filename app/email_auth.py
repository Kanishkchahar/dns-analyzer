"""DMARC and DKIM email authentication analysis.

This module provides async DNS-based checks for DMARC policies and DKIM
selectors, along with analysis functions that return actionable findings
and an overall email health score.
"""

import asyncio
import re
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

async def fetch_dmarc(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    apex: str | None = None,
) -> dict[str, Any] | None:
    """Fetch and parse the DMARC record for *domain*.

    Queries ``_dmarc.{domain}``. Per RFC 7489 §6.6.3, if no DMARC record is found
    for a subdomain, falls back to the organizational zone apex (``_dmarc.{apex}``).

    Returns:
        A dict with parsed DMARC data, or ``None`` if no DMARC record is found.
    """
    lookup_failed = False

    async def _query_dmarc(target_domain: str) -> list[str]:
        nonlocal lookup_failed
        qname = f"_dmarc.{target_domain}"
        try:
            answer = await resolver.resolve(qname, "TXT")
            return [
                b"".join(rr.strings).decode("utf-8", errors="replace")
                for rr in answer
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            lookup_failed = True
            return []

    txt_records = await _query_dmarc(domain)
    inherited_from: str | None = None

    # RFC 7489 Organizational Domain Fallback
    if not any(txt.strip().startswith("v=DMARC1") for txt in txt_records):
        if apex and apex.lower().rstrip(".") != domain.lower().rstrip("."):
            apex_txts = await _query_dmarc(apex)
            if any(txt.strip().startswith("v=DMARC1") for txt in apex_txts):
                txt_records = apex_txts
                inherited_from = apex.lower().rstrip(".")

    # Find the DMARC record among TXT results
    dmarc_raw: str | None = None
    for txt in txt_records:
        if txt.strip().startswith("v=DMARC1"):
            dmarc_raw = txt.strip()
            break

    if dmarc_raw is None:
        if lookup_failed:
            return {"status": "inconclusive", "reason": "One or more DMARC DNS queries failed."}
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
        "inherited_from": inherited_from,
    }


def analyze_dmarc(dmarc_data: dict[str, Any] | None) -> list[Finding]:
    """Analyze parsed DMARC data and return a list of findings.

    Checks for missing records, weak policies, reporting gaps, and
    partial enforcement.
    """
    findings: list[Finding] = []

    if dmarc_data and dmarc_data.get("status") == "inconclusive":
        findings.append(_finding(
            "info", "DMARC",
            f"DMARC could not be verified: {dmarc_data.get('reason', 'DNS lookup was inconclusive')}.",
        ))
        return findings

    if dmarc_data is None:
        findings.append(_finding(
            "error", "DMARC",
            "Your domain has no DMARC policy. Any server can spoof emails from your domain.",
        ))
        return findings

    if dmarc_data.get("inherited_from"):
        findings.append(_finding(
            "info", "DMARC",
            f"DMARC policy is inherited from organizational zone apex `{dmarc_data['inherited_from']}` per RFC 7489 (heuristic based on discovered SOA zone apex; organizational domain boundaries may differ across multi-part public suffixes).",
        ))

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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception as exc:
        return {"_query_error": type(exc).__name__}

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
    custom_selectors: list[str] | None = None,
) -> dict[str, Any]:
    """Check common DKIM selectors for *domain*.

    Queries all selectors concurrently and returns a summary dict with
    found selectors, the full list of selectors checked, and a boolean
    indicating whether any DKIM record was discovered.
    """
    custom = list(dict.fromkeys(
        selector.strip() for selector in (custom_selectors or [])
        if selector.strip() and re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", selector.strip())
    ))[:20]
    selectors = list(dict.fromkeys([*_COMMON_SELECTORS, *custom]))
    tasks = [_check_single_selector(domain, sel, resolver) for sel in selectors]
    results = await asyncio.gather(*tasks)

    query_errors = [r["_query_error"] for r in results if isinstance(r, dict) and "_query_error" in r]
    selectors_found: list[dict[str, Any]] = [
        r for r in results if r is not None and not (isinstance(r, dict) and "_query_error" in r)
    ]
    for selector in selectors_found:
        selector["custom"] = selector["selector"] in custom

    return {
        "status": "inconclusive" if query_errors and not selectors_found else ("partial" if query_errors else "complete"),
        "reason": f"{len(query_errors)} selector DNS query/queries failed ({', '.join(sorted(set(query_errors)))})." if query_errors else None,
        "selectors_found": selectors_found,
        "selectors_checked": selectors,
        "custom_selectors": custom,
        "has_dkim": len(selectors_found) > 0,
    }


def analyze_dkim(dkim_data: dict[str, Any]) -> list[Finding]:
    """Analyze DKIM selector data and return a list of findings.

    Flags missing selectors, empty public keys, testing-mode selectors,
    and valid configurations.
    """
    findings: list[Finding] = []

    if dkim_data.get("status") == "inconclusive":
        findings.append(_finding(
            "info", "DKIM",
            f"DKIM selector checks were inconclusive: {dkim_data.get('reason', 'DNS lookup failed')}",
        ))
        return findings

    if dkim_data.get("status") == "partial" and not dkim_data.get("has_dkim"):
        findings.append(_finding(
            "info", "DKIM",
            f"DKIM could not be fully verified: {dkim_data.get('reason', 'Some selector DNS queries failed')}",
        ))
        return findings

    if not dkim_data.get("has_dkim"):
        checked = len(dkim_data.get("selectors_checked", []))
        findings.append(_finding(
            "info", "DKIM",
            f"No DKIM records detected among {checked} checked standard selectors "
            f"({', '.join(list(_COMMON_SELECTORS)[:5])}...). Domains using private or custom selectors "
            f"may still be protected. Verify your selector configuration in your email sending provider.",
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


# ---------------------------------------------------------------------------
# Domain Security & Health Score (Holistic Posture)
# ---------------------------------------------------------------------------

_DOMAIN_GRADE_THRESHOLDS: list[tuple[int, str, str]] = [
    (95, "A+", "Optimal Posture"),
    (85, "A",  "Strong Posture"),
    (70, "B",  "Moderate Posture"),
    (55, "C",  "Needs Attention"),
    (40, "D",  "Vulnerable"),
    (0,  "F",  "High Risk"),
]


def compute_domain_score(
    records: dict[str, Any],
    dns_findings: list[Finding],
    email_score: dict[str, Any],
    dnssec_data: dict[str, Any] | None,
    takeover_data: dict[str, Any] | None,
    tls_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a holistic domain health & security posture score.

    Combines documented operational pillars:
      1. DNS Infrastructure & Redundancy (25% weight)
      2. Email Authentication Defense (35% weight)
      3. DNSSEC & Cryptographic Integrity (20% weight)
      4. Subdomain Takeover & Threat Defense (20% weight)
    Explicitly tracks inconclusive checks to avoid false reassurance.
    """
    inconclusive_checks: list[str] = []

    # 1. DNS Infrastructure (25 pts max)
    infra_pts = 0
    a_rec = records.get("A", {})
    if a_rec.get("status") == "ok" and a_rec.get("records"):
        infra_pts += 10
    aaaa_rec = records.get("AAAA", {})
    if aaaa_rec.get("status") == "ok" and aaaa_rec.get("records"):
        infra_pts += 5
    ns_rec = records.get("NS", {})
    ns_count = len(ns_rec.get("records", [])) if ns_rec.get("status") == "ok" else 0
    if ns_count >= 2:
        infra_pts += 5
    elif ns_count == 1:
        infra_pts += 2
    soa_rec = records.get("SOA", {})
    if soa_rec.get("status") == "ok" and soa_rec.get("records"):
        infra_pts += 5

    for f in dns_findings:
        if f.severity == "error":
            infra_pts -= 10
        elif f.severity == "warning":
            infra_pts -= 4
    infra_score = max(0, min(25, infra_pts))
    infra_status = "healthy" if infra_score >= 20 else ("warning" if infra_score >= 12 else "degraded")
    infra_summary = f"{'Dual-stack IPv4/IPv6' if aaaa_rec.get('status') == 'ok' else 'IPv4-only'}, {ns_count} NS redundant"

    # 2. Email Authentication (35 pts max)
    raw_email_score = email_score.get("score", 0)
    email_factor_score = max(0, min(35, round(raw_email_score * 0.35)))
    email_status = "enforced" if raw_email_score >= 85 else ("partial" if raw_email_score >= 60 else "vulnerable")
    email_summary = f"SPF, DMARC, DKIM ({raw_email_score}/100)"

    # 3. DNSSEC (20 pts max)
    dnssec_status = dnssec_data.get("status", "unsigned") if dnssec_data else "unsigned"
    if dnssec_status == "delegation_match_verified":
        dnssec_score = 16
        dnssec_stat = "delegation_match_verified"
        dnssec_summary = "Parent DS record matches zone DNSKEY digest (full RRSIG root anchor chain unvalidated)"
        inconclusive_checks.append("DNSSEC Root Anchor & RRSIG Validation")
    elif dnssec_status == "incomplete_chain":
        dnssec_score = 8
        dnssec_stat = "warning"
        dnssec_summary = "DNSKEY present but missing parent DS delegation"
    elif dnssec_status == "bogus":
        dnssec_score = 0
        dnssec_stat = "error"
        dnssec_summary = "Parent DS record without matching zone DNSKEY (causes SERVFAIL)"
    else:
        dnssec_score = 10
        dnssec_stat = "unsigned"
        dnssec_summary = "Zone unsigned (standard baseline, vulnerable to cache poisoning)"

    # 4. Takeover & Threat Defense (20 pts max)
    is_vulnerable = bool(takeover_data.get("vulnerable")) if takeover_data else False
    takeover_stat_str = takeover_data.get("status", "safe") if takeover_data else "safe"
    if is_vulnerable:
        threat_score = 0
        threat_status = "critical"
        threat_summary = f"Dangling CNAME pointing to unresolvable {takeover_data.get('provider', 'host')}"
    elif takeover_stat_str == "dangling_alias":
        threat_score = 10
        threat_status = "warning"
        threat_summary = "Dangling CNAME alias pointing to unresolvable destination"
    elif takeover_stat_str == "could_not_verify":
        threat_score = 15
        threat_status = "inconclusive"
        threat_summary = "Takeover resolution inconclusive due to resolver error or timeout"
        inconclusive_checks.append("Subdomain Takeover")
    else:
        threat_score = 20
        threat_status = "safe"
        threat_summary = "No dangling CNAME records or takeover vectors detected"

    if tls_data is not None and not tls_data.get("scanned", False):
        inconclusive_checks.append("TLS & HTTPS Audit")

    total_score = max(0, min(100, infra_score + email_factor_score + dnssec_score + threat_score))

    grade = "F"
    label = "High Risk"
    for threshold, g, lbl in _DOMAIN_GRADE_THRESHOLDS:
        if total_score >= threshold:
            grade = g
            label = lbl
            break

    if inconclusive_checks and total_score >= 85:
        label = f"{label} (With Inconclusive Checks)"

    return {
        "score": total_score,
        "grade": grade,
        "label": label,
        "inconclusive_count": len(inconclusive_checks),
        "inconclusive_checks": inconclusive_checks,
        "factors": {
            "infrastructure": {
                "category": "DNS Infrastructure",
                "weight": 25,
                "score": infra_score,
                "max_score": 25,
                "status": infra_status,
                "summary": infra_summary,
            },
            "email_auth": {
                "category": "Email Spoofing Defense",
                "weight": 35,
                "score": email_factor_score,
                "max_score": 35,
                "status": email_status,
                "summary": email_summary,
            },
            "dnssec": {
                "category": "DNSSEC & Integrity",
                "weight": 20,
                "score": dnssec_score,
                "max_score": 20,
                "status": dnssec_stat,
                "summary": dnssec_summary,
            },
            "threats": {
                "category": "Subdomain Threat Defense",
                "weight": 20,
                "score": threat_score,
                "max_score": 20,
                "status": threat_status,
                "summary": threat_summary,
            },
        },
    }
