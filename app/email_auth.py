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
        return {"_query_error": "DNS selector lookup failed"}

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
    inconclusive_count = sum(
        1 for finding in all_findings if finding.severity in ("inconclusive", "unverified")
    )

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

    if inconclusive_count:
        grade = f"{grade} (incomplete)"
        label = f"{label}; {inconclusive_count} check(s) could not be verified"

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "inconclusive_count": inconclusive_count,
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

DOMAIN_SCORE_WEIGHTS = {
    "infrastructure": 20,
    "email_auth": 25,
    "dnssec": 20,
    "threats": 15,
    "tls_web": 10,
    "mail_transport": 5,
    "dns_posture": 5,
}

DOMAIN_SCORE_CAPS = (
    {"code": "AXFR_EXPOSURE", "maximum": 54, "reason": "An authoritative server allowed a non-empty zone transfer."},
    {"code": "CONFIRMED_TAKEOVER", "maximum": 39, "reason": "A provider takeover rule was confirmed by verified evidence."},
    {"code": "BOGUS_DNSSEC", "maximum": 39, "reason": "A parent DS does not match the zone DNSKEY or the zone key is absent."},
)
TAKEOVER_STATE_FRACTIONS = {"safe": 1.0, "candidate": 0.45, "confirmed": 0.0}


def compute_domain_score(
    records: dict[str, Any],
    dns_findings: list[Finding],
    email_score: dict[str, Any],
    dnssec_data: dict[str, Any] | None,
    takeover_data: dict[str, Any] | None,
    tls_data: dict[str, Any] | None = None,
    dns_posture_data: dict[str, Any] | None = None,
    mail_transport_data: dict[str, Any] | None = None,
    subdomains_data: dict[str, Any] | None = None,
    email_data: dict[str, Any] | None = None,
    module_findings: list[Finding] | None = None,
) -> dict[str, Any]:
    """Score observed posture while exposing unavailable checks as unknown.

    Unknown checks inside a partially observed factor receive neutral midpoint
    credit; they are never reported as a per-check pass or failure. A factor
    with no completed checks is excluded. Not-applicable factors are also
    removed before the domain score is normalized to 100.
    """
    findings_by_type: dict[str, list[Finding]] = {}
    for finding in [*dns_findings, *(module_findings or [])]:
        findings_by_type.setdefault(finding.record_type.upper(), []).append(finding)

    def penalty_value(items: list[Finding]) -> float:
        errors = sum(item.severity == "error" for item in items)
        warnings = sum(item.severity == "warning" for item in items)
        return max(0.0, 1.0 - min(1.0, errors * 0.35 + warnings * 0.18))

    def check_value(label: str, value: float | None, max_points: float = 1.0) -> dict[str, Any]:
        earned = None if value is None else round(value * max_points, 2)
        return {"check": label, "points_earned": earned,
                "points_deducted": None if earned is None else round(max_points - earned, 2),
                "maximum": max_points, "status": "inconclusive" if value is None else "scored"}

    def make_factor(
        key: str,
        category: str,
        summary: str,
        checks: list[dict[str, Any]],
        related_findings: list[Finding],
        *,
        not_applicable: bool = False,
    ) -> dict[str, Any]:
        weight = DOMAIN_SCORE_WEIGHTS[key]
        completed = [check for check in checks if check["points_earned"] is not None]
        if not_applicable:
            status = "not_applicable"
            score = None
        elif not completed:
            status = "inconclusive"
            score = None
        else:
            status = "inconclusive" if len(completed) < len(checks) else "scored"
            earned_fraction = sum(check["points_earned"] / check["maximum"] for check in completed)
            inconclusive_count = len(checks) - len(completed)
            observed_fraction = (earned_fraction + 0.5 * inconclusive_count) / len(checks)
            score = round(weight * observed_fraction, 2)
        codes = sorted({item.code for item in related_findings if item.severity in ("warning", "error")})
        return {
            "category": category,
            "weight": weight,
            "score": score,
            "max_score": weight,
            "points_earned": score,
            "points_deducted": None if score is None else round(weight - score, 2),
            "maximum": weight,
            "status": status,
            "summary": summary,
            "checks_completed": len(completed),
            "checks_total": len(checks),
            "checks": checks,
            "finding_codes_costing_points": codes,
        }

    def records_component(name: str, points: float) -> dict[str, Any]:
        entry = records.get(name, {})
        status = entry.get("status")
        if status in ("ok", "no_answer", "nxdomain"):
            return check_value(name, 1.0 if status == "ok" and bool(entry.get("records")) else 0.0, points)
        return check_value(name, None, points)

    a_rec, aaaa_rec = records.get("A", {}), records.get("AAAA", {})
    ns_rec, soa_rec = records.get("NS", {}), records.get("SOA", {})
    ns_count = len(ns_rec.get("records", [])) if ns_rec.get("status") == "ok" else 0
    core_dns_statuses = [entry.get("status") for entry in (a_rec, aaaa_rec, ns_rec, soa_rec)]
    address_statuses = (a_rec.get("status"), aaaa_rec.get("status"))
    if any(
        entry.get("status") == "ok" and bool(entry.get("records"))
        for entry in (a_rec, aaaa_rec)
    ):
        address_value = 1.0
    elif all(status in ("no_answer", "nxdomain") for status in address_statuses):
        address_value = 0.0
    else:
        address_value = None
    dns_checks = [
        check_value("Address resolution (A or AAAA)", address_value),
        check_value("NS redundancy", (1.0 if ns_count >= 2 else 0.5 if ns_count == 1 else 0.0) if ns_rec.get("status") in ("ok", "no_answer", "nxdomain") else None, 1),
        records_component("SOA", 1),
        check_value("DNS finding review", penalty_value(dns_findings) if all(s in ("ok", "no_answer", "nxdomain") for s in core_dns_statuses) else None, 1),
    ]
    infra_findings = [f for f in dns_findings if f.record_type.upper() in {"GENERAL", "A", "AAAA", "NS", "MX", "SOA", "CNAME", "CAA", "TXT"}]
    has_ipv4 = a_rec.get("status") == "ok" and bool(a_rec.get("records"))
    has_ipv6 = aaaa_rec.get("status") == "ok" and bool(aaaa_rec.get("records"))
    family_summary = "A and AAAA records present" if has_ipv4 and has_ipv6 else ("AAAA records present; A absent" if has_ipv6 else ("A records present; AAAA absent" if has_ipv4 else "no address records"))
    factors: dict[str, dict[str, Any]] = {
        "infrastructure": make_factor("infrastructure", "DNS Infrastructure", f"{family_summary}, {ns_count} NS records", dns_checks, infra_findings),
    }

    all_email_findings = [f for values in findings_by_type.values() for f in values if f.record_type.upper() in ("SPF", "DMARC", "DKIM")]
    if email_data is None:
        raw = max(0, min(100, int(email_score.get("score", 0)))) / 100
        email_checks = [check_value("SPF / DMARC / DKIM", raw, 1)]
    else:
        txt_status = records.get("TXT", {}).get("status")
        spf_done = txt_status in ("ok", "no_answer", "nxdomain")
        dmarc_done = email_data.get("dmarc_status") != "inconclusive"
        dkim_status = email_data.get("dkim_status")
        dkim_done = dkim_status == "complete"
        email_checks = [
            check_value("SPF", penalty_value([f for f in all_email_findings if f.record_type.upper() == "SPF"]) if spf_done else None),
            check_value("DMARC", penalty_value([f for f in all_email_findings if f.record_type.upper() == "DMARC"]) if dmarc_done else None),
            check_value("DKIM selector discovery", penalty_value([f for f in all_email_findings if f.record_type.upper() == "DKIM"]) if dkim_done else None),
        ]
    factors["email_auth"] = make_factor("email_auth", "Email Authentication", "SPF, DMARC, and DKIM findings", email_checks, all_email_findings)

    dnssec_status = (dnssec_data or {}).get("status", "inconclusive")
    chain_result_is_informational = (dnssec_data or {}).get("validator") == "chain"
    scored_dnssec_status = (dnssec_data or {}).get("legacy_score_status", "inconclusive") if chain_result_is_informational else dnssec_status
    dnssec_scores = {"delegation_match_verified": 1.0, "incomplete_chain": 0.5, "unsigned": 0.5, "bogus": 0.0}
    dnssec_checks = [
        check_value("Observed DS / DNSKEY status", dnssec_scores.get(scored_dnssec_status)),
        check_value("RRSIG and root-chain validation", None),
    ]
    dnssec_summary = (
        f"Chain validator reported {dnssec_status}; this opt-in result is informational. Scoring uses the legacy delegation result."
        if chain_result_is_informational
        else f"Observed DNSSEC state: {dnssec_status}; full signature chain is not validated."
    )
    factors["dnssec"] = make_factor(
        "dnssec", "DNSSEC", dnssec_summary,
        dnssec_checks, [] if chain_result_is_informational else findings_by_type.get("DNSSEC", []),
    )

    subdomains = (subdomains_data or {}).get("subdomains", [])
    main_cname = records.get("CNAME", {})
    main_has_cname = bool((takeover_data or {}).get("has_cname"))
    ct_has_cname = any(item.get("cnames") or item.get("cname") for item in subdomains)
    has_takeover = main_has_cname or ct_has_cname
    takeover_statuses = [(takeover_data or {}).get("status")] if (takeover_data or {}).get("has_cname") else []
    takeover_statuses.extend((item.get("takeover") or {}).get("status") for item in subdomains if item.get("cnames") or item.get("cname"))
    takeover_checks = [
        check_value(f"CNAME takeover evidence {index + 1}", TAKEOVER_STATE_FRACTIONS.get(state))
        for index, state in enumerate(takeover_statuses)
    ]
    cname_absent_definite = main_cname.get("status") in ("no_answer", "nxdomain", "not_found")
    takeover_unknown = not main_has_cname and not cname_absent_definite
    if takeover_unknown:
        takeover_checks.append(check_value("Main-domain CNAME discovery", None))
    takeover_findings = [f for f in [*findings_by_type.get("TAKEOVER", []), *findings_by_type.get("SUBDOMAIN TAKEOVER", [])]]
    factors["threats"] = make_factor(
        "threats", "Takeover Risk", "Candidate and confirmed evidence is weighted conservatively.", takeover_checks,
        takeover_findings, not_applicable=not has_takeover and not takeover_unknown,
    )

    cname_rec = records.get("CNAME", {})
    has_site_target = bool(a_rec.get("records") or aaaa_rec.get("records") or cname_rec.get("records"))
    no_site_target_definite = (
        a_rec.get("status") in ("no_answer", "nxdomain")
        and aaaa_rec.get("status") in ("no_answer", "nxdomain")
        and cname_rec.get("status") in ("no_answer", "nxdomain", "not_found")
    )
    site_target_unknown = not has_site_target and not no_site_target_definite
    tls_checks: list[dict[str, Any]] = []
    tls_findings = [f for typ in ("TLS", "HTTPS", "CSP", "COOKIE", "HTTP METHODS", "SECURITY.TXT") for f in findings_by_type.get(typ, [])]
    if tls_data and tls_data.get("scanned"):
        cert = tls_data.get("certificate")
        tls_checks = [
            check_value("TLS certificate and negotiation", penalty_value(tls_findings) if cert or tls_data.get("status") == "certificate_error" else None),
            check_value("HTTPS behavior and headers", penalty_value(tls_findings) if tls_data.get("https_redirect") is not None or tls_data.get("security_headers") is not None else None),
        ]
    elif has_site_target or site_target_unknown:
        tls_checks = [check_value("TLS connection and certificate", None), check_value("HTTPS behavior and headers", None)]
    factors["tls_web"] = make_factor("tls_web", "TLS and Web", "Certificate, HTTPS behavior, and reported web findings.", tls_checks, tls_findings, not_applicable=no_site_target_definite)

    mx_status = records.get("MX", {}).get("status")
    has_mx = mx_status == "ok" and bool(records.get("MX", {}).get("records"))
    no_mx_definite = mx_status in ("no_answer", "nxdomain", "not_found")
    mail = mail_transport_data or {}
    sts = mail.get("mta_sts", {})
    rpt = mail.get("tls_rpt", {})
    mail_checks = [
        check_value("MTA-STS record and policy", 1.0 if sts.get("status") == "configured" and sts.get("policy_status") == "valid" else 0.0 if sts.get("status") == "not_configured" or sts.get("policy_status") == "invalid" else None),
        check_value("TLS-RPT record", 1.0 if rpt.get("status") == "configured" else 0.0 if rpt.get("status") == "not_configured" else None),
    ]
    mail_findings = findings_by_type.get("MTA-STS", []) + findings_by_type.get("TLS-RPT", [])
    if not has_mx and not no_mx_definite:
        mail_checks = [check_value("MTA-STS record and policy", None), check_value("TLS-RPT record", None)]
    factors["mail_transport"] = make_factor("mail_transport", "Mail Transport", "MTA-STS policy and TLS-RPT publication.", mail_checks, mail_findings, not_applicable=no_mx_definite)

    posture = dns_posture_data or {}
    axfr = posture.get("axfr", {})
    wildcard = posture.get("wildcard", {})
    ns_consistency = posture.get("nameserver_consistency", {})
    has_ns = ns_rec.get("status") == "ok" and bool(ns_rec.get("records"))
    no_ns_definite = ns_rec.get("status") in ("no_answer", "nxdomain", "not_found")
    server_states = [item.get("status") for item in axfr.get("servers", [])]
    axfr_value = 0.0 if any(state == "transfer_allowed" for state in server_states) else 1.0 if server_states and all(state not in ("budget_exhausted", "unresolved_or_non_public") for state in server_states) else None
    wildcard_value = 0.0 if wildcard.get("status") == "detected" else 1.0 if wildcard.get("status") == "not_detected" else None
    consistency_value = 1.0 if ns_consistency.get("status") == "complete" and ns_consistency.get("serials_match") is True and ns_consistency.get("ns_sets_match") is True and ns_consistency.get("soa_fields_match", True) is True else 0.0 if ns_consistency.get("status") == "complete" else None
    posture_checks = [check_value("AXFR", axfr_value), check_value("Wildcard DNS", wildcard_value), check_value("Nameserver consistency", consistency_value)]
    if not has_ns and not no_ns_definite:
        posture_checks = [check_value("AXFR", None), check_value("Wildcard DNS", None), check_value("Nameserver consistency", None)]
    posture_findings = findings_by_type.get("AXFR", []) + findings_by_type.get("WILDCARD DNS", []) + findings_by_type.get("NS CONSISTENCY", [])
    factors["dns_posture"] = make_factor("dns_posture", "DNS Posture", "AXFR, wildcard DNS, and authoritative nameserver consistency.", posture_checks, posture_findings, not_applicable=no_ns_definite)

    included = [
        factor for factor in factors.values()
        if factor["status"] != "not_applicable" and factor["checks_completed"] > 0
    ]
    excluded_factors = [
        {"category": factor["category"], "weight": factor["weight"], "status": factor["status"]}
        for factor in factors.values() if factor not in included
    ]
    active = included
    applicable_weight = sum(factor["weight"] for factor in active)
    completed_checks = sum(factor["checks_completed"] for factor in active)
    total_checks = sum(factor["checks_total"] for factor in active)
    included_factor_count = len(active)
    total_factor_count = len(factors)
    excluded_weight = sum(item["weight"] for item in excluded_factors)
    raw_score = (sum(factor["score"] for factor in active) / applicable_weight * 100) if applicable_weight else 0
    caps_applied: list[dict[str, Any]] = []
    axfr_confirmed = any(item.get("status") == "transfer_allowed" and item.get("records_exposed", 0) > 0 for item in axfr.get("servers", []))
    takeover_confirmed = any(state == "confirmed" for state in takeover_statuses)
    # The new chain validator remains opt-in until its signed-zone matrix passes;
    # do not let its unproven bogus result trigger the domain score cap.
    dnssec_bogus = (
        (scored_dnssec_status == "bogus" if chain_result_is_informational else dnssec_status == "bogus")
        and (dnssec_data or {}).get("validator", "legacy") in ("legacy", "chain")
    )
    cap_checks = ((axfr_confirmed, DOMAIN_SCORE_CAPS[0]), (takeover_confirmed, DOMAIN_SCORE_CAPS[1]), (dnssec_bogus, DOMAIN_SCORE_CAPS[2]))
    total_score = round(raw_score)
    for applies, cap in cap_checks:
        if applies:
            caps_applied.append(dict(cap))
            total_score = min(total_score, cap["maximum"])

    grade, label = "F", "High Risk"
    for threshold, candidate_grade, candidate_label in _DOMAIN_GRADE_THRESHOLDS:
        if total_score >= threshold:
            grade, label = candidate_grade, candidate_label
            break
    provisional = excluded_weight > 30
    if provisional:
        grade = f"{grade} (incomplete)"
    inconclusive_checks = [f"{factor['category']}: {factor['checks_completed']} of {factor['checks_total']} checks" for factor in factors.values() if factor["status"] == "inconclusive"]
    label = f"{label} (based on {included_factor_count} of {total_factor_count} factors)"
    if provisional:
        label = f"{label}; grade is provisional"
    if not included_factor_count:
        label = f"No factors could be scored (based on 0 of {total_factor_count} factors); grade is provisional"
    if caps_applied:
        label = f"{label} (capped: {', '.join(cap['code'] for cap in caps_applied)})"

    # Keep the legacy ``domain_score.factors.threats`` field working while the
    # new transparent breakdown uses the approved factor name, ``takeover``.
    breakdown_factors = {("takeover" if key == "threats" else key): value for key, value in factors.items()}
    score_breakdown = {
        "factors": breakdown_factors,
        "caps_applied": caps_applied,
        "applicable_weight": applicable_weight,
        "excluded_factors": excluded_factors,
        "excluded_weight": excluded_weight,
        "included_factor_count": included_factor_count,
        "total_factor_count": total_factor_count,
        "provisional": provisional,
        "checks_completed": completed_checks,
        "checks_total": total_checks,
        "inconclusive_policy": "Inconclusive checks in a partially observed factor receive neutral 50% credit. Factors with no completed checks and factors marked not_applicable are excluded; remaining factor weights are rescaled to 100.",
        "normalization": "Factors marked not_applicable or inconclusive with no completed checks are excluded; remaining weights are rescaled to 100.",
    }
    return {
        "score": total_score,
        "grade": grade,
        "label": label,
        "scope": "DNS, email authentication, DNSSEC, takeover evidence, TLS/web, mail transport, and DNS posture",
        "inconclusive_count": sum(factor["checks_total"] - factor["checks_completed"] for factor in factors.values() if factor["status"] == "inconclusive"),
        "inconclusive_checks": inconclusive_checks,
        "factors": factors,
        "score_breakdown": score_breakdown,
    }
