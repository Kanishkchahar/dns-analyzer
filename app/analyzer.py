"""Rule-based DNS misconfiguration analyzer."""

from typing import Any

from app.models import Finding

# Minimum SOA expire value considered reasonable (2 days in seconds)
_MIN_SOA_EXPIRE = 172_800
# Maximum TTL considered reasonable (7 days in seconds)
_MAX_TTL = 604_800


def _finding(severity: str, record_type: str, message: str) -> Finding:
    return Finding(severity=severity, record_type=record_type, message=message)


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------

def check_domain_resolves(data: dict[str, Any], domain: str | None = None) -> list[Finding]:
    """Check 1: Domain must resolve to at least one IP address."""
    a_ok = data.get("A", {}).get("status") == "ok"
    aaaa_ok = data.get("AAAA", {}).get("status") == "ok"
    if not a_ok and not aaaa_ok:
        subject = f" `{domain}`" if domain else ""
        return [_finding("error", "GENERAL", f"Domain{subject} does not resolve to any IP address.")]
    return []


def check_ns_exists(data: dict[str, Any]) -> list[Finding]:
    """Check 2: NS records must exist (or be delegated to authoritative zone apex)."""
    ns = data.get("NS", {})
    if ns.get("status") != "ok":
        return [_finding("error", "NS", "No nameservers found for this domain.")]
    inherited = ns.get("inherited_from")
    if inherited:
        return [_finding(
            "info", "NS",
            f"Hostname operates under authoritative zone `{inherited}` (inherits nameserver authority)."
        )]
    return []


def check_ns_redundancy(data: dict[str, Any]) -> list[Finding]:
    """Check 3: At least two NS records are recommended."""
    ns = data.get("NS", {})
    if ns.get("status") == "ok" and len(ns.get("records", [])) == 1:
        return [_finding(
            "warning", "NS",
            "Only one nameserver found — no redundancy. RFC 1035 recommends at least two."
        )]
    return []


def check_ns_resolves(data: dict[str, Any]) -> list[Finding]:
    """Check 4: Each NS host should resolve to an A record."""
    findings: list[Finding] = []
    ns = data.get("NS", {})
    if ns.get("status") == "ok":
        for entry in ns.get("records", []):
            if not entry.get("resolves", True):
                findings.append(_finding(
                    "error", "NS",
                    f"Nameserver `{entry['host']}` does not resolve."
                ))
    return findings


def check_mx_exists(data: dict[str, Any]) -> list[Finding]:
    """Check 5: MX records not found is informational (not an error)."""
    if data.get("MX", {}).get("status") != "ok":
        return [_finding("info", "MX", "No MX records found — domain may not accept email.")]
    return []


def check_mx_resolves(data: dict[str, Any]) -> list[Finding]:
    """Check 6: Each MX host should resolve to an A record."""
    findings: list[Finding] = []
    mx = data.get("MX", {})
    if mx.get("status") == "ok":
        for entry in mx.get("records", []):
            if not entry.get("resolves", True):
                findings.append(_finding(
                    "error", "MX",
                    f"Mail server `{entry['host']}` does not resolve."
                ))
    return findings


def check_cname_conflict(data: dict[str, Any]) -> list[Finding]:
    """Check 7: CNAME must not coexist with other record types."""
    cname_entry = data.get("CNAME", {})
    if cname_entry.get("status") != "ok" or not cname_entry.get("records"):
        return []
    # Other types that would conflict
    conflicting = [t for t in ("A", "AAAA", "MX", "TXT", "NS") if data.get(t, {}).get("status") == "ok" and data.get(t, {}).get("records")]
    if conflicting:
        return [_finding(
            "error", "CNAME",
            "CNAME record coexists with other record types at the same name — "
            "this violates RFC 1034 and may cause unpredictable resolution behavior."
        )]
    return []


def check_soa_sanity(data: dict[str, Any]) -> list[Finding]:
    """Check 8: SOA record sanity checks."""
    findings: list[Finding] = []
    soa = data.get("SOA", {})
    if soa.get("status") != "ok":
        findings.append(_finding("error", "SOA", "No SOA record found."))
        return findings

    rec = soa.get("records", {})
    refresh = rec.get("refresh", 0)
    retry = rec.get("retry", 0)
    expire = rec.get("expire", 0)

    if refresh < retry:
        findings.append(_finding(
            "warning", "SOA",
            f"SOA refresh interval ({refresh}s) is smaller than retry interval ({retry}s) — unusual configuration."
        ))
    if expire < _MIN_SOA_EXPIRE:
        findings.append(_finding(
            "warning", "SOA",
            f"SOA expire value ({expire}s) is unusually low — less than 2 days. "
            "Slaves may stop serving the zone before it can be refreshed."
        ))
    return findings


def check_ttl_sanity(data: dict[str, Any]) -> list[Finding]:
    """Check 9: TTL values should be within sane bounds."""
    findings: list[Finding] = []
    for rtype, entry in data.items():
        if entry.get("status") != "ok":
            continue
        ttl = entry.get("ttl", None)
        if ttl is None:
            continue
        if ttl == 0:
            findings.append(_finding(
                "warning", rtype,
                f"TTL of 0 on `{rtype}` record — disables caching and can increase load / latency."
            ))
        elif ttl > _MAX_TTL:
            findings.append(_finding(
                "info", rtype,
                f"TTL on `{rtype}` record is unusually high ({ttl}s / {ttl // 86400} days) — changes will propagate slowly."
            ))
    return findings


def check_caa(data: dict[str, Any]) -> list[Finding]:
    """Review Certificate Authority Authorization (CAA) records when DNS returned a definite answer."""
    caa = data.get("CAA", {})
    if caa.get("status") not in ("ok", "no_answer"):
        return []
    records = caa.get("records", []) if caa.get("status") == "ok" else []
    issue_records = [record for record in records if record.get("tag", "").lower() in ("issue", "issuewild")]
    if not issue_records:
        inherited = caa.get("inherited_from")
        note = f" Effective policy inherited from `{inherited}`." if inherited else ""
        return [_finding(
            "warning", "CAA",
            "No CAA issuance policy was found. Certificate authorities are not restricted by CAA for this hostname." + note,
        )]
    if all(not record.get("value", "").strip() for record in issue_records):
        return [_finding(
            "info", "CAA",
            "CAA policy explicitly forbids certificate issuance for this hostname (empty issue/issuewild values). Verify that this is intentional.",
        )]
    allowed_cas = sorted({record["value"].split(";")[0].strip() for record in issue_records if record.get("value", "").strip()})
    return [_finding(
        "info", "CAA",
        f"CAA restricts certificate issuance to: {', '.join(allowed_cas)}." + (f" Policy inherited from `{caa['inherited_from']}`." if caa.get("inherited_from") else ""),
    )]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_CHECKS = [
    check_domain_resolves,
    check_ns_exists,
    check_ns_redundancy,
    check_ns_resolves,
    check_mx_exists,
    check_mx_resolves,
    check_cname_conflict,
    check_soa_sanity,
    check_ttl_sanity,
    check_caa,
]


def analyze(domain: str, resolver_data: dict[str, Any]) -> list[Finding]:
    """Run all checks and return combined findings list."""
    findings: list[Finding] = []
    for check in _CHECKS:
        if check is check_domain_resolves:
            findings.extend(check(resolver_data, domain))
        else:
            findings.extend(check(resolver_data))
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    return {
        "errors": sum(1 for f in findings if f.severity == "error"),
        "warnings": sum(1 for f in findings if f.severity == "warning"),
        "info": sum(1 for f in findings if f.severity == "info"),
        "inconclusive": sum(1 for f in findings if f.severity in ("inconclusive", "unverified")),
    }
