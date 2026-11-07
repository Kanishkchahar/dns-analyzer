"""BIMI (Brand Indicators for Message Identification) Analyzer.

Inspects default._bimi.{domain} TXT records and cross-references with DMARC
policy enforcement to evaluate whether the brand is eligible to display official
verified logos in Gmail, Apple Mail, and Yahoo Mail inboxes.
"""

from typing import Any
import dns.asyncresolver
import dns.exception
from app.models import Finding


def _parse_tags(raw: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip()] = value.strip()
    return tags


async def check_bimi(
    domain: str,
    dmarc_data: dict[str, Any] | None,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query default._bimi.{domain} and evaluate BIMI eligibility."""
    findings: list[Finding] = []
    qname = f"default._bimi.{domain}"
    bimi_raw = None
    lookup_failed = False

    try:
        ans = await resolver.resolve(qname, "TXT")
        for rr in ans:
            txt = b"".join(rr.strings).decode("utf-8", errors="replace").strip()
            if txt.startswith("v=BIMI1"):
                bimi_raw = txt
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        bimi_raw = None
    except Exception:
        bimi_raw = None
        lookup_failed = True

    # Check DMARC prerequisite: must be p=quarantine (pct=100) or p=reject
    dmarc_policy = (dmarc_data or {}).get("policy", "none")
    dmarc_pct = (dmarc_data or {}).get("pct", 100)
    dmarc_eligible = dmarc_policy in ("quarantine", "reject") and dmarc_pct == 100

    if not bimi_raw:
        if lookup_failed:
            return {
                "has_bimi": False,
                "status": "inconclusive",
                "dmarc_eligible": dmarc_eligible,
                "logo_url": None,
                "vmc_url": None,
                "reason": "BIMI DNS lookup failed; record presence could not be verified.",
            }, [Finding(
                severity="info",
                record_type="BIMI",
                message="BIMI could not be verified because its DNS query failed.",
            )]
        if dmarc_eligible:
            findings.append(Finding(
                severity="info",
                record_type="BIMI",
                message=f"BIMI not configured. However, your strong DMARC policy ({dmarc_policy}) makes "
                        f"your domain eligible to publish a BIMI record and show verified logos in customer inboxes!"
            ))
        return {
            "has_bimi": False,
            "status": "not_configured",
            "dmarc_eligible": dmarc_eligible,
            "logo_url": None,
            "vmc_url": None,
        }, findings

    tags = _parse_tags(bimi_raw)
    logo_url = tags.get("l")
    vmc_url = tags.get("a")

    if not dmarc_eligible:
        findings.append(Finding(
            severity="warning",
            record_type="BIMI",
            message=f"BIMI record found, but DMARC policy is '{dmarc_policy}' (pct={dmarc_pct}%). "
                    f"Mail clients (Gmail/Apple Mail) will NOT display your logo until DMARC is set to "
                    f"'quarantine' or 'reject' with pct=100."
        ))
        status = "dmarc_ineligible"
    elif not logo_url:
        findings.append(Finding(
            severity="warning",
            record_type="BIMI",
            message="BIMI record is missing the required SVG logo location tag (l=)."
        ))
        status = "missing_logo"
    else:
        findings.append(Finding(
            severity="info",
            record_type="BIMI",
            message=f"BIMI is active with SVG logo '{logo_url}'. "
                    f"{'Verified Mark Certificate (VMC) detected.' if vmc_url else 'No VMC certificate specified (accepted by Yahoo Mail, VMC required for Gmail blue checkmark).'}"
        ))
        status = "active"

    return {
        "has_bimi": True,
        "raw": bimi_raw,
        "status": status,
        "logo_url": logo_url,
        "vmc_url": vmc_url,
        "dmarc_eligible": dmarc_eligible,
    }, findings
