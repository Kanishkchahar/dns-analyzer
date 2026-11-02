"""1-Click Remediation & DNS Fix Generator.

Translates diagnostic findings into copy-pasteable, valid DNS zone records
and configuration blocks for Cloudflare, AWS Route 53, GoDaddy, and BIND format.
"""

from typing import Any
from app.models import RemediationFix


def generate_remediation_fixes(
    domain: str,
    findings: list[Any],
    email_auth: Any,
    security: Any,
) -> list[RemediationFix]:
    """Analyze all findings and generate tailored DNS fix records."""
    fixes: list[RemediationFix] = []

    # 1. SPF Fix
    spf_data = getattr(email_auth, "spf", None) if email_auth else None
    if not spf_data:
        fixes.append(RemediationFix(
            title="Create Authoritative SPF Record",
            record_type="TXT",
            host="@",
            value="v=spf1 include:_spf.google.com ~all",
            ttl=3600,
            provider_guides={
                "Cloudflare": 'Type: TXT, Name: @, Content: "v=spf1 include:_spf.google.com ~all", TTL: Auto',
                "AWS Route 53": 'Name: (empty), Type: TXT, Value: "v=spf1 include:_spf.google.com ~all"',
                "GoDaddy / Namecheap": 'Type: TXT, Host: @, Value: v=spf1 include:_spf.google.com ~all',
            }
        ))
    else:
        # Check if over limit and flattened record is available
        spf_lookups = getattr(email_auth, "spf_lookups", None) if email_auth else None
        spf_flat = getattr(email_auth, "spf_flattened", None) if email_auth else None
        if spf_lookups and spf_lookups.get("over_limit") and spf_flat:
            fixes.append(RemediationFix(
                title="Replace SPF with Flattened Record (Bypass 10-Lookup Limit)",
                record_type="TXT",
                host="@",
                value=spf_flat.get("flattened_record", ""),
                ttl=3600,
                provider_guides={
                    "Cloudflare": f'Replace current SPF TXT with: "{spf_flat.get("flattened_record", "")}"',
                    "AWS Route 53": f'Update TXT record with: "{spf_flat.get("flattened_record", "")}"',
                }
            ))

    # 2. DMARC Fix
    dmarc_data = getattr(email_auth, "dmarc", None) if email_auth else None
    if not dmarc_data:
        fixes.append(RemediationFix(
            title="Deploy Anti-Spoofing DMARC Policy (Quarantine/Reject)",
            record_type="TXT",
            host=f"_dmarc",
            value=f"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100",
            ttl=3600,
            provider_guides={
                "Cloudflare": f'Type: TXT, Name: _dmarc, Content: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100"',
                "AWS Route 53": f'Name: _dmarc, Type: TXT, Value: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100"',
                "GoDaddy / Namecheap": f'Type: TXT, Host: _dmarc, Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100',
            }
        ))
    elif dmarc_data.get("policy") == "none":
        fixes.append(RemediationFix(
            title="Upgrade DMARC Policy from 'none' to 'quarantine' or 'reject'",
            record_type="TXT",
            host="_dmarc",
            value=f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; pct=100",
            ttl=3600,
            provider_guides={
                "Recommendation": "Upgrade policy tag from p=none to p=quarantine or p=reject for active enforcement.",
            }
        ))

    # 3. BIMI Fix (if DMARC is strong but no BIMI)
    bimi_data = getattr(security, "bimi", None) if security else None
    if bimi_data and bimi_data.get("dmarc_eligible") and not bimi_data.get("has_bimi"):
        fixes.append(RemediationFix(
            title="Enable BIMI Brand Logo in Inboxes",
            record_type="TXT",
            host="default._bimi",
            value=f"v=BIMI1; l=https://{domain}/brand-logo.svg; a=",
            ttl=3600,
            provider_guides={
                "Cloudflare": f'Type: TXT, Name: default._bimi, Content: "v=BIMI1; l=https://{domain}/brand-logo.svg; a="',
                "Requirement": "Ensure the SVG file is compliant with BIMI Tiny-PS (SVG 1.2 Tiny Profile).",
            }
        ))

    # 4. DNSSEC Guidance
    dnssec_data = getattr(security, "dnssec", None) if security else None
    if dnssec_data and not dnssec_data.get("enabled"):
        fixes.append(RemediationFix(
            title="Enable DNSSEC at Registrar / Cloudflare",
            record_type="DS",
            host="@",
            value="Enable 'DNSSEC' toggle in Cloudflare Dashboard -> DNS -> Settings -> Enable DNSSEC",
            ttl=3600,
            provider_guides={
                "Cloudflare": "Navigate to DNS -> Settings -> Click 'Enable DNSSEC' -> Copy the generated DS record to your domain registrar (GoDaddy/Namecheap).",
                "AWS Route 53": "In Hosted Zones, select domain -> DNSSEC Signing -> Enable DNSSEC signing.",
            }
        ))

    return fixes


def generate_bind_zone_file(domain: str, fixes: list[RemediationFix]) -> str:
    """Generate a standard BIND zone file configuration snippet."""
    lines = [
        f"; ── Generated DNS Fixes for {domain} ──",
        f"; Created by DNS Analyzer v2 (InboxShield Edition)",
        f"$ORIGIN {domain}.",
        f"$TTL 3600",
        "",
    ]
    for fix in fixes:
        if fix.record_type in ("TXT", "CNAME", "A", "AAAA"):
            lines.append(f"; {fix.title}")
            lines.append(f"{fix.host}\tIN\t{fix.record_type}\t\"{fix.value}\"")
            lines.append("")
    return "\n".join(lines)
