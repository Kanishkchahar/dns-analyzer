"""1-Click Remediation & DNS Fix Generator.

Translates diagnostic findings into copy-pasteable, valid DNS zone records
and configuration blocks for Cloudflare, AWS Route 53, GoDaddy, and BIND format.
"""

from typing import Any
from app.models import RemediationFix


def _detect_mx_provider(records: dict[str, Any] | None) -> tuple[str, str]:
    """Detect primary mail service provider from MX records to tailor SPF draft."""
    if not records:
        return "Google Workspace / Mail Provider", "include:_spf.google.com"
    mx_data = records.get("MX", {})
    raw_mx = " ".join(str(r).lower() for r in mx_data.get("records", []))
    if any(k in raw_mx for k in ("google", "googlemail", "aspmx")):
        return "Google Workspace", "include:_spf.google.com"
    if any(k in raw_mx for k in ("outlook", "protection.outlook", "microsoft")):
        return "Microsoft 365", "include:spf.protection.outlook.com"
    if "zoho" in raw_mx:
        return "Zoho Mail", "include:zoho.com"
    if any(k in raw_mx for k in ("protonmail", "proton")):
        return "Proton Mail", "include:_spf.protonmail.ch"
    if "icloud" in raw_mx:
        return "Apple iCloud", "include:icloud.com"
    return "Google Workspace / Mail Provider", "include:_spf.google.com"


def generate_remediation_fixes(
    domain: str,
    findings: list[Any],
    email_auth: Any,
    security: Any,
    records: dict[str, Any] | None = None,
) -> list[RemediationFix]:
    """Analyze all findings and generate tailored, safe DNS fix records."""
    fixes: list[RemediationFix] = []

    # 1. SPF Fix
    spf_data = getattr(email_auth, "spf", None) if email_auth else None
    if not spf_data:
        provider_name, spf_include = _detect_mx_provider(records)
        fixes.append(RemediationFix(
            title="Create Authoritative SPF Record (Draft)",
            record_type="TXT",
            host="@",
            value=f"v=spf1 {spf_include} ~all",
            ttl=3600,
            is_draft=True,
            impact_warning="Draft record. Publishing an incomplete SPF record will cause legitimate outbound emails from unlisted servers to fail delivery.",
            prerequisites=[
                "Confirm all third-party services sending mail on your behalf (e.g. SendGrid, Mailgun, CRM, helpdesks).",
                f"Confirm outbound mail provider (detected: {provider_name}) and adjust include: mechanisms accordingly.",
            ],
            provider_guides={
                "Cloudflare": f'Type: TXT, Name: @, Content: "v=spf1 {spf_include} ~all", TTL: Auto',
                "AWS Route 53": f'Name: (empty), Type: TXT, Value: "v=spf1 {spf_include} ~all"',
                "GoDaddy / Namecheap": f'Type: TXT, Host: @, Value: v=spf1 {spf_include} ~all',
            }
        ))
    else:
        # Check if over limit and flattened record is available and semantics-safe
        spf_lookups = getattr(email_auth, "spf_lookups", None) if email_auth else None
        spf_flat = getattr(email_auth, "spf_flattened", None) if email_auth else None
        if (
            spf_lookups
            and spf_lookups.get("over_limit")
            and spf_flat
            and spf_flat.get("can_flatten", True)
            and spf_flat.get("flattened_record")
        ):
            fixes.append(RemediationFix(
                title="Replace SPF with Flattened Record (Bypass 10-Lookup Limit — Advanced Review)",
                record_type="TXT",
                host="@",
                value=spf_flat.get("flattened_record", ""),
                ttl=3600,
                is_draft=True,
                impact_warning="Advanced option: Cloud email providers rotate IP ranges dynamically. Flattened records require automated regular re-syncing to avoid dropping legitimate mail when provider netblocks change.",
                prerequisites=[
                    "Verify all resolved IP addresses match your authorized email systems.",
                    "Establish a scheduled process (or automated updater) to keep flattened IP ranges synchronized.",
                ],
                provider_guides={
                    "Cloudflare": f'Replace current SPF TXT with: "{spf_flat.get("flattened_record", "")}"',
                    "AWS Route 53": f'Update TXT record with: "{spf_flat.get("flattened_record", "")}"',
                }
            ))

    # 2. DMARC Fix
    dmarc_data = getattr(email_auth, "dmarc", None) if email_auth else None
    if not dmarc_data:
        fixes.append(RemediationFix(
            title="Deploy Anti-Spoofing DMARC Policy (Phase 1: Monitor / p=none)",
            record_type="TXT",
            host="_dmarc",
            value=f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100",
            ttl=3600,
            is_draft=True,
            impact_warning="Phase 1 monitoring policy (p=none) observes and reports without blocking mail. Do not enforce p=reject immediately without first reviewing RUA reports.",
            prerequisites=[
                "Deploy p=none for 2-4 weeks to collect aggregate XML reports on all legitimate mail streams.",
                "Review SPF and DKIM pass rates before advancing policy to quarantine or reject.",
            ],
            provider_guides={
                "Cloudflare": f'Type: TXT, Name: _dmarc, Content: "v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100"',
                "AWS Route 53": f'Name: _dmarc, Type: TXT, Value: "v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100"',
                "GoDaddy / Namecheap": f'Type: TXT, Host: _dmarc, Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100',
            }
        ))
    elif dmarc_data.get("policy") == "none":
        fixes.append(RemediationFix(
            title="Upgrade DMARC Policy from 'none' to 'quarantine' or 'reject' (Staged Rollout)",
            record_type="TXT",
            host="_dmarc",
            value=f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; pct=100",
            ttl=3600,
            is_draft=True,
            impact_warning="Publishing p=reject instructs receiving mail servers to discard unauthenticated emails. Verify all mail flows pass SPF/DKIM before enforcing.",
            prerequisites=[
                "Ensure RUA reports show 100% pass rates for corporate, marketing, and transactional mail.",
                "Consider stepping through quarantine (e.g. p=quarantine; pct=25 -> pct=100) before reject.",
            ],
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
    """Generate a standard BIND zone file configuration snippet (Draft records)."""
    lines = [
        f"; ==============================================================================",
        f"; DRAFT BIND ZONE SNIPPET FOR {domain.upper()}",
        f"; Notice: These records are provisional suggestions generated by DNS Analyzer v2.",
        f"; Review and verify with your DNS host before publishing to production.",
        f"; ==============================================================================",
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
