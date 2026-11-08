"""1-Click Remediation & DNS Fix Generator.

Translates diagnostic findings into copy-pasteable, valid DNS zone records
and configuration blocks for Cloudflare, AWS Route 53, GoDaddy, and BIND format.
"""

from typing import Any
from app.models import RemediationFix
from app.provider_templates import _quote_txt, _txt_chunks, apply_provider_templates


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
        txt_status = (records or {}).get("TXT", {}).get("status")
        txt_was_checked = records is None or txt_status in ("ok", "no_answer", "nxdomain")
        if txt_was_checked:
            fixes.append(RemediationFix(
                title="Confirm mail use and authorized senders before creating SPF",
                record_type="SPF",
                host="@",
                value="",
                guidance=(
                    "No SPF record was generated. DNS records alone cannot establish every system "
                    "authorized to send email for this domain."
                ),
                guidance_only=True,
                is_draft=True,
                prerequisites=[
                    "Confirm whether this exact domain sends email; a subdomain used only for web hosting may not need its own SPF policy.",
                    "List every authorized sender, including business mail, marketing, transactional, CRM, and support systems.",
                    "Build one SPF record from the confirmed sender documentation, then validate it before publishing.",
                ],
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

    for fix in fixes:
        apply_provider_templates(domain, fix)
    return fixes


def generate_bind_zone_file(domain: str, fixes: list[RemediationFix]) -> str:
    """Generate a standard BIND zone file configuration snippet (Draft records)."""
    lines = [
        f"; ==============================================================================",
        f"; DRAFT BIND ZONE SNIPPET FOR {domain.upper()}",
        f"; Notice: These records are provisional suggestions generated by DNS Analyzer 2.2.0.",
        f"; Review and verify with your DNS host before publishing to production.",
        f"; ==============================================================================",
        f"$ORIGIN {domain}.",
        f"$TTL 3600",
        "",
    ]
    for fix in fixes:
        if fix.record_type in ("TXT", "CNAME", "A", "AAAA"):
            lines.append(f"; {fix.title}")
            value = " ".join(_quote_txt(chunk) for chunk in _txt_chunks(fix.value)) if fix.record_type == "TXT" else fix.value
            lines.append(f"{fix.host}\tIN\t{fix.record_type}\t{value}")
            lines.append("")
    return "\n".join(lines)
