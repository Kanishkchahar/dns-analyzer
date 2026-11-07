"""Subdomain Takeover & Dangling CNAME Vulnerability Scanner.

Detects dangling CNAME and MX records pointing to decommissioned or unclaimed
cloud service endpoints (e.g., GitHub Pages, AWS S3, Heroku, Shopify, Zendesk,
Surge, Ghost, Azure, Vercel).
"""

from typing import Any
import dns.asyncresolver
import dns.exception
from app.models import Finding

# Signatures of cloud services known to be susceptible to takeover when dangling
TAKEOVER_SIGNATURES: list[dict[str, str]] = [
    {
        "provider": "GitHub Pages",
        "cname_pattern": "github.io",
        "fingerprint": "There isn't a GitHub Pages site here",
        "remediation": "Claim the repository on GitHub Pages or remove the dangling CNAME."
    },
    {
        "provider": "Amazon S3",
        "cname_pattern": "s3.amazonaws.com",
        "fingerprint": "The specified bucket does not exist",
        "remediation": "Create the corresponding S3 bucket or remove the dangling CNAME."
    },
    {
        "provider": "Amazon S3 Website",
        "cname_pattern": "s3-website",
        "fingerprint": "404 Not Found",
        "remediation": "Recreate the S3 website endpoint or delete the CNAME record."
    },
    {
        "provider": "Heroku",
        "cname_pattern": "herokuapp.com",
        "fingerprint": "No such app",
        "remediation": "Claim the Heroku app name or remove the CNAME record."
    },
    {
        "provider": "Shopify",
        "cname_pattern": "myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable",
        "remediation": "Claim the custom domain inside Shopify Admin or remove the CNAME."
    },
    {
        "provider": "Zendesk",
        "cname_pattern": "zendesk.com",
        "fingerprint": "Help Center Closed",
        "remediation": "Claim the Zendesk host or remove the CNAME alias."
    },
    {
        "provider": "Ghost",
        "cname_pattern": "ghost.io",
        "fingerprint": "The thing you were looking for is no longer here",
        "remediation": "Re-associate with Ghost(Pro) or remove the CNAME."
    },
    {
        "provider": "Surge.sh",
        "cname_pattern": "surge.sh",
        "fingerprint": "project not found",
        "remediation": "Deploy an authorized project to Surge or remove the CNAME."
    },
    {
        "provider": "Vercel",
        "cname_pattern": "vercel-dns.com",
        "fingerprint": "404: NOT_FOUND",
        "remediation": "Verify project ownership in Vercel or point CNAME to an active app."
    },
    {
        "provider": "Microsoft Azure",
        "cname_pattern": "azurewebsites.net",
        "fingerprint": "404 Web Site not found",
        "remediation": "Claim the App Service name on Azure or remove the CNAME record."
    },
]


async def check_subdomain_takeover(
    domain: str,
    records: dict[str, Any],
    resolver: dns.asyncresolver.Resolver,
) -> tuple[dict[str, Any], list[Finding]]:
    """Scan the domain's CNAME record for dangling pointers and takeover vulnerabilities."""
    findings: list[Finding] = []
    cname_entry = records.get("CNAME", {})
    cname_target = None

    if cname_entry.get("status") == "ok":
        rec = cname_entry.get("records")
        if isinstance(rec, list) and rec:
            cname_target = str(rec[0]).rstrip(".")
        elif isinstance(rec, str):
            cname_target = rec.rstrip(".")

    if not cname_target:
        return {
            "scanned": True,
            "has_cname": False,
            "vulnerable": False,
            "status": "safe",
            "message": "No CNAME record present at this node. Not directly susceptible to CNAME takeover.",
        }, findings

    # Check if target matches any known cloud provider
    matched_provider = None
    for sig in TAKEOVER_SIGNATURES:
        if sig["cname_pattern"] in cname_target.lower():
            matched_provider = sig
            break

    # Resolve target's A records to see if it is dangling (unresolvable)
    target_resolves = False
    try:
        ans = await resolver.resolve(cname_target, "A")
        if len(ans) > 0:
            target_resolves = True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        target_resolves = False
    except Exception:
        target_resolves = False

    # If unresolvable (NXDOMAIN / NoAnswer)
    if not target_resolves:
        if matched_provider:
            prov_name = matched_provider["provider"]
            remedy = matched_provider["remediation"]
            findings.append(Finding(
                severity="error",
                record_type="TAKEOVER",
                message=f"CRITICAL: Dangling CNAME alias pointing to unresolvable host '{cname_target}' ({prov_name}). "
                        f"Attackers can claim the destination endpoint and hijack your subdomain! {remedy}"
            ))
            return {
                "scanned": True,
                "has_cname": True,
                "cname_target": cname_target,
                "provider": prov_name,
                "vulnerable": True,
                "status": "critical_vulnerability",
                "details": f"CNAME points to '{cname_target}' on {prov_name}, which does not resolve. Vulnerable to takeover.",
                "remediation": remedy,
            }, findings
        else:
            remedy = "Delete this obsolete CNAME record or point it to an active destination host."
            findings.append(Finding(
                severity="warning",
                record_type="TAKEOVER",
                message=f"Dangling CNAME alias: points to '{cname_target}', which does not resolve to any active IP address. "
                        f"This broken alias causes resolution failures; remove or point it to an active host."
            ))
            return {
                "scanned": True,
                "has_cname": True,
                "cname_target": cname_target,
                "provider": "Custom / Unknown",
                "vulnerable": False,
                "status": "dangling_alias",
                "details": f"CNAME points to '{cname_target}', which does not resolve (suspicious dangling alias).",
                "remediation": remedy,
            }, findings

    # If it resolves but points to a known cloud provider
    if matched_provider:
        findings.append(Finding(
            severity="info",
            record_type="TAKEOVER",
            message=f"CNAME alias points to active cloud provider '{matched_provider['provider']}' ({cname_target}). "
                    f"Ensure this cloud resource is actively registered in your organization's account."
        ))
        return {
            "scanned": True,
            "has_cname": True,
            "cname_target": cname_target,
            "provider": matched_provider["provider"],
            "vulnerable": False,
            "status": "cloud_hosted",
            "details": f"Points to active {matched_provider['provider']} endpoint.",
        }, findings

    return {
        "scanned": True,
        "has_cname": True,
        "cname_target": cname_target,
        "provider": "Custom",
        "vulnerable": False,
        "status": "safe",
        "details": f"Points to active host '{cname_target}'.",
    }, findings
