"""Stable finding identifiers and shared plain-language remediation guidance."""

from __future__ import annotations

import logging
import os
from typing import Any


_CATALOG: dict[str, dict[str, str]] = {
    "GENERAL": {"code": "DNS-001", "title": "Domain resolution", "why": "People and services may not be able to find this domain.", "attacker": "An attacker may exploit a lapse in ownership or routing to impersonate a service.", "fix": "Check the authoritative zone and correct the reported DNS records.", "technical": "Review A and AAAA resolution and authoritative delegation.", "reference": "RFC 1034, RFC 1035"},
    "A": {"code": "DNS-002", "title": "IPv4 address records", "why": "The host may not be reachable over IPv4.", "attacker": "An abandoned hostname can become a takeover risk if its target is later claimable.", "fix": "Publish the intended A record or remove an obsolete hostname.", "technical": "Verify the owner name, address set, and TTL at authoritative servers.", "reference": "RFC 1035"},
    "AAAA": {"code": "DNS-003", "title": "IPv6 address records", "why": "IPv6 users may fail to reach the intended service.", "attacker": "A stale IPv6 route can direct clients to an unintended host.", "fix": "Publish correct AAAA records or remove stale IPv6 records.", "technical": "Verify authoritative AAAA answers and reachability.", "reference": "RFC 3596"},
    "NS": {"code": "DNS-004", "title": "Nameserver delegation", "why": "Resolvers rely on these servers to find every record in the zone.", "attacker": "A dangling nameserver domain may let another party take control of the zone.", "fix": "Use active nameserver hostnames and keep their registered parent domains renewed.", "technical": "Confirm parent delegation, glue where required, and authoritative responses.", "reference": "RFC 1034, RFC 1035"},
    "MX": {"code": "MAIL-001", "title": "Mail exchange records", "why": "Incoming email may be delayed or rejected.", "attacker": "A stale mail route may expose traffic to an unintended provider.", "fix": "Update MX targets to active mail servers and verify their addresses.", "technical": "Check MX preference ordering and target A/AAAA answers.", "reference": "RFC 5321"},
    "CNAME": {"code": "DNS-005", "title": "DNS alias configuration", "why": "An invalid or stale alias can break service routing.", "attacker": "A dangling third-party alias may be claimable by another account.", "fix": "Remove the stale alias or point it to a resource controlled by your organization.", "technical": "Check CNAME exclusivity and the target's current provider state.", "reference": "RFC 1034, RFC 2181"},
    "SOA": {"code": "DNS-006", "title": "Zone authority parameters", "why": "Secondary DNS servers may become stale or stop serving the zone.", "attacker": "Inconsistent authority can make DNS changes unreliable and harder to detect.", "fix": "Review the primary server and refresh, retry, and expire values with your DNS operator.", "technical": "Validate SOA timers and monotonically updated serials.", "reference": "RFC 1035, RFC 1912"},
    "TXT": {"code": "DNS-007", "title": "TXT record policy", "why": "TXT records can carry important ownership and email security policies.", "attacker": "Incorrect sender policies can make domain spoofing easier.", "fix": "Review the published policy with the service that owns it before changing it.", "technical": "Check syntax, duplicate policy records, and provider-specific constraints.", "reference": "RFC 1035"},
    "CAA": {"code": "CERT-001", "title": "Certificate issuance policy", "why": "Without a CAA policy, certificate authorities are not restricted by this DNS mechanism.", "attacker": "A misissued certificate can make impersonation more convincing.", "fix": "Publish CAA issue and issuewild records for the certificate authorities you use.", "technical": "Evaluate issue and issuewild independently, including inherited parent policy.", "reference": "RFC 8659"},
    "SPF": {"code": "MAIL-002", "title": "SPF sender policy", "why": "Receiving mail systems may not know which servers are allowed to send for your domain.", "attacker": "Attackers may spoof your domain in email if sender policy is absent or permissive.", "fix": "List every legitimate sender and use an appropriate final mechanism after validating mail flows.", "technical": "Check SPF syntax, DNS lookup count, include recursion, and all mechanism.", "reference": "RFC 7208"},
    "DMARC": {"code": "MAIL-003", "title": "DMARC enforcement", "why": "DMARC tells receivers how to handle messages that fail domain alignment.", "attacker": "Weak enforcement leaves more room for brand spoofing.", "fix": "Review aggregate reports, then stage quarantine or reject after legitimate mail passes.", "technical": "Check policy, pct, alignment, organizational fallback, and rua configuration.", "reference": "RFC 7489"},
    "DKIM": {"code": "MAIL-004", "title": "DKIM signing key", "why": "DKIM lets receivers verify that signed email content was not altered.", "attacker": "Missing or weak signing can reduce the trust receivers place in your mail.", "fix": "Publish the provider's current selector key and rotate it according to provider guidance.", "technical": "Check selector TXT syntax, key material, and key strength.", "reference": "RFC 6376"},
    "MTA-STS": {"code": "MAIL-005", "title": "MTA-STS transport policy", "why": "A policy can ask sending mail systems to require TLS when delivering to your domain.", "attacker": "Without enforced TLS, mail transport may be more exposed to downgrade or interception.", "fix": "Publish and validate an MTA-STS policy using your mail provider's instructions.", "technical": "Verify the _mta-sts TXT id and HTTPS policy file.", "reference": "RFC 8461"},
    "TLS-RPT": {"code": "MAIL-006", "title": "SMTP TLS reporting", "why": "TLS reports can help identify mail delivery encryption failures.", "attacker": "Without reports, transport failures or downgrade attempts may go unnoticed.", "fix": "Publish a _smtp._tls TXT record with a monitored reporting destination.", "technical": "Validate the v=TLSRPTv1 record and rua destinations.", "reference": "RFC 8460"},
    "DNSSEC": {"code": "DNSSEC-001", "title": "DNSSEC trust chain", "why": "DNSSEC helps validating resolvers detect forged DNS answers.", "attacker": "A broken chain can cause outages; unsigned zones provide no DNSSEC authenticity.", "fix": "Enable DNSSEC with your DNS provider and confirm the registrar DS matches the zone key.", "technical": "This check validates DS-to-DNSKEY matching; complete RRSIG and root-anchor validation is a separate step.", "reference": "RFC 4033, RFC 4034, RFC 4035"},
    "TAKEOVER": {"code": "TAKEOVER-001", "title": "Dangling service alias", "why": "A DNS alias may point to a deleted or unavailable cloud resource.", "attacker": "If the provider allows the resource name to be claimed, another account may serve content under your hostname.", "fix": "Reclaim the resource in your provider account or remove the stale DNS record.", "technical": "A DNS failure or service fingerprint is a lead, not proof of claimability; confirm with the provider.", "reference": "Operational security guidance"},
    "SUBDOMAIN TAKEOVER": {"code": "TAKEOVER-002", "title": "Subdomain takeover candidate", "why": "A discovered hostname may still point to an abandoned external resource.", "attacker": "A claimable resource could let another party serve content on the hostname.", "fix": "Reclaim the resource or remove the DNS alias, then check the provider console.", "technical": "Provider fingerprinting is heuristic and should be manually validated.", "reference": "Operational security guidance"},
    "HTTPS": {"code": "WEB-001", "title": "HTTPS configuration", "why": "Visitors need a valid encrypted connection and consistent HTTPS behavior.", "attacker": "Weak transport configuration can expose users to interception or downgrade attacks.", "fix": "Renew or correct the certificate and configure a safe HTTP-to-HTTPS redirect.", "technical": "Review certificate chain, SAN coverage, protocol negotiation, and redirect behavior.", "reference": "RFC 8446, RFC 6797"},
    "TLS": {"code": "WEB-002", "title": "TLS service", "why": "A failed handshake or certificate problem can prevent secure access.", "attacker": "Legacy or misconfigured TLS can weaken confidentiality and integrity.", "fix": "Use a publicly trusted certificate and modern TLS settings.", "technical": "Review negotiated protocol, cipher, certificate validity, and hostname match.", "reference": "RFC 8446"},
    "CSP": {"code": "WEB-003", "title": "Content Security Policy", "why": "CSP can reduce the impact of injected scripts and other browser attacks.", "attacker": "A permissive policy can make cross-site scripting easier to exploit.", "fix": "Remove unnecessary unsafe sources and define narrow script and object policies.", "technical": "The scanner checks common directives; this is not a full CSP evaluator.", "reference": "W3C Content Security Policy"},
    "COOKIE": {"code": "WEB-004", "title": "Cookie security flags", "why": "Cookie flags help limit exposure to script access and insecure transport.", "attacker": "A stolen session cookie may let an attacker reuse a logged-in session.", "fix": "Set Secure, HttpOnly, and an appropriate SameSite value where the application permits.", "technical": "Only Set-Cookie names and attributes are retained; values are discarded.", "reference": "RFC 6265bis"},
    "HTTP METHODS": {"code": "WEB-005", "title": "HTTP method advertisement", "why": "Unexpected methods may warrant a configuration review.", "attacker": "If enabled and poorly protected, write methods can change or expose content.", "fix": "Disable unneeded methods and enforce authorization at the application or proxy.", "technical": "OPTIONS Allow is advisory; no write-method request is sent.", "reference": "RFC 9110"},
    "AXFR": {"code": "DNS-AXFR-001", "title": "Zone transfer access", "why": "An unrestricted AXFR can disclose the zone's DNS inventory.", "attacker": "An attacker could enumerate hosts and infrastructure from the transferred zone.", "fix": "Restrict transfers to approved secondary-server IP addresses or require TSIG.", "technical": "The scanner records only the nameserver and RR count, never record contents.", "reference": "RFC 5936"},
    "WILDCARD DNS": {"code": "DNS-WILDCARD-001", "title": "Wildcard DNS response", "why": "Catch-all DNS can make nonexistent hostnames appear real in inventories.", "attacker": "It can obscure real assets and help abuse of arbitrary subdomains.", "fix": "Keep wildcard records only when required and account for them when reviewing inventory.", "technical": "A high-entropy label is checked; matching CT IPs are marked wildcard-only when no explicit CNAME exists.", "reference": "RFC 1034"},
    "NS CONSISTENCY": {"code": "DNS-NS-002", "title": "Authoritative server consistency", "why": "Different authoritative answers can cause intermittent routing behavior.", "attacker": "Drift can hide malicious or stale records on a subset of servers.", "fix": "Synchronize zone data and verify every delegated nameserver answers authoritatively.", "technical": "SOA serial and NS RRset are queried directly from each public nameserver address.", "reference": "RFC 1034, RFC 1035"},
    "INVENTORY": {"code": "RECON-CT-001", "title": "Certificate Transparency inventory", "why": "Public certificates can reveal hostnames outside the main website.", "attacker": "Forgotten development or staging hosts may expose weaker services.", "fix": "Review each hostname, remove stale records, and protect environments that should not be public.", "technical": "CT data is historical and does not prove a hostname is currently active.", "reference": "RFC 6962"},
    "SUBDOMAINS": {"code": "RECON-SUB-001", "title": "Subdomain inventory", "why": "Exposed or stale subdomains can expand the public attack surface.", "attacker": "A forgotten hostname may point to an abandoned service.", "fix": "Review, secure, or remove each stale hostname.", "technical": "Inventory is assembled from CT data and current DNS observations.", "reference": "RFC 6962"},
    "BIMI": {"code": "MAIL-007", "title": "BIMI brand indicator", "why": "BIMI can display a domain's brand mark in supported mail clients.", "attacker": "Incorrect policy or logo records can undermine brand presentation.", "fix": "Publish a valid BIMI record and meet the mail provider's DMARC and logo requirements.", "technical": "Client support and VMC requirements vary by provider.", "reference": "RFC 8617"},
}


_DMARC_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    ("no dmarc policy", "MAIL-DMARC-001", "DMARC record missing", "Publish a DMARC TXT record at _dmarc and start with a monitored policy.", "RFC 7489"),
    ("policy is set to 'none'", "MAIL-DMARC-002", "DMARC policy is monitor-only", "Review reports, then move to quarantine or reject when legitimate mail aligns.", "RFC 7489"),
    ("no aggregate report address (rua)", "MAIL-DMARC-003", "DMARC aggregate reporting is disabled", "Add a monitored rua=mailto: address to receive aggregate reports.", "RFC 7489"),
    ("policy applies to only", "MAIL-DMARC-004", "DMARC policy is partially applied", "Set pct=100 after validating mail flows and report results.", "RFC 7489"),
)

# Stable condition codes split findings that historically shared a broad
# record-type code. The catalog's original broad codes remain available as
# compatibility aliases for clients that stored earlier responses.
_CONDITION_CODES: tuple[tuple[str, str, str], ...] = (
    ("GENERAL", "does not resolve to any ip address", "DNS-RESOLVE-001"),
    ("NS", "no nameservers found", "DNS-NS-001"),
    ("NS", "only one nameserver", "DNS-NS-003"),
    ("NS", "does not resolve", "DNS-NS-004"),
    ("NS", "operates under authoritative zone", "DNS-NS-005"),
    ("MX", "no mx records found", "MAIL-MX-001"),
    ("MX", "does not resolve", "MAIL-MX-002"),
    ("CNAME", "coexists with other record types", "DNS-CNAME-001"),
    ("SOA", "no soa record found", "DNS-SOA-001"),
    ("SOA", "refresh interval", "DNS-SOA-002"),
    ("SOA", "expire value", "DNS-SOA-003"),
    ("CAA", "no caa issuance policy", "DNS-CAA-002"),
    ("CAA", "explicitly forbids certificate issuance", "DNS-CAA-003"),
    ("CAA", "restricts certificate issuance to", "DNS-CAA-004"),
    ("A", "ttl of 0", "DNS-TTL-001"),
    ("AAAA", "ttl of 0", "DNS-TTL-001"),
    ("MX", "ttl of 0", "DNS-TTL-001"),
    ("NS", "ttl of 0", "DNS-TTL-001"),
    ("CNAME", "ttl of 0", "DNS-TTL-001"),
    ("TXT", "ttl of 0", "DNS-TTL-001"),
    ("CAA", "ttl of 0", "DNS-TTL-001"),
    ("SOA", "ttl of 0", "DNS-TTL-001"),
    ("A", "ttl on `a` record is unusually high", "DNS-TTL-002"),
    ("AAAA", "ttl on `aaaa` record is unusually high", "DNS-TTL-002"),
    ("MX", "ttl on `mx` record is unusually high", "DNS-TTL-002"),
    ("NS", "ttl on `ns` record is unusually high", "DNS-TTL-002"),
    ("CNAME", "ttl on `cname` record is unusually high", "DNS-TTL-002"),
    ("TXT", "ttl on `txt` record is unusually high", "DNS-TTL-002"),
    ("CAA", "ttl on `caa` record is unusually high", "DNS-TTL-002"),
    ("SOA", "ttl on `soa` record is unusually high", "DNS-TTL-002"),
    ("SPF", "no spf record found", "MAIL-SPF-001"),
    ("SPF", "multiple spf records found", "MAIL-SPF-002"),
    ("SPF", "exceeding the rfc 7208", "MAIL-SPF-003"),
    ("SPF", "approaching the", "MAIL-SPF-004"),
    ("SPF", "has no 'all' mechanism", "MAIL-SPF-005"),
    ("SPF", "uses '+all'", "MAIL-SPF-006"),
    ("SPF", "uses '?all'", "MAIL-SPF-007"),
    ("SPF", "uses '~all'", "MAIL-SPF-008"),
    ("SPF", "uses '-all'", "MAIL-SPF-009"),
    ("SPF", "deprecated 'ptr' mechanism", "MAIL-SPF-010"),
    ("SPF", "characters long, exceeding", "MAIL-SPF-011"),
    ("DMARC", "could not be verified", "MAIL-DMARC-005"),
    ("DMARC", "policy is inherited", "MAIL-DMARC-006"),
    ("DMARC", "policy is 'quarantine'", "MAIL-DMARC-007"),
    ("DMARC", "policy is 'reject'", "MAIL-DMARC-008"),
    ("DMARC", "no subdomain policy", "MAIL-DMARC-009"),
    ("DKIM", "checks were inconclusive", "MAIL-DKIM-001"),
    ("DKIM", "could not be fully verified", "MAIL-DKIM-002"),
    ("DKIM", "no dkim records detected", "MAIL-DKIM-003"),
    ("DKIM", "has an empty public key", "MAIL-DKIM-004"),
    ("DKIM", "is in testing mode", "MAIL-DKIM-005"),
    ("DKIM", "is configured for selector", "MAIL-DKIM-006"),
    ("DNSSEC", "could not be verified", "DNSSEC-002"),
    ("DNSSEC", "without usable digest data", "DNSSEC-003"),
    ("DNSSEC", "does not match", "DNSSEC-004"),
    ("DNSSEC", "none match the zone", "DNSSEC-004"),
    ("DNSSEC", "without matching zone dnskey", "DNSSEC-005"),
    ("DNSSEC", "no ds delegation record", "DNSSEC-006"),
    ("DNSSEC", "not enabled", "DNSSEC-007"),
    ("DNSSEC", "ds record matches zone dnskey", "DNSSEC-008"),
    ("TAKEOVER", "potential dangling cname", "TAKEOVER-002"),
    ("TAKEOVER", "unclaimed-service response fingerprint matched", "TAKEOVER-003"),
    ("TAKEOVER", "could not be verified", "TAKEOVER-004"),
    ("AXFR", "allowed an unauthenticated zone transfer", "DNS-AXFR-002"),
    ("WILDCARD DNS", "random hostname resolved", "DNS-WILDCARD-002"),
    ("WILDCARD DNS", "could not be evaluated", "DNS-WILDCARD-003"),
    ("NS CONSISTENCY", "could not obtain both soa and ns answers", "DNS-NSCONS-001"),
    ("NS CONSISTENCY", "different soa serial numbers", "DNS-NSCONS-002"),
    ("NS CONSISTENCY", "disagree on soa mname", "DNS-NSCONS-003"),
    ("NS CONSISTENCY", "different ns record sets", "DNS-NSCONS-004"),
    ("MTA-STS", "no mta-sts dns record", "MAIL-MTASTS-002"),
    ("MTA-STS", "policy file status is valid (mode=enforce)", "MAIL-MTASTS-001"),
    ("MTA-STS", "policy file status is valid", "MAIL-MTASTS-003"),
    ("MTA-STS", "policy file status is invalid", "MAIL-MTASTS-004"),
    ("MTA-STS", "policy file status is unavailable", "MAIL-MTASTS-006"),
    ("MTA-STS", "could not be verified", "MAIL-MTASTS-005"),
    ("TLS-RPT", "configured with", "MAIL-TLSRPT-001"),
    ("TLS-RPT", "no tls-rpt reporting record", "MAIL-TLSRPT-002"),
    ("TLS-RPT", "could not be verified", "MAIL-TLSRPT-003"),
    ("BIMI", "could not be verified", "MAIL-BIMI-001"),
    ("BIMI", "not configured", "MAIL-BIMI-004"),
    ("BIMI", "missing the required svg logo", "MAIL-BIMI-002"),
    ("BIMI", "record found, but dmarc policy", "MAIL-BIMI-003"),
    ("BIMI", "bimi is active", "MAIL-BIMI-005"),
    ("INVENTORY", "stream reached", "RECON-CT-002"),
    ("INVENTORY", "response exceeded", "RECON-CT-003"),
    ("INVENTORY", "could not be parsed", "RECON-CT-004"),
    ("INVENTORY", "returned http", "RECON-CT-005"),
    ("INVENTORY", "lookup failed", "RECON-CT-006"),
    ("INVENTORY", "limited to", "RECON-CT-007"),
    ("INVENTORY", "dns resolution was inconclusive", "RECON-CT-008"),
    ("SUBDOMAINS", "dangling cname pointers", "RECON-SUB-002"),
    ("SUBDOMAIN TAKEOVER", "ct inventory found", "TAKEOVER-005"),
    ("TLS", "ssrf safety guard", "WEB-TLS-001"),
    ("TLS", "encountered an error", "WEB-TLS-002"),
    ("TLS", "certificate verification failed", "WEB-TLS-003"),
    ("TLS", "was inconclusive", "WEB-TLS-007"),
    ("TLS", "certificate for", "WEB-TLS-004"),
    ("TLS", "certificate expires soon", "WEB-TLS-005"),
    ("TLS", "certificate is valid", "WEB-TLS-008"),
    ("TLS", "san mismatch", "WEB-TLS-006"),
    ("TLS", "modern encryption protocol", "WEB-TLS-009"),
    ("TLS", "legacy or deprecated tls protocol", "WEB-TLS-010"),
    ("HTTPS", "ssrf alert", "WEB-HTTPS-001"),
    ("HTTPS", "automatically redirects to https", "WEB-HTTPS-003"),
    ("HTTPS", "does not redirect to https", "WEB-HTTPS-002"),
    ("HTTPS", "redirect check was inconclusive", "WEB-HTTPS-004"),
    ("CSP", "common weaknesses", "WEB-CSP-001"),
    ("CSP", "is present; common", "WEB-CSP-003"),
    ("COOKIE", "observed cookie(s) miss", "WEB-COOKIE-001"),
    ("HTTPS", "security header inspection on port", "WEB-HEADERS-001"),
    ("HTTP METHODS", "advertises potentially sensitive", "WEB-METHODS-001"),
    ("SECURITY.TXT", "security.txt is missing", "WEB-SECURITYTXT-001"),
    ("SECURITY.TXT", "security.txt is malformed", "WEB-SECURITYTXT-002"),
    ("SECURITY.TXT", "security.txt is expired", "WEB-SECURITYTXT-003"),
    ("HTTPS", "additional browser isolation headers", "WEB-HEADERS-002"),
    ("HTTPS", "port 80 http", "WEB-HTTPS-005"),
    ("SPF LOOKUP COUNT", "check could not complete", "SCAN-SPF-001"),
    ("SPF FLATTENING", "check could not complete", "SCAN-SPF-002"),
    ("DNSSEC", "check could not complete", "SCAN-DNSSEC-001"),
    ("TAKEOVER", "check could not complete", "SCAN-TAKEOVER-001"),
    ("TLS", "check could not complete", "SCAN-TLS-001"),
    ("SUBDOMAINS", "check could not complete", "SCAN-SUBDOMAINS-001"),
    ("MAIL TRANSPORT", "check could not complete", "SCAN-MAIL-001"),
    ("AXFR", "check could not complete", "SCAN-AXFR-001"),
    ("WILDCARD DNS", "check could not complete", "SCAN-WILDCARD-001"),
    ("NS CONSISTENCY", "check could not complete", "SCAN-NSCONS-001"),
    ("DMARC", "check could not complete", "SCAN-DMARC-001"),
    ("DKIM", "check could not complete", "SCAN-DKIM-001"),
    ("BIMI", "check could not complete", "SCAN-BIMI-001"),
    ("HTTPS", "hsts is active", "WEB-HSTS-001"),
    ("HTTPS", "content-security-policy (csp) header is not published", "WEB-CSP-002"),
    ("HTTPS", "hsts header is missing", "WEB-HSTS-002"),
)

_LEGACY_CODE_BY_CONDITION = {
    (record_type, code): _CATALOG.get(record_type, {"code": "GEN-001"})["code"]
    for record_type, _marker, code in _CONDITION_CODES
}
_LEGACY_CODE_BY_CONDITION.update({("DMARC", code): _CATALOG["DMARC"]["code"] for _marker, code, *_ in _DMARC_RULES})
_logger = logging.getLogger(__name__)


def legacy_codes_for(guidance: dict[str, str], record_type: str | None = None) -> list[str]:
    """Return broad pre-condition codes as migration aliases when applicable."""
    code = guidance.get("code", "")
    legacy = _LEGACY_CODE_BY_CONDITION.get((str(record_type or "").upper(), code))
    return [legacy] if legacy and legacy != code else []


def get_finding_guidance(record_type: str, message: str = "") -> dict[str, str]:
    """Return a copy so callers cannot mutate the shared catalog."""
    key = str(record_type or "").strip().upper()
    normalized_message = str(message or "").lower()
    if key == "DMARC":
        for marker, code, title, fix, reference in _DMARC_RULES:
            if marker in normalized_message:
                return {
                    "code": code,
                    "title": title,
                    "why": "DMARC helps receiving mail systems identify messages that fail domain alignment.",
                    "attacker": "Weak or absent enforcement can leave more room for messages impersonating your domain.",
                    "fix": fix,
                    "technical": "Verify the authoritative _dmarc TXT answer and confirm changes after DNS caches expire.",
                    "reference": reference,
                }
    for record_type, marker, code in _CONDITION_CODES:
        if key == record_type and marker in normalized_message:
            entry = dict(_CATALOG.get(key, _CATALOG["GENERAL"]))
            entry["code"] = code
            return entry
    if key in _CATALOG:
        return dict(_CATALOG[key])
    return {
        "code": "GEN-001",
        "title": f"{record_type or 'Security'} check",
        "why": "This check identified a condition that may need review.",
        "attacker": "The practical risk depends on the system configuration and exposure.",
        "fix": "Review the finding details and verify the configuration with the responsible service owner.",
        "technical": "The check could not be categorized in the finding catalog.",
        "reference": "—",
    }


def catalog_for_export() -> dict[str, dict[str, str]]:
    return {key: dict(value) for key, value in _CATALOG.items()}


def known_finding_codes() -> set[str]:
    """Every code that the shared Finding model is permitted to emit."""
    return {
        *(entry["code"] for entry in _CATALOG.values()),
        *(code for _marker, code, *_ in _DMARC_RULES),
        *(code for _record_type, _marker, code in _CONDITION_CODES),
        "GEN-001",
    }


def condition_catalog() -> list[dict[str, str]]:
    """Return condition-level rules with stable codes and broad legacy aliases."""
    rows = []
    for record_type, marker, code in _CONDITION_CODES:
        legacy = _LEGACY_CODE_BY_CONDITION.get((record_type, code), "")
        rows.append({"module": record_type, "condition": marker, "code": code, "legacy_alias": legacy})
    for marker, code, _title, _fix, _reference in _DMARC_RULES:
        rows.append({"module": "DMARC", "condition": marker, "code": code, "legacy_alias": _CATALOG["DMARC"]["code"]})
    return rows


def render_condition_catalog_markdown() -> str:
    """Render the checked-in condition table directly from the runtime catalog."""
    lines = [
        "# Finding condition codes", "",
        "Each row is a condition rule used to assign a finding code. Legacy alias is the earlier broad record-type code retained for existing consumers; `—` means no earlier distinct code existed.", "",
        "| Module/type | Condition marker | Stable code | Legacy alias |",
        "|---|---|---|---|",
    ]
    for row in condition_catalog():
        lines.append("| {} | `{}` | `{}` | `{}` |".format(
            row["module"], row["condition"], row["code"], row["legacy_alias"] or "—",
        ))
    rows = condition_catalog()
    primary_codes = {row["code"] for row in rows} | {"GEN-001"}
    alias_codes = {row["legacy_alias"] for row in rows if row["legacy_alias"]}
    alias_only = sorted(alias_codes - primary_codes)
    lines.extend(["", "## Alias-only codes", "", "These broad compatibility codes are not emitted as the primary `code`; matching findings retain them in `legacy_codes`."])
    lines.append(", ".join(f"`{code}`" for code in alias_only) if alias_only else "None.")
    reserved = sorted({entry["code"] for entry in _CATALOG.values()} - primary_codes - alias_codes)
    lines.extend(["", "## Reserved codes", ""])
    if reserved:
        lines.extend(f"- `{code}` — reserved; not currently emitted as a primary or legacy code." for code in reserved)
    else:
        lines.append("None. Every catalog code is used as a primary code or a legacy alias.")
    return "\n".join(lines) + "\n"
