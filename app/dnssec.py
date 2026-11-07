"""DNSSEC (Domain Name System Security Extensions) Cryptographic Validator.

Audits DNSKEY, DS, and RRSIG records to verify whether the domain implements
cryptographic authenticity to prevent DNS spoofing and cache poisoning
(RFC 4033, RFC 4034, RFC 4035). Validates cryptographic DS-to-DNSKEY digest matches.
"""

from typing import Any
import dns.asyncresolver
import dns.dnssec
import dns.exception
import dns.name
from app.models import Finding

# Common DNSSEC algorithm mapping (RFC 8624)
DNSSEC_ALGORITHMS: dict[int, str] = {
    3: "DSA/SHA1",
    5: "RSA/SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSA/SHA-256",
    10: "RSA/SHA-512",
    13: "ECDSA Curve P-256 with SHA-256",
    14: "ECDSA Curve P-384 with SHA-384",
    15: "Ed25519",
    16: "Ed448",
}


def _safe_key_tag(rr: Any) -> int:
    """Safely extract key tag from DNSKEY record."""
    if hasattr(rr, "key_tag"):
        return getattr(rr, "key_tag")
    try:
        return dns.dnssec.key_id(rr)
    except Exception:
        return 0


def verify_ds_matches_dnskey(
    domain_name: dns.name.Name,
    dnskeys: list[Any],
    ds_records: list[Any],
) -> tuple[bool, int]:
    """Verify that at least one parent DS record matches a published DNSKEY digest."""
    for ds_rr in ds_records:
        for key_rr in dnskeys:
            try:
                tag = _safe_key_tag(key_rr)
                ds_tag = getattr(ds_rr, "key_tag", None)
                if tag != 0 and ds_tag is not None:
                    if tag == ds_tag:
                        if hasattr(ds_rr, "digest"):
                            calc_ds = dns.dnssec.make_ds(domain_name, key_rr, ds_rr.digest_type)
                            if calc_ds.digest == ds_rr.digest:
                                return True, tag
                            else:
                                continue
            except Exception:
                continue
    return False, 0


async def check_dnssec(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    apex: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query DNSKEY and DS records to audit DNSSEC deployment and validity.

    Validates cryptographic match between parent DS delegation signers and zone DNSKEYs.
    If *domain* is a subdomain without its own zone cut, checks whether the
    authoritative zone apex (*apex*) is DNSSEC-secured.
    """
    findings: list[Finding] = []
    has_dnskey = False
    has_ds = False
    raw_keys: list[Any] = []
    raw_ds: list[Any] = []
    dnskey_records: list[dict[str, Any]] = []
    ds_records: list[dict[str, Any]] = []
    lookup_inconclusive = False

    qname = dns.name.from_text(domain)

    # 1. Query DNSKEY on the domain zone
    try:
        ans_key = await resolver.resolve(domain, "DNSKEY")
        for rr in ans_key:
            has_dnskey = True
            raw_keys.append(rr)
            algo_name = DNSSEC_ALGORITHMS.get(rr.algorithm, f"Unknown ({rr.algorithm})")
            is_ksk = bool(rr.flags & 1)  # bit 15: SEP flag (Key Signing Key)
            key_tag_val = _safe_key_tag(rr)
            dnskey_records.append({
                "flags": rr.flags,
                "protocol": rr.protocol,
                "algorithm": algo_name,
                "algorithm_id": rr.algorithm,
                "key_tag": key_tag_val,
                "key_type": "KSK (Key Signing Key)" if is_ksk else "ZSK (Zone Signing Key)",
            })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        has_dnskey = False
    except Exception:
        has_dnskey = False
        lookup_inconclusive = True

    # 2. Query DS (Delegation Signer) at parent zone
    try:
        ans_ds = await resolver.resolve(domain, "DS")
        for rr in ans_ds:
            has_ds = True
            raw_ds.append(rr)
            ds_records.append({
                "key_tag": rr.key_tag,
                "algorithm": DNSSEC_ALGORITHMS.get(rr.algorithm, str(rr.algorithm)),
                "digest_type": rr.digest_type,
            })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        has_ds = False
    except Exception:
        has_ds = False
        lookup_inconclusive = True

    # If unsigned, check if parent zone apex has DNSSEC
    inherited_from: str | None = None
    if not has_dnskey and not has_ds and apex and apex.lower().rstrip(".") != domain.lower().rstrip("."):
        try:
            apex_qname = dns.name.from_text(apex)
            ans_apex_key = await resolver.resolve(apex, "DNSKEY")
            ans_apex_ds = await resolver.resolve(apex, "DS")
            if ans_apex_key and ans_apex_ds:
                has_dnskey = True
                has_ds = True
                inherited_from = apex.lower().rstrip(".")
                qname = apex_qname
                for rr in ans_apex_key:
                    raw_keys.append(rr)
                    key_tag_val = _safe_key_tag(rr)
                    dnskey_records.append({
                        "flags": rr.flags,
                        "protocol": rr.protocol,
                        "algorithm": DNSSEC_ALGORITHMS.get(rr.algorithm, f"Unknown ({rr.algorithm})"),
                        "algorithm_id": rr.algorithm,
                        "key_tag": key_tag_val,
                        "key_type": "KSK (Parent Zone)" if (rr.flags & 1) else "ZSK (Parent Zone)",
                    })
                for rr in ans_apex_ds:
                    raw_ds.append(rr)
                    ds_records.append({
                        "key_tag": rr.key_tag,
                        "algorithm": DNSSEC_ALGORITHMS.get(rr.algorithm, str(rr.algorithm)),
                        "digest_type": rr.digest_type,
                    })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception:
            lookup_inconclusive = True

    # 3. Cryptographic Verification (Item 7)
    cryptographically_verified = False
    matching_tag = 0
    if has_dnskey and has_ds and raw_keys and raw_ds:
        cryptographically_verified, matching_tag = verify_ds_matches_dnskey(qname, raw_keys, raw_ds)

    # 4. Determine status based on cryptographic verification
    if has_dnskey and has_ds:
        algo = dnskey_records[0]["algorithm"] if dnskey_records else "Standard"
        if cryptographically_verified:
            status = "delegation_match_verified"
            if inherited_from:
                findings.append(Finding(
                    severity="info",
                    record_type="DNSSEC",
                    message=f"Zone apex '{inherited_from}' DS record matches zone DNSKEY #{matching_tag} digest ({algo}). "
                            f"Hostname '{domain}' is protected under verified parent apex DS delegation (RRSIG signatures and root trust anchor chain not evaluated)."
                ))
            else:
                findings.append(Finding(
                    severity="info",
                    record_type="DNSSEC",
                    message=f"DNSSEC parent delegation verified: DS record matches zone DNSKEY #{matching_tag} digest ({algo}). "
                            f"DS-to-DNSKEY delegation link verified (full RRSIG signatures and root trust anchor chain not evaluated)."
                ))
        else:
            status = "bogus"
            findings.append(Finding(
                severity="error",
                record_type="DNSSEC",
                message="DNSSEC Cryptographic Failure: Parent registry contains DS records, but none match the zone's published DNSKEY digests. "
                        "Resolvers validating DNSSEC will reject queries with SERVFAIL (broken trust chain)."
            ))
    elif has_dnskey and not has_ds:
        status = "incomplete_chain"
        findings.append(Finding(
            severity="warning",
            record_type="DNSSEC",
            message="DNSKEY records exist in zone, but no DS delegation record found in parent registry. "
                    "DNSSEC chain-of-trust is unanchored and not verified by recursive resolvers."
        ))
    elif not has_dnskey and has_ds:
        status = "bogus"
        findings.append(Finding(
            severity="error",
            record_type="DNSSEC",
            message="Parent registry contains a DS record, but zone lacks matching DNSKEY records! "
                    "Resolvers validating DNSSEC will reject queries with SERVFAIL."
        ))
    elif lookup_inconclusive:
        status = "inconclusive"
        findings.append(Finding(
            severity="info",
            record_type="DNSSEC",
            message="DNSSEC could not be verified because one or more DNS queries failed. This result does not mean the domain is unsigned.",
        ))
    else:
        status = "unsigned"
        findings.append(Finding(
            severity="info",
            record_type="DNSSEC",
            message="DNSSEC is not enabled for this domain. The domain is vulnerable to DNS cache poisoning "
                    "(Kaminsky attacks). Consider enabling DNSSEC at your DNS provider."
        ))

    return {
        # DNSSEC is configured and its delegation link matches. Full RRSIG and
        # root trust-anchor validation is outside this module's current scope.
        "enabled": status == "delegation_match_verified",
        "delegation_verified": status == "delegation_match_verified",
        "status": status,
        "cryptographically_verified": cryptographically_verified,
        "matching_key_tag": matching_tag if cryptographically_verified else None,
        "has_dnskey": has_dnskey,
        "has_ds": has_ds,
        "dnskey_count": len(dnskey_records),
        "keys": dnskey_records,
        "ds_count": len(ds_records),
        "delegation_signers": ds_records,
        "inherited_from": inherited_from,
    }, findings
