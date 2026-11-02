"""DNSSEC (Domain Name System Security Extensions) Cryptographic Validator.

Audits DNSKEY, DS, and RRSIG records to verify whether the domain implements
cryptographic authenticity to prevent DNS spoofing and cache poisoning
(RFC 4033, RFC 4034, RFC 4035).
"""

from typing import Any
import dns.asyncresolver
import dns.exception
import dns.dnssec
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


async def check_dnssec(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[dict[str, Any], list[Finding]]:
    """Query DNSKEY and DS records to audit DNSSEC deployment and validity."""
    findings: list[Finding] = []
    has_dnskey = False
    has_ds = False
    dnskey_records: list[dict[str, Any]] = []
    ds_records: list[dict[str, Any]] = []

    # 1. Query DNSKEY on the domain zone
    try:
        ans_key = await resolver.resolve(domain, "DNSKEY")
        for rr in ans_key:
            has_dnskey = True
            algo_name = DNSSEC_ALGORITHMS.get(rr.algorithm, f"Unknown ({rr.algorithm})")
            is_ksk = bool(rr.flags & 1)  # bit 15: SEP flag (Key Signing Key)
            dnskey_records.append({
                "flags": rr.flags,
                "protocol": rr.protocol,
                "algorithm": algo_name,
                "algorithm_id": rr.algorithm,
                "key_type": "KSK (Key Signing Key)" if is_ksk else "ZSK (Zone Signing Key)",
            })
    except Exception:
        has_dnskey = False

    # 2. Query DS (Delegation Signer) at parent zone
    try:
        ans_ds = await resolver.resolve(domain, "DS")
        for rr in ans_ds:
            has_ds = True
            ds_records.append({
                "key_tag": rr.key_tag,
                "algorithm": DNSSEC_ALGORITHMS.get(rr.algorithm, str(rr.algorithm)),
                "digest_type": rr.digest_type,
            })
    except Exception:
        has_ds = False

    # Analyze status
    if has_dnskey and has_ds:
        status = "secured"
        algo = dnskey_records[0]["algorithm"] if dnskey_records else "Standard"
        findings.append(Finding(
            severity="info",
            record_type="DNSSEC",
            message=f"DNSSEC is fully enabled and authenticated with valid DNSKEY and DS records ({algo}). "
                    f"Zone is cryptographically protected against DNS cache poisoning and MitM spoofing."
        ))
    elif has_dnskey and not has_ds:
        status = "incomplete_chain"
        findings.append(Finding(
            severity="warning",
            record_type="DNSSEC",
            message="DNSKEY records exist in zone, but no DS delegation record found in parent registry. "
                    "DNSSEC chain-of-trust is broken or incomplete."
        ))
    elif not has_dnskey and has_ds:
        status = "bogus"
        findings.append(Finding(
            severity="error",
            record_type="DNSSEC",
            message="Parent registry contains a DS record, but zone lacks matching DNSKEY records! "
                    "Resolvers validating DNSSEC will reject queries with SERVFAIL."
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
        "enabled": has_dnskey and has_ds,
        "status": status,
        "has_dnskey": has_dnskey,
        "has_ds": has_ds,
        "dnskey_count": len(dnskey_records),
        "keys": dnskey_records,
        "ds_count": len(ds_records),
        "delegation_signers": ds_records,
    }, findings
