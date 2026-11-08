"""DNSSEC cryptographic chain validation using IANA trust anchors."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver

from app.models import Finding
from app.work_budget import ScanBudgetExhausted

ANCHOR_PATH = Path(__file__).parent / "data" / "root_trust_anchors.json"
CLOCK_SKEW = timedelta(minutes=5)
SIGNATURE_WARNING = timedelta(days=7)
NSEC3_MAX_ITERATIONS = 150
SUPPORTED_ALGORITHMS = {8, 10, 13, 14, 15}
DEPRECATED_ALGORITHMS = {3, 5, 6, 7}
ALGORITHM_NAMES = {3: "DSA/SHA-1", 5: "RSA/SHA-1", 7: "RSA/SHA-1-NSEC3", 8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA P-256", 14: "ECDSA P-384", 15: "Ed25519"}


class AnchorFileError(ValueError):
    pass


def load_root_trust_anchors(path: Path = ANCHOR_PATH, now: datetime | None = None) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("anchors"), list):
            raise ValueError("expected object with anchors list")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        usable = []
        for item in data["anchors"]:
            if not isinstance(item, dict):
                raise ValueError("anchor entry must be an object")
            start = datetime.fromisoformat(item["validFrom"].replace("Z", "+00:00"))
            end_text = item.get("validUntil")
            end = datetime.fromisoformat(end_text.replace("Z", "+00:00")) if end_text else None
            for field in ("key_tag", "algorithm", "digest_type", "digest"):
                if field not in item:
                    raise ValueError(f"anchor missing {field}")
            if item.get("revoked") or start > current or (end and end <= current):
                continue
            usable.append(item)
        if not usable:
            raise AnchorFileError("No currently valid, non-revoked DNSSEC root trust anchors remain")
        return usable
    except AnchorFileError:
        raise
    except Exception as exc:
        raise AnchorFileError(f"Malformed DNSSEC root trust anchor file: {exc}") from exc


def _rrset(answer: Any, qname: dns.name.Name, rdtype: int) -> tuple[Any, Any]:
    response = getattr(answer, "response", None)
    if response is None:
        return getattr(answer, "rrset", None), None
    if response.flags & dns.flags.TC:
        raise dns.exception.FormError("truncated response")
    found = sigs = None
    for section in (response.answer, response.authority):
        for entry in section:
            if entry.name == qname and entry.rdtype == rdtype:
                found = entry
            elif entry.name == qname and entry.rdtype == dns.rdatatype.RRSIG and entry.covers() == rdtype:
                sigs = entry
    return found, sigs


def _validity(sigs: Any, now: datetime) -> tuple[bool, datetime | None, datetime | None, str | None]:
    if not sigs:
        return False, None, None, "missing_rrsig"
    inception = min(sig.inception for sig in sigs)
    expiration = max(sig.expiration for sig in sigs)
    start = datetime.fromtimestamp(inception, timezone.utc)
    end = datetime.fromtimestamp(expiration, timezone.utc)
    if now + CLOCK_SKEW < start:
        return False, start, end, "signature_not_yet_valid"
    if now - CLOCK_SKEW > end:
        return False, start, end, "signature_expired"
    return True, start, end, None


def _validate(rrset: Any, sigs: Any, keys: Any, owner: dns.name.Name, now: datetime) -> tuple[str, str | None, datetime | None, datetime | None]:
    valid, start, end, reason = _validity(sigs, now)
    if not valid:
        return ("inconclusive" if reason == "missing_rrsig" else "bogus"), reason, start, end
    for sig in sigs:
        if sig.algorithm not in SUPPORTED_ALGORITHMS | DEPRECATED_ALGORITHMS:
            return "inconclusive", "unsupported_algorithm", start, end
    try:
        dns.dnssec.validate(rrset, sigs, {owner: keys}, now=now.timestamp())
        return "secure", None, start, end
    except (dns.dnssec.UnsupportedAlgorithm, NotImplementedError):
        return "inconclusive", "unsupported_algorithm", start, end
    except Exception:
        return "bogus", "signature_validation_failed", start, end


async def _resolve(resolver: Any, name: dns.name.Name, kind: str) -> Any:
    try:
        return await resolver.resolve(name, kind, search=False, raise_on_no_answer=False, tcp=False)
    except TypeError as exc:
        if "keyword" not in str(exc):
            raise
        return await resolver.resolve(name, kind)


def _anchor_ds(anchors: list[dict[str, Any]]) -> list[Any]:
    return [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
            f"{a['key_tag']} {a['algorithm']} {a['digest_type']} {a['digest']}") for a in anchors]


async def check_dnssec(domain: str, resolver: dns.asyncresolver.Resolver, apex: str | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Keep established scan behavior until the signed-chain test matrix is complete."""
    if os.environ.get("ENABLE_DNSSEC_CHAIN_VALIDATION", "false").strip().lower() not in ("1", "true", "yes"):
        return await _legacy_delegation_check(domain, resolver, apex)
    legacy_result, _ = await _legacy_delegation_check(domain, resolver, apex)
    chain_result, chain_findings = await validate_dnssec_chain(domain, resolver, apex)
    # Retain the exact scoring input the default legacy path would have produced.
    # The opt-in chain result is returned as evidence but cannot affect scoring.
    chain_result["chain_status"] = chain_result["status"]
    chain_result["status"] = legacy_result["status"]
    chain_result["legacy_score_status"] = legacy_result["status"]
    return chain_result, chain_findings


async def _legacy_delegation_check(domain: str, resolver: Any, apex: str | None) -> tuple[dict[str, Any], list[Finding]]:
    qname = dns.name.from_text((apex or domain).rstrip("."))
    try:
        keys = await resolver.resolve(qname.to_text(omit_final_dot=True), "DNSKEY")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result = _base("unsigned", "no_dnskey")
        result["validator"] = "legacy"
        return result, [Finding(severity="info", record_type="DNSSEC", message="DNSSEC records were not found; legacy delegation check only.")]
    except Exception:
        result = _base("inconclusive", "legacy_lookup_failed")
        result["validator"] = "legacy"
        return result, [Finding(severity="info", record_type="DNSSEC", message="DNSSEC lookup failed; result is inconclusive.")]

    try:
        ds = await resolver.resolve(qname.to_text(omit_final_dot=True), "DS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result = _base("incomplete_chain", "dnskey_without_parent_ds")
        result.update({"validator": "legacy", "enabled": False, "has_dnskey": bool(keys), "has_ds": False,
                       "dnskey_count": len(keys), "ds_count": 0})
        return result, [Finding(severity="warning", record_type="DNSSEC", message="DNSKEY records are present, but the parent DS delegation record is missing (incomplete chain).")]
    except Exception:
        result = _base("inconclusive", "legacy_ds_lookup_failed")
        result.update({"validator": "legacy", "has_dnskey": bool(keys), "dnskey_count": len(keys)})
        return result, [Finding(severity="info", record_type="DNSSEC", message="DNSSEC DS lookup failed; result is inconclusive.")]

    matched_tag = None
    comparable = False
    supported_digest_types = {1, 2, 4}
    supported_algorithms = {3, 5, 6, 7, 8, 10, 13, 14, 15, 16}
    for key in keys:
        for record in ds:
            digest = getattr(record, "digest", None)
            digest_type = getattr(record, "digest_type", None)
            algorithm = getattr(record, "algorithm", None)
            if not digest or digest_type not in supported_digest_types or algorithm not in supported_algorithms:
                continue
            try:
                calculated = dns.dnssec.make_ds(qname, key, digest_type)
            except (dns.dnssec.UnsupportedAlgorithm, NotImplementedError, ValueError):
                continue
            except Exception:
                continue
            comparable = True
            if dns.dnssec.key_id(key) == record.key_tag and key.algorithm == algorithm and calculated.digest == digest:
                matched_tag = record.key_tag
                break
        if matched_tag is not None:
            break
    if matched_tag is not None:
        status, reason = "delegation_match_verified", None
    elif comparable:
        status, reason = "bogus", "ds_dnskey_mismatch"
    else:
        status, reason = "inconclusive", "ds_not_comparable"
    result = _base(status, reason)
    result.update({"validator": "legacy", "enabled": bool(matched_tag), "delegation_verified": bool(matched_tag), "has_dnskey": True, "has_ds": True,
                   "dnskey_count": len(keys), "ds_count": len(ds), "matching_key_tag": matched_tag})
    severity = "info" if matched_tag else "error" if status == "bogus" else "info"
    message = ("Legacy DNSSEC DS/DNSKEY delegation comparison; full chain validation is disabled." if matched_tag
               else "DNSSEC DS does not match a DNSKEY." if status == "bogus"
               else "DNSSEC DS data could not be compared; result is inconclusive.")
    return result, [Finding(severity=severity, record_type="DNSSEC", message=message)]


async def validate_dnssec_chain(domain: str, resolver: dns.asyncresolver.Resolver, apex: str | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Validate DNSKEY/DS/SOA signatures from root trust anchor to the zone; AD is ignored."""
    now = datetime.now(timezone.utc)
    if hasattr(resolver, "use_edns"):
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
    try:
        anchors = load_root_trust_anchors(now=now)
    except AnchorFileError:
        return _base("inconclusive", "trust_anchor_file_invalid"), [Finding(severity="info", record_type="DNSSEC", message="DNSSEC trust anchors are unavailable.")]
    zone = dns.name.from_text((apex or domain).rstrip(".").lower())
    labels = zone.labels[:-1]
    chain_zones = [dns.name.root] + [dns.name.Name(tuple(labels[index:]) + (b"",)) for index in range(len(labels) - 1, -1, -1)]
    chain = []
    parent_keys = None
    state, reason = "secure", None
    for index, current in enumerate(chain_zones):
        entry = {"zone": current.to_text(omit_final_dot=True) or ".", "key_tags": [], "ds_digests": [], "algorithms": [], "signature_inception": None, "signature_expiration": None, "result": "inconclusive", "reason_code": None}
        try:
            answer = await _resolve(resolver, current, "DNSKEY")
            keys, key_sigs = _rrset(answer, current, dns.rdatatype.DNSKEY)
            if not keys:
                if index:
                    entry.update(result="insecure", reason_code="ds_absent_denial_not_validated")
                    chain.append(entry)
                    state, reason = "insecure", "insecure (denial not validated)"
                else:
                    entry.update(reason_code="root_dnskey_absent")
                    chain.append(entry)
                    state, reason = "inconclusive", "root DNSKEY response unavailable"
                break
            entry["key_tags"] = [dns.dnssec.key_id(k) for k in keys]
            entry["algorithms"] = sorted({ALGORITHM_NAMES.get(k.algorithm, f"algorithm-{k.algorithm}") for k in keys})
            entry["deprecated_algorithms"] = sorted({k.algorithm for k in keys if k.algorithm in DEPRECATED_ALGORITHMS})
            if index == 0:
                ds_set = _anchor_ds(anchors)
                matches = any(dns.dnssec.key_id(k) == ds.key_tag and dns.dnssec.make_ds(current, k, ds.digest_type).digest == ds.digest for k in keys for ds in ds_set)
                if not matches:
                    entry.update(result="bogus", reason_code="root_anchor_mismatch")
                    chain.append(entry)
                    state, reason = "bogus", "root DNSKEY did not match a valid IANA anchor"
                    break
            else:
                ds_answer = await _resolve(resolver, current, "DS")
                ds_rrset, ds_sigs = _rrset(ds_answer, current, dns.rdatatype.DS)
                if not ds_rrset:
                    entry.update(result="insecure", reason_code="ds_absent_denial_not_validated")
                    chain.append(entry)
                    state, reason = "insecure", "insecure (denial not validated)"
                    break
                entry["ds_digests"] = [{"digest_type": ds.digest_type, "digest": ds.digest.hex().upper()} for ds in ds_rrset]
                checked = _validate(ds_rrset, ds_sigs, parent_keys, chain_zones[index - 1], now)
                if checked[0] != "secure":
                    entry.update(result=checked[0], reason_code=checked[1])
                    chain.append(entry)
                    state, reason = checked[0], checked[1]
                    break
                match = any(dns.dnssec.key_id(k) == ds.key_tag and dns.dnssec.make_ds(current, k, ds.digest_type).digest == ds.digest for k in keys for ds in ds_rrset)
                if not match:
                    entry.update(result="bogus", reason_code="ds_dnskey_mismatch")
                    chain.append(entry)
                    state, reason = "bogus", "DS did not match a child DNSKEY"
                    break
            checked = _validate(keys, key_sigs, keys, current, now)
            if checked[0] != "secure":
                entry.update(result=checked[0], reason_code=checked[1])
                chain.append(entry)
                state, reason = checked[0], checked[1]
                break
            entry.update(result="secure", signature_inception=checked[2].isoformat() if checked[2] else None, signature_expiration=checked[3].isoformat() if checked[3] else None)
            if checked[3] and checked[3] - now < SIGNATURE_WARNING:
                entry["signature_warning"] = "expires_within_7_days"
            if current == zone:
                soa_answer = await _resolve(resolver, current, "SOA")
                soa, soa_sigs = _rrset(soa_answer, current, dns.rdatatype.SOA)
                checked_soa = _validate(soa, soa_sigs, keys, current, now) if soa else ("inconclusive", "soa_missing", None, None)
                if checked_soa[0] != "secure":
                    entry.update(result=checked_soa[0], reason_code=checked_soa[1])
                    chain.append(entry)
                    state, reason = checked_soa[0], checked_soa[1]
                    break
            chain.append(entry)
            parent_keys = keys
        except ScanBudgetExhausted:
            entry.update(reason_code="budget_exhausted")
            chain.append(entry)
            state, reason = "inconclusive", "DNSSEC reserved query budget exhausted"
            break
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.FormError):
            entry.update(reason_code="dns_response_unavailable")
            chain.append(entry)
            state, reason = "inconclusive", "DNS response unavailable or truncated after TCP retry"
            break
        except Exception:
            entry.update(reason_code="validation_incomplete")
            chain.append(entry)
            state, reason = "inconclusive", "DNSSEC validation could not be completed"
            break
    verified = state == "secure" and len(chain) == len(chain_zones)
    result = _base(state, reason)
    result["validator"] = "chain"
    result.update({"enabled": state in ("secure", "bogus"), "delegation_verified": verified, "cryptographically_verified": verified, "chain": chain,
                   "has_dnskey": bool(chain and chain[-1]["key_tags"]), "has_ds": bool(len(chain) > 1 and chain[-1]["ds_digests"]),
                   "dnskey_count": len(chain[-1]["key_tags"]) if chain else 0, "ds_count": len(chain[-1]["ds_digests"]) if chain else 0,
                   "keys": [{"key_tag": k, "algorithm": a} for k, a in zip(chain[-1]["key_tags"], chain[-1]["algorithms"])] if chain else [],
                   "delegation_signers": chain[-1]["ds_digests"] if chain else [], "matching_key_tag": chain[-1]["key_tags"][0] if verified and chain[-1]["key_tags"] else None,
                   "nsec": {"type": None, "nsec3_opt_out": None, "iteration_limit": NSEC3_MAX_ITERATIONS, "denial_validated": False}})
    severity, message = (("info", "DNSSEC chain validated from the IANA root trust anchor to the zone.") if state == "secure" else ("error", f"DNSSEC validation failed: {reason}.") if state == "bogus" else ("warning", f"DNSSEC is {reason}.") if state == "insecure" else ("info", "DNSSEC validation is inconclusive; this does not prove the zone is bogus or unsigned."))
    findings = [Finding(severity=severity, record_type="DNSSEC", message=message)]
    for node in chain:
        if node.get("signature_warning"):
            findings.append(Finding(severity="warning", record_type="DNSSEC", message=f"DNSSEC signature for {node['zone']} expires within 7 days."))
    return result, findings


def _base(status: str, reason: str | None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "enabled": False, "delegation_verified": False, "cryptographically_verified": False, "has_dnskey": False, "has_ds": False, "dnskey_count": 0, "ds_count": 0, "keys": [], "delegation_signers": [], "chain": []}
