"""DNSSEC cryptographic chain validation using IANA trust anchors."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any
import hashlib

import dns.asyncresolver
import dns.asyncquery
import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

from app.models import Finding
from app.work_budget import BudgetedResolver, ScanBudgetExhausted

ANCHOR_PATH = Path(__file__).parent / "data" / "root_trust_anchors.json"
CLOCK_SKEW = timedelta(minutes=5)
SIGNATURE_WARNING = timedelta(days=7)
NSEC3_MAX_ITERATIONS = 0
SUPPORTED_ALGORITHMS = {8, 10, 13, 14, 15}
DEPRECATED_ALGORITHMS = {3, 5, 6, 7}
ALGORITHM_NAMES = {3: "DSA/SHA-1", 5: "RSA/SHA-1", 7: "RSA/SHA-1-NSEC3", 8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA P-256", 14: "ECDSA P-384", 15: "Ed25519"}


class AnchorFileError(ValueError):
    pass


# Only validated RRsets are retained. Expiration is bounded by both the RRset
# TTL and its RRSIG expiration. The resolver identity prevents test resolvers or
# separately configured recursive resolvers from sharing answers accidentally.
_VALIDATED_RRSET_CACHE: dict[tuple[int, str, int, str], tuple[float, Any]] = {}
_LAST_ANCHOR_ID: str | None = None


def reload_root_trust_anchors(path: Path = ANCHOR_PATH, now: datetime | None = None) -> list[dict[str, Any]]:
    """Reload trust anchors and invalidate every cached DNSSEC RRset."""
    anchors = load_root_trust_anchors(path, now)
    _VALIDATED_RRSET_CACHE.clear()
    return anchors


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
            elif entry.name == qname and entry.rdtype == dns.rdatatype.RRSIG:
                covers = entry.covers() if callable(entry.covers) else entry.covers
                if covers == rdtype:
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
        dns.dnssec.validate(rrset, sigs, {owner: keys}, now=now.timestamp(), policy=dns.dnssec.allow_all_policy)
        return "secure", None, start, end
    except (dns.dnssec.UnsupportedAlgorithm, NotImplementedError):
        return "inconclusive", "unsupported_algorithm", start, end
    except Exception:
        return "bogus", "signature_validation_failed", start, end


async def _resolve(resolver: Any, name: dns.name.Name, kind: str) -> Any:
    budget = resolver.budget if isinstance(resolver, BudgetedResolver) else None
    module = resolver.module if isinstance(resolver, BudgetedResolver) else "dnssec"
    base = resolver._resolver if isinstance(resolver, BudgetedResolver) else resolver
    # dnspython's Resolver may hide its UDP-to-TCP retry inside one resolve()
    # call. For standard DNS-over-UDP recursive resolvers, issue packets here so
    # the shared budget accounts for both attempts. Other resolver transports
    # retain their own safe/custom resolve implementation.
    if isinstance(base, dns.asyncresolver.Resolver) and base.nameservers and all(isinstance(ns, str) or (hasattr(ns, "address") and hasattr(ns, "port")) for ns in base.nameservers):
        request = dns.message.make_query(name, kind, use_edns=0, want_dnssec=True)
        request.flags |= dns.flags.CD
        last_error: Exception | None = None
        for nameserver in base.nameservers:
            address = getattr(nameserver, "address", str(nameserver))
            port = getattr(nameserver, "port", base.port)
            try:
                if budget and not await budget.reserve_dns(module):
                    raise ScanBudgetExhausted(f"{module} DNS query budget exhausted")
                response = await dns.asyncquery.udp(request, address, timeout=base.timeout, port=port, raise_on_truncation=False)
                if response.flags & dns.flags.TC:
                    if budget and not await budget.reserve_dns(module):
                        raise ScanBudgetExhausted(f"{module} DNS query budget exhausted before TCP fallback")
                    response = await dns.asyncquery.tcp(request, address, timeout=base.timeout, port=port)
                    if response.flags & dns.flags.TC:
                        raise dns.exception.FormError("truncated TCP response")
                rcode = response.rcode()
                if rcode == dns.rcode.SERVFAIL:
                    last_error = dns.resolver.NoNameservers
                    continue
                if rcode == dns.rcode.NXDOMAIN:
                    raise dns.resolver.NXDOMAIN(qnames=[name], responses={name: response})
                if rcode != dns.rcode.NOERROR:
                    last_error = dns.resolver.NoNameservers
                    continue
                return type("DNSSECAnswer", (), {"rrset": next((rr for rr in response.answer if rr.name == name and rr.rdtype == dns.rdatatype.from_text(kind)), None), "response": response})()
            except (dns.exception.Timeout, OSError) as exc:
                last_error = exc
                continue
        if last_error:
            raise last_error
        raise dns.resolver.NoNameservers
    try:
        answer = await resolver.resolve(name, kind, search=False, raise_on_no_answer=False, tcp=False)
    except TypeError as exc:
        if "keyword" not in str(exc):
            raise
        answer = await resolver.resolve(name, kind)
    response = getattr(answer, "response", None)
    if response is not None and response.flags & dns.flags.TC:
        # Make TCP retry explicit so the shared BudgetedResolver charges both
        # outbound DNS requests. A still-truncated TCP response is inconclusive.
        return await resolver.resolve(name, kind, search=False, raise_on_no_answer=False, tcp=True)
    return answer


def _isolated_resolver(resolver: Any) -> Any:
    """Clone dnspython resolver settings so DO/CD do not affect parallel modules."""
    budget = resolver.budget if isinstance(resolver, BudgetedResolver) else None
    module = resolver.module if isinstance(resolver, BudgetedResolver) else "dnssec"
    base = resolver
    while isinstance(base, BudgetedResolver):
        base = base._resolver
    if not isinstance(base, dns.asyncresolver.Resolver):
        return resolver
    isolated = dns.asyncresolver.Resolver(configure=False)
    for attribute in ("nameservers", "port", "timeout", "lifetime", "retry_servfail", "ndots", "search", "use_search_by_default", "rotate"):
        if hasattr(base, attribute):
            value = getattr(base, attribute)
            setattr(isolated, attribute, list(value) if attribute in {"nameservers", "search"} else value)
    return budget.resolver_for(isolated, module) if budget else isolated


def _cache_key(resolver: Any, name: dns.name.Name, kind: int, anchor_id: str) -> tuple[int, str, int, str]:
    base = resolver
    while hasattr(base, "_resolver"):
        base = base._resolver
    nameservers = getattr(base, "nameservers", None)
    if nameservers:
        endpoint_ids = tuple(
            (getattr(server, "address", str(server)), getattr(server, "port", 53))
            for server in nameservers
        )
        resolver_id = int.from_bytes(hashlib.sha256(repr(endpoint_ids).encode()).digest()[:8], "big")
    else:
        resolver_id = id(base)
    return resolver_id, name.to_text().lower(), kind, anchor_id


def _cache_validated_answer(key: tuple[int, str, int, str], answer: Any, now: datetime) -> None:
    rrset, sigs = _rrset(answer, dns.name.from_text(key[1]), key[2])
    if rrset is None or not sigs:
        return
    ttl_expiry = now.timestamp() + max(0, int(getattr(rrset, "ttl", 0)))
    signature_expiry = min(sig.expiration for sig in sigs)
    expiry = min(ttl_expiry, float(signature_expiry))
    if expiry > now.timestamp():
        _VALIDATED_RRSET_CACHE[key] = (expiry, answer)


async def _resolve_chain_rrset(
    resolver: Any, name: dns.name.Name, kind: int, now: datetime, anchor_id: str,
) -> tuple[Any, tuple[int, str, int, str]]:
    key = _cache_key(resolver, name, kind, anchor_id)
    cached = _VALIDATED_RRSET_CACHE.get(key)
    if cached:
        expires, answer = cached
        if expires > now.timestamp():
            return answer, key
        _VALIDATED_RRSET_CACHE.pop(key, None)
    return await _resolve(resolver, name, dns.rdatatype.to_text(kind)), key


def _matching_ds_keys(zone: dns.name.Name, keys: Any, ds_rrset: Any) -> tuple[list[Any], bool]:
    """Return keys matched by a DS and whether any DS/key pair was comparable."""
    matched: list[Any] = []
    comparable = False
    for key in keys:
        for ds in ds_rrset:
            if ds.algorithm not in SUPPORTED_ALGORITHMS | DEPRECATED_ALGORITHMS:
                continue
            if ds.digest_type not in {1, 2, 4}:
                continue
            try:
                calculated = dns.dnssec.make_ds(zone, key, ds.digest_type, policy=dns.dnssec.allow_all_policy)
            except (dns.dnssec.UnsupportedAlgorithm, NotImplementedError, ValueError):
                continue
            comparable = True
            if dns.dnssec.key_id(key) == ds.key_tag and key.algorithm == ds.algorithm and calculated.digest == ds.digest:
                if key not in matched:
                    matched.append(key)
    return matched, comparable


def _nsec_metadata(answer: Any) -> dict[str, Any]:
    response = getattr(answer, "response", None)
    observed = []
    opt_out = False
    iterations = None
    if response is not None:
        for rrset in (*response.answer, *response.authority):
            if rrset.rdtype == dns.rdatatype.NSEC:
                observed.append("NSEC")
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                observed.append("NSEC3")
                opt_out = opt_out or any(bool(getattr(record, "flags", 0) & 1) for record in rrset)
                iterations = max((getattr(record, "iterations", 0) for record in rrset), default=iterations)
            elif rrset.rdtype == dns.rdatatype.NSEC3PARAM:
                observed.append("NSEC3")
                iterations = max((getattr(record, "iterations", 0) for record in rrset), default=iterations)
    return {"type": "+".join(dict.fromkeys(observed)) or None, "nsec3_opt_out": opt_out if "NSEC3" in observed else None,
            "iterations": iterations}


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


async def validate_dnssec_chain(
    domain: str, resolver: dns.asyncresolver.Resolver, apex: str | None = None, *,
    trust_anchors: list[dict[str, Any]] | None = None, now: datetime | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Validate DNSKEY/DS/SOA signatures from root to zone; AD is never trusted.

    DNS questions use the configured recursive resolver and request DNSSEC data
    (DO) with checking disabled (CD). The validator independently checks signed
    RRsets against the local IANA trust anchors.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    try:
        anchors = trust_anchors if trust_anchors is not None else load_root_trust_anchors(now=now)
        if not anchors:
            raise AnchorFileError("No trust anchors provided")
    except AnchorFileError:
        return _base("inconclusive", "trust_anchor_file_invalid"), [Finding(severity="info", record_type="DNSSEC", message="DNSSEC trust anchors are unavailable.")]
    resolver = _isolated_resolver(resolver)
    # Resolver.flags is the DNS header flags field; use_edns receives only EDNS
    # flags. Preserve the configured resolver and make DO/CD explicit on every
    # DNSSEC query. The CD bit is intentionally not treated as validation proof.
    if hasattr(resolver, "use_edns"):
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
    if hasattr(resolver, "flags"):
        resolver.flags |= dns.flags.CD
    zone = dns.name.from_text((apex or domain).rstrip(".").lower())
    labels = zone.labels[:-1]
    chain_zones = [dns.name.root] + [dns.name.Name(tuple(labels[index:]) + (b"",)) for index in range(len(labels) - 1, -1, -1)]
    anchor_id = hashlib.sha256(json.dumps(anchors, sort_keys=True, default=str).encode()).hexdigest()
    global _LAST_ANCHOR_ID
    if _LAST_ANCHOR_ID is not None and _LAST_ANCHOR_ID != anchor_id:
        _VALIDATED_RRSET_CACHE.clear()
    _LAST_ANCHOR_ID = anchor_id
    chain: list[dict[str, Any]] = []
    parent_keys = None
    parent_state = "secure"
    state, reason = "secure", None
    all_findings: list[Finding] = []
    for index, current in enumerate(chain_zones):
        entry = {"zone": current.to_text(omit_final_dot=True) or ".", "key_tags": [], "ds_digests": [], "algorithms": [], "signature_inception": None, "signature_expiration": None, "result": "inconclusive", "reason_code": None}
        try:
            if index and parent_state == "insecure":
                entry.update(result="insecure", reason_code="parent_zone_insecure")
                chain.append(entry)
                state, reason = "insecure", "parent zone is insecure"
                break
            # Decide the delegation from the parent response before requesting
            # child DNSKEY data. An absent DS is not authenticated here.
            ds_key = None
            ds_answer = None
            if index:
                ds_answer, ds_key = await _resolve_chain_rrset(resolver, current, dns.rdatatype.DS, now, anchor_id)
                ds_rrset, ds_sigs = _rrset(ds_answer, current, dns.rdatatype.DS)
                if not ds_rrset:
                    entry.update(result="inconclusive", reason_code="ds_absent_denial_not_validated")
                    chain.append(entry)
                    state, reason = "inconclusive", "DS absence could not be authenticated"
                    break
                entry["ds_digests"] = [{"digest_type": ds.digest_type, "digest": ds.digest.hex().upper()} for ds in ds_rrset]
                if any(ds.digest_type == 1 for ds in ds_rrset):
                    all_findings.append(Finding(severity="warning", record_type="DNSSEC", message="DNSSEC uses a SHA-1 DS digest type."))
                checked_ds = _validate(ds_rrset, ds_sigs, parent_keys, chain_zones[index - 1], now)
                if checked_ds[0] != "secure":
                    entry.update(result=checked_ds[0], reason_code=checked_ds[1])
                    chain.append(entry)
                    state, reason = checked_ds[0], checked_ds[1]
                    break
                _cache_validated_answer(ds_key, ds_answer, now)

            key_answer, key_cache_key = await _resolve_chain_rrset(resolver, current, dns.rdatatype.DNSKEY, now, anchor_id)
            keys, key_sigs = _rrset(key_answer, current, dns.rdatatype.DNSKEY)
            if not keys:
                result = "bogus" if index and ds_answer is not None else "inconclusive"
                code = "dnskey_missing_for_validated_ds" if result == "bogus" else "root_dnskey_absent"
                entry.update(result=result, reason_code=code)
                chain.append(entry)
                state, reason = result, code
                break
            entry["key_tags"] = [dns.dnssec.key_id(k) for k in keys]
            entry["algorithms"] = sorted({ALGORITHM_NAMES.get(k.algorithm, f"algorithm-{k.algorithm}") for k in keys})
            deprecated = sorted({k.algorithm for k in keys if k.algorithm in DEPRECATED_ALGORITHMS})
            entry["deprecated_algorithms"] = deprecated
            if deprecated:
                all_findings.append(Finding(severity="warning", record_type="DNSSEC", message="DNSSEC uses a deprecated algorithm."))
            if any(k.algorithm not in SUPPORTED_ALGORITHMS | DEPRECATED_ALGORITHMS for k in keys):
                entry.update(result="inconclusive", reason_code="unsupported_algorithm")
                chain.append(entry)
                state, reason = "inconclusive", "unsupported DNSSEC algorithm"
                break
            if index == 0:
                anchor_ds = _anchor_ds(anchors)
                matched, comparable = _matching_ds_keys(current, keys, anchor_ds)
                if not comparable:
                    entry.update(result="inconclusive", reason_code="root_anchor_not_comparable")
                    chain.append(entry)
                    state, reason = "inconclusive", "root trust anchor could not be compared"
                    break
                if not matched:
                    entry.update(result="bogus", reason_code="root_anchor_mismatch")
                    chain.append(entry)
                    state, reason = "bogus", "root DNSKEY did not match a valid IANA anchor"
                    break
            else:
                ds_rrset, _ = _rrset(ds_answer, current, dns.rdatatype.DS)
                matched, comparable = _matching_ds_keys(current, keys, ds_rrset)
                if not comparable:
                    entry.update(result="inconclusive", reason_code="ds_not_comparable")
                    chain.append(entry)
                    state, reason = "inconclusive", "DS data could not be compared"
                    break
                if not matched:
                    entry.update(result="bogus", reason_code="ds_dnskey_mismatch")
                    chain.append(entry)
                    state, reason = "bogus", "DS did not match a child DNSKEY"
                    break
            checked_key = _validate(keys, key_sigs, matched if index else matched, current, now)
            if checked_key[0] != "secure":
                entry.update(result=checked_key[0], reason_code=checked_key[1])
                chain.append(entry)
                state, reason = checked_key[0], checked_key[1]
                break
            _cache_validated_answer(key_cache_key, key_answer, now)
            entry.update(result="secure", signature_inception=checked_key[2].isoformat() if checked_key[2] else None, signature_expiration=checked_key[3].isoformat() if checked_key[3] else None)
            if checked_key[3] and checked_key[3] - now < SIGNATURE_WARNING:
                entry["signature_warning"] = "expires_within_7_days"
                all_findings.append(Finding(severity="warning", record_type="DNSSEC", message=f"DNSSEC signature expires soon for {entry['zone']}."))
            if current == zone:
                soa_answer, soa_cache_key = await _resolve_chain_rrset(resolver, current, dns.rdatatype.SOA, now, anchor_id)
                soa, soa_sigs = _rrset(soa_answer, current, dns.rdatatype.SOA)
                checked_soa = _validate(soa, soa_sigs, keys, current, now) if soa else ("inconclusive", "soa_missing", None, None)
                if checked_soa[0] != "secure":
                    entry.update(result=checked_soa[0], reason_code=checked_soa[1])
                    chain.append(entry)
                    state, reason = checked_soa[0], checked_soa[1]
                    break
                if checked_soa[3] and checked_soa[3] - now < SIGNATURE_WARNING:
                    entry["signature_warning"] = "expires_within_7_days"
                    all_findings.append(Finding(severity="warning", record_type="DNSSEC", message=f"DNSSEC signature expires soon for {entry['zone']}."))
                _cache_validated_answer(soa_cache_key, soa_answer, now)
                nsec = _nsec_metadata(soa_answer)
                nsecparam_answer = await _resolve(resolver, current, "NSEC3PARAM")
                nsecparam, _ = _rrset(nsecparam_answer, current, dns.rdatatype.NSEC3PARAM)
                if nsecparam:
                    nsec["type"] = "NSEC3"
                    nsec["iterations"] = max((record.iterations for record in nsecparam), default=0)
                entry["nsec"] = nsec
                # RFC 9276 recommends zero additional iterations. We cap local
                # work there; nonzero parameters are inconclusive because this
                # engine does not validate denial proofs.
                if nsec.get("iterations") is not None and nsec["iterations"] > NSEC3_MAX_ITERATIONS:
                    entry.update(result="inconclusive", reason_code="nsec3_iterations_over_limit")
                    chain.append(entry)
                    state, reason = "inconclusive", "NSEC3 iterations exceed the local limit"
                    break
            chain.append(entry)
            parent_keys = keys
            parent_state = "secure"
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
                   "nsec": chain[-1].get("nsec", {"type": None, "nsec3_opt_out": None, "iterations": None}) | {"iteration_limit": NSEC3_MAX_ITERATIONS, "denial_validated": False}})
    severity, message = (("info", "DNSSEC chain validated from the IANA root trust anchor to the zone.") if state == "secure" else ("error", f"DNSSEC validation failed: {reason}.") if state == "bogus" else ("warning", f"DNSSEC is {reason}.") if state == "insecure" else ("info", "DNSSEC validation is inconclusive; this does not prove the zone is bogus or unsigned."))
    if reason == "signature_expired":
        all_findings.append(Finding(severity="error", record_type="DNSSEC", message="DNSSEC signature expired."))
    elif reason == "signature_not_yet_valid":
        all_findings.append(Finding(severity="error", record_type="DNSSEC", message="DNSSEC signature is not yet valid."))
    findings = [Finding(severity=severity, record_type="DNSSEC", message=message), *all_findings]
    return result, findings


def _base(status: str, reason: str | None) -> dict[str, Any]:
    return {"status": status, "reason": reason, "enabled": False, "delegation_verified": False, "cryptographically_verified": False, "has_dnskey": False, "has_ds": False, "dnskey_count": 0, "ds_count": 0, "keys": [], "delegation_signers": [], "chain": []}
