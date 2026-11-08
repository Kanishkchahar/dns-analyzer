"""Locally signed DNSSEC test hierarchy and deterministic fake resolver."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

import dns.dnssec
import dns.flags
import dns.name
import dns.exception
import dns.resolver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


ROOT = dns.name.root
TLD = dns.name.from_text("test.")
ZONE = dns.name.from_text("example.test.")


def _keypair(algorithm: int):
    if algorithm in (5, 8):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == 13:
        private = ec.generate_private_key(ec.SECP256R1())
    elif algorithm == 14:
        private = ec.generate_private_key(ec.SECP384R1())
    elif algorithm == 15:
        private = ed25519.Ed25519PrivateKey.generate()
    else:
        raise ValueError(f"Unsupported test key algorithm: {algorithm}")
    dnskey = dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=257)
    return private, dnskey


def _signed_rrset(owner, kind, text, private, key, now, mode=None):
    rrset = dns.rrset.from_text(owner, 300, "IN", kind, text)
    inception = now - timedelta(minutes=2)
    expiration = now + timedelta(days=30)
    if mode == "expired":
        inception, expiration = now - timedelta(days=4), now - timedelta(days=1)
    elif mode == "not_yet_valid":
        inception, expiration = now + timedelta(days=1), now + timedelta(days=20)
    elif mode == "expires_soon":
        expiration = now + timedelta(days=2)
    sig = dns.dnssec.sign(rrset, private, owner, key, inception=inception, expiration=expiration)
    if mode == "bad_signature":
        altered = text.replace(" 1 3600 ", " 2 3600 ")
        rrset = dns.rrset.from_text(owner, 300, "IN", kind, altered)
    return rrset, sig


@dataclass
class Answer:
    rrset: Any
    response: Any

    def __iter__(self):
        return iter(self.rrset or ())

    def __len__(self):
        return len(self.rrset or ())


class FakeDNSSECResolver:
    """Fake recursive resolver; models DO/CD, TCP retry and requested faults."""
    def __init__(self, hierarchy, mode=None):
        self.hierarchy = hierarchy
        self.mode = mode
        self.ednsflags = 0
        self.flags = 0
        self.calls = []
        self.nsec3_iterations = 0

    def use_edns(self, edns=0, ednsflags=0):
        self.ednsflags = ednsflags

    async def resolve(self, name, rdtype, tcp=False, **kwargs):
        name = dns.name.from_text(name) if isinstance(name, str) else name
        kind = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        self.calls.append((name, kind, tcp, self.ednsflags, self.flags))
        if self.mode == "timeout":
            raise dns.exception.Timeout
        if self.mode == "servfail_without_cd" and not (self.flags & dns.flags.CD):
            raise dns.resolver.NoNameservers
        if self.mode == "budget_exhaustion" and len(self.calls) > 2:
            from app.work_budget import ScanBudgetExhausted
            raise ScanBudgetExhausted("test budget exhausted")
        truncated = self.mode == "truncated_response" and not tcp
        rrset, sigset = self.hierarchy.get((name, kind), (None, None))
        if not (self.ednsflags & dns.flags.DO):
            sigset = None
        if self.mode == "dnskey_stripped" and name == ZONE and kind == dns.rdatatype.DNSKEY:
            rrset = sigset = None
        if self.mode == "missing_ds" and kind == dns.rdatatype.DS:
            rrset = sigset = None
        if self.mode == "missing_ds_tld" and name == TLD and kind == dns.rdatatype.DS:
            rrset = sigset = None
        if self.mode == "truncated_unrecoverable" or truncated:
            message = type("Response", (), {"flags": dns.flags.TC, "answer": [], "authority": []})()
            return Answer(None, message)
        signature_rrset = dns.rrset.from_rdata(name, 300, sigset) if sigset is not None else None
        authority = []
        if kind == dns.rdatatype.SOA and name == ZONE and self.mode in ("nsec3_opt_out", "nsec3_over_limit"):
            iterations = 1 if self.mode == "nsec3_over_limit" else 0
            nsec3 = dns.rrset.from_text(
                "00000000000000000000000000000000.example.test.", 300, "IN", "NSEC3",
                f"1 1 {iterations} - 00000000000000000000000000000000 A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM",
            )
            authority.append(nsec3)
        message = type("Response", (), {"flags": 0, "answer": [x for x in (rrset, signature_rrset) if x is not None], "authority": authority})()
        return Answer(rrset, message)


def make_signed_hierarchy(now: datetime | None = None, algorithm: int = 8, mode: str | None = None):
    now = now or datetime.now(timezone.utc)
    hierarchy = {}
    private_keys = {}
    dnskeys = {}
    for zone in (ROOT, TLD, ZONE):
        alg = 253 if mode == "unsupported_algorithm" and zone == ZONE else (5 if mode == "deprecated_algorithm" and zone == ZONE else algorithm)
        if alg in (253,):
            # Unknown algorithm is represented in the DNSKEY and tested as metadata;
            # signing still uses an available key and its signature algorithm.
            alg = algorithm
        private, key = _keypair(alg)
        private_keys[zone], dnskeys[zone] = private, key
        keyrr, keysig = _signed_rrset(zone, "DNSKEY", key.to_text(), private, key, now)
        if mode == "unsupported_algorithm" and zone == ZONE:
            fields = key.to_text().split()
            fields[2] = "253"
            keyrr = dns.rrset.from_text(ZONE, 300, "IN", "DNSKEY", " ".join(fields))
        hierarchy[(zone, dns.rdatatype.DNSKEY)] = (keyrr, keysig)
        mname = "ns." + (zone.to_text() if zone != ROOT else "root.")
        soa_text = mname + " hostmaster.example. 1 3600 600 86400 300"
        soarr, soasig = _signed_rrset(zone, "SOA", soa_text, private, key, now, mode if zone == ZONE else None)
        hierarchy[(zone, dns.rdatatype.SOA)] = (soarr, soasig)
    for child, parent in ((TLD, ROOT), (ZONE, TLD)):
        digest_type = "SHA1" if mode == "deprecated_algorithm" and child == ZONE else "SHA256"
        if digest_type == "SHA1":
            wire = child.canonicalize().to_wire() + dnskeys[child].to_wire()
            digest = hashlib.sha1(wire).hexdigest()
            ds = dns.rdata.from_text("IN", "DS", f"{dns.dnssec.key_id(dnskeys[child])} {dnskeys[child].algorithm} 1 {digest}")
        else:
            ds = dns.dnssec.make_ds(child, dnskeys[child], digest_type)
        if mode == "ds_mismatch" and child == ZONE:
            ds = dns.rdata.from_text("IN", "DS", f"{(ds.key_tag + 1) % 65536} {ds.algorithm} {ds.digest_type} {ds.digest.hex()}")
        dsrr = dns.rrset.from_rdata(child, 300, ds)
        dssig = dns.dnssec.sign(dsrr, private_keys[parent], parent, dnskeys[parent], inception=now-timedelta(minutes=2), expiration=now+timedelta(days=30))
        if mode == "ds_bad_signature" and child == ZONE:
            dsrr = dns.rrset.from_text(child, 300, "IN", "DS", f"{(ds.key_tag + 1) % 65536} {ds.algorithm} {ds.digest_type} {ds.digest.hex()}")
        if mode == "ds_no_signature" and child == ZONE:
            dssig = None
        hierarchy[(child, dns.rdatatype.DS)] = (dsrr, dssig)
    if mode == "missing_ds":
        hierarchy.pop((ZONE, dns.rdatatype.DS), None)
    if mode == "dnskey_stripped":
        hierarchy[(ZONE, dns.rdatatype.DNSKEY)] = (None, None)
    # Signature-time and data-tampering modes affect only the target SOA.
    if mode in ("expired", "not_yet_valid", "bad_signature", "expires_soon"):
        hierarchy[(ZONE, dns.rdatatype.SOA)] = _signed_rrset(ZONE, "SOA", "ns.example.test. hostmaster.example.test. 1 3600 600 86400 300", private_keys[ZONE], dnskeys[ZONE], now, mode)
    anchor = dns.dnssec.make_ds(ROOT, dnskeys[ROOT], "SHA256")
    if mode == "ds_mismatch":
        anchor = dns.dnssec.make_ds(ROOT, dnskeys[ROOT], "SHA256")
    return {"hierarchy": hierarchy, "resolver": FakeDNSSECResolver(hierarchy, mode), "trust_anchor": anchor,
            "now": now, "private_keys": private_keys, "dnskeys": dnskeys}
