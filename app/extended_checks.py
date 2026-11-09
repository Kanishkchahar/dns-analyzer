"""Bounded DANE/TLSA, SMTP STARTTLS, and RPKI checks for the plugin registry."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import ssl
from typing import Any
from urllib.parse import urlencode

import dns.exception
import dns.resolver
import httpx
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization

from app.http_config import outbound_http_headers
from app.models import Finding
from app.tls_check import PinnedIPTransport, resolve_and_verify_all_ips

RIPESTAT_HOST = "stat.ripe.net"
DNSBL_ZONES = {
    "Spamhaus ZEN": ("zen.spamhaus.org", {2, 3, 4, 9, 10, 11}),
    "Barracuda BRBL": ("b.barracudacentral.org", {2}),
    "SpamCop": ("bl.spamcop.net", {2}),
}


async def _ripe_request(endpoint: str, params: dict[str, str], addresses: list[str], budget: Any) -> dict[str, Any] | None:
    if not await budget.reserve_http("rpki"):
        return None
    url = f"https://{RIPESTAT_HOST}/data/{endpoint}/data.json?{urlencode(params)}"
    try:
        transport = PinnedIPTransport(addresses[0], verify=True)
        async with httpx.AsyncClient(transport=transport, timeout=4.0, headers=outbound_http_headers()) as client:
            response = await client.get(url)
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


async def _rpki_check(domain: str, resolver: Any, budget: Any) -> tuple[dict[str, Any], list[Finding]]:
    safe, addresses, reason = await resolve_and_verify_all_ips(domain, resolver=resolver)
    if not safe or not addresses:
        return {"status": "inconclusive", "reason": reason, "addresses": []}, [Finding(
            severity="inconclusive", record_type="RPKI", message="RPKI origin validation could not run because the domain did not resolve to safe public addresses.",
        )]
    safe, ripe_addresses, _ = await resolve_and_verify_all_ips(RIPESTAT_HOST, resolver=resolver)
    if not safe or not ripe_addresses:
        return {"status": "inconclusive", "addresses": []}, [Finding(
            severity="inconclusive", record_type="RPKI", message="RPKI validation service could not be reached safely.",
        )]

    observations = []
    for address in addresses[:2]:
        network = await _ripe_request("network-info", {"resource": address}, ripe_addresses, budget)
        prefix = network.get("prefix") if network else None
        origins = network.get("asns", []) if network else []
        if not prefix or not isinstance(origins, list) or not origins:
            observations.append({"address": address, "status": "unavailable"})
            continue
        for origin in origins[:2]:
            asn = origin.get("asn") if isinstance(origin, dict) else origin
            if not str(asn).isdigit():
                continue
            validation = await _ripe_request(
                "rpki-validation", {"resource": str(asn), "prefix": str(prefix)}, ripe_addresses, budget,
            )
            state = validation.get("status") if validation else "unavailable"
            observations.append({"address": address, "prefix": prefix, "asn": int(asn),
                                 "holder": origin.get("holder") if isinstance(origin, dict) else None,
                                 "status": state})

    states = {item["status"] for item in observations}
    if not observations or "unavailable" in states:
        status = "partial" if observations else "inconclusive"
    elif states.intersection({"invalid_asn", "invalid_length"}):
        status = "invalid"
    elif states == {"valid"}:
        status = "valid"
    else:
        status = "unknown"
    if status == "invalid":
        finding = Finding(severity="error", record_type="RPKI", message="At least one observed route origin does not match its Route Origin Authorization (ROA). Confirm the advertised prefix and ASN at the network operator.")
    elif status == "valid":
        finding = Finding(severity="info", record_type="RPKI", message="RIPEstat reports the observed route origins as RPKI valid. This reflects RIPE RIS observations at scan time.")
    elif status == "unknown":
        finding = Finding(severity="warning", record_type="RPKI", message="RIPEstat found no matching ROA for at least one observed route origin; the route status is RPKI unknown, not invalid.")
    else:
        finding = Finding(severity="inconclusive", record_type="RPKI", message="RPKI route validation was incomplete or unavailable.")
    return {"status": status, "source": "RIPEstat", "observations": observations}, [finding]


def _tlsa_match(certificate_der: bytes, tlsa_record: dict[str, Any]) -> bool | None:
    """Match DANE-EE (usage 3) certificate/SPKI associations; other usages need chain validation."""
    if tlsa_record["usage"] != 3:
        return None
    try:
        if tlsa_record["selector"] == 0:
            selected = certificate_der
        elif tlsa_record["selector"] == 1:
            certificate = x509.load_der_x509_certificate(certificate_der)
            selected = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            return None
        matching_type = tlsa_record["matching_type"]
        if matching_type == 0:
            actual = selected
        elif matching_type == 1:
            actual = hashlib.sha256(selected).digest()
        elif matching_type == 2:
            actual = hashlib.sha512(selected).digest()
        else:
            return None
        expected = bytes.fromhex(tlsa_record["association_data"])
        return actual == expected
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None


async def _https_leaf_certificate(host: str, address: str) -> bytes | None:
    transport = PinnedIPTransport(address, verify=False, limits=httpx.Limits(max_connections=1, max_keepalive_connections=0))
    try:
        async with httpx.AsyncClient(transport=transport, timeout=4.0, follow_redirects=False, headers=outbound_http_headers()) as client:
            request = client.build_request("HEAD", f"https://{host}/")
            response = await client.send(request, stream=True)
            try:
                network_stream = response.extensions.get("network_stream")
                ssl_object = network_stream.get_extra_info("ssl_object") if network_stream else None
                return ssl_object.getpeercert(binary_form=True) if ssl_object else None
            finally:
                await response.aclose()
    except Exception:
        return None


async def _smtp_leaf_certificate(host: str, address: str) -> bytes | None:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 25), timeout=3.0)
        await _smtp_reply(reader)
        writer.write(b"EHLO dns-analyzer.invalid\r\n")
        await writer.drain()
        capabilities = await _smtp_reply(reader)
        if not any("STARTTLS" in line.upper() for line in capabilities):
            return None
        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        if not (await _smtp_reply(reader))[-1].startswith("220"):
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        await writer.start_tls(context, server_hostname=host, ssl_handshake_timeout=4.0)
        ssl_object = writer.get_extra_info("ssl_object")
        return ssl_object.getpeercert(binary_form=True) if ssl_object else None
    except Exception:
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _tlsa_check(domain: str, resolver: Any, records: dict[str, Any], budget: Any) -> tuple[dict[str, Any], list[Finding]]:
    mx = records.get("MX", {}).get("records", [])
    mx_hosts = [str(item.get("host", "")).rstrip(".") for item in mx if isinstance(item, dict) and item.get("host")]
    endpoints = [(f"_443._tcp.{domain}", domain, 443)] + [(f"_25._tcp.{host}", host, 25) for host in mx_hosts[:3]]
    observations: list[dict[str, Any]] = []
    published_any = False
    incomplete = False
    matched_any = False
    mismatch_any = False
    for name, host, port in endpoints:
        try:
            answer = await resolver.resolve(name, "TLSA", lifetime=3.0)
            tlsa_records = [
                {
                    "usage": int(item.usage), "selector": int(item.selector),
                    "matching_type": int(item.mtype),
                    "association_data": item.cert.hex(),
                } for item in answer
            ]
            published_any = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            observations.append({"name": name, "host": host, "port": port, "status": "not_published", "records": [], "addresses": []})
            continue
        except Exception:
            incomplete = True
            observations.append({"name": name, "host": host, "port": port, "status": "inconclusive", "records": [], "addresses": []})
            continue

        safe, addresses, reason = await resolve_and_verify_all_ips(host, port=port, resolver=resolver)
        if not safe or not addresses:
            incomplete = True
            observations.append({"name": name, "host": host, "port": port, "status": "inconclusive", "reason": reason, "records": tlsa_records, "addresses": []})
            continue
        address_results = []
        for address in addresses[:2]:
            if not await budget.reserve_http("tlsa_probe"):
                address_results.append({"address": address, "status": "inconclusive", "reason": "TLS probe budget exhausted", "matches": []})
                incomplete = True
                continue
            cert_der = await (_https_leaf_certificate(host, address) if port == 443 else _smtp_leaf_certificate(host, address))
            if not cert_der:
                address_results.append({"address": address, "status": "inconclusive", "matches": []})
                incomplete = True
                continue
            cert_hash = hashlib.sha256(cert_der).hexdigest()
            match_results = []
            for tlsa_record in tlsa_records:
                matched = _tlsa_match(cert_der, tlsa_record)
                match_results.append({
                    "usage": tlsa_record["usage"], "selector": tlsa_record["selector"],
                    "matching_type": tlsa_record["matching_type"], "matched": matched,
                    "reason": None if matched is not None else "DANE usage or TLSA selector requires chain validation not implemented by this check.",
                })
            address_matches = [item["matched"] for item in match_results]
            if True in address_matches:
                matched_any = True
            elif address_matches and all(value is False for value in address_matches):
                mismatch_any = True
            address_results.append({"address": address, "status": "observed", "certificate_sha256": cert_hash, "matches": match_results})
        observations.append({"name": name, "host": host, "port": port, "status": "observed", "records": tlsa_records, "addresses": address_results})

    if not published_any:
        status = "inconclusive" if incomplete else "not_configured"
    elif incomplete:
        status = "partial"
    elif mismatch_any:
        status = "mismatch_unvalidated"
    elif matched_any:
        status = "matched_unvalidated"
    else:
        status = "published_unmatched_or_unsupported"
    findings = []
    if status == "mismatch_unvalidated":
        findings.append(Finding(severity="warning", record_type="DANE/TLSA", message="A supported DANE-EE TLSA association does not match an observed service certificate. DNSSEC authentication is not validated, so review the DNS record and certificate before changing either."))
    elif status == "matched_unvalidated":
        findings.append(Finding(severity="info", record_type="DANE/TLSA", message="An observed service certificate matches a supported DANE-EE TLSA association. The DNSSEC chain is not validated, so this is a match observation rather than a complete DANE validation."))
    elif status in {"partial", "inconclusive"}:
        findings.append(Finding(severity="inconclusive", record_type="DANE/TLSA", message="TLSA DNS checks were inconclusive for one or more service names."))
    elif status == "not_configured":
        findings.append(Finding(severity="info", record_type="DANE/TLSA", message="No TLSA records were found for the HTTPS hostname or the first three MX hosts."))
    else:
        findings.append(Finding(severity="info", record_type="DANE/TLSA", message="TLSA records are published, but supported certificate matching could not be established for the published usage and selector combinations."))
    return {"status": status, "dnssec_validation": "not_performed", "observations": observations}, findings


def _dnsbl_query_name(address: str, zone: str) -> str:
    ip = ipaddress.ip_address(address)
    if ip.version != 4 or not ip.is_global:
        raise ValueError("DNSBL checks require a public IPv4 address")
    return f"{'.'.join(reversed(str(ip).split('.')))}.{zone}."


def _dnsbl_addresses(answer: Any) -> set[str]:
    addresses: set[str] = set()
    for record in answer:
        value = getattr(record, "address", str(record))
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if parsed.version == 4 and parsed in ipaddress.ip_network("127.0.0.0/8"):
            addresses.add(str(parsed))
    return addresses


async def _dnsbl_check(records: dict[str, Any], resolver: Any) -> tuple[dict[str, Any], list[Finding]]:
    """Check a small bounded set of public MX IPv4 addresses against DNSBLs."""
    mx = records.get("MX", {}).get("records", [])
    hosts = list(dict.fromkeys(
        str(item.get("host", "")).rstrip(".")
        for item in mx if isinstance(item, dict) and item.get("host")
    ))[:3]
    if not hosts:
        return {"status": "not_applicable", "observations": []}, []

    observations: list[dict[str, Any]] = []
    for host in hosts:
        try:
            answer = await resolver.resolve(host, "A", lifetime=3.0)
            addresses = list(dict.fromkeys(
                str(item.address) for item in answer
                if hasattr(item, "address") and ipaddress.ip_address(str(item.address)).is_global
            ))[:2]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            observations.append({"host": host, "status": "unresolved", "lists": []})
            continue
        except Exception:
            observations.append({"host": host, "status": "inconclusive", "lists": []})
            continue

        if not addresses:
            observations.append({"host": host, "status": "inconclusive", "lists": []})
            continue
        for address in addresses:
            list_results = []
            for provider, (zone, listed_codes) in DNSBL_ZONES.items():
                query_name = _dnsbl_query_name(address, zone)
                try:
                    answer = await resolver.resolve(query_name, "A", lifetime=3.0)
                    answer_records = list(answer)
                    response_addresses = _dnsbl_addresses(answer_records)
                    codes = {int(value.rsplit(".", 1)[1]) for value in response_addresses if value.startswith("127.0.0.")}
                    # Spamhaus's public-resolver and query-limit responses are not listings.
                    blocked = provider == "Spamhaus ZEN" and bool(response_addresses.intersection({"127.255.255.254", "127.255.255.255"}))
                    is_listed = any(value in {f"127.0.0.{code}" for code in listed_codes} for value in response_addresses)
                    status = "inconclusive" if blocked or (answer_records and not is_listed) else "listed" if is_listed else "not_listed"
                    list_results.append({"provider": provider, "status": status, "return_codes": sorted(codes)})
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    list_results.append({"provider": provider, "status": "not_listed", "return_codes": []})
                except Exception:
                    list_results.append({"provider": provider, "status": "inconclusive", "return_codes": []})
            observations.append({"host": host, "address": address, "status": "complete" if all(item["status"] != "inconclusive" for item in list_results) else "partial", "lists": list_results})

    listed = [
        {"host": item["host"], "address": item["address"], "provider": provider["provider"], "return_codes": provider["return_codes"]}
        for item in observations for provider in item.get("lists", []) if provider["status"] == "listed"
    ]
    if listed:
        status = "listed"
        pbl_listing = listed[0]["provider"] == "Spamhaus ZEN" and listed[0]["return_codes"][0] in {10, 11}
        severity = "warning" if pbl_listing else "error"
        if pbl_listing:
            message = (
                f"MX IP {listed[0]['address']} is in Spamhaus PBL (127.0.0.{listed[0]['return_codes'][0]}), "
                "a policy listing for addresses not expected to send mail directly. Verify the host's role; "
                "if it sends outbound mail, use an authorized relay or ask the network provider about its policy."
            )
        else:
            message = (
                f"MX IP {listed[0]['address']} is listed by {listed[0]['provider']} "
                f"(DNS return code 127.0.0.{listed[0]['return_codes'][0]}). Review the provider's listing details."
            )
        findings = [Finding(
            severity=severity, record_type="MAIL-DNSBL",
            message=message,
        )]
    elif any(item["status"] in ("inconclusive", "partial", "unresolved") for item in observations):
        status = "inconclusive"
        findings = [Finding(severity="inconclusive", record_type="MAIL-DNSBL", message="DNS blacklist status could not be determined for every checked MX address; this does not mean the addresses are unlisted.")]
    else:
        status = "clear"
        findings = []
    return {"status": status, "observations": observations, "sources": list(DNSBL_ZONES)}, findings


async def _smtp_reply(reader: asyncio.StreamReader, timeout: float = 3.0) -> list[str]:
    lines = []
    for _ in range(20):
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line or len(line) > 2048:
            break
        decoded = line.decode("ascii", errors="replace").rstrip("\r\n")
        lines.append(decoded)
        if len(decoded) < 4 or decoded[3] != "-":
            break
    return lines


async def _probe_mx(host: str, resolver: Any) -> dict[str, Any]:
    safe, addresses, reason = await resolve_and_verify_all_ips(host, port=25, resolver=resolver)
    if not safe or not addresses:
        return {"host": host, "status": "inconclusive", "reason": reason}
    for address in addresses[:2]:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 25), timeout=3.0)
            greeting = await _smtp_reply(reader)
            writer.write(b"EHLO dns-analyzer.invalid\r\n")
            await writer.drain()
            capabilities = await _smtp_reply(reader)
            advertises = any("STARTTLS" in line.upper() for line in capabilities)
            result: dict[str, Any] = {"host": host, "status": "advertised" if advertises else "not_advertised",
                                      "starttls": advertises, "greeting_received": bool(greeting)}
            if not advertises:
                return result
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            reply = await _smtp_reply(reader)
            if not reply or not reply[-1].startswith("220"):
                return {**result, "status": "handshake_failed", "tls": False}
            await writer.start_tls(ssl.create_default_context(), server_hostname=host, ssl_handshake_timeout=4.0)
            ssl_object = writer.get_extra_info("ssl_object")
            cipher = ssl_object.cipher() if ssl_object else None
            return {**result, "status": "tls_established", "tls": True,
                    "tls_version": ssl_object.version() if ssl_object else None,
                    "cipher": cipher[0] if cipher else None}
        except Exception:
            continue
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    return {"host": host, "status": "unavailable"}


async def _starttls_check(resolver: Any, records: dict[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
    mx = records.get("MX", {}).get("records", [])
    hosts = list(dict.fromkeys(str(item.get("host", "")).rstrip(".") for item in mx
                               if isinstance(item, dict) and item.get("host")))[:3]
    if not hosts:
        return {"status": "not_applicable", "hosts": []}, []
    observations = await asyncio.gather(*(_probe_mx(host, resolver) for host in hosts))
    statuses = {item["status"] for item in observations}
    if "tls_established" in statuses:
        status = "complete"
        finding = Finding(severity="info", record_type="STARTTLS", message="At least one of the first three MX hosts accepted SMTP STARTTLS and completed a certificate-verified TLS handshake.")
    elif "not_advertised" in statuses:
        status = "warning"
        finding = Finding(severity="warning", record_type="STARTTLS", message="At least one reachable MX host did not advertise SMTP STARTTLS. Review the mail transport policy and provider configuration.")
    elif "handshake_failed" in statuses:
        status = "partial"
        finding = Finding(severity="warning", record_type="STARTTLS", message="An MX host advertised STARTTLS but could not complete a certificate-verified TLS handshake.")
    else:
        status = "inconclusive"
        finding = Finding(severity="inconclusive", record_type="STARTTLS", message="SMTP STARTTLS support could not be determined for the checked MX hosts.")
    return {"status": status, "hosts": observations, "mail_sent": False}, [finding]


async def check_extended_security(domain: str, resolver: Any, budget: Any, records: dict[str, Any]) -> tuple[dict[str, Any], list[Finding]]:
    shared_resolver = budget.resolver_for(resolver, "shared")
    rpki_resolver = budget.resolver_for(resolver, "shared")
    dnsbl_resolver = budget.resolver_for(resolver, "dnsbl")
    outcomes = await asyncio.gather(
        _rpki_check(domain, rpki_resolver, budget),
        _tlsa_check(domain, shared_resolver, records, budget),
        _starttls_check(shared_resolver, records),
        _dnsbl_check(records, dnsbl_resolver),
        return_exceptions=True,
    )
    keys = ("rpki", "dane_tlsa", "smtp_starttls", "dnsbl")
    data: dict[str, Any] = {}
    findings: list[Finding] = []
    for key, outcome in zip(keys, outcomes):
        if isinstance(outcome, BaseException):
            data[key] = {"status": "inconclusive", "reason": "Check could not complete."}
            findings.append(Finding(severity="inconclusive", record_type=key.upper(), message=f"{key.replace('_', ' ')} check could not complete."))
        else:
            result, result_findings = outcome
            data[key] = result
            findings.extend(result_findings)
    return data, findings


def register(register_function: Any) -> None:
    register_function("extended_security", check_extended_security,
                      "RPKI, DANE/TLSA, SMTP STARTTLS, and MX DNSBL checks")


