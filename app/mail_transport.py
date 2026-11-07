"""MTA-STS and TLS reporting checks for domain mail transport security."""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.models import Finding
from app.tls_check import PinnedIPTransport, resolve_and_verify_all_ips


async def _query_txt(resolver: dns.asyncresolver.Resolver, name: str) -> tuple[list[str], str | None]:
    try:
        answer = await resolver.resolve(name, "TXT")
        return [b"".join(rr.strings).decode("utf-8", errors="replace") for rr in answer], None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except Exception as exc:
        return [], type(exc).__name__


def _parse_sts_policy(text: str) -> dict[str, Any]:
    values: dict[str, Any] = {"mx": []}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            values["mx"].append(value)
        elif key == "max_age":
            try:
                values[key] = int(value)
            except ValueError:
                values[key] = value
        else:
            values[key] = value
    return values


async def check_mail_transport(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    timeout: float = 3.0,
) -> tuple[dict[str, Any], list[Finding]]:
    """Check MTA-STS DNS/policy and TLS-RPT DNS records, without sending email."""
    findings: list[Finding] = []
    sts_name = f"_mta-sts.{domain}"
    rpt_name = f"_smtp._tls.{domain}"
    (sts_records, sts_error), (rpt_records, rpt_error) = await asyncio.gather(
        _query_txt(resolver, sts_name), _query_txt(resolver, rpt_name)
    )

    sts_txt = next((item for item in sts_records if item.strip().lower().startswith("v=stsv1")), None)
    sts_data: dict[str, Any] = {"status": "inconclusive" if sts_error else "not_configured", "dns_name": sts_name, "record": sts_txt, "policy": None, "reason": f"DNS lookup failed ({sts_error})." if sts_error else None}
    if sts_txt:
        tags = {}
        for part in sts_txt.split(";"):
            key, separator, value = part.strip().partition("=")
            if separator:
                tags[key.strip().lower()] = value.strip()
        sts_data.update({"status": "configured", "id": tags.get("id"), "version": tags.get("v")})
        safe_all, ips, reason = await resolve_and_verify_all_ips(f"mta-sts.{domain}", port=443)
        if not safe_all or not ips:
            sts_data.update({"policy_status": "blocked", "policy_reason": reason})
        else:
            policy_errors: list[str] = []
            policy_body = None
            policy_status_code = None
            for address in ips:
                try:
                    transport = PinnedIPTransport(address, verify=True)
                    async with httpx.AsyncClient(transport=transport, timeout=timeout, follow_redirects=False) as client:
                        async with client.stream("GET", f"https://mta-sts.{domain}/.well-known/mta-sts.txt") as response:
                            policy_status_code = response.status_code
                            if 200 <= response.status_code < 300:
                                chunks = bytearray()
                                async for chunk in response.aiter_bytes():
                                    chunks.extend(chunk[: max(0, 16 * 1024 - len(chunks))])
                                    if len(chunks) >= 16 * 1024:
                                        break
                                policy_body = bytes(chunks).decode("utf-8", errors="replace")
                            break
                except Exception as exc:
                    policy_errors.append(type(exc).__name__)
            if policy_body is not None:
                parsed = _parse_sts_policy(policy_body)
                valid = parsed.get("version") == "STSv1" and parsed.get("mode") in ("testing", "enforce", "none") and isinstance(parsed.get("max_age"), int) and parsed["max_age"] >= 0
                sts_data.update({"policy_status": "valid" if valid else "invalid", "policy_http_status": policy_status_code, "policy": parsed, "policy_reason": None if valid else "Policy file is missing required or valid fields."})
            else:
                sts_data.update({"policy_status": "unavailable", "policy_http_status": policy_status_code, "policy_reason": f"Policy file could not be retrieved ({', '.join(policy_errors) or f'HTTP {policy_status_code}'})."})

    rpt_txt = next((item for item in rpt_records if item.strip().lower().startswith("v=tlsrptv1")), None)
    rpt_data: dict[str, Any] = {"status": "inconclusive" if rpt_error else "not_configured", "dns_name": rpt_name, "record": rpt_txt, "reporting_uris": [], "reason": f"DNS lookup failed ({rpt_error})." if rpt_error else None}
    if rpt_txt:
        uris = []
        for part in rpt_txt.split(";"):
            key, separator, value = part.strip().partition("=")
            if separator and key.strip().lower() == "rua":
                uris.extend(uri.strip() for uri in value.split(",") if uri.strip())
        rpt_data.update({"status": "configured", "reporting_uris": uris})

    if sts_data["status"] == "configured":
        policy_mode = (sts_data.get("policy") or {}).get("mode")
        severity = "info" if sts_data.get("policy_status") == "valid" and policy_mode == "enforce" else "warning"
        findings.append(Finding(severity=severity, record_type="MTA-STS", message=f"MTA-STS DNS is published; policy file status is {sts_data.get('policy_status')} (mode={policy_mode or 'unknown'})."))
    elif sts_data["status"] == "not_configured":
        findings.append(Finding(severity="warning", record_type="MTA-STS", message="No MTA-STS DNS record was found; sending servers may not enforce encrypted delivery to this domain."))
    else:
        findings.append(Finding(severity="info", record_type="MTA-STS", message=f"MTA-STS could not be verified: {sts_data['reason']}"))

    if rpt_data["status"] == "configured":
        findings.append(Finding(severity="info", record_type="TLS-RPT", message=f"TLS-RPT is configured with {len(rpt_data['reporting_uris'])} reporting destination(s)."))
    elif rpt_data["status"] == "not_configured":
        findings.append(Finding(severity="info", record_type="TLS-RPT", message="No TLS-RPT reporting record was found."))
    else:
        findings.append(Finding(severity="info", record_type="TLS-RPT", message=f"TLS-RPT could not be verified: {rpt_data['reason']}"))

    return {"mta_sts": sts_data, "tls_rpt": rpt_data}, findings
