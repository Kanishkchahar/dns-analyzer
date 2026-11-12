"""FastAPI application — routes, static file serving, error handling."""

import asyncio
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.analyzer import analyze, summarize
from app.auth import require_api_key
from app.check_registry import run_registered_checks
from app.bimi import check_bimi
from app.dnssec import check_dnssec
from app.dns_posture import (
    check_nameserver_asn_diversity,
    check_nameserver_consistency,
    check_parent_child_delegation,
    check_wildcard_dns,
    check_zone_transfers,
)
from app.email_auth import (
    analyze_dkim,
    analyze_dmarc,
    check_dkim_selectors,
    compute_domain_score,
    compute_email_score,
    fetch_dmarc,
)
from app.models import (
    AnalyzeRequest,
    BatchAnalyzeRequest,
    AnalyzeResponse,
    DomainScore,
    EmailAuth,
    EmailScore,
    DkimSelectorRequest,
    Finding,
    FfufPathRequest,
    ListScanRequest,
    PortScanRequest,
    PathScanRequest,
    SubdomainEnumerateRequest,
    SecurityAudit,
    Summary,
)
from app.mail_transport import check_mail_transport
from app.network_scan import (
    COMMON_PATH_SCAN_HTTP_BUDGET,
    WIDE_PATH_SCAN_HTTP_BUDGET,
    is_active_scan_allowed,
    is_wide_directory_scan_allowed,
    run_common_path_scan,
    run_list_scan,
    run_port_scan,
    scan_capabilities,
    verify_port_scan_authorization,
    verify_wide_path_authorization,
    run_ffuf_scan,
)
from app.remediation import generate_bind_zone_file, generate_remediation_fixes
from app.report import build_report
from app.resolver import resolve_domain
from app.spf import analyze_spf, count_spf_lookups, flatten_spf, parse_spf
from app.subdomains import discover_passive_subdomains, enumerate_active_subdomains
from app.takeover import check_subdomain_takeover
from app.tls_check import audit_tls_and_https
from app.work_budget import ScanWorkBudget
from app.http_config import warn_if_placeholder_documentation_url

logger = logging.getLogger("dns_analyzer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    warn_if_placeholder_documentation_url()
    yield


app = FastAPI(title="DNS Analyzer", version="2.2.0", lifespan=lifespan)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path == "/" or request.url.path.startswith("/api/report/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
        )
    return response

# Concurrency & runtime throttle budgets
SCAN_SEMAPHORE = asyncio.Semaphore(8)
SCAN_TIMEOUT_SECONDS = 60.0
CHECK_TIMEOUT_SECONDS = 18.0
SPF_CHECK_TIMEOUT_SECONDS = 12.0
SEMAPHORE_WAIT_TIMEOUT = 3.0

# In-memory recent scan cache (TTL 60s, max 128 domains) to prevent redundant queries
_SCAN_CACHE: dict[str, tuple[float, AnalyzeResponse]] = {}
_SCAN_CACHE_TTL = 60.0
_PATH_SCAN_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_PATH_SCAN_CACHE_TTL = 900.0
_CUSTOM_DKIM_CACHE_TTL = 900.0
_CUSTOM_DKIM_CACHE: dict[tuple[str, tuple[str, ...]], tuple[float, dict[str, Any]]] = {}
_BADGE_CACHE: dict[str, tuple[float, bytes]] = {}

# In-memory client rate limiter (60 requests per minute per IP, bounded to 2048 client records)
_CLIENT_REQUESTS: dict[str, list[float]] = {}
_RATE_WINDOW = 60.0
_MAX_REQ_PER_WINDOW = 60
_MAX_TRACKED_IPS = 2048
_TARGET_LAST_SCAN: dict[str, float] = {}


def _configured_limit(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _get_cached_scan(domain: str) -> AnalyzeResponse | None:
    now = asyncio.get_running_loop().time()
    if domain in _SCAN_CACHE:
        cached_time, response = _SCAN_CACHE[domain]
        if now - cached_time < _SCAN_CACHE_TTL:
            return response.model_copy(deep=True)
        del _SCAN_CACHE[domain]
    return None


def _store_cached_scan(domain: str, response: AnalyzeResponse) -> None:
    now = asyncio.get_running_loop().time()
    if len(_SCAN_CACHE) >= 128:
        oldest_key = min(_SCAN_CACHE.keys(), key=lambda k: _SCAN_CACHE[k][0])
        del _SCAN_CACHE[oldest_key]
    _SCAN_CACHE[domain] = (now, response.model_copy(deep=True))
    _BADGE_CACHE.pop(domain, None)


def _store_path_scan_results(result: dict[str, Any]) -> None:
    now = asyncio.get_running_loop().time()
    for target_result in result.get("targets", []):
        target = str(target_result.get("target", "")).lower().rstrip(".")
        if not target:
            continue
        if len(_PATH_SCAN_CACHE) >= 128 and target not in _PATH_SCAN_CACHE:
            oldest = min(_PATH_SCAN_CACHE, key=lambda key: _PATH_SCAN_CACHE[key][0])
            del _PATH_SCAN_CACHE[oldest]
        _PATH_SCAN_CACHE[target] = (now, {"targets": [target_result], "path_count": result.get("path_count", 0), "scan_mode": result.get("scan_mode")})


def _get_cached_path_scan(domain: str) -> dict[str, Any] | None:
    target = domain.lower().rstrip(".")
    cached = _PATH_SCAN_CACHE.get(target)
    if not cached:
        return None
    cached_time, result = cached
    if asyncio.get_running_loop().time() - cached_time >= _PATH_SCAN_CACHE_TTL:
        del _PATH_SCAN_CACHE[target]
        return None
    return result


def _store_custom_dkim(domain: str, selectors: list[str], result: dict[str, Any]) -> None:
    key = (domain.lower().rstrip("."), tuple(sorted({item.strip().lower() for item in selectors if item.strip()})))
    if len(_CUSTOM_DKIM_CACHE) >= 128 and key not in _CUSTOM_DKIM_CACHE:
        oldest = min(_CUSTOM_DKIM_CACHE, key=lambda key: _CUSTOM_DKIM_CACHE[key][0])
        del _CUSTOM_DKIM_CACHE[oldest]
    _CUSTOM_DKIM_CACHE[key] = (asyncio.get_running_loop().time(), dict(result))


def _get_cached_custom_dkim(domain: str) -> dict[str, Any] | None:
    now = asyncio.get_running_loop().time()
    merged: dict[str, Any] | None = None
    found: dict[str, dict[str, Any]] = {}
    for key, (cached_time, result) in list(_CUSTOM_DKIM_CACHE.items()):
        if now - cached_time >= _CUSTOM_DKIM_CACHE_TTL:
            del _CUSTOM_DKIM_CACHE[key]
            continue
        if key[0] != domain.lower().rstrip("."):
            continue
        merged = dict(result) if merged is None else {**merged, **result}
        for item in result.get("selectors_found", []):
            found[item.get("selector", "")] = item
    if merged is not None:
        merged["selectors_found"] = list(found.values())
        merged["has_dkim"] = bool(found)
    return merged


def _extract_client_ip(request: Request) -> str:
    """Extract client IP, inspecting X-Forwarded-For only if proxy trust is enabled.

    WARNING: Only enable TRUST_REVERSE_PROXY=true when running behind an upstream reverse
    proxy that appends the connecting client address to X-Forwarded-For (or replaces the
    header). If enabled on an exposed direct host, callers may spoof their rate-limiting IP.
    """
    trust_proxy = os.environ.get("TRUST_REVERSE_PROXY", "false").strip().lower() in ("true", "1", "yes")
    if trust_proxy and "x-forwarded-for" in request.headers:
        # Walk from the nearest proxy toward the client, skipping malformed
        # entries. The configured hop count must match the trusted proxy chain.
        try:
            trusted_count = int(os.environ.get("TRUSTED_PROXY_COUNT", "1"))
        except ValueError:
            trusted_count = 1
        if trusted_count > 0:
            import ipaddress
            valid_forwarded = []
            for value in reversed(request.headers["x-forwarded-for"].split(",")):
                try:
                    valid_forwarded.append(str(ipaddress.ip_address(value.strip())))
                except ValueError:
                    continue
            if len(valid_forwarded) >= trusted_count:
                return valid_forwarded[trusted_count - 1]
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request, cost: int = 1, *, limit: int | None = None) -> None:
    client_ip = _extract_client_ip(request)
    bucket_key = f"{client_ip}:expensive" if limit is not None else client_ip
    now = asyncio.get_running_loop().time()
    cutoff = now - _RATE_WINDOW

    # Bounded cache cleanup: purge stale IP records if table exceeds limit
    if len(_CLIENT_REQUESTS) >= _MAX_TRACKED_IPS and bucket_key not in _CLIENT_REQUESTS:
        stale_keys = [ip for ip, timestamps in _CLIENT_REQUESTS.items() if not timestamps or timestamps[-1] <= cutoff]
        for ip in stale_keys:
            del _CLIENT_REQUESTS[ip]
        if len(_CLIENT_REQUESTS) > _MAX_TRACKED_IPS:
            oldest_ip = min(_CLIENT_REQUESTS, key=lambda ip: _CLIENT_REQUESTS[ip][-1] if _CLIENT_REQUESTS[ip] else 0)
            del _CLIENT_REQUESTS[oldest_ip]
        if len(_CLIENT_REQUESTS) >= _MAX_TRACKED_IPS:
            oldest_ip = min(_CLIENT_REQUESTS, key=lambda ip: _CLIENT_REQUESTS[ip][-1] if _CLIENT_REQUESTS[ip] else 0)
            del _CLIENT_REQUESTS[oldest_ip]

    reqs = _CLIENT_REQUESTS.setdefault(bucket_key, [])
    _CLIENT_REQUESTS[bucket_key] = [t for t in reqs if t > cutoff]

    # General API traffic has a configurable limit; expensive endpoints use
    # their own lower configured limit. Loopback gets a larger general budget.
    max_reqs = limit or _configured_limit("DNS_ANALYZER_RATE_LIMIT_PER_MIN", _MAX_REQ_PER_WINDOW)
    if limit is None and client_ip == "127.0.0.1":
        max_reqs = max(max_reqs, 120)
    if len(_CLIENT_REQUESTS[bucket_key]) + max(1, cost) > max_reqs:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait a moment before sending additional requests.",
        )
    _CLIENT_REQUESTS[bucket_key].extend([now] * max(1, cost))


def _enforce_target_cooldown(target: str, check_type: str = "analysis") -> None:
    now = asyncio.get_running_loop().time()
    cooldown = _configured_limit("DNS_ANALYZER_TARGET_COOLDOWN_SECONDS", 10)
    key = f"{check_type}:{target.strip().lower().rstrip('.')}"
    last_scan = _TARGET_LAST_SCAN.get(key)
    if last_scan is not None and now - last_scan < cooldown:
        raise HTTPException(status_code=429, detail="This target was scanned recently. Retry after the cooldown.")
    if len(_TARGET_LAST_SCAN) >= 2048:
        expired = [name for name, timestamp in _TARGET_LAST_SCAN.items() if now - timestamp >= cooldown]
        for name in expired:
            _TARGET_LAST_SCAN.pop(name, None)
        if len(_TARGET_LAST_SCAN) >= 2048:
            oldest = min(_TARGET_LAST_SCAN, key=_TARGET_LAST_SCAN.get)
            _TARGET_LAST_SCAN.pop(oldest, None)
    _TARGET_LAST_SCAN[key] = now


@asynccontextmanager
async def _scan_slot():
    """Acquire a bounded slot for any endpoint that performs outbound scan work."""
    try:
        await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=SEMAPHORE_WAIT_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=503,
            detail="Server is experiencing high scan volume. Please retry shortly.",
        ) from exc
    try:
        yield
    finally:
        SCAN_SEMAPHORE.release()


async def _await_scan_or_disconnect(request: Request, operation: Any) -> Any:
    """Cancel outbound scan work when the browser closes its request."""
    task = asyncio.ensure_future(operation)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=0.15)
            if done:
                return task.result()
            if await request.is_disconnected():
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
                raise HTTPException(status_code=499, detail="Scan cancelled because the client disconnected.")
    except asyncio.CancelledError:
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        raise




# ---------------------------------------------------------------------------
# Helper & Shared Scan Pipeline
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _build_scan_coverage(
    records: dict[str, Any],
    spf_lookups: dict[str, Any] | None,
    dmarc: dict[str, Any] | None,
    dkim: dict[str, Any] | None,
    dnssec: dict[str, Any] | None,
    takeover: dict[str, Any] | None,
    tls: dict[str, Any] | None,
    subdomains: dict[str, Any] | None,
    bimi: dict[str, Any] | None,
    mail_transport: dict[str, Any] | None,
    dns_posture: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    def item(name: str, status: str, detail: str) -> dict[str, str]:
        return {"name": name, "status": status, "detail": detail}

    record_errors = [
        name for name, entry in records.items()
        if isinstance(entry, dict) and entry.get("status") in ("timeout", "no_nameservers", "error", "budget_exhausted")
    ]
    dns_status = "partial" if record_errors else "complete"
    result = [item("DNS records / CAA", dns_status, f"{len(record_errors)} query error(s)" if record_errors else "Queries completed")]
    result.append(item("SPF", "partial" if (spf_lookups or {}).get("status") == "inconclusive" else "complete", "Lookup expansion checked" if spf_lookups else "Record presence checked"))
    for label, data in (("DMARC", dmarc), ("DKIM", dkim), ("DNSSEC", dnssec)):
        status = (data or {}).get("status", "complete")
        result.append(item(label, "partial" if status in ("inconclusive", "partial") else "complete", f"Result: {status}"))
    bimi_status = (bimi or {}).get("status", "unavailable")
    result.append(item("BIMI", "partial" if bimi_status == "inconclusive" else "complete", f"Result: {bimi_status}"))
    result.append(item("MTA-STS / TLS-RPT", "partial" if any((mail_transport or {}).get(key, {}).get("status") == "inconclusive" for key in ("mta_sts", "tls_rpt")) else "complete", "DNS and policy-file checks"))
    result.append(item("Subdomain takeover", "complete" if (takeover or {}).get("scanned") else "partial", f"Result: {(takeover or {}).get('status', 'unavailable')}"))
    tls_status = (tls or {}).get("status", "unavailable")
    if tls_status == "blocked":
        tls_coverage = "blocked"
    elif not (tls or {}).get("scanned") or (tls or {}).get("security_headers") is None:
        tls_coverage = "partial"
    elif (tls or {}).get("http_methods", {}).get("status") == "inconclusive":
        tls_coverage = "partial"
    else:
        tls_coverage = "complete"
    result.append(item("TLS, headers, cookies, CSP, methods", tls_coverage, f"Result: {tls_status}"))
    ct_status = (subdomains or {}).get("status", "unavailable")
    result.append(item("Certificate Transparency", "complete" if ct_status == "complete" else "partial", f"Result: {ct_status}"))
    result.append(item("Common web paths", "not_run", "Run separately from Network & Scope"))
    result.append(item("Active port probes", "not_run", "Opt-in and controlled by server policy"))
    posture = dns_posture or {}
    axfr = posture.get("axfr", {})
    consistency = posture.get("nameserver_consistency", {})
    wildcard = posture.get("wildcard", {})
    result.append(item(
        "AXFR exposure",
        "partial" if axfr.get("status") == "inconclusive" else "complete",
        f"{axfr.get('nameservers_checked', 0)} nameserver(s) checked",
    ))
    result.append(item(
        "Nameserver consistency",
        "partial" if consistency.get("status") != "complete" else "complete",
        f"{len(consistency.get('observations', []))} direct observations",
    ))
    result.append(item("Wildcard DNS", "partial" if wildcard.get("status") == "inconclusive" else "complete", f"Result: {wildcard.get('status', 'unavailable')}"))
    asn_diversity = posture.get("nameserver_asn_diversity", {})
    result.append(item(
        "Nameserver network diversity",
        "partial" if asn_diversity.get("status") != "complete" else "complete",
        f"Origin ASNs: {', '.join(asn_diversity.get('asns', [])) or 'unavailable'}",
    ))
    delegation = posture.get("parent_child_delegation", {})
    result.append(item(
        "Parent-child delegation and glue",
        "partial" if delegation.get("status") != "complete" else "complete",
        f"Parent responses: {len(delegation.get('parent_observations', []))}; glue records: {len(delegation.get('glue', []))}",
    ))
    return result


def _check_failure(name: str, exc: Exception) -> Finding:
    logger.error("%s check failed", name, exc_info=(type(exc), exc, exc.__traceback__))
    return Finding(
        severity="inconclusive",
        record_type=name,
        message=f"{name} check could not complete. Other scan results are still available.",
    )


async def _isolated_data_check(name: str, awaitable: Any, fallback: Any) -> tuple[Any, list[Finding]]:
    try:
        return await asyncio.wait_for(awaitable, timeout=CHECK_TIMEOUT_SECONDS), []
    except Exception as exc:
        return fallback, [_check_failure(name, exc)]


async def _isolated_pair_check(name: str, awaitable: Any, fallback_data: Any) -> tuple[Any, list[Finding]]:
    try:
        return await asyncio.wait_for(awaitable, timeout=CHECK_TIMEOUT_SECONDS)
    except Exception as exc:
        return fallback_data, [_check_failure(name, exc)]


async def run_full_scan(domain: str) -> AnalyzeResponse:
    """Execute end-to-end DNS, security, and email authentication audit for a domain."""
    import dns.asyncresolver
    work_budget = ScanWorkBudget()
    base_resolver = dns.asyncresolver.Resolver()
    records_resolver = work_budget.resolver_for(base_resolver, "records")
    records = await resolve_domain(domain, resolver=records_resolver)
    findings = analyze(domain, records)

    zone_meta = records.get("zone_metadata", {})
    zone_apex = zone_meta.get("zone_apex", domain)
    ns_records = records.get("NS", {}).get("records", [])
    ns_hosts = [item.get("host") if isinstance(item, dict) else str(item) for item in ns_records]

    # SPF
    txt_records = records.get("TXT", {}).get("records", [])
    txt_status = records.get("TXT", {}).get("status")
    spf_data = parse_spf(txt_records)
    spf_lookup_data = None
    spf_flat_data = None
    spf_scan_findings: list[Finding] = []
    spf_query_complete = txt_status in ("ok", "no_answer", "nxdomain")
    if not spf_query_complete:
        reason = "SPF could not be verified because the TXT lookup did not complete."
        spf_data = {"status": "inconclusive", "reason": reason}
        spf_lookup_data = {
            "status": "inconclusive", "total_lookups": 0, "limit": 10,
            "over_limit": False, "lookup_tree": [], "reason": reason,
        }
        spf_flat_data = {
            "can_flatten": False, "flattened_record": None, "reason": reason,
            "ip4_ranges": [], "ip6_ranges": [], "original_lookups": 0, "flattened_lookups": 0,
        }
        spf_findings = [Finding(severity="inconclusive", record_type="SPF", message=reason)]
    else:
        spf_findings = []
    if spf_query_complete and spf_data:
        spf_resolver = work_budget.resolver_for(base_resolver, "spf")
        lookup_result, flatten_result = await asyncio.gather(
            asyncio.wait_for(count_spf_lookups(domain, spf_resolver), timeout=SPF_CHECK_TIMEOUT_SECONDS),
            asyncio.wait_for(flatten_spf(domain, spf_resolver), timeout=SPF_CHECK_TIMEOUT_SECONDS),
            return_exceptions=True,
        )
        if isinstance(lookup_result, BaseException):
            spf_lookup_data = {
                "status": "inconclusive", "total_lookups": 0, "limit": 10,
                "over_limit": False, "lookup_tree": [], "reason": "SPF lookup count could not be completed.",
            }
            spf_scan_findings.append(_check_failure("SPF Lookup Count", lookup_result if isinstance(lookup_result, Exception) else RuntimeError(type(lookup_result).__name__)))
        else:
            spf_lookup_data = lookup_result
        if isinstance(flatten_result, BaseException):
            spf_flat_data = {
                "can_flatten": False, "flattened_record": None,
                "reason": "SPF flattening could not be completed.",
                "ip4_ranges": [], "ip6_ranges": [], "original_lookups": 0, "flattened_lookups": 0,
            }
            spf_scan_findings.append(_check_failure("SPF Flattening", flatten_result if isinstance(flatten_result, Exception) else RuntimeError(type(flatten_result).__name__)))
        else:
            spf_flat_data = flatten_result
    if spf_query_complete:
        spf_findings = analyze_spf(spf_data, spf_lookup_data, txt_records=txt_records)
    spf_findings.extend(spf_scan_findings)

    # DMARC & DKIM & DNSSEC & Subdomain Takeover & TLS & Passive CT Recon (run concurrently)
    (
        (dmarc_data, dmarc_scan_findings),
        (dkim_data, dkim_scan_findings),
        (dnssec_data, dnssec_findings),
        (takeover_data, takeover_findings),
        (tls_data, tls_findings),
        (sub_data, sub_findings),
        (mail_transport_data, mail_transport_findings),
        (axfr_data, axfr_findings),
        (wildcard_data, wildcard_findings),
        (ns_consistency_data, ns_consistency_findings),
        (ns_asn_data, ns_asn_findings),
    ) = await asyncio.gather(
        _isolated_data_check("DMARC", fetch_dmarc(domain, work_budget.resolver_for(base_resolver, "dmarc"), apex=zone_apex), {"status": "inconclusive", "policy": None, "reason": "DMARC lookup failed."}),
        _isolated_data_check("DKIM", check_dkim_selectors(domain, work_budget.resolver_for(base_resolver, "dkim")), {"status": "inconclusive", "selectors_found": [], "selectors_checked": [], "has_dkim": False}),
        _isolated_pair_check("DNSSEC", check_dnssec(domain, work_budget.resolver_for(base_resolver, "dnssec")), {"status": "inconclusive", "enabled": False, "delegation_verified": False, "reason": "DNSSEC queries failed."}),
        _isolated_pair_check("TAKEOVER", check_subdomain_takeover(domain, records, work_budget.resolver_for(base_resolver, "takeover"), budget=work_budget), {"scanned": False, "vulnerable": False, "status": "could_not_verify", "details": "Takeover check did not complete."}),
        _isolated_pair_check("TLS", audit_tls_and_https(domain, resolver=work_budget.resolver_for(base_resolver, "tls"), work_budget=work_budget), {"scanned": False, "status": "error", "reason": "TLS audit did not complete."}),
        _isolated_pair_check("SUBDOMAINS", discover_passive_subdomains(zone_apex, work_budget.resolver_for(base_resolver, "subdomains"), work_budget=work_budget), {"domain": zone_apex, "source": "Certificate Transparency (crt.sh)", "status": "unavailable", "reason": "Subdomain inventory did not complete.", "discovered_count": 0, "subdomains": []}),
        _isolated_pair_check("MAIL TRANSPORT", check_mail_transport(domain, work_budget.resolver_for(base_resolver, "mail_transport"), work_budget=work_budget), {"mta_sts": {"status": "inconclusive", "reason": "Check did not complete."}, "tls_rpt": {"status": "inconclusive", "reason": "Check did not complete."}}),
        _isolated_pair_check("AXFR", check_zone_transfers(zone_apex, ns_hosts, work_budget.resolver_for(base_resolver, "dns_posture"), work_budget=work_budget), {"zone": zone_apex, "status": "inconclusive", "nameservers_checked": 0, "servers": []}),
        _isolated_pair_check("WILDCARD DNS", check_wildcard_dns(zone_apex, work_budget.resolver_for(base_resolver, "dns_posture")), {"status": "inconclusive", "addresses": [], "records": {"A": [], "AAAA": []}}),
        _isolated_pair_check("NS CONSISTENCY", check_nameserver_consistency(zone_apex, ns_hosts, work_budget.resolver_for(base_resolver, "dns_posture"), work_budget=work_budget), {"status": "inconclusive", "observations": [], "serials_match": None, "ns_sets_match": None}),
        _isolated_pair_check("NS DIVERSITY", check_nameserver_asn_diversity(ns_hosts, work_budget.resolver_for(base_resolver, "dns_posture"), work_budget=work_budget), {"status": "inconclusive", "nameservers": [], "asns": [], "single_asn": None}),
    )
    parent_child_data, parent_child_findings = await _isolated_pair_check(
        "NS DELEGATION",
        check_parent_child_delegation(
            zone_apex, base_resolver, ns_consistency_data.get("observations", []),
            work_budget=work_budget,
        ),
        {"status": "inconclusive", "zone": zone_apex, "parent_zone": None,
         "parent_observations": [], "parent_nameservers": [], "child_nameservers": [],
         "glue": [], "delegation_matches": None},
    )
    wildcard_ips = set(wildcard_data.get("addresses", []))
    if wildcard_data.get("status") == "detected" and sub_data.get("subdomains"):
        for subdomain in sub_data["subdomains"]:
            ips = set(subdomain.get("ips", []))
            if ips and not subdomain.get("cname") and ips.issubset(wildcard_ips):
                subdomain["status"] = "wildcard_only"
                subdomain["wildcard_only"] = True
        sub_data["subdomains"].sort(key=lambda item: (
            -item.get("risk_score", 0),
            {"dangling": 0, "unverified": 1, "resolving": 2, "wildcard_only": 3, "inactive": 4}.get(item.get("status"), 5),
            item.get("subdomain", ""),
        ))
    dmarc_findings = analyze_dmarc(dmarc_data) + dmarc_scan_findings
    dkim_findings = analyze_dkim(dkim_data) + dkim_scan_findings

    # BIMI check (needs parsed DMARC)
    bimi_data, bimi_scan_findings = await _isolated_pair_check(
        "BIMI", check_bimi(domain, dmarc_data, work_budget.resolver_for(base_resolver, "bimi")),
        {"status": "inconclusive", "has_bimi": False, "dmarc_eligible": False, "error": "BIMI lookup failed."},
    )
    bimi_findings = bimi_scan_findings

    extensions, extension_findings = await run_registered_checks(
        domain,
        base_resolver,
        work_budget,
        records,
    )

    # Email health score
    email_score_data = compute_email_score(spf_findings, dmarc_findings, dkim_findings)

    # Holistic Domain Security & Health Score
    domain_score_data = compute_domain_score(
        records=records,
        dns_findings=findings,
        email_score=email_score_data,
        dnssec_data=dnssec_data,
        takeover_data=takeover_data,
        tls_data=tls_data,
        dns_posture_data={"axfr": axfr_data, "wildcard": wildcard_data, "nameserver_consistency": ns_consistency_data, "nameserver_asn_diversity": ns_asn_data, "parent_child_delegation": parent_child_data},
        mail_transport_data=mail_transport_data,
        subdomains_data=sub_data,
        email_data={
            "spf_status": "complete" if records.get("TXT", {}).get("status") in ("ok", "no_answer", "nxdomain") else "inconclusive",
            "dmarc_status": (dmarc_data or {}).get("status", "complete"),
            "dkim_status": dkim_data.get("status", "inconclusive"),
        },
        module_findings=(spf_findings + dmarc_findings + dkim_findings + mail_transport_findings + dnssec_findings + takeover_findings + tls_findings + sub_findings + axfr_findings + wildcard_findings + ns_consistency_findings + ns_asn_findings + parent_child_findings),
    )

    email_auth = EmailAuth(
        spf=spf_data,
        spf_lookups=spf_lookup_data,
        spf_flattened=spf_flat_data,
        dmarc=dmarc_data,
        dkim=dkim_data,
        mta_sts=mail_transport_data.get("mta_sts"),
        tls_rpt=mail_transport_data.get("tls_rpt"),
        score=EmailScore(**email_score_data),
    )

    security_audit = SecurityAudit(
        dnssec=dnssec_data,
        takeover=takeover_data,
        bimi=bimi_data,
    )

    # Merge all findings
    all_findings = (
        findings
        + spf_findings
        + dmarc_findings
        + dkim_findings
        + mail_transport_findings
        + dnssec_findings
        + takeover_findings
        + bimi_findings
        + tls_findings
        + sub_findings
        + axfr_findings
        + wildcard_findings
        + ns_consistency_findings
        + ns_asn_findings
        + parent_child_findings
        + extension_findings
    )
    all_counts = summarize(all_findings)
    # Findings carry severity counts; scan completeness is counted from the
    # canonical scoring checks so the summary agrees with its detailed score.
    all_counts["inconclusive"] = domain_score_data["inconclusive_count"] + sum(
        finding.severity == "inconclusive" for finding in extension_findings
    )

    # Generate Tailored 1-Click DNS Fixes
    fixes = generate_remediation_fixes(domain, all_findings, email_auth, security_audit, records=records)
    zone_snippet = generate_bind_zone_file(domain, fixes)
    coverage = _build_scan_coverage(
        records, spf_lookup_data, dmarc_data, dkim_data, dnssec_data,
        takeover_data, tls_data, sub_data, bimi_data, mail_transport_data,
        {"axfr": axfr_data, "wildcard": wildcard_data, "nameserver_consistency": ns_consistency_data, "nameserver_asn_diversity": ns_asn_data, "parent_child_delegation": parent_child_data},
    )
    for name, data in extensions.items():
        checks = data if data and all(isinstance(value, dict) for value in data.values()) else {name: data}
        for check_name, check_data in checks.items():
            status = check_data.get("status", "complete")
            coverage.append({
                "name": check_name.replace("_", " ").title(),
                "status": "partial" if status in ("inconclusive", "unavailable", "partial") else "complete",
                "detail": f"Result: {status}",
            })

    return AnalyzeResponse(
        domain=domain,
        scan_timestamp=_now_utc(),
        records=records,
        findings=all_findings,
        summary=Summary(**all_counts),
        zone_metadata=zone_meta,
        domain_score=DomainScore(**domain_score_data),
        score_breakdown=domain_score_data["score_breakdown"],
        email_auth=email_auth,
        security=security_audit,
        tls=tls_data,
        subdomains=sub_data,
        dns_posture={
            "axfr": axfr_data,
            "wildcard": wildcard_data,
            "nameserver_consistency": ns_consistency_data,
            "nameserver_asn_diversity": ns_asn_data,
            "parent_child_delegation": parent_child_data,
        },
        extensions=extensions,
        coverage=coverage,
        remediation=fixes,
        bind_zone_snippet=zone_snippet,
    )


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/health/live", include_in_schema=False)
async def health_live() -> dict[str, str]:
    """Liveness probe: the application process can serve requests."""
    return {"status": "alive"}


@app.get("/health/ready", include_in_schema=False)
async def health_ready() -> JSONResponse:
    """Readiness probe: required dashboard assets are present."""
    required_assets = (STATIC_DIR / "index.html", STATIC_DIR / "app.js", STATIC_DIR / "style.css")
    missing = [asset.name for asset in required_assets if not asset.is_file()]
    if missing:
        return JSONResponse(status_code=503, content={"status": "not_ready", "missing_assets": missing})
    return JSONResponse(content={"status": "ready"})

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def api_analyze(req: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    return await _await_scan_or_disconnect(request, _analyze_domain(req))


async def _analyze_domain(req: AnalyzeRequest) -> AnalyzeResponse:
    # Fast-path cache lookup unless force_refresh is requested
    if not req.force_refresh:
        cached = _get_cached_scan(req.domain)
        if cached:
            return cached

    async with _scan_slot():
        _enforce_target_cooldown(req.domain)
        try:
            res = await asyncio.wait_for(run_full_scan(req.domain), timeout=SCAN_TIMEOUT_SECONDS)
            _store_cached_scan(req.domain, res)
            return res
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail=f"DNS and security audit timed out after {SCAN_TIMEOUT_SECONDS:g} seconds. Please try again.",
            )
        except Exception as exc:
            logger.exception("Analysis failed for domain: %s", req.domain)
            raise HTTPException(
                status_code=500,
                detail="An error occurred during DNS analysis. Please check the domain and try again.",
            ) from exc


@app.post("/api/analyze/batch")
async def api_analyze_batch(req: BatchAnalyzeRequest, request: Request) -> dict[str, Any]:
    """Analyze a small domain set concurrently for dashboard comparison."""
    require_api_key(request)
    _enforce_rate_limit(
        request,
        cost=len(req.domains),
        limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10),
    )

    async def analyze_one(domain: str) -> dict[str, Any]:
        try:
            result = await _analyze_domain(AnalyzeRequest(domain=domain, force_refresh=req.force_refresh))
            return {"domain": domain, "status": "complete", "data": result.model_dump(mode="json")}
        except HTTPException as exc:
            return {"domain": domain, "status": "error", "status_code": exc.status_code, "error": exc.detail}

    results = await _await_scan_or_disconnect(request, asyncio.gather(*(analyze_one(domain) for domain in req.domains)))
    return {"results": results}


@app.get("/api/network/capabilities")
async def api_network_capabilities(request: Request) -> dict[str, Any]:
    """Report which optional active checks this deployment permits (no secrets returned)."""
    require_api_key(request)
    _enforce_rate_limit(request)
    return scan_capabilities()


@app.post("/api/network/list-scan")
async def api_network_list_scan(req: ListScanRequest, request: Request) -> dict[str, Any]:
    """Execute non-intrusive DNS list scan across user-specified target scope."""
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    if not req.targets or len(req.targets) > 50:
        raise HTTPException(status_code=400, detail="Provide between 1 and 50 target hostnames or IPs.")
    async def execute() -> dict[str, Any]:
        async with _scan_slot():
            for target in req.targets:
                _enforce_target_cooldown(target, "resolve")
            import dns.asyncresolver
            budget = ScanWorkBudget(profile="network_scan")
            resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
            return await run_list_scan(req.targets, resolver=resolver, work_budget=budget)

    return await _await_scan_or_disconnect(request, execute())


@app.post("/api/network/path-scan")
async def api_network_path_scan(req: PathScanRequest, request: Request) -> dict[str, Any]:
    """Check a fixed, bounded set of public website paths without crawling."""
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    if not req.targets or len(req.targets) > 5:
        raise HTTPException(status_code=400, detail="Provide between 1 and 5 target hostnames or public IPs.")
    if req.wide and not req.confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required for wide directory discovery.")
    if req.wide and len(req.targets) > 2:
        raise HTTPException(status_code=400, detail="Wide directory discovery is limited to 2 targets per request.")
    if req.wide:
        wide_token = request.headers.get("x-wide-path-token")
        auth_header = f"Bearer {wide_token}" if wide_token else request.headers.get("authorization")
        denied = [target for target in req.targets if not verify_wide_path_authorization(auth_header, target)[0]]
        if denied:
            _, message = verify_wide_path_authorization(auth_header, denied[0])
            raise HTTPException(status_code=403, detail=message)
    async def execute() -> dict[str, Any]:
        async with _scan_slot():
            for target in req.targets:
                _enforce_target_cooldown(target, "paths")
            try:
                import dns.asyncresolver
                http_budget = WIDE_PATH_SCAN_HTTP_BUDGET if req.wide else COMMON_PATH_SCAN_HTTP_BUDGET
                budget = ScanWorkBudget(profile="network_scan", http_requests=http_budget)
                resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
                result = await asyncio.wait_for(run_common_path_scan(req.targets, resolver=resolver, work_budget=budget, wide=req.wide), timeout=100.0 if req.wide else 30.0)
                _store_path_scan_results(result)
                return result
            except asyncio.TimeoutError as exc:
                raise HTTPException(status_code=504, detail="Common web path checks timed out. Retry with fewer targets.") from exc

    return await _await_scan_or_disconnect(request, execute())


@app.post("/api/network/ffuf-path-scan")
async def api_network_ffuf_path_scan(req: FfufPathRequest, request: Request) -> dict[str, Any]:
    """Execute ffuf fast fuzzing against a target using a wordlist of paths."""
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    if not req.target or len(req.target) > 253:
        raise HTTPException(status_code=400, detail="Invalid target provided.")
    if not req.confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required for ffuf directory discovery.")
    async def execute() -> dict[str, Any]:
        async with _scan_slot():
            if not is_wide_directory_scan_allowed():
                raise HTTPException(status_code=403, detail="Wide directory discovery is disabled by server policy.")
            wide_token = request.headers.get("x-wide-path-token")
            auth_header = f"Bearer {wide_token}" if wide_token else request.headers.get("authorization")
            auth_ok, auth_msg = verify_wide_path_authorization(auth_header, req.target)
            if not auth_ok:
                raise HTTPException(status_code=403, detail=auth_msg)
            import dns.asyncresolver
            budget = ScanWorkBudget(profile="network_scan")
            budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
            result = await asyncio.wait_for(
                run_ffuf_scan(req.target, wordlist=req.wordlist, rate=req.rate, timeout=req.timeout, auth_header=auth_header),
                timeout=60.0,
            )
            _store_path_scan_results(result)
            return result

    return await _await_scan_or_disconnect(request, execute())


@app.post("/api/email/dkim-selectors")
async def api_dkim_selector_check(req: DkimSelectorRequest, request: Request) -> dict[str, Any]:
    """Check user-supplied DKIM selectors for the analyzed domain."""
    _enforce_rate_limit(request)
    async with _scan_slot():
        import dns.asyncresolver
        budget = ScanWorkBudget()
        resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "dkim")
        try:
            result = await asyncio.wait_for(
                check_dkim_selectors(req.domain, resolver, custom_selectors=req.selectors),
                timeout=12.0,
            )
            _store_custom_dkim(req.domain, req.selectors, result)
            return result
        except asyncio.TimeoutError as exc:
            raise HTTPException(status_code=504, detail="DKIM selector checks timed out.") from exc


@app.post("/api/network/port-scan")
async def api_network_port_scan(req: PortScanRequest, request: Request) -> dict[str, Any]:
    """Execute scoped, opt-in port & service verification on explicitly approved target."""
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    if not req.target or len(req.target) > 253:
        raise HTTPException(status_code=400, detail="Invalid target provided.")
    auth_header = request.headers.get("authorization")
    port_token = request.headers.get("x-port-scan-token")
    if req.auth_token:
        logger.warning("Deprecated port-scan auth_token body field used; use X-Port-Scan-Token")
        port_token = port_token or req.auth_token
    if port_token:
        auth_header = f"Bearer {port_token}"
    target_cooldown_eligible = (
        req.confirmed
        and is_active_scan_allowed()
        and verify_port_scan_authorization(auth_header, req.target)[0]
    )
    async def execute() -> dict[str, Any]:
        async with _scan_slot():
            if target_cooldown_eligible:
                _enforce_target_cooldown(req.target, "ports")
            import dns.asyncresolver
            budget = ScanWorkBudget(profile="network_scan")
            resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
            return await run_port_scan(
                req.target,
                ports=req.ports,
                confirmed=req.confirmed,
                auth_header=auth_header,
                resolver=resolver,
                scanner=req.scanner,
                wide=req.wide,
            )

    return await _await_scan_or_disconnect(request, execute())


@app.get("/api/subdomains/{domain}")
async def api_subdomains(domain: str, request: Request) -> dict[str, Any]:
    """Query Certificate Transparency logs for passive subdomain discovery."""
    _enforce_rate_limit(request)
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    async with _scan_slot():
        try:
            import dns.asyncresolver
            budget = ScanWorkBudget()
            resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "subdomains")
            data, _ = await asyncio.wait_for(
                discover_passive_subdomains(req.domain, resolver, work_budget=budget),
                timeout=10.0,
            )
            return data
        except asyncio.TimeoutError:
            raise HTTPException(status_code=504, detail="Subdomain discovery timed out.")
        except Exception as exc:
            logger.exception("Subdomain discovery failed for domain: %s", req.domain)
            raise HTTPException(status_code=500, detail="Failed to retrieve subdomain records.") from exc


@app.post("/api/subdomains/enumerate")
async def api_subdomains_enumerate(req: SubdomainEnumerateRequest, request: Request) -> dict[str, Any]:
    """Actively enumerate common high-signal subdomains using fast DNS probes."""
    require_api_key(request)
    _enforce_rate_limit(request)
    async with _scan_slot():
        try:
            import dns.asyncresolver
            budget = ScanWorkBudget(profile="network_scan")
            resolver = budget.resolver_for(dns.asyncresolver.Resolver(), "network_scan")
            return await _await_scan_or_disconnect(
                request,
                enumerate_active_subdomains(
                    req.domain,
                    resolver=resolver,
                    wordlist=req.custom_words,
                    work_budget=budget,
                ),
            )
        except Exception as exc:
            logger.exception("Subdomain enumeration failed for domain: %s", req.domain)
            raise HTTPException(status_code=500, detail="Failed to enumerate subdomains.") from exc


@app.get("/api/badge/{domain}", response_class=Response)
async def api_grade_badge(domain: str, request: Request) -> Response:
    """Serve a cached grade badge only after an analysis has populated scan cache."""
    _enforce_rate_limit(request)
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = asyncio.get_running_loop().time()
    scan = _get_cached_scan(req.domain)
    if not scan or not scan.domain_score:
        _BADGE_CACHE.pop(req.domain, None)
        raise HTTPException(status_code=404, detail="No recent scan is available for this domain. Run an analysis first.")
    scan_cached_at = _SCAN_CACHE[req.domain][0]
    remaining_ttl = max(0, int(_SCAN_CACHE_TTL - (now - scan_cached_at)))
    cached_badge = _BADGE_CACHE.get(req.domain)
    if cached_badge and now - scan_cached_at < _SCAN_CACHE_TTL:
        return Response(cached_badge[1], media_type="image/svg+xml", headers={"Cache-Control": f"public, max-age={remaining_ttl}"})
    grade = scan.domain_score.grade
    color = "#63b995" if grade.startswith("A") else "#e0a458" if grade.startswith(("B", "C")) else "#e36d6d"
    label = f"{req.domain} · {grade} · {scan.domain_score.score}/100"
    import html as html_module
    escaped_label = html_module.escape(label, quote=True)
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="310" height="28" role="img" '
        f'aria-label="{escaped_label}"><title>{escaped_label}</title>'
        '<rect width="310" height="28" rx="5" fill="#1b1e22"/>'
        f'<path d="M0 5a5 5 0 0 1 5-5h300a5 5 0 0 1 5 5v18a5 5 0 0 1-5 5H5a5 5 0 0 1-5-5z" fill="#1b1e22"/>'
        f'<path d="M0 5a5 5 0 0 1 5-5h82v28H5a5 5 0 0 1-5-5z" fill="{color}"/>'
        f'<text x="10" y="18" fill="#0c0d0e" font-family="Arial,sans-serif" font-size="11" font-weight="700">{html_module.escape(req.domain)}</text>'
        f'<text x="96" y="18" fill="#f2f0ea" font-family="Arial,sans-serif" font-size="11" font-weight="700">Grade {grade} · {scan.domain_score.score}/100</text></svg>'
    ).encode("utf-8")
    if len(_BADGE_CACHE) >= 256 and req.domain not in _BADGE_CACHE:
        del _BADGE_CACHE[min(_BADGE_CACHE, key=lambda key: _BADGE_CACHE[key][0])]
    _BADGE_CACHE[req.domain] = (now, svg)
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": f"public, max-age={remaining_ttl}"})


@app.get("/api/report/{domain}", response_class=HTMLResponse)
async def api_report(domain: str, request: Request) -> HTMLResponse:
    """Return a downloadable self-contained HTML report (reusing recent scan if available)."""
    require_api_key(request)
    _enforce_rate_limit(request, limit=_configured_limit("DNS_ANALYZER_EXPENSIVE_RATE_LIMIT_PER_MIN", 10))
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        scan = _get_cached_scan(req.domain)
        if not scan:
            try:
                await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=SEMAPHORE_WAIT_TIMEOUT)
            except asyncio.TimeoutError:
                raise HTTPException(
                    status_code=503,
                    detail="Server is experiencing high scan volume. Please retry shortly.",
                )
            try:
                _enforce_target_cooldown(req.domain)
                scan = await asyncio.wait_for(run_full_scan(req.domain), timeout=SCAN_TIMEOUT_SECONDS)
                _store_cached_scan(req.domain, scan)
            finally:
                SCAN_SEMAPHORE.release()

        report_coverage = [dict(item) for item in (scan.coverage or [])]
        cached_paths = _get_cached_path_scan(req.domain)
        report_email_auth = scan.email_auth
        custom_dkim = _get_cached_custom_dkim(req.domain)
        if custom_dkim and report_email_auth:
            standard_dkim = report_email_auth.dkim or {}
            found = {item.get("selector"): item for item in standard_dkim.get("selectors_found", [])}
            found.update({item.get("selector"): item for item in custom_dkim.get("selectors_found", [])})
            merged_dkim = {
                **standard_dkim,
                **custom_dkim,
                "selectors_found": list(found.values()),
                "has_dkim": bool(found),
            }
            report_email_auth = report_email_auth.model_copy(update={"dkim": merged_dkim})
        if cached_paths:
            matching = next((item for item in cached_paths.get("targets", []) if item.get("target", "").lower().rstrip(".") == req.domain), None)
            if matching:
                for coverage_item in report_coverage:
                    if coverage_item["name"] == "Common web paths":
                        coverage_item["status"] = matching.get("status", "partial")
                        coverage_item["detail"] = "Recent standalone path scan included in this report"
        html = build_report(
            domain=scan.domain,
            scan_timestamp=scan.scan_timestamp,
            records=scan.records,
            findings=scan.findings,
            summary=scan.summary,
            email_auth=report_email_auth,
            security=scan.security,
            remediation=scan.remediation or [],
            tls=scan.tls,
            subdomains=scan.subdomains,
            path_scan=cached_paths,
            coverage=report_coverage,
            dns_posture=scan.dns_posture,
            domain_score=scan.domain_score,
            extensions=scan.extensions,
        )
        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition": f'attachment; filename="dns-report-{req.domain}.html"'
            },
        )
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Report generation timed out.")
    except Exception as exc:
        logger.exception("Report generation failed for domain: %s", domain)
        raise HTTPException(
            status_code=500,
            detail="Failed to generate domain security report. Please try again later.",
        ) from exc



# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled server exception at %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred. Please try again later."},
    )


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Do not echo rejected request values, which may contain credentials."""
    return JSONResponse(status_code=422, content={"detail": "Invalid request."})


# ---------------------------------------------------------------------------
# Static files (served last so /api/* routes take priority)
# ---------------------------------------------------------------------------

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if not STATIC_DIR.is_dir():
    import sys
    STATIC_DIR = Path(sys.prefix) / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    with open(STATIC_DIR / "index.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
