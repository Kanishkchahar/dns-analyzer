"""FastAPI application — routes, static file serving, error handling."""

import asyncio
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.analyzer import analyze, summarize
from app.bimi import check_bimi
from app.dnssec import check_dnssec
from app.dns_posture import check_nameserver_consistency, check_wildcard_dns, check_zone_transfers
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
    AnalyzeResponse,
    DomainScore,
    EmailAuth,
    EmailScore,
    DkimSelectorRequest,
    Finding,
    ListScanRequest,
    PortScanRequest,
    PathScanRequest,
    RemediationFix,
    SecurityAudit,
    Summary,
)
from app.mail_transport import check_mail_transport
from app.network_scan import run_common_path_scan, run_list_scan, run_port_scan
from app.remediation import generate_bind_zone_file, generate_remediation_fixes
from app.report import build_report
from app.resolver import resolve_domain
from app.spf import analyze_spf, count_spf_lookups, flatten_spf, parse_spf
from app.subdomains import discover_passive_subdomains
from app.takeover import check_subdomain_takeover
from app.tls_check import audit_tls_and_https

logger = logging.getLogger("dns_analyzer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = FastAPI(title="DNS Analyzer", version="2.1.0")

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
_CUSTOM_DKIM_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_BADGE_CACHE: dict[str, tuple[float, bytes]] = {}

# In-memory client rate limiter (60 requests per minute per IP, bounded to 2048 client records)
_CLIENT_REQUESTS: dict[str, list[float]] = {}
_RATE_WINDOW = 60.0
_MAX_REQ_PER_WINDOW = 60
_MAX_TRACKED_IPS = 2048


def _get_cached_scan(domain: str) -> AnalyzeResponse | None:
    now = asyncio.get_running_loop().time()
    if domain in _SCAN_CACHE:
        cached_time, response = _SCAN_CACHE[domain]
        if now - cached_time < _SCAN_CACHE_TTL:
            return response
        del _SCAN_CACHE[domain]
    return None


def _store_cached_scan(domain: str, response: AnalyzeResponse) -> None:
    now = asyncio.get_running_loop().time()
    if len(_SCAN_CACHE) >= 128:
        oldest_key = min(_SCAN_CACHE.keys(), key=lambda k: _SCAN_CACHE[k][0])
        del _SCAN_CACHE[oldest_key]
    _SCAN_CACHE[domain] = (now, response)
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


def _store_custom_dkim(domain: str, result: dict[str, Any]) -> None:
    if len(_CUSTOM_DKIM_CACHE) >= 128 and domain not in _CUSTOM_DKIM_CACHE:
        oldest = min(_CUSTOM_DKIM_CACHE, key=lambda key: _CUSTOM_DKIM_CACHE[key][0])
        del _CUSTOM_DKIM_CACHE[oldest]
    _CUSTOM_DKIM_CACHE[domain] = (asyncio.get_running_loop().time(), result)


def _get_cached_custom_dkim(domain: str) -> dict[str, Any] | None:
    cached = _CUSTOM_DKIM_CACHE.get(domain)
    if not cached:
        return None
    cached_time, result = cached
    if asyncio.get_running_loop().time() - cached_time >= _PATH_SCAN_CACHE_TTL:
        del _CUSTOM_DKIM_CACHE[domain]
        return None
    return result


def _extract_client_ip(request: Request) -> str:
    """Extract client IP, inspecting X-Forwarded-For only if proxy trust is enabled.

    WARNING: Only enable TRUST_REVERSE_PROXY=true when running behind an upstream reverse
    proxy that strips or overwrites untrusted incoming X-Forwarded-For headers from external
    clients. If enabled on an exposed direct host, callers may spoof their rate-limiting IP.
    """
    trust_proxy = os.environ.get("TRUST_REVERSE_PROXY", "false").strip().lower() in ("true", "1", "yes")
    if trust_proxy and "x-forwarded-for" in request.headers:
        forwarded = request.headers["x-forwarded-for"].split(",")
        if forwarded:
            return forwarded[0].strip()
    return request.client.host if request.client else "unknown"


def _enforce_rate_limit(request: Request) -> None:
    client_ip = _extract_client_ip(request)
    # Unit tests bypass artificial rate limit
    if os.environ.get("TESTING") == "true" or client_ip == "testclient":
        return

    now = asyncio.get_running_loop().time()
    cutoff = now - _RATE_WINDOW

    # Bounded cache cleanup: purge stale IP records if table exceeds limit
    if len(_CLIENT_REQUESTS) > _MAX_TRACKED_IPS:
        stale_keys = [ip for ip, timestamps in _CLIENT_REQUESTS.items() if not timestamps or timestamps[-1] <= cutoff]
        for ip in stale_keys:
            del _CLIENT_REQUESTS[ip]
        if len(_CLIENT_REQUESTS) > _MAX_TRACKED_IPS:
            for ip in list(_CLIENT_REQUESTS.keys())[:512]:
                del _CLIENT_REQUESTS[ip]

    reqs = _CLIENT_REQUESTS.setdefault(client_ip, [])
    _CLIENT_REQUESTS[client_ip] = [t for t in reqs if t > cutoff]

    # Limit: 60 req/min for public clients, 120 req/min for local loopback
    max_reqs = 120 if client_ip == "127.0.0.1" else _MAX_REQ_PER_WINDOW
    if len(_CLIENT_REQUESTS[client_ip]) >= max_reqs:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please wait a moment before sending additional requests.",
        )
    _CLIENT_REQUESTS[client_ip].append(now)




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
        if isinstance(entry, dict) and entry.get("status") in ("timeout", "no_nameservers", "error")
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
    return result


def _check_failure(name: str, exc: Exception) -> Finding:
    logger.warning("%s check failed: %s", name, type(exc).__name__)
    return Finding(
        severity="info",
        record_type=name,
        message=f"{name} check could not complete ({type(exc).__name__}). Other scan results are still available.",
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
    records = await resolve_domain(domain)
    findings = analyze(domain, records)

    zone_meta = records.get("zone_metadata", {})
    zone_apex = zone_meta.get("zone_apex", domain)

    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    ns_records = records.get("NS", {}).get("records", [])
    ns_hosts = [item.get("host") if isinstance(item, dict) else str(item) for item in ns_records]

    # SPF
    txt_records = records.get("TXT", {}).get("records", [])
    spf_data = parse_spf(txt_records)
    spf_lookup_data = None
    spf_flat_data = None
    spf_scan_findings: list[Finding] = []
    if spf_data:
        lookup_result, flatten_result = await asyncio.gather(
            asyncio.wait_for(count_spf_lookups(domain, resolver), timeout=SPF_CHECK_TIMEOUT_SECONDS),
            asyncio.wait_for(flatten_spf(domain, resolver), timeout=SPF_CHECK_TIMEOUT_SECONDS),
            return_exceptions=True,
        )
        if isinstance(lookup_result, BaseException):
            spf_lookup_data = {
                "status": "inconclusive", "total_lookups": 0, "limit": 10,
                "over_limit": False, "lookup_tree": [], "reason": str(lookup_result) or type(lookup_result).__name__,
            }
            spf_scan_findings.append(_check_failure("SPF Lookup Count", lookup_result if isinstance(lookup_result, Exception) else RuntimeError(type(lookup_result).__name__)))
        else:
            spf_lookup_data = lookup_result
        if isinstance(flatten_result, BaseException):
            spf_flat_data = {
                "can_flatten": False, "flattened_record": None,
                "reason": f"SPF flattening could not complete ({type(flatten_result).__name__}).",
                "ip4_ranges": [], "ip6_ranges": [], "original_lookups": 0, "flattened_lookups": 0,
            }
            spf_scan_findings.append(_check_failure("SPF Flattening", flatten_result if isinstance(flatten_result, Exception) else RuntimeError(type(flatten_result).__name__)))
        else:
            spf_flat_data = flatten_result
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
    ) = await asyncio.gather(
        _isolated_data_check("DMARC", fetch_dmarc(domain, resolver, apex=zone_apex), {"status": "inconclusive", "policy": None, "reason": "DMARC lookup failed."}),
        _isolated_data_check("DKIM", check_dkim_selectors(domain, resolver), {"status": "inconclusive", "selectors_found": [], "selectors_checked": [], "has_dkim": False}),
        _isolated_pair_check("DNSSEC", check_dnssec(domain, resolver, apex=zone_apex), {"status": "inconclusive", "enabled": False, "delegation_verified": False, "reason": "DNSSEC queries failed."}),
        _isolated_pair_check("TAKEOVER", check_subdomain_takeover(domain, records, resolver), {"scanned": False, "vulnerable": False, "status": "could_not_verify", "details": "Takeover check did not complete."}),
        _isolated_pair_check("TLS", audit_tls_and_https(domain), {"scanned": False, "status": "error", "reason": "TLS audit did not complete."}),
        _isolated_pair_check("SUBDOMAINS", discover_passive_subdomains(zone_apex, resolver), {"domain": zone_apex, "source": "Certificate Transparency (crt.sh)", "status": "unavailable", "reason": "Subdomain inventory did not complete.", "discovered_count": 0, "subdomains": []}),
        _isolated_pair_check("MAIL TRANSPORT", check_mail_transport(domain, resolver), {"mta_sts": {"status": "inconclusive", "reason": "Check did not complete."}, "tls_rpt": {"status": "inconclusive", "reason": "Check did not complete."}}),
        _isolated_pair_check("AXFR", check_zone_transfers(zone_apex, ns_hosts, resolver), {"zone": zone_apex, "status": "inconclusive", "nameservers_checked": 0, "servers": []}),
        _isolated_pair_check("WILDCARD DNS", check_wildcard_dns(zone_apex, resolver), {"status": "inconclusive", "addresses": [], "records": {"A": [], "AAAA": []}}),
        _isolated_pair_check("NS CONSISTENCY", check_nameserver_consistency(zone_apex, ns_hosts, resolver), {"status": "inconclusive", "observations": [], "serials_match": None, "ns_sets_match": None}),
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
        "BIMI", check_bimi(domain, dmarc_data, resolver),
        {"status": "inconclusive", "has_bimi": False, "dmarc_eligible": False, "error": "BIMI lookup failed."},
    )
    bimi_findings = bimi_scan_findings

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
    )
    all_counts = summarize(all_findings)

    # Generate Tailored 1-Click DNS Fixes
    fixes = generate_remediation_fixes(domain, all_findings, email_auth, security_audit, records=records)
    zone_snippet = generate_bind_zone_file(domain, fixes)
    coverage = _build_scan_coverage(
        records, spf_lookup_data, dmarc_data, dkim_data, dnssec_data,
        takeover_data, tls_data, sub_data, bimi_data, mail_transport_data,
        {"axfr": axfr_data, "wildcard": wildcard_data, "nameserver_consistency": ns_consistency_data},
    )

    return AnalyzeResponse(
        domain=domain,
        scan_timestamp=_now_utc(),
        records=records,
        findings=all_findings,
        summary=Summary(**all_counts),
        zone_metadata=zone_meta,
        domain_score=DomainScore(**domain_score_data),
        email_auth=email_auth,
        security=security_audit,
        tls=tls_data,
        subdomains=sub_data,
        dns_posture={
            "axfr": axfr_data,
            "wildcard": wildcard_data,
            "nameserver_consistency": ns_consistency_data,
        },
        coverage=coverage,
        remediation=fixes,
        bind_zone_snippet=zone_snippet,
    )


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def api_analyze(req: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    _enforce_rate_limit(request)

    # Fast-path cache lookup unless force_refresh is requested
    if not req.force_refresh:
        cached = _get_cached_scan(req.domain)
        if cached:
            return cached

    # Bound concurrency queue wait
    try:
        await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=SEMAPHORE_WAIT_TIMEOUT)
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=503,
            detail="Server is experiencing high scan volume. Please retry shortly.",
        )

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
    finally:
        SCAN_SEMAPHORE.release()


@app.post("/api/network/list-scan")
async def api_network_list_scan(req: ListScanRequest, request: Request) -> dict[str, Any]:
    """Execute non-intrusive DNS list scan across user-specified target scope."""
    _enforce_rate_limit(request)
    if not req.targets or len(req.targets) > 50:
        raise HTTPException(status_code=400, detail="Provide between 1 and 50 target hostnames or IPs.")
    return await run_list_scan(req.targets)


@app.post("/api/network/path-scan")
async def api_network_path_scan(req: PathScanRequest, request: Request) -> dict[str, Any]:
    """Check a fixed, bounded set of public website paths without crawling."""
    _enforce_rate_limit(request)
    if not req.targets or len(req.targets) > 5:
        raise HTTPException(status_code=400, detail="Provide between 1 and 5 target hostnames or public IPs.")
    try:
        result = await asyncio.wait_for(run_common_path_scan(req.targets), timeout=30.0)
        _store_path_scan_results(result)
        return result
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Common web path checks timed out. Retry with fewer targets.") from exc


@app.post("/api/email/dkim-selectors")
async def api_dkim_selector_check(req: DkimSelectorRequest, request: Request) -> dict[str, Any]:
    """Check user-supplied DKIM selectors for the analyzed domain."""
    _enforce_rate_limit(request)
    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    try:
        result = await asyncio.wait_for(
            check_dkim_selectors(req.domain, resolver, custom_selectors=req.selectors),
            timeout=12.0,
        )
        _store_custom_dkim(req.domain, result)
        return result
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="DKIM selector checks timed out.") from exc


@app.post("/api/network/port-scan")
async def api_network_port_scan(req: PortScanRequest, request: Request) -> dict[str, Any]:
    """Execute scoped, opt-in port & service verification on explicitly approved target."""
    _enforce_rate_limit(request)
    if not req.target or len(req.target) > 253:
        raise HTTPException(status_code=400, detail="Invalid target provided.")
    auth_header = request.headers.get("authorization")
    return await run_port_scan(
        req.target,
        ports=req.ports,
        confirmed=req.confirmed,
        auth_token=req.auth_token,
        auth_header=auth_header,
    )


@app.get("/api/subdomains/{domain}")
async def api_subdomains(domain: str, request: Request) -> dict[str, Any]:
    """Query Certificate Transparency logs for passive subdomain discovery."""
    _enforce_rate_limit(request)
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()
        data, _ = await asyncio.wait_for(
            discover_passive_subdomains(req.domain, resolver),
            timeout=10.0,
        )
        return data
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Subdomain discovery timed out.")
    except Exception as exc:
        logger.exception("Subdomain discovery failed for domain: %s", req.domain)
        raise HTTPException(status_code=500, detail="Failed to retrieve subdomain records.") from exc


@app.get("/api/badge/{domain}", response_class=Response)
async def api_grade_badge(domain: str, request: Request) -> Response:
    """Serve a cached grade badge only after an analysis has populated scan cache."""
    _enforce_rate_limit(request)
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = asyncio.get_running_loop().time()
    cached_badge = _BADGE_CACHE.get(req.domain)
    if cached_badge and now - cached_badge[0] < 3600:
        return Response(cached_badge[1], media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})
    scan = _get_cached_scan(req.domain)
    if not scan or not scan.domain_score:
        raise HTTPException(status_code=404, detail="No recent scan is available for this domain. Run an analysis first.")
    grade = scan.domain_score.grade
    color = "#63b995" if grade.startswith("A") else "#e0a458" if grade in ("B", "C") else "#e36d6d"
    label = f"{req.domain} · {grade} · {scan.domain_score.score}/100"
    import html as html_module
    escaped_label = html_module.escape(label, quote=True)
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="230" height="28" role="img" '
        f'aria-label="{escaped_label}"><title>{escaped_label}</title>'
        '<rect width="230" height="28" rx="5" fill="#1b1e22"/>'
        f'<path d="M0 5a5 5 0 0 1 5-5h220a5 5 0 0 1 5 5v18a5 5 0 0 1-5 5H5a5 5 0 0 1-5-5z" fill="#1b1e22"/>'
        f'<path d="M0 5a5 5 0 0 1 5-5h82v28H5a5 5 0 0 1-5-5z" fill="{color}"/>'
        f'<text x="10" y="18" fill="#0c0d0e" font-family="Arial,sans-serif" font-size="11" font-weight="700">{html_module.escape(req.domain)}</text>'
        f'<text x="96" y="18" fill="#f2f0ea" font-family="Arial,sans-serif" font-size="11" font-weight="700">Grade {grade} · {scan.domain_score.score}/100</text></svg>'
    ).encode("utf-8")
    if len(_BADGE_CACHE) >= 256 and req.domain not in _BADGE_CACHE:
        del _BADGE_CACHE[min(_BADGE_CACHE, key=lambda key: _BADGE_CACHE[key][0])]
    _BADGE_CACHE[req.domain] = (now, svg)
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})


@app.get("/api/report/{domain}", response_class=HTMLResponse)
async def api_report(domain: str, request: Request) -> HTMLResponse:
    """Return a downloadable self-contained HTML report (reusing recent scan if available)."""
    _enforce_rate_limit(request)
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
