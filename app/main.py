"""FastAPI application — routes, static file serving, error handling."""

import asyncio
from datetime import datetime, timezone
import logging
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.analyzer import analyze, summarize
from app.bimi import check_bimi
from app.dnssec import check_dnssec
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
    Finding,
    ListScanRequest,
    PortScanRequest,
    RemediationFix,
    SecurityAudit,
    Summary,
)
from app.network_scan import run_list_scan, run_port_scan
from app.remediation import generate_bind_zone_file, generate_remediation_fixes
from app.report import build_report
from app.resolver import resolve_domain
from app.spf import analyze_spf, count_spf_lookups, flatten_spf, parse_spf
from app.subdomains import discover_passive_subdomains
from app.takeover import check_subdomain_takeover
from app.tls_check import audit_tls_and_https

logger = logging.getLogger("dns_analyzer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

app = FastAPI(title="DNS Analyzer", version="2.0.0")

# Concurrency & runtime throttle budgets
SCAN_SEMAPHORE = asyncio.Semaphore(8)
SCAN_TIMEOUT_SECONDS = 15.0
SEMAPHORE_WAIT_TIMEOUT = 3.0

# In-memory recent scan cache (TTL 60s, max 128 domains) to prevent redundant queries
_SCAN_CACHE: dict[str, tuple[float, AnalyzeResponse]] = {}
_SCAN_CACHE_TTL = 60.0

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


async def run_full_scan(domain: str) -> AnalyzeResponse:
    """Execute end-to-end DNS, security, and email authentication audit for a domain."""
    records = await resolve_domain(domain)
    findings = analyze(domain, records)

    zone_meta = records.get("zone_metadata", {})
    zone_apex = zone_meta.get("zone_apex", domain)

    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()

    # SPF
    txt_records = records.get("TXT", {}).get("records", [])
    spf_data = parse_spf(txt_records)
    spf_lookup_data = await count_spf_lookups(domain, resolver) if spf_data else None
    spf_flat_data = await flatten_spf(domain, resolver) if spf_data else None
    spf_findings = analyze_spf(spf_data, spf_lookup_data, txt_records=txt_records)

    # DMARC & DKIM & DNSSEC & Subdomain Takeover & TLS & Passive CT Recon (run concurrently)
    (
        dmarc_data,
        dkim_data,
        (dnssec_data, dnssec_findings),
        (takeover_data, takeover_findings),
        (tls_data, tls_findings),
        (sub_data, sub_findings),
    ) = await asyncio.gather(
        fetch_dmarc(domain, resolver, apex=zone_apex),
        check_dkim_selectors(domain, resolver),
        check_dnssec(domain, resolver, apex=zone_apex),
        check_subdomain_takeover(domain, records, resolver),
        audit_tls_and_https(domain),
        discover_passive_subdomains(zone_apex, resolver),
    )
    dmarc_findings = analyze_dmarc(dmarc_data)
    dkim_findings = analyze_dkim(dkim_data)

    # BIMI check (needs parsed DMARC)
    bimi_data, bimi_findings = await check_bimi(domain, dmarc_data, resolver)

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
        + dnssec_findings
        + takeover_findings
        + bimi_findings
        + tls_findings
        + sub_findings
    )
    all_counts = summarize(all_findings)

    # Generate Tailored 1-Click DNS Fixes
    fixes = generate_remediation_fixes(domain, all_findings, email_auth, security_audit, records=records)
    zone_snippet = generate_bind_zone_file(domain, fixes)

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
            detail="DNS and security audit timed out after 15 seconds. Please try again.",
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

        html = build_report(
            domain=scan.domain,
            scan_timestamp=scan.scan_timestamp,
            records=scan.records,
            findings=scan.findings,
            summary=scan.summary,
            email_auth=scan.email_auth,
            security=scan.security,
            remediation=scan.remediation or [],
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

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
