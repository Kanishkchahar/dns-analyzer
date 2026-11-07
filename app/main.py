"""FastAPI application — routes, static file serving, error handling."""

import asyncio
from datetime import datetime, timezone
import logging
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
async def api_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return await run_full_scan(req.domain)
    except Exception as exc:
        logger.exception("Analysis failed for domain: %s", req.domain)
        raise HTTPException(
            status_code=500,
            detail="An error occurred during DNS analysis. Please check the domain and try again.",
        ) from exc


@app.post("/api/network/list-scan")
async def api_network_list_scan(req: ListScanRequest) -> dict[str, Any]:
    """Execute non-intrusive DNS list scan across user-specified target scope."""
    if not req.targets or len(req.targets) > 50:
        raise HTTPException(status_code=400, detail="Provide between 1 and 50 target hostnames or IPs.")
    return await run_list_scan(req.targets)


@app.post("/api/network/port-scan")
async def api_network_port_scan(req: PortScanRequest) -> dict[str, Any]:
    """Execute scoped, opt-in port & service verification on explicitly approved target."""
    if not req.target or len(req.target) > 253:
        raise HTTPException(status_code=400, detail="Invalid target provided.")
    return await run_port_scan(req.target, ports=req.ports, confirmed=req.confirmed)


@app.get("/api/subdomains/{domain}")
async def api_subdomains(domain: str) -> dict[str, Any]:
    """Query Certificate Transparency logs for passive subdomain discovery."""
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    data, _ = await discover_passive_subdomains(req.domain, resolver)
    return data


@app.get("/api/report/{domain}", response_class=HTMLResponse)
async def api_report(domain: str) -> HTMLResponse:
    """Re-run analysis and return a downloadable self-contained HTML report."""
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        scan = await run_full_scan(req.domain)
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
