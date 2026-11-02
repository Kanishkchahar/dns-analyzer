"""FastAPI application — routes, static file serving, error handling."""

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.analyzer import analyze, summarize
from app.bimi import check_bimi
from app.dnssec import check_dnssec
from app.email_auth import analyze_dkim, analyze_dmarc, check_dkim_selectors, compute_email_score, fetch_dmarc
from app.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    EmailAuth,
    EmailScore,
    Finding,
    RemediationFix,
    SecurityAudit,
    Summary,
)
from app.remediation import generate_bind_zone_file, generate_remediation_fixes
from app.report import build_report
from app.resolver import resolve_domain
from app.spf import analyze_spf, count_spf_lookups, flatten_spf, parse_spf
from app.takeover import check_subdomain_takeover

app = FastAPI(title="DNS Analyzer", version="2.0.0")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def api_analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    try:
        records = await resolve_domain(req.domain)
        findings = analyze(req.domain, records)
        counts = summarize(findings)

        # ── Email authentication analysis ──
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()

        # SPF
        txt_records = records.get("TXT", {}).get("records", [])
        spf_data = parse_spf(txt_records)
        spf_lookup_data = await count_spf_lookups(req.domain, resolver) if spf_data else None
        spf_flat_data = await flatten_spf(req.domain, resolver) if spf_data else None
        spf_findings = analyze_spf(spf_data, spf_lookup_data, txt_records=txt_records)

        # DMARC & DKIM (run concurrently)
        dmarc_data, dkim_data, (dnssec_data, dnssec_findings), (takeover_data, takeover_findings) = await asyncio.gather(
            fetch_dmarc(req.domain, resolver),
            check_dkim_selectors(req.domain, resolver),
            check_dnssec(req.domain, resolver),
            check_subdomain_takeover(req.domain, records, resolver),
        )
        dmarc_findings = analyze_dmarc(dmarc_data)
        dkim_findings = analyze_dkim(dkim_data)

        # BIMI check (needs parsed DMARC)
        bimi_data, bimi_findings = await check_bimi(req.domain, dmarc_data, resolver)

        # Email health score
        score_data = compute_email_score(spf_findings, dmarc_findings, dkim_findings)

        email_auth = EmailAuth(
            spf=spf_data,
            spf_lookups=spf_lookup_data,
            spf_flattened=spf_flat_data,
            dmarc=dmarc_data,
            dkim=dkim_data,
            score=EmailScore(**score_data),
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
        )
        all_counts = summarize(all_findings)

        # Generate Tailored 1-Click DNS Fixes
        fixes = generate_remediation_fixes(req.domain, all_findings, email_auth, security_audit)
        zone_snippet = generate_bind_zone_file(req.domain, fixes)

        return AnalyzeResponse(
            domain=req.domain,
            scan_timestamp=_now_utc(),
            records=records,
            findings=all_findings,
            summary=Summary(**all_counts),
            email_auth=email_auth,
            security=security_audit,
            remediation=fixes,
            bind_zone_snippet=zone_snippet,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal error during DNS analysis: {exc}") from exc


@app.get("/api/report/{domain}", response_class=HTMLResponse)
async def api_report(domain: str) -> HTMLResponse:
    """Re-run analysis and return a downloadable self-contained HTML report."""
    try:
        req = AnalyzeRequest(domain=domain)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        records = await resolve_domain(req.domain)
        findings = analyze(req.domain, records)

        # ── Email authentication analysis ──
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()

        txt_records = records.get("TXT", {}).get("records", [])
        spf_data = parse_spf(txt_records)
        spf_lookup_data = await count_spf_lookups(req.domain, resolver) if spf_data else None
        spf_flat_data = await flatten_spf(req.domain, resolver) if spf_data else None
        spf_findings = analyze_spf(spf_data, spf_lookup_data, txt_records=txt_records)

        dmarc_data, dkim_data, (dnssec_data, dnssec_findings), (takeover_data, takeover_findings) = await asyncio.gather(
            fetch_dmarc(req.domain, resolver),
            check_dkim_selectors(req.domain, resolver),
            check_dnssec(req.domain, resolver),
            check_subdomain_takeover(req.domain, records, resolver),
        )
        dmarc_findings = analyze_dmarc(dmarc_data)
        dkim_findings = analyze_dkim(dkim_data)

        bimi_data, bimi_findings = await check_bimi(req.domain, dmarc_data, resolver)

        score_data = compute_email_score(spf_findings, dmarc_findings, dkim_findings)

        email_auth = EmailAuth(
            spf=spf_data,
            spf_lookups=spf_lookup_data,
            spf_flattened=spf_flat_data,
            dmarc=dmarc_data,
            dkim=dkim_data,
            score=EmailScore(**score_data),
        )

        all_findings = (
            findings
            + spf_findings
            + dmarc_findings
            + dkim_findings
            + dnssec_findings
            + takeover_findings
            + bimi_findings
        )
        all_counts = summarize(all_findings)
        ts = _now_utc()

        security_audit = SecurityAudit(
            dnssec=dnssec_data,
            takeover=takeover_data,
            bimi=bimi_data,
        )
        fixes = generate_remediation_fixes(req.domain, all_findings, email_auth, security_audit)

        html = build_report(
            domain=req.domain,
            scan_timestamp=ts,
            records=records,
            findings=all_findings,
            summary=Summary(**all_counts),
            email_auth=email_auth,
            security=security_audit,
            remediation=fixes,
        )
        return HTMLResponse(
            content=html,
            headers={
                "Content-Disposition": f'attachment; filename="dns-report-{req.domain}.html"'
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": f"Unexpected server error: {exc}"})


# ---------------------------------------------------------------------------
# Static files (served last so /api/* routes take priority)
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def root() -> HTMLResponse:
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
