"""FastAPI application — routes, static file serving, error handling."""

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.analyzer import analyze, summarize
from app.models import AnalyzeRequest, AnalyzeResponse, Finding, Summary
from app.report import build_report
from app.resolver import resolve_domain

app = FastAPI(title="DNS Analyzer", version="1.0.0")


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
        return AnalyzeResponse(
            domain=req.domain,
            scan_timestamp=_now_utc(),
            records=records,
            findings=findings,
            summary=Summary(**counts),
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
        counts = summarize(findings)
        ts = _now_utc()
        html = build_report(
            domain=req.domain,
            scan_timestamp=ts,
            records=records,
            findings=findings,
            summary=Summary(**counts),
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
