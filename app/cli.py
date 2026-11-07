"""Command-line interface for the same scan pipeline used by the web API."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Sequence

from pydantic import ValidationError

from app.main import run_full_scan
from app.models import AnalyzeRequest


_GRADE_SCORE = {"A+": 100, "A": 90, "B": 80, "C": 70, "D": 60, "F": 0}
EXIT_TOOL_ERROR = 1
EXIT_GRADE_TOO_LOW = 2
EXIT_FINDINGS_ERRORS = 3


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _render_text(scan) -> str:
    score = scan.domain_score
    grade = score.grade if score else "N/A"
    numeric = score.score if score else 0
    lines = [
        _color(f"DNS Analyzer · {scan.domain}", "1;36"),
        f"Scan: {scan.scan_timestamp}",
        f"Grade: {_color(grade, '1;32' if grade.startswith('A') else '1;33' if grade in ('B', 'C') else '1;31')} ({numeric}/100)",
        f"Findings: {scan.summary.errors} errors · {scan.summary.warnings} warnings · {scan.summary.info} info",
        "",
    ]
    for finding in scan.findings:
        tone = "1;31" if finding.severity == "error" else "1;33" if finding.severity == "warning" else "36"
        lines.append(f"[{_color(finding.severity.upper(), tone)}] {getattr(finding, 'code', 'GEN-001')} · {finding.record_type}: {finding.message}")
        explanation = getattr(finding, "explanation", {}) or {}
        if explanation:
            lines.append(f"  Why: {explanation.get('why', '')}")
            lines.append(f"  Fix: {explanation.get('fix', '')}")
    return "\n".join(lines)


async def _scan(domain: str):
    normalized = AnalyzeRequest(domain=domain).domain
    # Calling the service function directly bypasses the web layer's short cache.
    return await run_full_scan(normalized)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dns-analyzer", description="Audit a domain using the DNS Analyzer scan pipeline.")
    parser.add_argument("domain", help="Domain to analyze, or a full URL whose hostname will be extracted")
    parser.add_argument("--json", action="store_true", help="Print the complete scan result as JSON")
    parser.add_argument("--min-grade", choices=tuple(_GRADE_SCORE), help="Exit with code 2 when the grade is below this threshold")
    args = parser.parse_args(argv)

    try:
        scan = asyncio.run(_scan(args.domain))
    except (ValidationError, ValueError) as exc:
        print(f"Invalid domain: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except Exception as exc:
        print(f"Scan failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    if args.json:
        print(json.dumps(scan.model_dump(mode="json"), indent=2, ensure_ascii=False))
    else:
        print(_render_text(scan))

    if scan.summary.errors:
        return EXIT_FINDINGS_ERRORS
    if args.min_grade and (scan.domain_score.score if scan.domain_score else 0) < _GRADE_SCORE[args.min_grade]:
        return EXIT_GRADE_TOO_LOW
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
