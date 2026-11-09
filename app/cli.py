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


_GRADE_RANK = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4, "A+": 5}
EXIT_TOOL_ERROR = 1
EXIT_GRADE_TOO_LOW = 2
EXIT_FINDINGS_ERRORS = 3
EXIT_GRADE_PROVISIONAL = 4


def _color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _render_text(scan, *, min_grade: str | None = None) -> str:
    score = scan.domain_score
    grade = score.grade if score else "N/A"
    numeric = score.score if score else 0
    lines = [
        _color(f"DNS Analyzer · {scan.domain}", "1;36"),
        f"Scan: {scan.scan_timestamp}",
        f"Grade: {_color(grade, '1;32' if grade.startswith('A') else '1;33' if grade in ('B', 'C') else '1;31')} ({numeric}/100)",
        ("Grade status: provisional; excluded factor weight exceeds 30%" if "(incomplete)" in grade else ""),
        (f"Warning: provisional grade is treated as base grade for --min-grade {min_grade}." if min_grade and "(incomplete)" in grade else ""),
        f"Findings: {scan.summary.errors} errors · {scan.summary.warnings} warnings · {scan.summary.info} info · {getattr(scan.summary, 'inconclusive', 0)} inconclusive checks",
        "",
    ]
    for finding in scan.findings:
        tone = "1;31" if finding.severity == "error" else "1;33" if finding.severity in ("warning", "inconclusive") else "36"
        lines.append(f"[{_color(finding.severity.upper(), tone)}] {getattr(finding, 'code', 'GEN-001')} · {finding.record_type}: {finding.message}")
        explanation = getattr(finding, "explanation", {}) or {}
        if explanation:
            lines.append(f"  Why: {explanation.get('why', '')}")
            lines.append(f"  Fix: {explanation.get('fix', '')}")
    return "\n".join(line for line in lines if line)


def _render_sarif(scan) -> dict:
    """Return a SARIF 2.1.0 report for CI and code-scanning integrations."""
    level_by_severity = {
        "error": "error",
        "warning": "warning",
        "info": "note",
        "inconclusive": "none",
    }
    rules: dict[str, dict] = {}
    results = []
    for finding in scan.findings:
        rule_id = finding.code or "GEN-001"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.record_type,
            "shortDescription": {"text": (finding.explanation or {}).get("title", finding.record_type)},
        })
        result = {
            "ruleId": rule_id,
            "level": level_by_severity.get(finding.severity, "note"),
            "message": {"text": finding.message},
            "properties": {
                "severity": finding.severity,
                "recordType": finding.record_type,
                "legacyCodes": finding.legacy_codes,
            },
        }
        if finding.severity == "inconclusive":
            result["kind"] = "review"
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DNS Analyzer",
                "version": "2.2.0",
                "rules": list(rules.values()),
            }},
            "properties": {"domain": scan.domain, "scanTimestamp": scan.scan_timestamp},
            "results": results,
        }],
    }


async def _scan(domain: str):
    normalized = AnalyzeRequest(domain=domain).domain
    # Calling the service function directly bypasses the web layer's short cache.
    return await run_full_scan(normalized)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dns-analyzer", description="Audit a domain using the DNS Analyzer scan pipeline.")
    parser.add_argument("domain", help="Domain to analyze, or a full URL whose hostname will be extracted")
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument("--json", action="store_true", help="Print the complete scan result as JSON")
    output_format.add_argument("--sarif", action="store_true", help="Print findings as SARIF 2.1.0 for code-scanning tools")
    parser.add_argument("--min-grade", choices=("A+", "A", "B", "C", "D", "F"), help="Exit with code 2 when the base grade is below this threshold")
    parser.add_argument("--require-complete", action="store_true", help="Exit with code 4 when the grade is provisional")
    args = parser.parse_args(argv)

    try:
        scan = asyncio.run(_scan(args.domain))
    except (ValidationError, ValueError) as exc:
        print(f"Invalid domain: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except Exception:
        print("Scan failed. Check the server logs for diagnostic details.", file=sys.stderr)
        return EXIT_TOOL_ERROR

    if args.json or args.sarif:
        payload = _render_sarif(scan) if args.sarif else scan.model_dump(mode="json")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if args.min_grade and scan.domain_score and "(incomplete)" in scan.domain_score.grade:
            print(f"Warning: provisional grade is treated as base grade for --min-grade {args.min_grade}.", file=sys.stderr)
    else:
        print(_render_text(scan, min_grade=args.min_grade))

    if scan.summary.errors:
        return EXIT_FINDINGS_ERRORS
    grade = scan.domain_score.grade if scan.domain_score else "F"
    provisional = "(incomplete)" in grade
    base_grade = grade.removesuffix(" (incomplete)")
    if args.require_complete and provisional:
        return EXIT_GRADE_PROVISIONAL
    if args.min_grade and _GRADE_RANK[base_grade] < _GRADE_RANK[args.min_grade]:
        return EXIT_GRADE_TOO_LOW
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
