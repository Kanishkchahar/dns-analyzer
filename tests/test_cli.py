from types import SimpleNamespace

from app import cli


def _scan(*, score=70, grade="C", errors=0):
    findings = [SimpleNamespace(severity="error", record_type="DNS", message="Example error")] * errors
    return SimpleNamespace(
        domain="example.com",
        scan_timestamp="2026-11-07 00:00:00 UTC",
        domain_score=SimpleNamespace(score=score, grade=grade),
        summary=SimpleNamespace(errors=errors, warnings=0, info=0),
        findings=findings,
        model_dump=lambda **_: {"domain": "example.com", "score": score},
    )


def test_cli_grade_threshold_has_distinct_exit_code(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=70, grade="C")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com", "--min-grade", "B"]) == cli.EXIT_GRADE_TOO_LOW
    assert "Grade: C (70/100)" in capsys.readouterr().out


def test_cli_errors_have_distinct_exit_code(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=95, grade="A", errors=1)

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com"]) == cli.EXIT_FINDINGS_ERRORS
    assert "Example error" in capsys.readouterr().out


def test_cli_json_output(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=100, grade="A+")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com", "--json"]) == 0
    assert '"score": 100' in capsys.readouterr().out
