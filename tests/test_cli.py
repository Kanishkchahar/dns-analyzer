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
        model_dump=lambda **_: {"domain": "example.com", "score": score, "grade": grade},
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


def test_cli_displays_provisional_grade_and_status(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=82, grade="B (incomplete)")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com"]) == 0
    output = capsys.readouterr().out
    assert "Grade: B (incomplete) (82/100)" in output
    assert "Grade status: provisional" in output


def test_min_grade_uses_provisional_base_letter_and_warns(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=79, grade="B (incomplete)")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com", "--min-grade", "B"]) == 0
    output = capsys.readouterr().out
    assert "Warning: provisional grade is treated as base grade for --min-grade B" in output


def test_require_complete_returns_distinct_exit_code_for_provisional_grade(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=90, grade="A (incomplete)")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com", "--require-complete"]) == cli.EXIT_GRADE_PROVISIONAL
    assert "Grade status: provisional" in capsys.readouterr().out


def test_cli_json_keeps_incomplete_grade_suffix(monkeypatch, capsys):
    async def fake_scan(_):
        return _scan(score=79, grade="B (incomplete)")

    monkeypatch.setattr(cli, "_scan", fake_scan)
    assert cli.main(["example.com", "--json"]) == 0
    assert '"grade": "B (incomplete)"' in capsys.readouterr().out
