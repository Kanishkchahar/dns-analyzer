"""Finding conditions must resolve to a registered stable code and alias."""

import pytest
from pydantic import ValidationError

from pathlib import Path

from app.finding_catalog import (
    condition_catalog,
    get_finding_guidance,
    known_finding_codes,
    render_condition_catalog_markdown,
)
from app.models import Finding


def test_each_registered_condition_resolves_to_a_known_code_and_legacy_alias():
    known = known_finding_codes()
    rows = condition_catalog()
    assert rows
    for row in rows:
        guidance = get_finding_guidance(row["module"], row["condition"])
        assert guidance["code"] == row["code"]
        assert row["code"] in known
        if row["legacy_alias"]:
            assert row["legacy_alias"] in known


def test_module_condition_markers_emit_every_primary_catalog_code():
    rows = condition_catalog()
    emitted_codes = set()
    for row in rows:
        finding = Finding(
            severity="info", record_type=row["module"], message=row["condition"],
        )
        assert finding.code == row["code"]
        emitted_codes.add(finding.code)
    assert {row["code"] for row in rows} <= emitted_codes


def test_finding_model_rejects_codes_not_present_in_catalog():
    with pytest.raises(ValidationError, match="missing from the finding catalog"):
        Finding(severity="warning", record_type="DNSSEC", message="module output", code="UNLISTED-900")


def test_checked_in_finding_code_table_matches_catalog():
    path = Path(__file__).parents[1] / "docs" / "FINDING_CODES.md"
    assert path.read_text(encoding="utf-8") == render_condition_catalog_markdown()


def test_unknown_finding_code_falls_back_to_generic_in_production(monkeypatch, caplog):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    finding = Finding(
        severity="warning", record_type="DNSSEC", message="module output", code="UNLISTED-900"
    )
    assert finding.code == "GEN-001"
    assert "missing from catalog" in caplog.text
