from pathlib import Path
import tomllib


ROOT = Path(__file__).parents[1]


def test_release_metadata_uses_version_2_2_0_and_documents_score_change():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert version == "2.2.0"
    for filename in ("app/main.py", "app/report.py", "Dockerfile", "run.sh", "README.md"):
        assert "2.2.0" in (ROOT / filename).read_text(encoding="utf-8")
    assert "v2.2.0" in (ROOT / "run.sh").read_text(encoding="utf-8")
    assert "Grades and `--min-grade` results may differ from earlier versions" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Grades and `--min-grade` results may differ from earlier versions" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
