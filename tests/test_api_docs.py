import json
from pathlib import Path

from app.models import AnalyzeResponse


def test_documented_analyze_response_example_validates_against_model():
    sample_path = Path(__file__).parents[1] / "docs" / "examples" / "analyze-response.json"
    payload = json.loads(sample_path.read_text(encoding="utf-8"))
    response = AnalyzeResponse.model_validate(payload)
    assert response.domain == "example.com"
