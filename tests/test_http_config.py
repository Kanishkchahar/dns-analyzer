import ast
from pathlib import Path

from app.http_config import DEFAULT_DOCUMENTATION_URL, outbound_http_headers


def test_outbound_user_agent_uses_configurable_documentation_link(monkeypatch):
    monkeypatch.delenv("DNS_ANALYZER_DOCUMENTATION_URL", raising=False)
    assert outbound_http_headers()["User-Agent"] == (
        f"DNSAnalyzer/2.2.0 (+{DEFAULT_DOCUMENTATION_URL})"
    )
    monkeypatch.setenv("DNS_ANALYZER_DOCUMENTATION_URL", "https://docs.example.test/scanner")
    assert outbound_http_headers()["User-Agent"] == (
        "DNSAnalyzer/2.2.0 (+https://docs.example.test/scanner)"
    )


def test_every_application_async_http_client_sets_scanner_user_agent():
    app_dir = Path(__file__).parents[1] / "app"
    clients = []
    for source_path in app_dir.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "AsyncClient":
                clients.append((source_path.name, node))
    assert clients, "Expected application outbound AsyncClient calls"
    for source_name, node in clients:
        headers = next((kw.value for kw in node.keywords if kw.arg == "headers"), None)
        assert isinstance(headers, ast.Call) and isinstance(headers.func, ast.Name) and headers.func.id == "outbound_http_headers", (
            f"{source_name}:{node.lineno} must use outbound_http_headers()"
        )
