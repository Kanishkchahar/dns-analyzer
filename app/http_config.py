"""Shared identity for outbound HTTP requests."""

import os

DEFAULT_DOCUMENTATION_URL = "https://example.com/dns-analyzer-scanner"


def outbound_http_headers() -> dict[str, str]:
    """Return the scanner User-Agent, with a deployment-editable documentation link."""
    documentation_url = os.environ.get(
        "DNS_ANALYZER_DOCUMENTATION_URL", DEFAULT_DOCUMENTATION_URL
    ).strip() or DEFAULT_DOCUMENTATION_URL
    return {"User-Agent": f"DNSAnalyzer/2.2.0 (+{documentation_url})"}
