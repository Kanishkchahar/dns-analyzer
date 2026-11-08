"""Shared identity for outbound HTTP requests."""

import logging
import os

DEFAULT_DOCUMENTATION_URL = "https://example.com/dns-analyzer-scanner"
logger = logging.getLogger(__name__)


def warn_if_placeholder_documentation_url() -> None:
    """Warn once at application startup when the scanner URL is still a placeholder."""
    configured = os.environ.get("DNS_ANALYZER_DOCUMENTATION_URL", "").strip()
    if not configured or configured == DEFAULT_DOCUMENTATION_URL:
        logger.warning(
            "DNS_ANALYZER_DOCUMENTATION_URL is using the default placeholder; configure a real scanner documentation/contact URL."
        )


def outbound_http_headers() -> dict[str, str]:
    """Return the scanner User-Agent, with a deployment-editable documentation link."""
    documentation_url = os.environ.get(
        "DNS_ANALYZER_DOCUMENTATION_URL", DEFAULT_DOCUMENTATION_URL
    ).strip() or DEFAULT_DOCUMENTATION_URL
    return {"User-Agent": f"DNSAnalyzer/2.2.0 (+{documentation_url})"}
