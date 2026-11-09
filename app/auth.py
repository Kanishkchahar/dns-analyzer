"""Optional API-key checks and deployment target restrictions."""

from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
import os
import socket

from fastapi import HTTPException, Request


def require_api_key(request: Request) -> None:
    """Require a configured bearer key for protected API routes, when enabled."""
    configured = [key.strip() for key in os.environ.get("DNS_ANALYZER_API_KEYS", "").split(",") if key.strip()]
    if not configured:
        return

    authorization = request.headers.get("authorization", "")
    scheme, _, supplied = authorization.partition(" ")
    if scheme.lower() != "bearer" or not supplied.strip():
        raise HTTPException(status_code=401, detail="A valid API key is required.", headers={"WWW-Authenticate": "Bearer"})

    supplied_digest = hashlib.sha256(supplied.strip().encode("utf-8")).digest()
    valid = False
    for key in configured:
        expected_digest = hashlib.sha256(key.encode("utf-8")).digest()
        valid |= hmac.compare_digest(supplied_digest, expected_digest)
    if not valid:
        raise HTTPException(status_code=401, detail="A valid API key is required.", headers={"WWW-Authenticate": "Bearer"})


@lru_cache(maxsize=1)
def _local_hostnames() -> frozenset[str]:
    """Look up local host aliases once per process."""
    names = {"localhost", "localhost.localdomain"}
    for value in (socket.gethostname(), socket.getfqdn()):
        normalized = value.strip().lower().rstrip(".")
        if normalized:
            names.add(normalized)
    return frozenset(names)


def blocked_target_names() -> set[str]:
    """Return cached local host aliases plus dynamic deployment-configured names."""
    names = set(_local_hostnames())
    names.update(
        item.strip().lower().rstrip(".")
        for item in os.environ.get("DNS_ANALYZER_BLOCKED_TARGETS", "").split(",")
        if item.strip()
    )
    return names


def validate_public_target_name(domain: str) -> str:
    """Reject special-use names and hostnames identifying this server."""
    normalized = domain.lower().rstrip(".")
    private_suffixes = {
        "local", "internal", "onion", "localhost", "test", "invalid", "example", "lan", "home.arpa",
    }
    if any(normalized == suffix or normalized.endswith("." + suffix) for suffix in private_suffixes):
        raise ValueError("Private or special-use domain suffixes cannot be scanned.")
    blocked = blocked_target_names()
    if normalized in blocked or any(normalized.endswith("." + name) for name in blocked if "." in name):
        raise ValueError("The DNS Analyzer server's own hostname or address cannot be scanned.")
    return domain
