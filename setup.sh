#!/usr/bin/env bash
# ============================================================
# setup.sh — Setup dependencies (redirects to unified run.sh)
# ============================================================
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run.sh" --setup-only
