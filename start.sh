#!/usr/bin/env bash
# ============================================================
# start.sh — Start server (redirects to unified run.sh)
# ============================================================
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run.sh" "$@"
