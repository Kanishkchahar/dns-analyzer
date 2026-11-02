#!/usr/bin/env bash
# ============================================================
# start.sh — Start the DNS Analyzer web server
# Usage: bash start.sh [port]   (default port: 8000)
# ============================================================

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

PORT=${1:-8000}

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       DNS Analyzer — Starting        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Activate venv if it exists ────────────────────────────────
if [ -x "venv/bin/python" ]; then
  PYTHON="venv/bin/python"
  echo -e "  ${YELLOW}→${NC} Using virtual environment: venv/"
else
  PYTHON="python3"
  echo -e "  ${YELLOW}⚠${NC}  No virtual environment found; checking system Python."
fi

# ── Check uvicorn is available ────────────────────────────────
if ! "$PYTHON" -c 'import uvicorn' >/dev/null 2>&1; then
  echo ""
  echo -e "  ${RED}✗ uvicorn not found.${NC}"
  echo -e "    Run ${YELLOW}bash setup.sh${NC} to install dependencies first."
  exit 1
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  echo -e "  ${RED}✗ Invalid port: ${PORT}. Use a number from 1 to 65535.${NC}"
  exit 2
fi

echo ""
echo -e "  ${CYAN}➜  Local:   http://127.0.0.1:${PORT}/${NC}"
if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
  NETWORK_IP=$(hostname -I | awk '{print $1}')
  if [ -n "$NETWORK_IP" ]; then
    echo -e "  ${CYAN}➜  Network: http://${NETWORK_IP}:${PORT}/${NC}"
  fi
fi
echo ""
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop the server."
echo ""

# ── Launch ────────────────────────────────────────────────────
"$PYTHON" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --reload
