#!/usr/bin/env bash
# ============================================================
# start.sh — Start the DNS Analyzer web server
# Usage: bash start.sh [port]   (default port: 8000)
# ============================================================

set -e

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
if [ -d "venv" ]; then
  source venv/bin/activate
  echo -e "  ${YELLOW}→${NC} Using virtual environment: venv/"
else
  echo -e "  ${YELLOW}⚠${NC}  No venv found. Run ${YELLOW}bash setup.sh${NC} first, or using system Python."
fi

# ── Check uvicorn is available ────────────────────────────────
if ! command -v uvicorn &>/dev/null; then
  echo ""
  echo -e "  ${RED}✗ uvicorn not found.${NC}"
  echo -e "    Run ${YELLOW}bash setup.sh${NC} to install dependencies first."
  exit 1
fi

echo ""
echo -e "  ${CYAN}➜  Local:   http://127.0.0.1:${PORT}/${NC}"
echo -e "  ${CYAN}➜  Network: http://$(hostname -I | awk '{print $1}'):${PORT}/${NC}"
echo ""
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop the server."
echo ""

# ── Launch ────────────────────────────────────────────────────
uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --reload
