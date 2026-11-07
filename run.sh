#!/usr/bin/env bash
# ============================================================
# run.sh — All-in-one Setup, Test & Server Launcher for DNS Analyzer
# Usage:
#   bash run.sh              # Auto-setup (if needed) & start on port 8000
#   bash run.sh 9000         # Auto-setup & start on custom port 9000
#   bash run.sh --docker     # Build & launch container via Docker
#   bash run.sh --test       # Run the 112-test automated test suite
#   bash run.sh --setup-only # Run setup/dependency install only
#   bash run.sh --help       # Display help reference
# ============================================================

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

SETUP_ONLY=false
RUN_TESTS=false
RUN_DOCKER=false
PORT=8000

# Parse arguments
for arg in "$@"; do
  if [ "$arg" = "--setup-only" ]; then
    SETUP_ONLY=true
  elif [ "$arg" = "--docker" ] || [ "$arg" = "-d" ]; then
    RUN_DOCKER=true
  elif [ "$arg" = "--test" ] || [ "$arg" = "-t" ]; then
    RUN_TESTS=true
  elif [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
    echo ""
    echo -e "${GREEN}DNS Analyzer v2 — Security Posture Cockpit Edition${NC}"
    echo "Usage:"
    echo "  bash run.sh              Start server on http://127.0.0.1:8000"
    echo "  bash run.sh <port>       Start server on custom port (e.g., 9000)"
    echo "  bash run.sh --docker, -d Build & launch containerized service via Docker"
    echo "  bash run.sh --test, -t   Run the 112 automated pytest suite"
    echo "  bash run.sh --setup-only Prepare virtual environment without running server"
    echo "  bash run.sh --help, -h   Show this help message"
    echo ""
    exit 0
  elif [[ "$arg" =~ ^[0-9]+$ ]]; then
    PORT="$arg"
  fi
done

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   DNS Analyzer v2 — Security Posture Cockpit         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

if [ "$RUN_DOCKER" = true ]; then
  echo -e "  ${CYAN}➜ Building and starting DNS Analyzer v2 container via Docker...${NC}"
  docker build -t kanishkchahar/dns-analyzer:v2 .
  docker rm -f dns-analyzer-v2 2>/dev/null || true
  docker run -d --name dns-analyzer-v2 --restart unless-stopped -p "${PORT:-8000}:8000" kanishkchahar/dns-analyzer:v2
  echo ""
  echo -e "  ${GREEN}✔ Container running on http://127.0.0.1:${PORT:-8000}/${NC}"
  echo -e "  To view logs:  ${YELLOW}docker logs -f dns-analyzer-v2${NC}"
  echo -e "  To stop:       ${YELLOW}docker stop dns-analyzer-v2${NC}"
  echo ""
  exit 0
fi

# ── 1. Python version check ───────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo -e "  ${RED}✗ Python 3 not found. Please install Python 3.11 or newer.${NC}"
  exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
  echo -e "  ${RED}✗ Python 3.11+ required. Found Python ${PY_VER}.${NC}"
  exit 1
fi

# ── 2. Virtual environment verification & creation ────────────
NEED_PIP_INSTALL=false

if [ ! -d "venv" ] || ! venv/bin/python -c 'import sys' &>/dev/null; then
  if [ -d "venv" ]; then
    echo -e "  ${YELLOW}⚠${NC} Existing venv is invalid or corrupted. Rebuilding..."
    rm -rf venv
  fi
  echo -e "  ${YELLOW}→${NC} Creating virtual environment in venv/..."
  python3 -m venv venv
  NEED_PIP_INSTALL=true
fi

PYTHON="venv/bin/python"

# ── 3. Check / install dependencies ───────────────────────────
if ! "$PYTHON" -c 'import fastapi, uvicorn, dns.resolver, jinja2, pytest' &>/dev/null; then
  NEED_PIP_INSTALL=true
fi

if [ "$NEED_PIP_INSTALL" = true ]; then
  echo -e "  ${YELLOW}→${NC} Installing / updating dependencies from requirements.txt..."
  "$PYTHON" -m pip install --upgrade pip -q
  "$PYTHON" -m pip install -r requirements.txt -q
  echo -e "  ${GREEN}✔ Dependencies ready.${NC}"
else
  echo -e "  ${GREEN}✔ Virtual environment and dependencies verified.${NC}"
fi

if [ "$SETUP_ONLY" = true ]; then
  echo ""
  echo -e "  ${GREEN}✔ Setup complete! Run ${YELLOW}bash run.sh${GREEN} to start the server.${NC}"
  echo ""
  exit 0
fi

if [ "$RUN_TESTS" = true ]; then
  echo ""
  echo -e "  ${CYAN}➜ Running automated test suite (122 tests)...${NC}"
  "$PYTHON" -m pytest -v
  exit $?
fi

# ── 4. Port validation ────────────────────────────────────────
if (( PORT < 1 || PORT > 65535 )); then
  echo -e "  ${RED}✗ Invalid port: ${PORT}. Use a number from 1 to 65535.${NC}"
  exit 2
fi

# ── 5. Launch server ──────────────────────────────────────────
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

exec "$PYTHON" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --reload
