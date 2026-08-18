#!/usr/bin/env bash
# ============================================================
# setup.sh — Install all dependencies for DNS Analyzer
# Usage: bash setup.sh
# ============================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       DNS Analyzer — Setup           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── Check Python ──────────────────────────────────────────────
echo -e "${YELLOW}[1/3]${NC} Checking Python version..."
if ! command -v python3 &>/dev/null; then
  echo -e "${RED}✗ Python 3 not found. Please install Python 3.11 or newer.${NC}"
  exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "    Found Python ${PY_VERSION}"

# ── Create virtual environment ────────────────────────────────
echo ""
echo -e "${YELLOW}[2/3]${NC} Setting up virtual environment..."

if [ ! -d "venv" ]; then
  python3 -m venv venv
  echo -e "    Created venv/"
else
  echo -e "    venv/ already exists, skipping creation."
fi

# Activate
source venv/bin/activate

# ── Install dependencies ──────────────────────────────────────
echo ""
echo -e "${YELLOW}[3/3]${NC} Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo -e "${GREEN}✔ All dependencies installed successfully!${NC}"
echo ""
echo -e "  To start the app, run:  ${YELLOW}bash start.sh${NC}"
echo ""
