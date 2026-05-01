#!/usr/bin/env bash
set -euo pipefail

# Network Scanner — one-shot local setup for an already cloned repo.
# Run from repository root:
#   bash setup.sh

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

echo "==> Project root: $PROJECT_ROOT"

if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source ".venv/Scripts/activate"
  echo "==> Activated existing virtual environment (.venv)"
else
  echo "==> Creating virtual environment (.venv)"
  python -m venv .venv
  # shellcheck disable=SC1091
  source ".venv/Scripts/activate"
fi

echo "==> Installing dependencies"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "==> Running quick checks"
python -m py_compile scanner.py gui.py
python -c "import scanner, gui; print('Imports OK:', scanner.__name__, gui.NetworkScannerApp.__name__)"

echo "==> Running Phase 2 scanner demo"
python scanner.py

echo "==> Done"
