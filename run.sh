#!/usr/bin/env bash
set -euo pipefail

# run.sh - create venv, install requirements, run compile checks,
# then start the GUI or CLI. Designed for Git Bash / WSL / Linux/macOS.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"

echo "Project: $PROJECT_DIR"

# Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment in $VENV_DIR..."
  if command -v python3 >/dev/null 2>&1; then
    python3 -m venv "$VENV_DIR"
  else
    python -m venv "$VENV_DIR"
  fi
fi

# Activate venv (support Scripts for Windows Git Bash and bin for Unix)
if [ -f "$VENV_DIR/Scripts/activate" ]; then
  # Git Bash on Windows
  # shellcheck source=/dev/null
  source "$VENV_DIR/Scripts/activate"
elif [ -f "$VENV_DIR/bin/activate" ]; then
  # Unix / WSL / Linux / macOS
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"
else
  echo "ERROR: Could not find venv activation script in $VENV_DIR"
  exit 1
fi

echo "Using python: $(which python)"

# Upgrade pip and install requirements
echo "Installing requirements..."
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

# Optional quick compile checks
echo "Running quick compile checks..."
python -m py_compile scanner.py || true
python -m py_compile gui.py || true

usage() {
  cat <<EOF
Usage: $0 [gui|cli|smoke|help] [-- <scanner args...>]

Commands:
  gui       Start the desktop GUI (default if no command provided)
  cli       Run `python scanner.py` — any following args are passed to scanner.py
  smoke     Quick smoke test: small local scan and write smoke_results.txt
  help      Show this message

Examples:
  bash run.sh gui
  bash run.sh cli -- --target 127.0.0.1 --ports 22,80
  bash run.sh smoke
EOF
}

CMD="${1:-gui}"
shift || true
case "$CMD" in
  gui)
    echo "Initializing database..."
    python init_db_startup.py
    echo "Starting GUI (press Ctrl-C to quit)..."
    python gui.py
    ;;
  cli)
    echo "Starting CLI: python scanner.py $*"
    python scanner.py "$@"
    ;;
  smoke)
    echo "Running smoke scan against localhost (ports 22,80)"
    python scanner.py --target 127.0.0.1 --ports 22,80 --threads 20 --timeout 0.5 --output smoke_results.txt || true
    echo "Smoke results saved to smoke_results.txt"
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    echo "Unknown command: $CMD"
    usage
    exit 2
    ;;
esac
