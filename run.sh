#!/usr/bin/env bash
# EmbedXPL-Forge — launcher with local .venv (Linux/macOS)
# Usage: ./run.sh [-m module] [-s "target IP"] ...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [ ! -x "$VENV/bin/python" ]; then
    echo "[!] Venv not found. Running setup_venv.sh ..."
    bash "$SCRIPT_DIR/setup_venv.sh"
fi

exec "$VENV/bin/python" "$SCRIPT_DIR/exf.py" "$@"
