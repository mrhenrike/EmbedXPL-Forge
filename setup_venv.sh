#!/usr/bin/env bash
# setup_venv.sh — Virtual environment for EmbedXPL-Forge (exf.py)
# Author: André Henrique (@mrhenrike)
# Compatible with Linux, macOS, and Android (Termux)

set -euo pipefail

VENV_DIR=".venv"
PYTHON_MIN="3.8"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=== EmbedXPL-Forge — Virtual Environment Setup ==="
echo ""

OS="$(uname -s)"
case "$OS" in
    Linux*)
        if [ -d "/data/data/com.termux" ]; then
            PLATFORM="android-termux"
        else
            PLATFORM="linux"
        fi
        ;;
    Darwin*)  PLATFORM="macos" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)        PLATFORM="unknown" ;;
esac
echo "Platform detected: $PLATFORM"

install_prereqs() {
    echo ""
    echo "--- Installing OS prerequisites ---"
    case "$PLATFORM" in
        linux)
            if command -v apt-get &>/dev/null; then
                sudo apt-get update -qq
                sudo apt-get install -y -qq python3 python3-pip python3-venv \
                    libpcap-dev nmap 2>/dev/null || true
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y python3 python3-pip libpcap-devel nmap 2>/dev/null || true
            elif command -v pacman &>/dev/null; then
                sudo pacman -Sy --noconfirm python python-pip libpcap nmap 2>/dev/null || true
            elif command -v apk &>/dev/null; then
                apk add --no-cache python3 py3-pip libpcap-dev nmap 2>/dev/null || true
            fi
            ;;
        macos)
            if command -v brew &>/dev/null; then
                brew install python3 libpcap nmap 2>/dev/null || true
            fi
            ;;
        android-termux)
            pkg update -y 2>/dev/null || true
            pkg install -y python clang libpcap nmap 2>/dev/null || true
            ;;
    esac
}

if ! command -v python3 &>/dev/null; then
    echo "Python3 not found. Attempting to install prerequisites..."
    install_prereqs
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 still not found. Install Python >= ${PYTHON_MIN}."
    exit 1
fi

PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
echo "Python version: $PY_VER"

_venv_python() {
    [ -x "$VENV_DIR/bin/python" ] && "$VENV_DIR/bin/python" -c "import sys" 2>/dev/null
}

if [ ! -d "$VENV_DIR" ] || ! _venv_python; then
    if [ -d "$VENV_DIR" ]; then
        echo "Removing broken venv at $VENV_DIR"
        rm -rf "$VENV_DIR"
    fi
    python3 -m venv "$VENV_DIR"
    echo "venv created at $VENV_DIR"
else
    echo "venv already exists at $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip --quiet

echo ""
echo "--- Installing core dependencies ---"
"$VENV_DIR/bin/pip" install -r requirements.txt
"$VENV_DIR/bin/pip" install -e . --quiet

touch "$VENV_DIR/.embedxpl-venv-ready"

echo ""
echo "=== Environment ready! ==="
echo ""
echo "Run:      ./run.sh"
echo "Or:       python exf.py          # auto-detects .venv"
echo "Activate: source .venv/bin/activate"
echo "Doctor:   .venv/bin/python tools/env_doctor.py"
echo ""
