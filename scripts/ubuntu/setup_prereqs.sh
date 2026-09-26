#!/usr/bin/env bash
# =============================================================================
# EmbedXPL v5.0.0 — Ubuntu Prerequisites Setup
# Run: bash setup_prereqs.sh
# Tested on: Ubuntu 22.04 LTS / 24.04 LTS
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

info "=== EmbedXPL v5.0.0 Ubuntu Prerequisites ==="
echo ""

# ─── System ───────────────────────────────────────────────────────────────────
info "Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# ─── Core build tools ─────────────────────────────────────────────────────────
info "Installing core build tools..."
sudo apt-get install -y -qq \
    build-essential git curl wget unzip tar \
    cmake ninja-build pkg-config \
    libssl-dev libffi-dev zlib1g-dev \
    ca-certificates gnupg lsb-release

# ─── Python ───────────────────────────────────────────────────────────────────
info "Installing Python 3.11+..."
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    python3-setuptools python3-wheel

PY_VER=$(python3 --version | awk '{print $2}')
info "Python: $PY_VER"

# EmbedXPL Python dependencies
info "Installing EmbedXPL Python packages..."
pip3 install --user --quiet \
    requests paramiko pysnmp pycryptodome scapy \
    colorama rich aiohttp numpy psutil python-nmap \
    telnetlib3 setuptools wheel

# ─── C/C++ cross-compilers ────────────────────────────────────────────────────
info "Installing C/C++ cross-compilers for embedded targets..."
sudo apt-get install -y -qq \
    gcc g++ clang clang++ \
    gcc-12 g++-12 \
    gcc-arm-linux-gnueabi g++-arm-linux-gnueabi \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu \
    binutils-arm-linux-gnueabi \
    binutils-aarch64-linux-gnu \
    binutils-mips-linux-gnu \
    binutils-mipsel-linux-gnu \
    libc6-dev-armel-cross \
    libc6-dev-mips-cross

# Verify cross-compilers
for cc in arm-linux-gnueabi-gcc aarch64-linux-gnu-gcc mips-linux-gnu-gcc mipsel-linux-gnu-gcc; do
    if command -v "$cc" &>/dev/null; then
        info "  ✓ $cc $(${cc} --version 2>&1 | head -1 | awk '{print $NF}')"
    else
        warn "  ✗ $cc not found"
    fi
done

# ─── Go ───────────────────────────────────────────────────────────────────────
info "Installing Go..."
GO_VER="1.23.1"
GO_TAR="go${GO_VER}.linux-amd64.tar.gz"

if command -v go &>/dev/null; then
    INSTALLED_GO=$(go version | awk '{print $3}' | sed 's/go//')
    info "Go $INSTALLED_GO already installed"
else
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm -f "/tmp/${GO_TAR}"

    # Add to PATH for current session
    export PATH="$PATH:/usr/local/go/bin"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"

    # Add to shell profile
    PROFILE="$HOME/.bashrc"
    if ! grep -q 'GOPATH' "$PROFILE" 2>/dev/null; then
        cat >> "$PROFILE" <<'GOENV'
# Go
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
GOENV
    fi
    info "Go $(go version | awk '{print $3}') installed"
fi

# ─── Rust ─────────────────────────────────────────────────────────────────────
info "Installing Rust..."
if command -v rustc &>/dev/null; then
    info "Rust $(rustc --version) already installed"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
    info "Rust $(rustc --version) installed"
fi

# Add to bashrc if needed
if ! grep -q 'cargo/env' "$HOME/.bashrc" 2>/dev/null; then
    echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
fi

# ─── Ruby ─────────────────────────────────────────────────────────────────────
info "Installing Ruby (for MSF module compatibility)..."
sudo apt-get install -y -qq ruby ruby-dev ruby-bundler
RB_VER=$(ruby --version | awk '{print $2}')
info "Ruby: $RB_VER"

# MSF Ruby gems (minimal set for module execution)
gem install --user-install --quiet \
    rex-core \
    rex-socket \
    rex-text \
    rex-encoder \
    metasploit-concern \
    2>/dev/null || warn "Some MSF gems failed — install MSF for full support"

# ─── GitHub CLI ───────────────────────────────────────────────────────────────
info "Installing GitHub CLI..."
if command -v gh &>/dev/null; then
    info "gh $(gh --version | head -1 | awk '{print $3}') already installed"
else
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq gh
    info "gh $(gh --version | head -1 | awk '{print $3}') installed"
fi

# ─── Additional tools ─────────────────────────────────────────────────────────
info "Installing additional security tools..."
sudo apt-get install -y -qq \
    nmap wireshark-common tshark \
    rsync jq bc \
    python3-scapy

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
info "=== INSTALLATION SUMMARY ==="
echo ""
printf "%-30s %s\n" "Python:"  "$(python3 --version 2>&1)"
printf "%-30s %s\n" "pip:"     "$(pip3 --version 2>&1 | awk '{print $1,$2}')"
printf "%-30s %s\n" "gcc:"     "$(gcc --version 2>&1 | head -1)"
printf "%-30s %s\n" "g++:"     "$(g++ --version 2>&1 | head -1)"
printf "%-30s %s\n" "clang:"   "$(clang --version 2>&1 | head -1)"
printf "%-30s %s\n" "arm-gcc:" "$(arm-linux-gnueabi-gcc --version 2>&1 | head -1)"
printf "%-30s %s\n" "mips-gcc:""$(mips-linux-gnu-gcc --version 2>&1 | head -1)"
printf "%-30s %s\n" "Go:"      "$(go version 2>&1)"
printf "%-30s %s\n" "Rust:"    "$(rustc --version 2>&1)"
printf "%-30s %s\n" "Ruby:"    "$(ruby --version 2>&1)"
printf "%-30s %s\n" "gh CLI:"  "$(gh --version 2>&1 | head -1)"
echo ""
info "=== All prerequisites installed successfully ==="
echo ""
echo "Next step: bash clone_repos.sh"
