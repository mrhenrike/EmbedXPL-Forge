#!/usr/bin/env bash
# =============================================================================
# EmbedXPL v5.0.0 — Verify Ubuntu Environment Before Starting
# Run: bash verify_env.sh
# =============================================================================
set -uo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; FAILED=$((FAILED+1)); }
warn() { echo -e "  ${YELLOW}?${NC} $*"; }

FAILED=0
BASE="${BASE:-$HOME/projects}"

echo "=== EmbedXPL v5.0.0 Environment Verification ==="
echo ""

echo "── Compilers ────────────────────────────────"
command -v gcc &>/dev/null && ok "gcc $(gcc -dumpversion)" || fail "gcc NOT FOUND — sudo apt install gcc"
command -v g++ &>/dev/null && ok "g++ $(g++ -dumpversion)" || fail "g++ NOT FOUND"
command -v clang &>/dev/null && ok "clang $(clang --version 2>&1 | head -1 | awk '{print $3}')" || warn "clang optional"
command -v arm-linux-gnueabi-gcc &>/dev/null && ok "ARM32 cross-compiler" || fail "ARM32 NOT FOUND — sudo apt install gcc-arm-linux-gnueabi"
command -v aarch64-linux-gnu-gcc &>/dev/null && ok "ARM64 cross-compiler" || fail "ARM64 NOT FOUND — sudo apt install gcc-aarch64-linux-gnu"
command -v mips-linux-gnu-gcc &>/dev/null && ok "MIPS BE cross-compiler" || fail "MIPS NOT FOUND — sudo apt install gcc-mips-linux-gnu"
command -v mipsel-linux-gnu-gcc &>/dev/null && ok "MIPS LE cross-compiler" || fail "MIPSEL NOT FOUND — sudo apt install gcc-mipsel-linux-gnu"

echo ""
echo "── Languages ────────────────────────────────"
command -v python3 &>/dev/null && ok "Python $(python3 --version 2>&1 | awk '{print $2}')" || fail "python3 NOT FOUND"
command -v go &>/dev/null && ok "Go $(go version | awk '{print $3}')" || fail "Go NOT FOUND — see setup_prereqs.sh"
command -v rustc &>/dev/null && ok "Rust $(rustc --version 2>&1 | awk '{print $2}')" || warn "Rust optional (Phase 12)"
command -v ruby &>/dev/null && ok "Ruby $(ruby --version 2>&1 | awk '{print $2}')" || fail "Ruby NOT FOUND — sudo apt install ruby"

echo ""
echo "── Tools ────────────────────────────────────"
command -v git &>/dev/null && ok "git $(git --version | awk '{print $3}')" || fail "git NOT FOUND"
command -v gh &>/dev/null && ok "GitHub CLI $(gh --version 2>&1 | head -1 | awk '{print $3}')" || fail "gh CLI NOT FOUND"
command -v rsync &>/dev/null && ok "rsync" || fail "rsync NOT FOUND — sudo apt install rsync"
gh auth status &>/dev/null && ok "GitHub authenticated" || warn "GitHub not authenticated — run: gh auth login"

echo ""
echo "── Python packages ──────────────────────────"
for pkg in requests paramiko pysnmp Cryptodome scapy rich aiohttp numpy psutil; do
    python3 -c "import ${pkg,,}" 2>/dev/null && ok "$pkg" || warn "$pkg not installed (pip3 install ${pkg,,})"
done

echo ""
echo "── Repositories ─────────────────────────────"
REPOS=(
    "XPL-Suite/EmbedXPL-Forge"
    "XPL-Suite/FirewallXPL-Forge"
    "XPL-Suite/IndustrialXPL-Forge"
    "XPL-Suite/WirelessXPL-Forge"
    "XPL-Suite/PrinterXPL-Forge"
    "XPL-Suite/WordlistXPL-Forge"
    "MikrotikAPI-BF"
    "Labs/rapid7/metasploit-framework"
    "Labs/rapid7/recog"
    "Labs/new-arsenal-2026-09/cameradar"
    "Labs/new-arsenal-2026-09/meltdown"
    "Labs/new-arsenal-2026-09/Ingram-Pro"
)

for r in "${REPOS[@]}"; do
    if [ -d "$BASE/$r/.git" ]; then
        ok "$r"
    else
        warn "$BASE/$r missing — run clone_repos.sh"
    fi
done

echo ""
echo "── Malware Research Sources ─────────────────"
MALWARE_DIRS=(
    "Labs/malware-samples/IoT_ARM"
    "Labs/malware-samples/TRISIS-TRITON-HATMAN"
    "Labs/malware-samples/cube-maliot-2021"
    "Submodulos/malware/thezoo"
    "Submodulos/OT"
    "Submodulos/IoT"
)

for d in "${MALWARE_DIRS[@]}"; do
    if [ -d "$BASE/$d" ]; then
        COUNT=$(find "$BASE/$d" -type f 2>/dev/null | wc -l)
        ok "$d ($COUNT files)"
    else
        warn "$BASE/$d not found (may be Windows-only)"
    fi
done

echo ""
echo "═══════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Environment ready — $FAILED critical issues${NC}"
    echo ""
    echo "Start Phase 0 with Cursor/Claude:"
    echo "  'Implement Phase 0 of the EmbedXPL v5.0.0 plan'"
    echo "  Plan file: $BASE/XPL-Suite/docs/PLAN-EMBEDXPL-V5.md"
else
    echo -e "${RED}✗ $FAILED critical issues found — fix before proceeding${NC}"
    echo ""
    echo "Run: bash setup_prereqs.sh"
fi
