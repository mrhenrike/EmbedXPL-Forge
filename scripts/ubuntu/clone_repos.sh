#!/usr/bin/env bash
# =============================================================================
# EmbedXPL v5.0.0 — Clone All Required Repositories
# Run: bash clone_repos.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
section(){ echo -e "${CYAN}[====]${NC} $*"; }

GH_ORG="${GH_ORG:-UniaoGeek}"
BASE="${BASE:-$HOME/projects}"

clone_or_pull() {
    local url="$1" name="${2:-$(basename $1 .git)}" dir="${3:-$name}"
    if [ -d "$dir/.git" ]; then
        info "Updating $dir..."
        (cd "$dir" && git pull --quiet 2>&1 | tail -1) || warn "$dir pull failed"
    else
        info "Cloning $name..."
        git clone --quiet "$url" "$dir" 2>&1 || warn "WARN: failed to clone $url"
    fi
}

mkdir -p "$BASE"

# ─── XPL Suite ────────────────────────────────────────────────────────────────
section "XPL Suite repositories"
mkdir -p "$BASE/XPL-Suite"
cd "$BASE/XPL-Suite"

for repo in EmbedXPL-Forge FirewallXPL-Forge IndustrialXPL-Forge \
            WirelessXPL-Forge PrinterXPL-Forge WordlistXPL-Forge; do
    clone_or_pull "https://github.com/$GH_ORG/$repo"
done

# TupaXPL — private, requires auth
info "Cloning TupaXPL-Forge (private — requires gh auth)..."
if gh auth status &>/dev/null; then
    clone_or_pull "https://github.com/$GH_ORG/TupaXPL-Forge" || warn "TupaXPL-Forge: ensure you have access"
else
    warn "gh not authenticated — skipping TupaXPL-Forge (run: gh auth login)"
fi

# ─── MikrotikAPI-BF ───────────────────────────────────────────────────────────
section "MikrotikAPI-BF"
mkdir -p "$BASE"
cd "$BASE"
clone_or_pull "https://github.com/$GH_ORG/MikrotikAPI-BF"

# ─── Arsenal repos ────────────────────────────────────────────────────────────
section "Arsenal repos (new-arsenal-2026-09)"
mkdir -p "$BASE/Labs/new-arsenal-2026-09"
cd "$BASE/Labs/new-arsenal-2026-09"

declare -A ARSENAL=(
    ["wifit3"]="https://github.com/derv82/wifit3"
    ["atomic-red-team"]="https://github.com/redcanaryco/atomic-red-team"
    ["meltdown"]="https://github.com/isec-tugraz/meltdown"
    ["pocindex"]="https://github.com/0xMarcio/pocindex"
    ["rapid7-CVE-2026-15409"]="https://github.com/remmons-r7/rapid7-CVE-2026-15409"
    ["CVE-2024-4577"]="https://github.com/watchtowrlabs/CVE-2024-4577"
    ["watchTowr-vs-FortiWeb-CVE-2025-25257"]="https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257"
    ["watchTowr-vs-WatchGuard-CVE-2025-9242"]="https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242"
    ["Fortijump-Exploit-CVE-2024-47575"]="https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575"
    ["juniper-rce_cve-2023-36844"]="https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844"
    ["watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127"]="https://github.com/watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127"
    ["watchTowr-vs-Netscaler-CVE-2026-8451"]="https://github.com/watchtowrlabs/watchTowr-vs-Netscaler-CVE-2026-8451"
    ["watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523"]="https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523"
    ["watchTowr-vs-Progress-ShareFile-CVE-2026-2699"]="https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699"
    ["watchtowr-vs-telnetd-CVE-2026-32746"]="https://github.com/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746"
    ["watchTowr-vs-Splunk-CVE-2026-20253"]="https://github.com/watchtowrlabs/watchTowr-vs-Splunk-CVE-2026-20253"
    ["watchTowr-vs-Check-Point-CVE-2026-50751"]="https://github.com/watchtowrlabs/watchTowr-vs-Check-Point-CVE-2026-50751"
    ["watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452"]="https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452"
    ["cameradar"]="https://github.com/Ullaakut/cameradar"
)

for name in "${!ARSENAL[@]}"; do
    clone_or_pull "${ARSENAL[$name]}" "$name" "$name"
done

# Ingram-Pro (check multiple possible sources)
if [ ! -d "Ingram-Pro" ]; then
    git clone https://github.com/pwnfan/Ingram-Pro Ingram-Pro 2>/dev/null || \
    git clone https://github.com/alienatedorangutan/Ingram-Pro Ingram-Pro 2>/dev/null || \
    warn "Ingram-Pro: manual download needed — check GitHub for 'Ingram-Pro camera scanner'"
fi

# ─── Rapid7 (large repos) ─────────────────────────────────────────────────────
section "Rapid7 repositories (large downloads)"
mkdir -p "$BASE/Labs/rapid7"
cd "$BASE/Labs/rapid7"

info "Cloning rapid7/recog (~50MB)..."
clone_or_pull "https://github.com/rapid7/recog"

info "Cloning rapid7/metasploit-framework (~4GB shallow clone)..."
info "  This may take 10-30 minutes depending on connection..."
if [ ! -d "metasploit-framework/.git" ]; then
    git clone --depth=1 --quiet \
        https://github.com/rapid7/metasploit-framework \
        metasploit-framework 2>&1 | tail -1
    info "MSF cloned: $(find metasploit-framework/modules -name '*.rb' 2>/dev/null | wc -l) Ruby modules"
else
    info "MSF already cloned"
fi

info "Cloning rapid7/vulnerability-feeds..."
clone_or_pull "https://github.com/rapid7/vulnerability-feeds" 2>/dev/null || warn "vulnerability-feeds not accessible"

# ─── Tenable ─────────────────────────────────────────────────────────────────
section "Tenable public repositories"
mkdir -p "$BASE/Labs/tenable"
cd "$BASE/Labs/tenable"

for repo in "tenable/pyTenable" "tenable/terrascan"; do
    name=$(basename "$repo")
    clone_or_pull "https://github.com/$repo" "$name" 2>/dev/null || warn "$repo not accessible"
done

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
section "CLONE SUMMARY"
echo ""

REPOS=(
    "$BASE/XPL-Suite/EmbedXPL-Forge"
    "$BASE/XPL-Suite/FirewallXPL-Forge"
    "$BASE/XPL-Suite/IndustrialXPL-Forge"
    "$BASE/XPL-Suite/WirelessXPL-Forge"
    "$BASE/XPL-Suite/PrinterXPL-Forge"
    "$BASE/XPL-Suite/WordlistXPL-Forge"
    "$BASE/MikrotikAPI-BF"
    "$BASE/Labs/rapid7/metasploit-framework"
    "$BASE/Labs/rapid7/recog"
)

for r in "${REPOS[@]}"; do
    if [ -d "$r/.git" ]; then
        COUNT=$(find "$r" -name "*.py" -o -name "*.rb" -o -name "*.go" 2>/dev/null | wc -l)
        printf "  %-55s %5d files\n" "${r/$HOME\//~/}" "$COUNT"
    else
        printf "  %-55s  MISSING\n" "${r/$HOME\//~/}"
    fi
done

echo ""
info "=== All repos ready ==="
echo ""
echo "Next step: Run Cursor/Claude with the plan file:"
echo "  Plan: ~/projects/XPL-Suite/docs/PLAN-EMBEDXPL-V5.md"
echo "  Start with: 'Implement Phase 0 of the plan'"
