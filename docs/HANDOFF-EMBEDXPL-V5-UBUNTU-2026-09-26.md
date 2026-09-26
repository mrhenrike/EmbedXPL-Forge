# HANDOFF — EmbedXPL v5.0.0 Ubuntu Continuation
## Session: Sep 26, 2026 | Source: Windows 11 → Target: Ubuntu Linux

---

## Context

This handoff documents the **EmbedXPL v5.0.0 absorption plan** that was designed
on Windows 11 but needs to be executed on **Ubuntu Linux** due to:

- Cross-compilers (ARM, MIPS) not available on Windows without WSL
- Go compilation for Linux embedded targets requires Linux toolchain
- Ruby/MSF execution more reliable on Linux
- Large file sync operations (50K+ malware files) more stable on Linux
- `apt` access to all needed build tools

---

## What Is This Plan?

Transform EmbedXPL into the **unified XPL Suite framework** (v5.0.0) that:
1. Contains a **multi-language runtime** (Python / C / C++ / Go / Rust / Ruby)
2. Receives a **full copy** of all specialized XPL Suite tools (WirelessXPL, PrinterXPL, FirewallXPL, IndustrialXPL, WordlistXPL)
3. Absorbs **MikrotikAPI-BF** completely (that tool stops development)
4. Integrates **Ingram-Pro cameras**, **Cameradar (Go RTSP)**, **Mirai IoT source**, **TRISIS-TRITON-HATMAN ICS malware research**
5. Clones **Rapid7 Metasploit** + **rapid7/recog** for Ruby executor integration
6. Executes each phase only after **explicit user approval** (phase gates)

**Phase gates:** user types `APROVADO: P<N>` to release each phase.

---

## Repository Paths (Windows → Ubuntu mapping)

```
Windows source:                         Ubuntu clone path:
D:\Projects\UniaoGeek\XPL-Suite\       ~/projects/XPL-Suite/
D:\Projects\UniaoGeek\MikrotikAPI-BF\  ~/projects/MikrotikAPI-BF/
D:\Projects\Labs\                       ~/projects/Labs/
D:\Projects\Submodulos\                 ~/projects/Submodulos/
```

All repos are on GitHub under `UniaoGeek` org. Clone them fresh on Ubuntu.

---

## Step 1 — Ubuntu Prerequisites

Run as the Ubuntu user (assumes `sudo` access):

```bash
#!/bin/bash
# setup_ubuntu_prereqs.sh
set -e

echo "=== Updating system ==="
sudo apt-get update && sudo apt-get upgrade -y

echo "=== Core build tools ==="
sudo apt-get install -y \
  build-essential git curl wget unzip \
  python3 python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev

echo "=== C/C++ cross-compilers (for embedded targets) ==="
sudo apt-get install -y \
  gcc g++ clang \
  gcc-arm-linux-gnueabi g++-arm-linux-gnueabi \
  gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
  gcc-mips-linux-gnu g++-mips-linux-gnu \
  gcc-mipsel-linux-gnu g++-mipsel-linux-gnu \
  binutils-arm-linux-gnueabi \
  binutils-aarch64-linux-gnu \
  binutils-mips-linux-gnu \
  binutils-mipsel-linux-gnu

echo "=== Go ==="
# Remove old, install latest
sudo apt-get remove -y golang* 2>/dev/null || true
wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin

echo "=== Rust ==="
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

echo "=== Ruby (for MSF modules) ==="
sudo apt-get install -y ruby ruby-dev ruby-bundler

echo "=== Python packages for EmbedXPL ==="
pip3 install --user \
  requests paramiko pysnmp pycryptodome scapy \
  colorama rich aiohttp numpy psutil python-nmap \
  telnetlib3

echo "=== GitHub CLI ==="
type -p curl >/dev/null || sudo apt install curl -y
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install -y gh

echo "=== Verify ==="
gcc --version | head -1
arm-linux-gnueabi-gcc --version | head -1
aarch64-linux-gnu-gcc --version | head -1
mips-linux-gnu-gcc --version | head -1
go version
rustc --version
ruby --version
python3 --version
gh --version

echo ""
echo "=== ALL PREREQS INSTALLED ==="
```

---

## Step 2 — Clone All Repos

```bash
#!/bin/bash
# clone_repos.sh
set -e

GH_ORG="UniaoGeek"
BASE="$HOME/projects"
mkdir -p "$BASE"

echo "=== XPL Suite repos ==="
cd "$BASE"
git clone https://github.com/$GH_ORG/XPL-Suite || true
mkdir -p XPL-Suite
cd XPL-Suite

for repo in EmbedXPL-Forge FirewallXPL-Forge IndustrialXPL-Forge \
            WirelessXPL-Forge PrinterXPL-Forge WordlistXPL-Forge \
            TupaXPL-Forge; do
  if [ ! -d "$repo" ]; then
    git clone https://github.com/$GH_ORG/$repo
  else
    echo "$repo already exists, pulling..."
    (cd "$repo" && git pull)
  fi
done

echo "=== MikrotikAPI-BF ==="
cd "$BASE"
if [ ! -d "MikrotikAPI-BF" ]; then
  git clone https://github.com/$GH_ORG/MikrotikAPI-BF
fi

echo "=== Labs repos (arsenal) ==="
mkdir -p "$BASE/Labs/new-arsenal-2026-09"
cd "$BASE/Labs/new-arsenal-2026-09"

# From D:\Projects\Labs\new-arsenal-2026-09\ on Windows:
ARSENAL_REPOS=(
  "https://github.com/derv82/wifit3"
  "https://github.com/redcanaryco/atomic-red-team"
  "https://github.com/irsdl/ysonet"
  "https://github.com/d6fault/APTF"
  "https://github.com/watchtowrlabs/watchTowr-vs-FortiWeb-CVE-2025-25257"
  "https://github.com/watchtowrlabs/watchTowr-vs-WatchGuard-CVE-2025-9242"
  "https://github.com/watchtowrlabs/Fortijump-Exploit-CVE-2024-47575"
  "https://github.com/watchtowrlabs/juniper-rce_cve-2023-36844"
  "https://github.com/watchtowrlabs/CVE-2024-4577"
  "https://github.com/watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127"
  "https://github.com/watchtowrlabs/watchTowr-vs-Netscaler-CVE-2026-8451"
  "https://github.com/watchtowrlabs/watchTowr-vs-Ivanti-Sentry-RCE-CVE-2026-10520-CVE-2026-10523"
  "https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699"
  "https://github.com/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746"
  "https://github.com/watchtowrlabs/watchTowr-vs-Splunk-CVE-2026-20253"
  "https://github.com/watchtowrlabs/watchTowr-vs-Check-Point-CVE-2026-50751"
  "https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452"
  "https://github.com/isec-tugraz/meltdown"
  "https://github.com/0xMarcio/pocindex"
  "https://github.com/remmons-r7/rapid7-CVE-2026-15409"
)

for repo in "${ARSENAL_REPOS[@]}"; do
  name=$(basename "$repo")
  if [ ! -d "$name" ]; then
    git clone "$repo" || echo "WARN: failed to clone $repo"
  fi
done

echo "=== Rapid7 MSF (large ~4GB) ==="
mkdir -p "$BASE/Labs/rapid7"
cd "$BASE/Labs/rapid7"
if [ ! -d "metasploit-framework" ]; then
  echo "Cloning MSF (this will take a while)..."
  git clone --depth=1 https://github.com/rapid7/metasploit-framework
fi
if [ ! -d "recog" ]; then
  git clone https://github.com/rapid7/recog
fi

echo "=== Tenable public repos ==="
mkdir -p "$BASE/Labs/tenable"
cd "$BASE/Labs/tenable"
# Clone available public tenable repos
for r in tenable/pyTenable tenable/terrascan; do
  name=$(basename "$r")
  if [ ! -d "$name" ]; then
    git clone https://github.com/$r || echo "WARN: $r not accessible"
  fi
done

echo "=== Ingram-Pro ==="
mkdir -p "$BASE/Labs/new-arsenal-2026-09"
cd "$BASE/Labs/new-arsenal-2026-09"
if [ ! -d "Ingram-Pro" ]; then
  git clone https://github.com/pwnfan/Ingram-Pro || \
  git clone https://github.com/alienatedorangutan/Ingram-Pro || \
  echo "WARN: check Ingram-Pro repo URL"
fi

if [ ! -d "cameradar" ]; then
  git clone https://github.com/Ullaakut/cameradar native_src_cameradar
fi

echo ""
echo "=== ALL REPOS CLONED ==="
echo "Run verify_repos.sh to check counts"
```

---

## Step 3 — Phase Execution Script

Save this as `run_phase.sh` and use it to execute each phase:

```bash
#!/bin/bash
# run_phase.sh — execute one phase of EmbedXPL v5.0.0 plan
# Usage: ./run_phase.sh <phase_number>
# Example: ./run_phase.sh 0

PHASE=$1
EMBEDXPL_ROOT="$HOME/projects/XPL-Suite/EmbedXPL-Forge"
MIKROTIK_ROOT="$HOME/projects/MikrotikAPI-BF"
LABS="$HOME/projects/Labs"
SUITE="$HOME/projects/XPL-Suite"
LOG_DIR="$HOME/projects/XPL-Suite/docs/phase_logs"

mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/phase_${PHASE}_$(date +%Y%m%d_%H%M%S).log"

echo "=== PHASE $PHASE STARTING $(date) ===" | tee -a "$LOG"

case "$PHASE" in
  0) bash "${0%/*}/phases/phase0_runtime.sh" 2>&1 | tee -a "$LOG" ;;
  1) bash "${0%/*}/phases/phase1_audit.sh" 2>&1 | tee -a "$LOG" ;;
  2) bash "${0%/*}/phases/phase2_sync_model.sh" 2>&1 | tee -a "$LOG" ;;
  3) bash "${0%/*}/phases/phase3_wireless.sh" 2>&1 | tee -a "$LOG" ;;
  4) bash "${0%/*}/phases/phase4_wordlist.sh" 2>&1 | tee -a "$LOG" ;;
  5) bash "${0%/*}/phases/phase5_printers.sh" 2>&1 | tee -a "$LOG" ;;
  6) bash "${0%/*}/phases/phase6_firewall.sh" 2>&1 | tee -a "$LOG" ;;
  7) bash "${0%/*}/phases/phase7_industrial.sh" 2>&1 | tee -a "$LOG" ;;
  8) bash "${0%/*}/phases/phase8_mikrotik.sh" 2>&1 | tee -a "$LOG" ;;
  9) bash "${0%/*}/phases/phase9_cameras.sh" 2>&1 | tee -a "$LOG" ;;
  10) bash "${0%/*}/phases/phase10_malware.sh" 2>&1 | tee -a "$LOG" ;;
  11) bash "${0%/*}/phases/phase11_rapid7.sh" 2>&1 | tee -a "$LOG" ;;
  12) bash "${0%/*}/phases/phase12_native_src.sh" 2>&1 | tee -a "$LOG" ;;
  13) bash "${0%/*}/phases/phase13_cves.sh" 2>&1 | tee -a "$LOG" ;;
  14) bash "${0%/*}/phases/phase14_osint.sh" 2>&1 | tee -a "$LOG" ;;
  15) bash "${0%/*}/phases/phase15_release.sh" 2>&1 | tee -a "$LOG" ;;
  *) echo "Unknown phase $PHASE. Valid: 0-15"; exit 1 ;;
esac

echo "" | tee -a "$LOG"
echo "=== PHASE $PHASE COMPLETE $(date) ===" | tee -a "$LOG"
echo "Log saved to: $LOG"
echo ""
echo ">>> REVIEW LOG AND REPORT TO USER BEFORE PROCEEDING TO NEXT PHASE <<<"
```

---

## Phase Details for Linux Execution

### PHASE 0 — Multi-Language Runtime
**What it does:** Creates `embedxpl/runtime/` with all language executors.
**Key files to create:**
```
embedxpl/runtime/__init__.py
embedxpl/runtime/executor.py        # XplRuntime orchestrator
embedxpl/runtime/python_exec.py     # Python executor (passthrough)
embedxpl/runtime/c_exec.py          # gcc/clang + cross-compile
embedxpl/runtime/cpp_exec.py        # g++/clang++
embedxpl/runtime/go_exec.py         # go build + cache
embedxpl/runtime/rust_exec.py       # rustc/cargo
embedxpl/runtime/ruby_exec.py       # ruby .rb MSF-compatible
embedxpl/runtime/toolchain.py       # detect all compilers
embedxpl/runtime/crosscompile.py    # ARM/MIPS/MIPSLE targets
embedxpl/runtime/cache.py           # binary cache
```
**Linux advantage:** All cross-compilers available via `apt`.

**Verify cross-compilers work:**
```bash
arm-linux-gnueabi-gcc --version
mips-linux-gnu-gcc --version
aarch64-linux-gnu-gcc --version
```

### PHASE 1 — Deep Research Audit
**What it does:** Reads and catalogs all unanalyzed repos, generates mapping report.

**Key repos to audit:**
- `~/projects/Submodulos/OT/` — 62K files (BusPwn, ics-tools, modbus-tcp-auditor, s7comm-auditor)
- `~/projects/Submodulos/IoT/` — 56K files (third-party-router-poc, aic8800-src, _loose-root)
- `~/projects/Submodulos/Hacking/` — 23K files (26 security tools)
- `~/projects/Labs/malware-samples/TRISIS-TRITON-HATMAN/` — 228 files (ICS attack malware)
- `~/projects/Labs/malware-samples/IoT_ARM/` — 6K files (Mirai source C+Go)
- `~/projects/Labs/malware-samples/cube-maliot-2021/` — 48K files (IoT malware dataset)
- `~/projects/Labs/malware-samples/thezoo/` — 1.5K files (malware zoo)
- `~/projects/Labs/rapid7/metasploit-framework/` — post-clone

**Output:** `docs/PHASE1-AUDIT-REPORT-$(date).md`

### PHASE 2 — Sync Model
**Creates:** `EmbedXPL-Forge/tools/sync_from_suite.py`
```python
SYNC_MAP = {
    "~/projects/XPL-Suite/WirelessXPL-Forge/wirelessxpl/modules/": "modules/exploits/wireless/",
    "~/projects/XPL-Suite/PrinterXPL-Forge/printerxpl/modules/exploits/": "modules/exploits/printers/",
    "~/projects/XPL-Suite/FirewallXPL-Forge/firewallxpl/modules/exploits/": "modules/exploits/firewalls/",
    "~/projects/XPL-Suite/IndustrialXPL-Forge/industrialxpl/modules/exploits/": "modules/exploits/ics/",
    "~/projects/XPL-Suite/WordlistXPL-Forge/wfh_modules/": "engines/wordlists/",
}
```

### PHASES 3–7 — Specialized Tool Copy
Each phase syncs one specialized tool into EmbedXPL:
```bash
# Example for Phase 3 (WirelessXPL):
rsync -av \
  ~/projects/XPL-Suite/WirelessXPL-Forge/wirelessxpl/modules/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/modules/exploits/wireless/
```

### PHASE 8 — MikrotikAPI-BF Absorção
```bash
# Copy all Python modules
rsync -av \
  ~/projects/MikrotikAPI-BF/core/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/modules/exploits/network_os/mikrotik/

# Copy NSE scripts
rsync -av \
  ~/projects/MikrotikAPI-BF/nse/*.nse \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/resources/nse/mikrotik/

# Archive on GitHub (use gh CLI)
gh repo archive UniaoGeek/MikrotikAPI-BF --yes
```

### PHASE 9 — Cameras + Cameradar Go
```bash
# Build Cameradar (Go required)
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/go/cameradar
cp -r ~/projects/Labs/new-arsenal-2026-09/native_src_cameradar/* \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/go/cameradar/

# Test build
cd ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/go/cameradar
go build ./cmd/cameradar/  # verify it compiles on Linux
```

### PHASE 10 — Malware Research
```bash
# Copy IoT_ARM source
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/c/mirai_iot
cp ~/projects/Labs/malware-samples/IoT_ARM/attack_*.c \
   ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/c/mirai_iot/ 2>/dev/null || true

# Copy IoT_ARM Go source
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/go/mirai_bot
cp ~/projects/Labs/malware-samples/IoT_ARM/attack.go \
   ~/projects/Labs/malware-samples/IoT_ARM/bot.go \
   ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/go/mirai_bot/ 2>/dev/null || true

# Extract crosscompiler patterns from IoT_ARM/crosscompiler.bash
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/malware_research/mirai
cp -r ~/projects/Labs/malware-samples/IoT_ARM \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/malware_research/mirai/IoT_ARM_source

# TRISIS-TRITON-HATMAN
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/malware_research/ics_apt/trisis
cp -r ~/projects/Labs/malware-samples/TRISIS-TRITON-HATMAN \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/malware_research/ics_apt/trisis/
```

### PHASE 11 — Rapid7 + Tenable
```bash
# MSF modules selection (linux/ + hardware/ + multi/ + auxiliary/scanner/)
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/ruby/msf
rsync -av --include="*.rb" --include="*/" --exclude="*" \
  ~/projects/Labs/rapid7/metasploit-framework/modules/exploits/linux/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/ruby/msf/exploits_linux/

rsync -av --include="*.rb" --include="*/" --exclude="*" \
  ~/projects/Labs/rapid7/metasploit-framework/modules/exploits/hardware/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/ruby/msf/exploits_hardware/

rsync -av --include="*.rb" --include="*/" --exclude="*" \
  ~/projects/Labs/rapid7/metasploit-framework/modules/auxiliary/scanner/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/ruby/msf/auxiliary_scanner/

# Recog fingerprinting
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/engines/fingerprint/recog
cp -r ~/projects/Labs/rapid7/recog/xml/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/engines/fingerprint/recog/
```

### PHASE 12 — Native Source Trees
```bash
# meltdown (C)
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/c/meltdown
cp ~/projects/Labs/new-arsenal-2026-09/meltdown/*.c \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/c/meltdown/

# oboromi (C++)
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/cpp/oboromi
cp -r ~/projects/Labs/new-arsenal-2026-09/oboromi/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/cpp/oboromi/

# Test compilation
cd ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/native_src/c/meltdown
gcc meltdown.c -o /tmp/meltdown_test -lm && echo "C compile OK" && rm /tmp/meltdown_test

# ARM cross-compile test
arm-linux-gnueabi-gcc meltdown.c -o /tmp/meltdown_arm -lm && echo "ARM compile OK" && rm /tmp/meltdown_arm
mips-linux-gnu-gcc meltdown.c -o /tmp/meltdown_mips -lm && echo "MIPS compile OK" && rm /tmp/meltdown_mips
```

### PHASE 13 — Arsenal CVEs Pending
```bash
# murrez CVE batch — implement Python exploits
# CVE-2026-13355, 19658, 12227, 92229, 6433, 8181, 14281, 89055, 41940
# Each is a separate exploit module in routers/ or misc/

# CheckPoint CVE-2026-50751
# Add to both EmbedXPL firewalls/checkpoint/ AND FirewallXPL

# Pruva.dev REPROs — run and verify
ls ~/projects/Labs/pruva-repros/
```

### PHASE 14 — Intel/OSINT
```bash
# nuclei-templates
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/engines/nuclei
cp -r ~/projects/Submodulos/Hacking/nuclei-templates/ \
  ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/engines/nuclei/templates/ 2>/dev/null || \
  echo "WARN: nuclei-templates not found at Hacking/nuclei-templates"

# maigret, theHarvester, spiderfoot
mkdir -p ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/intel/osint
for tool in maigret theHarvester spiderfoot; do
  if [ -d ~/projects/Submodulos/Hacking/$tool ]; then
    cp -r ~/projects/Submodulos/Hacking/$tool \
      ~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/intel/osint/
  fi
done
```

### PHASE 15 — Releases
```bash
# Authenticate GitHub CLI first
gh auth login

# Archive MikrotikAPI-BF
gh api repos/UniaoGeek/MikrotikAPI-BF \
  --method PATCH \
  --field archived=true \
  --field private=false

# EmbedXPL: bump version, create release
cd ~/projects/XPL-Suite/EmbedXPL-Forge
# Update version.py to 5.0.0
sed -i 's/__version__ = ".*"/__version__ = "5.0.0"/' embedxpl/version.py 2>/dev/null || \
  echo "5.0.0" > embedxpl/VERSION

# Commit and push
git add -A
git commit -m "feat: EmbedXPL v5.0.0 — Unified XPL Suite Framework

Absorbed tools: MikrotikAPI-BF (fully), WirelessXPL (copy), PrinterXPL (copy),
FirewallXPL (copy), IndustrialXPL (copy), WordlistXPL (copy).

New: Multi-language runtime (Python/C/C++/Go/Rust/Ruby),
native_src/ (Cameradar Go, Mirai C/Go, meltdown C, MSF Ruby),
malware_research/ (TRISIS-TRITON-HATMAN, IoT_ARM, Mirai),
intel/ (nuclei-templates, OSINT tools).

Co-authored-by: mrhenrike <mrhenrike@users.noreply.github.com>"

git push origin main

# Create release
gh release create v5.0.0 \
  --title "EmbedXPL v5.0.0 — Unified XPL Suite Framework" \
  --notes-file docs/RELEASE-V5.0.0-NOTES.md
```

---

## GitHub Authentication (Ubuntu)

```bash
# Option 1: gh CLI (recommended)
gh auth login
# Choose: GitHub.com → HTTPS → Yes → Login with browser

# Option 2: PAT token
export GITHUB_TOKEN="ghp_YOUR_TOKEN_HERE"
gh auth login --with-token <<< "$GITHUB_TOKEN"

# Verify
gh auth status
```

---

## Key File Locations

| What | Windows Path | Ubuntu Path |
|---|---|---|
| EmbedXPL | `D:\Projects\UniaoGeek\XPL-Suite\EmbedXPL-Forge` | `~/projects/XPL-Suite/EmbedXPL-Forge` |
| MikrotikAPI-BF | `D:\Projects\UniaoGeek\MikrotikAPI-BF` | `~/projects/MikrotikAPI-BF` |
| Labs arsenal | `D:\Projects\Labs\new-arsenal-2026-09` | `~/projects/Labs/new-arsenal-2026-09` |
| Malware samples | `D:\Projects\Labs\malware-samples` | `~/projects/Labs/malware-samples` |
| Submodulos | `D:\Projects\Submodulos` | `~/projects/Submodulos` |
| Pruva repros | `D:\Projects\Labs\pruva-repros` | `~/projects/Labs/pruva-repros` |
| Plan file | `C:\Users\mrhen\.cursor\plans\embedxpl_arsenal_absorption_ef488eca.plan.md` | `~/projects/XPL-Suite/docs/PLAN-EMBEDXPL-V5.md` |

---

## Phase Gate Protocol (copy this to AI assistant)

```
IMPORTANT — PHASE GATES:
Each phase must end with a COMPLETION REPORT showing:
- Files created/modified (full list)
- Modules integrated (count + names)
- Issues found and resolved
- Preview of next phase

Then STOP and wait for: "APROVADO: P<N+1>"
Only then proceed to next phase.

Phase sequence: P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8 →
                P9 → P10 → P11 → P12 → P13 → P14 → P15 (RELEASE)
```

---

## What Was Already Done (Windows session)

| Component | Status |
|---|---|
| Plan created | ✅ `embedxpl_arsenal_absorption_ef488eca.plan.md` |
| Architecture designed | ✅ Multi-language runtime, sync model, domain mapping |
| Phase 0 runtime | ❌ Not yet implemented (blocked by Windows toolchain) |
| All other phases | ❌ Not yet started |
| Existing `multi_lang_module.py` | ✅ Basic C/Ruby/Bash runner (161 lines) — Phase 0 extends this |
| EmbedXPL current version | v3.9.0 (latest) |
| EmbedXPL current modules | ~4,959 Python files |

---

## Existing Foundation (use as starting point for Phase 0)

File: `embedxpl/core/multi_lang_module.py` (161 lines)
Already has: `run_c_source()`, `run_ruby_source()`, `run_bash_source()`
Phase 0 extends this into the full `runtime/` package.

---

## Priority Order on Ubuntu

1. **Install prereqs** (setup_ubuntu_prereqs.sh) — 10 min
2. **Clone repos** (clone_repos.sh) — 20-60 min (MSF is 4GB)
3. **Phase 0** — build `runtime/` package — 45 min
4. **Verify** all cross-compilers, Go, Ruby work — 15 min
5. **Present report** → wait for `APROVADO: P1`
6. Continue sequentially through phases with gates

---

*Generated: 2026-09-26 | Session: EmbedXPL v5.0.0 Architecture*
*Plan: `embedxpl_arsenal_absorption_ef488eca.plan.md`*
*Continues from: Windows 11 planning session*
