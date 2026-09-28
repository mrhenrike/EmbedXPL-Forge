# Introduction, Scope, and Installation

**Language:** English (en-US) | **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

---

## What EmbedXPL-Forge is

**EmbedXPL-Forge** (`embedxpl`, CLI shorthand: `exf`) is an open-source, modular Python framework for **authorized** security assessment of network devices, IoT appliances, and embedded systems. It bundles credential testing, vulnerability exploitation, network discovery and fingerprinting, payload generation, NSE script management, CVE intelligence, and post-exploitation utilities in a single extensible tool.

> **Authorization required.** Use only on systems you own or have explicit written permission to test. Unauthorized use is illegal.

| Metric | Value |
|--------|-------|
| Active modules | 2800+ |
| CVEs mapped | 700+ (2001–2026) |
| Vendor families | 114+ |
| Python versions | 3.8 – 3.13 |
| Platforms | Linux, macOS, Windows |
| License | BSD-3-Clause |
| History file | `~/.exf_history` (100 entries) |
| Session store | `~/.exf_sessions/` (one JSON per host) |

---

## Supported Device Classes

| Class | Coverage |
|-------|----------|
| **Routers / GPON ONT / CPE** | Primary focus — 580+ modules, 85+ vendor folders (D-Link, TP-Link, NETGEAR, Huawei, ZTE, MikroTik, Ubiquiti, ASUS, Linksys, Totolink, and more) |
| **IP Cameras / NVR / DVR** | Hikvision, Dahua, Herospeed/Longsee (all OEM brands), Axis, Reolink, Amcrest, Annke, Intelbras, Uniview, Bosch, ACTi, Avigilon, and more |
| **Firewalls / VPN / Perimeter appliances** | 80+ modules — Fortinet, Palo Alto, Cisco, SonicWall, Check Point, Sophos, WatchGuard, Juniper |
| **Printers / MFP** | 185+ modules — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung, CUPS |
| **Managed Switches L2/L3** | Cisco, D-Link, NETGEAR |
| **ICS / OT / Industrial** | 35+ modules — PLCs, SCADA HMIs, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **BMC / IPMI** | ASUS ASMB8 (IPMI), Dell iDRAC9, Supermicro IPMI |
| **BMS (Building Management)** | ABB Cylon Aspect |
| **NAS** | QNAP, Synology, D-Link NAS |
| **Smart Home** | eNet SMART HOME, OpenRemote, Tuya |
| **Embedded OS** | OpenWrt, VxWorks, RIOT OS, wolfSSL, QNX, RAUC |
| **Hypervisors** | Proxmox VE |
| **SOHO Edge** | Travel routers, access points, HooToo |
| **Smart TV** | Samsung, LG, Sony Bravia, Roku, Amazon Fire TV |
| **APs (Access Points)** | MediaTek MT7622 series |

---

## Requirements

| Requirement | Value | Notes |
|-------------|-------|-------|
| Python | **3.8 – 3.13** | Tested on CPython |
| pip | 21.0 or newer | Recommended |
| nmap | Optional | Enables `discover` enhanced scanning |
| Npcap | Optional (Windows) | Required for Scapy raw-socket operations |

### Mandatory runtime dependencies

These are installed automatically via `pip install embedxpl`:

```
requests        - HTTP/HTTPS client
paramiko        - SSH client
pysnmp          - SNMP v1/v2c/v3
pycryptodome    - AES/DES/RSA crypto primitives
scapy           - Raw packet crafting and network discovery
colorama        - Cross-platform terminal colors
rich >= 13.0    - Rich terminal tables and panels
aiohttp >= 3.9  - Async HTTP (camera/NVR modules)
numpy >= 1.24   - ML advisor computations
psutil >= 5.9   - System hardware profiling (sysinfo)
python-nmap >= 0.7.1  - nmap Python binding
```

> Python 3.13+ uses `telnetlib3` instead of the removed `telnetlib`. EmbedXPL-Forge handles this automatically.

---

## Installation

### Option 1 — PyPI (recommended for most users)

```bash
pip install embedxpl
```

Expected output (abbreviated):

```text
Collecting embedxpl
  Downloading embedxpl-1.0.0-py3-none-any.whl (4.2 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.2/4.2 MB 12.3 MB/s eta 0:00:00
Collecting requests>=2.28.0
  ...
Successfully installed embedxpl-1.0.0 requests-2.34.2 paramiko-5.0.0 ...
```

### Optional extras

Install additional capabilities with pip extras:

| Extra | Command | What it adds |
|-------|---------|--------------|
| NSE script manager | `pip install "embedxpl[nse]"` | 11 Nmap NSE script bundles, `embedxpl-nse` entry point |
| Printer stack | `pip install "embedxpl[printers]"` | Extended printer exploitation stack |
| All extras | `pip install "embedxpl[all]"` | Everything above |

```bash
pip install "embedxpl[nse]"

# Expected output:
Collecting embedxpl[nse]
  ...
Collecting python-nmap>=0.7.1
  Downloading python_nmap-0.7.1-py3-none-any.whl (23 kB)
Successfully installed embedxpl-1.0.0 python-nmap-0.7.1
```

### Entry points after installation

| Command | Purpose |
|---------|---------|
| `embedxpl` | Start the interactive shell |
| `exf` | Alias for `embedxpl` |
| `fxf` | Alias for `embedxpl` (FirewallXPL compat) |
| `embedxpl-nse` | NSE script manager (requires `[nse]` extra) |
| `firmware-dl` | Firmware download utility |
| `firmware-analyze` | Firmware analysis utility |

---

### Option 2 — Git clone + editable install (development / contribution)

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge

# Create and activate a virtual environment (strongly recommended)
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell
# .venv\Scripts\activate.bat       # Windows cmd.exe

pip install -r requirements.txt
pip install -e ".[nse]"           # editable install with NSE support
```

Alternative entry points from the clone root:

```bash
python exf.py              # legacy bootstrap script
python -m embedxpl         # module invocation
```

---

### Option 3 — One-shot non-interactive (no shell needed)

```bash
pip install embedxpl
embedxpl -m exploits/routers/dlink/dir_300_600_rce -s "target 192.168.0.1"
```

See [04-non-interactive-mode.md](04-non-interactive-mode.md) for the full CLI reference.

---

## First run — interactive shell

```text
$ embedxpl

  ____  __  __ _____
 |  _ \ \ \/ /|  ___|   EmbedXPL-Forge v1.0.0
 | |_) | \  / | |_      Network Device Security Assessment Framework
 |  _ <  /  \ |  _|
 |_| \_\/_/\_\|_|        Author: Andre Henrique (@mrhenrike) | Uniao Geek

 Target scope: Routers - Switches L2/L3 - IP Cameras - GPON ONTs - ISP CPEs - IoT/Embedded Edge

 [modules] 2807 total -- Exploits: 1842 | Scanners: 134 | Creds: 687 | Generic: 22 | Payloads: 32 | Encoders: 13
 [system]  Intel Core i7-12700H | 16 cores | 32 GB RAM | NVIDIA RTX 3060 6 GB | compute: auto

exf >
```

> The `[modules]` line shows the actual count from the local install. The `[system]` line is generated by `HWProfiler.detect()` at startup.

---

## Environment diagnostics (`env_doctor`)

Run this after installation to verify all dependencies and detect missing optional components:

```bash
python tools/env_doctor.py
```

Sample output (healthy system):

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
[OK]  paramiko 5.0.0
[OK]  pycryptodome 3.23.0
[OK]  scapy 2.7.0
[OK]  rich 15.0.0
[OK]  colorama 0.4.6
[OK]  aiohttp 3.10.1
[OK]  numpy 1.26.4
[OK]  psutil 5.9.8
[OK]  python-nmap 0.7.1
[OK]  nmap found in PATH (/usr/bin/nmap, version 7.95)
[OK]  Module index: 2807 modules loaded
```

Sample output (nmap missing):

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
...
[WARN] nmap not found in PATH — discover fingerprinting will use Scapy only (reduced accuracy)
[OK]  Module index: 2807 modules loaded
```

Sample output (dependency problem):

```text
[OK]  Python 3.9.18
[-]   rich not installed — install with: pip install "rich>=13.0"
[OK]  Module index: 2807 modules loaded
```

---

## Log files and history

| Path | Content | Rotation |
|------|---------|----------|
| `./embedxpl.log` | Rolling log file | 500 KB max, rotates to `.1` backup automatically |
| `~/.exf_history` | Interactive shell command history | 100 entries (oldest removed on overflow) |
| `~/.exf_sessions/` | Persistent scan session files (JSON) | One file per host, keyed by `sha256(ip + mac)` |

### Log rotation behavior

The log file `embedxpl.log` is created in the current working directory (wherever you invoke `exf`). When it exceeds 500 KB it is renamed to `embedxpl.log.1` and a fresh file is started. Only one backup is kept (`embedxpl.log.1`).

---

## Compute mode (GPU acceleration)

EmbedXPL-Forge supports GPU acceleration for ML-assisted device fingerprinting and the AutoPwn advisor:

```text
exf > compute auto      # Auto-detect best backend (default at startup)
[+] compute_mode => auto
    auto resolves to: hybrid

exf > compute cpu       # Force CPU-only mode
[+] compute_mode => cpu

exf > compute gpu       # Require GPU (falls back to cpu if no GPU is found)
[+] compute_mode => gpu

exf > compute hybrid    # CPU + GPU mixed
[+] compute_mode => hybrid
```

Attempting to set `gpu` when no GPU is detected:

```text
exf > compute gpu
[!] No GPU detected -- falling back to compute_mode=cpu
```

Valid modes: `cpu`, `gpu`, `hybrid`, `auto`. The selected mode is persisted in the local config and restored on next startup.

---

## `sysinfo` — hardware profile

```text
exf > sysinfo
```

Sample output (system with GPU):

```text
┌──────────────────────────────────────┐
│                  CPU                 │
├──────────────┬───────────────────────┤
│ Property     │ Value                 │
├──────────────┼───────────────────────┤
│ Model        │ Intel Core i7-12700H  │
│ Architecture │ x86_64                │
│ Cores        │ 14                    │
│ Threads      │ 20                    │
│ Frequency    │ 2300 MHz              │
└──────────────┴───────────────────────┘

┌──────────────────────────────────────┐
│             Memory (RAM)             │
├──────────────┬───────────────────────┤
│ Property     │ Value                 │
├──────────────┼───────────────────────┤
│ Total        │ 32,768 MB             │
│ Available    │ 24,512 MB             │
└──────────────┴───────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                              GPU Devices                                     │
├───┬────────────────────┬────────┬──────────┬─────────┬─────────┬────────────┤
│ # │ Name               │ Vendor │ VRAM     │ Backend │ Driver  │ Compute Cap│
├───┼────────────────────┼────────┼──────────┼─────────┼─────────┼────────────┤
│ 0 │ NVIDIA RTX 3060    │ NVIDIA │ 6,144 MB │ cuda    │ 545.23  │ 8.6        │
└───┴────────────────────┴────────┴──────────┴─────────┴─────────┴────────────┘

 Compute mode: auto -> hybrid  |  Best backend: cuda
```

Sample output (no GPU):

```text
...RAM table...
[!] No GPU detected on this system

 Compute mode: auto -> cpu  |  Best backend: cpu
```

---

## Architecture overview

```
CLI (exf / embedxpl / fxf)
    │
    ├── Interactive Shell  (embedxpl/interpreter.py)
    │       ├── Global: help, use, search, show, exec, sysinfo, compute
    │       ├── Global: discover, sessions, apt
    │       └── Module: run/exploit, check, set, setg, unsetg, back
    │
    ├── Non-Interactive Mode  (-m / -s / -T / --infra flags)
    │
    ├── Core Engine  (embedxpl/core/)
    │       ├── HTTP/HTTPS client with retry + TLS
    │       ├── SSH / Telnet / FTP / SNMP protocol clients
    │       ├── RTSP / Cameradar integration
    │       ├── Shell Stager (PTY, Meterpreter, bind/reverse)
    │       ├── CVE Database (embedded + NVD query)
    │       └── InfraOrchestrator (--infra scan planning)
    │
    ├── Intelligence Layer
    │       ├── HWProfiler (CPU/RAM/GPU detection)
    │       ├── ML Fingerprinter (OUI + banner analysis, AttackAdvisor)
    │       ├── APT Attack Engine (nation-state chain replay)
    │       └── SessionManager (persistent per-host scan state)
    │
    └── Module Arsenal  (embedxpl/modules/)
            ├── exploits/     (1842 modules — routers, cameras, firewalls, printers, ICS, BMC...)
            ├── creds/        (687 modules — SSH, Telnet, FTP, HTTP, SNMP per-vendor)
            ├── scanners/     (134 modules — network discovery, protocol scanners, autopwn)
            ├── payloads/     (32 modules — x86, x64, ARM, MIPS, cmd, perl, php, python)
            ├── encoders/     (13 modules — base64, hex, Python/PHP/Perl)
            └── generic/      (22 modules — CVE lookup, UPnP, SNMP, wordlist, DNS, PCAP)
```

---

## Related tools (XPL-Forge Suite)

| Tool | pip install | CLI | Scope |
|------|-------------|-----|-------|
| EmbedXPL-Forge | `pip install embedxpl` | `embedxpl` / `exf` | IoT / network devices (broad) |
| FirewallXPL-Forge | `pip install firewallxpl` | `fxf` | Firewall / VPN specialist |
| PrinterXPL-Forge | `pip install printerxpl-forge` | `printerxpl-forge` | Printer / MFP specialist |
| WirelessXPL-Forge | `pip install wirelessxpl` | `wxf` | Wireless — Wi-Fi, BLE, Zigbee, Z-Wave |
| MikrotikAPI-BF | `pip install mikrotikapi-bf` | `mikrotik-bf` | MikroTik RouterOS API brute-force |

---

[Wiki hub](../README.md)
