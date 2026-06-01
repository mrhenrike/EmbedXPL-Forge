# Introduction, Scope, and Installation

**Language:** English (en-US) | **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

---

## What EmbedXPL-Forge is

**EmbedXPL-Forge** (`embedxpl`, CLI: `exf`) is an open-source, modular Python framework for **authorized** security assessment of IoT devices, perimeter appliances, and embedded systems. It bundles credential testing, vulnerability exploitation, network scanning, payload generation, NSE script management, firmware analysis, and post-exploitation utilities in a single, extensible tool.

> **Authorization required.** Use only on systems you own or have explicit written permission to test.

| Metric | Value |
|--------|-------|
| Active modules | 2800+ |
| CVEs mapped | 700+ (2001–2026) |
| Vendor families | 114+ |
| Python versions | 3.8 – 3.13 |
| Platforms | Linux, macOS, Windows |
| License | BSD-3-Clause |

---

## Supported Device Classes

| Class | Coverage |
|-------|----------|
| **Routers / GPON ONT / CPE** | Primary focus — 580+ modules, 85+ vendor folders |
| **Printers / MFP** | 185+ modules — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung, CUPS |
| **Firewalls / VPN / Perimeter** | 80+ modules — Fortinet, Palo Alto, Cisco, SonicWall, Check Point, Sophos, WatchGuard, Juniper |
| **IP Cameras / NVR / DVR / RTSP** | Hikvision, Dahua, Herospeed, Longsee, Uniview, Reolink, Axis, Amcrest |
| **ICS / OT / Industrial** | 35+ modules — PLCs, SCADA, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **Smart Home / Maritime** | eNet SMART HOME, OpenRemote, Metis maritime IoT |
| **Embedded OS** | RIOT OS, OpenWrt, VxWorks, QNX, wolfSSL, Tuya |
| **Managed Switches L2/L3** | Cisco, D-Link, NETGEAR |
| **SOHO Edge** | NAS, APs, travel routers |
| **NAS** | QNAP, Synology, D-Link NAS |

---

## Requirements

| Requirement | Value |
|-------------|-------|
| Python | **3.8 – 3.13** |
| Pip | 21.0 or newer recommended |
| Optional | `nmap` binary for enhanced network discovery |
| Optional | Npcap (Windows) for Scapy raw-socket discovery |

Mandatory runtime dependencies (installed automatically via pip):

```
requests, paramiko, pysnmp, pycryptodome, scapy, colorama,
rich>=13.0, aiohttp>=3.9, numpy>=1.24, psutil>=5.9, python-nmap>=0.7.1
```

Python 3.13+ automatically uses `telnetlib3` instead of the removed `telnetlib`.

---

## Installation

### Option 1 — PyPI (recommended)

```bash
pip install embedxpl
```

Install optional extras for additional capabilities:

```bash
pip install "embedxpl[nse]"       # Nmap NSE script manager (11 scripts)
pip install "embedxpl[printers]"  # extended printer stack
pip install "embedxpl[all]"       # everything
```

After installation, the following commands are available:

| Command | Purpose |
|---------|---------|
| `embedxpl` | Start the interactive shell |
| `exf` | Alias for `embedxpl` |
| `fxf` | Alias for `embedxpl` |
| `embedxpl-nse` | NSE script manager |
| `firmware-dl` | Firmware download utility |
| `firmware-analyze` | Firmware analysis utility |

### Option 2 — Git clone + editable install (development)

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge

# Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows PowerShell
# .venv\Scripts\activate.bat     # Windows cmd

pip install -r requirements.txt
pip install -e ".[nse]"          # editable install with NSE support
```

Run directly from the clone root:

```bash
python exf.py          # legacy bootstrap
python -m embedxpl     # module entry point
```

### Option 3 — PyPI, non-interactive one-shot

```bash
pip install embedxpl
embedxpl -m exploits/routers/dlink/dir_300_600_rce -s "target 192.168.0.1"
```

---

## First run

```text
$ embedxpl

    ███████╗███╗   ███╗██████╗ ███████╗██████╗ ██╗  ██╗██████╗ ██╗
    ██╔════╝████╗ ████║██╔══██╗██╔════╝██╔══██╗╚██╗██╔╝██╔══██╗██║
    █████╗  ██╔████╔██║██████╔╝█████╗  ██║  ██║ ╚███╔╝ ██████╔╝██║
    ██╔══╝  ██║╚██╔╝██║██╔══██╗██╔══╝  ██║  ██║ ██╔██╗ ██╔═══╝ ██║
    ███████╗██║ ╚═╝ ██║██████╔╝███████╗██████╔╝██╔╝ ██╗██║     ███████╗
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝

    EmbedXPL-Forge v3.2.1  |  2800+ modules  |  700+ CVEs  |  114+ vendors
    https://github.com/mrhenrike/EmbedXPL-Forge

exf >
```

---

## Environment diagnostics

Run this after installation to verify all dependencies and detect missing optional components:

```bash
python tools/env_doctor.py
```

Sample output:

```text
[OK]  Python 3.11.9
[OK]  requests 2.34.2
[OK]  paramiko 5.0.0
[OK]  pycryptodome 3.23.0
[OK]  scapy 2.7.0
[OK]  rich 15.0.0
[OK]  colorama 0.4.6
[WARN] nmap not found in PATH — discovery features limited
[OK]  Module index: 2807 modules loaded
```

---

## Log files and history

| Path | Content |
|------|---------|
| `./embedxpl.log` | Rolling log file (500 KB max), created in working directory |
| `~/.exf_history` | Interactive shell command history (100 entries) |
| `~/.exf_sessions/` | Persistent scan session files, one JSON per host |

---

## Compute mode

EmbedXPL-Forge can leverage GPU acceleration for ML-assisted fingerprinting:

```text
exf > compute auto     # Auto-detect best backend (default)
exf > compute cpu      # Force CPU-only
exf > compute gpu      # Require GPU (falls back to CPU if unavailable)
exf > compute hybrid   # CPU + GPU mixed
```

Current compute mode is shown at startup and in `sysinfo`.

---

## Architecture overview

```
CLI (exf / embedxpl)
    │
    ├── Interactive Shell (interpreter.py)
    │       ├── use / set / check / run / search / discover
    │       └── sessions / apt / sysinfo / compute
    │
    ├── Non-Interactive Mode  (--module / --targets flags)
    │
    ├── Core Engine
    │       ├── HTTP/HTTPS client
    │       ├── SSH / Telnet / FTP / SNMP clients
    │       ├── RTSP / Cameradar
    │       ├── Shell Stager (PTY, Meterpreter, bind/reverse)
    │       └── CVE Database
    │
    ├── Intelligence Layer
    │       ├── ML Fingerprinter (OUI + banner analysis)
    │       ├── APT Attack Engine (nation-state chain replay)
    │       └── Phase Gate Quality System
    │
    └── Module Arsenal (2800+ modules)
            ├── exploits/    creds/    scanners/
            └── payloads/    encoders/ generic/
```

---

## Related tools (XPL-Forge Suite)

| Tool | pip | CLI | Scope |
|------|-----|-----|-------|
| EmbedXPL-Forge | `pip install embedxpl` | `embedxpl` | IoT/perimeter broad |
| FirewallXPL-Forge | `pip install firewallxpl` | `fxf` | Firewall/VPN specialist |
| PrinterXPL-Forge | `pip install printerxpl-forge` | `printerxpl-forge` | Printer specialist |
| WirelessXPL-Forge | `pip install wirelessxpl` | `wxf` | Wireless (Wi-Fi/BLE/Zigbee) |
| MikrotikAPI-BF | `pip install mikrotikapi-bf` | `mikrotik-bf` | MikroTik RouterOS |


[Wiki hub](../README.md)
