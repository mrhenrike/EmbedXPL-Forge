# Introduction, Scope, and Installation

**Language:** English (en-US). **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

## What EmbedXPL-Forge is

**EmbedXPL-Forge** is a modular **Python** framework for **authorized** security testing of routers, GPON ONTs, CPE devices, printers, IoT, OT/ICS, smart home, maritime IoT, and SOHO edge equipment. It bundles credential checks, vulnerability-oriented modules, scanners, payloads, exploit chains, and supporting utilities.

- **2800+** active modules organized by role and vendor (625+ exploits, 185+ printer exploits, 88 creds, 14 generic, 5+ scanners, 32 payloads, 13 encoders).
- **114+** vendor families covered, **700+ CVEs** mapped (2001-2026).
- **Network discovery** with T0–T5 timing profiles, OUI lookup (IEEE 39k+ entries), and session management.
- **Chained autopwn modules** — multi-phase exploitation chains (Huawei EG8145X6, CUPS Pwn2Own 2026, Lexmark Pwn2Own 2026, etc.).
- **7 automated quality gates** — `tools/phase_gate.py` validates all modules before release.

## Supported Device Classes

| Class | Coverage |
|-------|----------|
| **Routers / GPON ONT / CPE** | Primary focus — 580+ modules, 85+ vendor folders |
| **Printers / MFP** | 185+ modules — HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung, CUPS |
| **Firewalls / VPN / Perimeter** | 80+ modules — Fortinet, Palo Alto, Cisco, SonicWall, CheckPoint, Sophos, WatchGuard |
| **ICS / OT / Industrial** | 35+ modules — PLCs, SCADA, Modbus, S7comm, EtherNet/IP, Universal Robots |
| **Smart Home / Maritime** | 10+ modules — eNet SMART HOME, OpenRemote, Metis maritime IoT |
| **Embedded OS** | 25+ modules — RIOT OS, OpenWrt, VxWorks, QNX, wolfSSL, Tuya |
| **Managed Switches L2/L3** | Limited — 3 exploit modules (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** (NAS, APs, travel routers) | 9 exploit modules |

## Framework Architecture

### Component Architecture

Full layered view: CLI, Core Engine (orchestrator, protocol clients, shell engines), Intelligence Layer (ML, OUI lookup, CVE DB), Quality Gates, and the 2800+ module arsenal.

<p align="center">
  <img src="../../assets/embedxpl_architecture.png" width="920" alt="EmbedXPL-Forge Component Architecture v3.1.0"/>
</p>

### Audit and Exploitation Flow

End-to-end flow from target input through discovery, fingerprinting, module selection, exploitation, and reporting.

<p align="center">
  <img src="../../assets/embedxpl_flow.png" width="920" alt="EmbedXPL-Forge Exploitation Flow v3.1.0"/>
</p>

## Requirements

- **Python 3.8–3.13**
- Optional: `nmap` binary for enhanced network discovery
- Install dependencies from `requirements.txt` after cloning the repository.

## Install

Recommended (PyPI):

```bash
python3 -m pip install embedxpl
# optional domain extras
python3 -m pip install "embedxpl[nse]"        # Nmap NSE helper scripts
python3 -m pip install "embedxpl[printers]"   # printer stack
python3 -m pip install "embedxpl[all]"        # everything
```

Alternative (repository clone, for development):

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
python3 -m pip install -r requirements.txt
python3 -m pip install -e .                   # editable install (optional)
```

## Diagnostics

Run the environment check:

```bash
python tools/env_doctor.py
```

## Start the interactive shell

After `pip install embedxpl`, just run:

```bash
embedxpl
```

Equivalents when running from a clone:

```bash
python -m embedxpl
python exf.py            # legacy bootstrap
```

## Log file and history

- **Log file:** `embedxpl.log` (created in the current working directory).
- **Command history:** typically `~/.exf_history`.
- **Session data:** `~/.exf_sessions/` — persistent scan history per host.


[Wiki hub](../README.md)
