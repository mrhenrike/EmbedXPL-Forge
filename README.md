# EmbedXPL-Forge

**Embedded Device Security Assessment Framework**

EmbedXPL-Forge is an open-source exploitation framework designed for security professionals to audit routers, switches, IP cameras, GPON ONTs, ISP CPEs, and IoT/embedded edge devices. It provides **700 modules** covering credential testing, vulnerability exploitation, network scanning, payload generation, and encoding — with **350 CVEs** mapped across **55 vendors** and an **APT Group Attack Engine** that reproduces real-world nation-state attack chains.

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Features

- **540+ exploit modules** — RCE, auth bypass, path traversal, info disclosure, buffer overflow, DNS hijacking, command injection, backdoor, CSRF, config decrypt
- **88 credential modules** — dictionary attacks against FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **5 scanner modules** — AutoPwn, device-specific scanners
- **32 payload modules** — reverse/bind TCP shells for x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 encoder modules** — Base64 and hex encoding for Python, PHP, Perl
- **14 generic modules** — Heartbleed, ShellShock, UPnP IGD, SNMP bruteforce, TCP Xmas, UDP amplification, CVE lookup, DNS hijack detector, AITM interceptor
- **350 CVEs mapped** — from 2001 to 2026, covering all major vulnerability classes
- **APT Group Attack Engine** — browse and reproduce attack chains from APT28, Volt Typhoon, Sandworm, Quad7, Turla, APT40 with MITRE ATT&CK mapping
- **23 vendor-specific wordlists** — externalized default credentials per vendor (incl. ISP-specific Brazil)
- **Network discovery** — SSDP, ARP, Nmap, Masscan, Scapy fallback, OUI lookup (IEEE database), T0–T5 timing profiles
- **Session management** — persistent scan history per host (IP+MAC), resume/restart, full findings index
- **Chained autopwn modules** — multi-phase vendor-specific exploitation chains (Huawei GPON ONT, D-Link, TP-Link APT28 chain, etc.)

## Supported Device Types

| Type | Coverage | Description |
|------|----------|-------------|
| **Routers / GPON ONT / CPE** | 580+ modules | SOHO routers, enterprise gateways, GPON CPE/ONT (primary focus) |
| **Switches L2/L3** | 3 modules | Managed switches (Cisco, D-Link, NETGEAR) — limited coverage |
| **SOHO Edge** | 9 modules | Travel routers, NAS, wireless APs |

## Supported Vendors

2Wire · 3Com · ActionTec · Arris · Aruba · Asmax · ASUS · Belkin · BHU · Billion · Calix · CERIO · Cisco · Comtrend · D-Link · Draytek · FiberHome · Fortinet · GPON · HooToo · Huawei · Intelbras · IPFire · Juniper · LG · Linksys · Mercury · MikroTik · MitraStar · Movistar · Netcore · NETGEAR · Netsys · OpenWrt · Ruijie · SerComm · Shuttle · SonicWall · Technicolor · Tenda · Thomson · TOTOLINK · TP-Link · TRENDnet · Ubiquiti · Wavlink · Xiaomi · Zhone · ZTE · ZyXEL

## Installation

### Option 1 — PyPI (recommended)

```bash
pip install embedxpl
embedxpl
```

### Option 2 — From source

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
pip install -r requirements.txt
python exf.py
```

### Option 3 — Python module

```bash
pip install embedxpl
python -m embedxpl
```

## Quick Start

```bash
# Install
pip install embedxpl

# Launch interactive shell
embedxpl

# Run a specific module directly
embedxpl -m exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224 -s target 192.168.1.1

# Network discovery
embedxpl -c "discover 192.168.1.0/24"
```

## Usage

### Interactive Shell

```
exf > use exploits/routers/dlink/dir_300_600_rce
exf (D-Link DIR-300 & DIR-600 RCE) > show options
exf (D-Link DIR-300 & DIR-600 RCE) > set target 192.168.1.1
exf (D-Link DIR-300 & DIR-600 RCE) > check
exf (D-Link DIR-300 & DIR-600 RCE) > run
```

### Common Commands

| Command | Description |
|---------|-------------|
| `use <module>` | Select a module |
| `show options` | Display configurable options |
| `show info` | Display module metadata and references |
| `show devices` | List supported device types |
| `set <option> <value>` | Configure an option |
| `check` | Verify if target is vulnerable |
| `run` | Execute the module |
| `search <term>` | Search modules by keyword |
| `discover [subnet] [--timing T0-T5] [--fresh]` | Scan subnet, fingerprint targets, suggest modules |
| `sessions list\|show\|delete\|export\|purge` | Manage persistent scan history per host |
| `apt` | List APT groups with reproducible attack chains |
| `apt show <group>` | View attack chain details (MITRE ATT&CK, CVEs, modules) |
| `apt search <device\|CVE>` | Find APT groups targeting a device or CVE |
| `apt run <group> [#]` | Execute APT attack chain (all or specific attack) |

### APT Group Attack Engine

```
# List all cataloged threat actors
exf > apt list

# Show APT28 attack chain details
exf > apt show apt28

# Search for groups targeting MikroTik
exf > apt search mikrotik

# Execute the full APT28 DNS hijack chain (interactive)
exf > apt run apt28

# Execute only the credential disclosure attack (#0)
exf > apt run apt28 0
```

### Network Discovery

```
# Auto-detect subnet from active interfaces and scan (default timing T3)
exf > discover

# Scan specific subnet with stealth timing
exf > discover 192.168.1.0/24 --timing T1

# Force fresh scan, ignore previous session history
exf > discover 192.168.1.0/24 --fresh
```

Discovery uses a multi-phase pipeline: ARP sweep → Nmap (multi-method host probes) → Scapy → TCP connect fallback. Results are matched against the module catalog and filtered by vendor/model. The IEEE OUI database (`embedxpl/data/oui.txt`) resolves MAC addresses to vendors with online-first lookup and local fallback. When a host exposes WiFi capabilities, the tool recommends [WirelessXPL-Forge](https://github.com/mrhenrike/WirelessXPL-Forge) for wireless-specific attacks.

**Timing profiles (T0–T5)** mirror Nmap conventions:

| Profile | Delay | Use case |
|---------|-------|----------|
| T0 | paranoid — 300s | IDS evasion |
| T1 | sneaky — 15s | Quiet audits |
| T2 | polite — 2s | Minimal impact |
| T3 | normal — 0.5s | Default |
| T4 | aggressive — 0.1s | Fast LAN scans |
| T5 | insane — 0s | CTF / lab only |

### Session Management

```
# List all hosts with scan history
exf > sessions list

# Full history for one host: tested modules, findings, timestamps
exf > sessions show 192.168.1.1

# Export session as JSON
exf > sessions export 192.168.1.1

# Delete one session
exf > sessions delete 192.168.1.1

# Purge all sessions
exf > sessions purge
```

Sessions are stored in `~/.exf_sessions/` as JSON, keyed by SHA-256 of IP+MAC. On re-discovery of a known host, already-tested modules are shown as `[Tested]` and skipped by default.

### AutoPwn Scanner

```
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.0/24
exf (AutoPwn) > run
```

## Module Structure

```
embedxpl/modules/
├── creds/             # Credential testing (FTP, SSH, Telnet, HTTP, SNMP)
│   ├── generic/       # Protocol-agnostic bruteforce and defaults
│   └── routers/       # Vendor-specific default credentials
├── exploits/          # Vulnerability exploitation
│   ├── generic/       # Cross-vendor (Heartbleed, ShellShock, GPON)
│   ├── routers/       # Router exploits by vendor (44 vendor folders)
│   ├── switches/      # Switch exploits (Cisco, D-Link, NETGEAR)
│   └── soho_edge/     # SOHO edge device exploits
├── scanners/          # Network scanning and AutoPwn
├── payloads/          # Reverse/bind shells (multi-arch)
├── encoders/          # Payload encoding (Base64, Hex)
└── generic/           # CVE lookup, SNMP, UPnP SSDP, UPnP IGD exploit, wordlist tools
```

## Architecture & Attack Surface Maps

Attack surface maps showing module coverage per access vector, in the style of operational security diagrams.
Source files in [`docs/diagrams/architecture/`](docs/diagrams/architecture/).

### Module Architecture Overview

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_overview.png" width="900" alt="EmbedXPL-Forge Architecture Overview"/>
</p>

### APT Group Attack Chains

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_apt_chains.png" width="900" alt="APT Group Attack Chains"/>
</p>

### SOHO Router Attack Surface

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_soho_router.png" width="900" alt="SOHO Router Attack Surface"/>
</p>

### TP-Link Attack Surface (APT28/GRU Campaign)

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_tplink_apt28.png" width="900" alt="TP-Link APT28 Attack Surface"/>
</p>

### MikroTik RouterOS Attack Surface

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_mikrotik.png" width="900" alt="MikroTik Attack Surface"/>
</p>

### GPON ONT Attack Surface (Huawei EG8145)

<p align="center">
  <img src="docs/diagrams/architecture/exf_arch_gpon_ont.png" width="900" alt="GPON ONT Attack Surface"/>
</p>

## Requirements

- Python 3.8+
- Optional: `nmap` (binary) for enhanced network discovery
- Dependencies: `requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `colorama`, `rich`, `python-nmap`

Full list: [`requirements.txt`](requirements.txt)

## Legal Disclaimer

EmbedXPL-Forge is intended for authorized security testing and research only. Use this tool exclusively on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## License

BSD License — see [LICENSE](LICENSE) for details.

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
