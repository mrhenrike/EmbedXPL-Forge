# RouterXPL-Forge

**Network Device Security Assessment Framework**

RouterXPL-Forge is an open-source exploitation framework designed for security professionals to audit routers, switches, TAPs, and SOHO edge devices. It provides **647 modules** covering credential testing, vulnerability exploitation, network scanning, payload generation, and encoding — with **338 CVEs** mapped across **49 vendors**.

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Features

- **500 exploit modules** — RCE, auth bypass, path traversal, info disclosure, buffer overflow, DNS hijacking, command injection, backdoor, CSRF, config decrypt
- **88 credential modules** — dictionary attacks against FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **5 scanner modules** — AutoPwn, device-specific scanners
- **32 payload modules** — reverse/bind TCP shells for x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 encoder modules** — Base64 and hex encoding for Python, PHP, Perl
- **9 generic modules** — Heartbleed, ShellShock, UPnP SSDP, UPnP IGD full exploitation, SNMP, CVE lookup
- **338 CVEs mapped** — from 2001 to 2026, covering all major vulnerability classes
- **23 vendor-specific wordlists** — externalized default credentials per vendor (incl. ISP-specific Brazil)
- **Network discovery** — SSDP, ARP, Nmap, Scapy fallback, OUI lookup (IEEE database), T0–T5 timing profiles
- **Session management** — persistent scan history per host (IP+MAC), resume/restart, full findings index
- **Huawei EG8145X6 autopwn** — 9-phase chained exploitation with generic module fallback and WiFi detection

## Supported Device Types

| Type | Coverage | Description |
|------|----------|-------------|
| **Routers** | 580+ modules | SOHO routers, enterprise gateways, GPON CPE/ONT |
| **Switches L2/L3** | 3 modules | Managed and unmanaged switches |
| **SOHO Edge** | 12 modules | Travel routers, NAS, wireless APs, smart plugs, firewalls |
| **TAPs** | Planned | Network TAP devices |

## Supported Vendors

2Wire · 3Com · ActionTec · Arris · Aruba · Asmax · ASUS · Belkin · BHU · Billion · Calix · CERIO · Cisco · Comtrend · D-Link · Draytek · FiberHome · Fortinet · GPON · HooToo · Huawei · Intelbras · IPFire · Juniper · LG · Linksys · Mercury · MikroTik · MitraStar · Movistar · Netcore · NETGEAR · Netsys · OpenWrt · Ruijie · SerComm · Shuttle · SonicWall · Technicolor · Tenda · Thomson · TOTOLINK · TP-Link · TRENDnet · Ubiquiti · Wavlink · Xiaomi · Zhone · ZTE · ZyXEL

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge

# Install dependencies
pip install -r requirements.txt

# Launch the interactive shell
python rxf.py

# Or run a specific module non-interactively
python rxf.py -m exploits/routers/dlink/dir_300_600_rce -s target 192.168.1.1
```

## Usage

### Interactive Shell

```
rxf > use exploits/routers/dlink/dir_300_600_rce
rxf (D-Link DIR-300 & DIR-600 RCE) > show options
rxf (D-Link DIR-300 & DIR-600 RCE) > set target 192.168.1.1
rxf (D-Link DIR-300 & DIR-600 RCE) > check
rxf (D-Link DIR-300 & DIR-600 RCE) > run
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

### Network Discovery

```
# Auto-detect subnet from active interfaces and scan (default timing T3)
rxf > discover

# Scan specific subnet with stealth timing
rxf > discover 192.168.1.0/24 --timing T1

# Force fresh scan, ignore previous session history
rxf > discover 192.168.1.0/24 --fresh
```

Discovery uses a multi-phase pipeline: ARP sweep → Nmap (multi-method host probes) → Scapy → TCP connect fallback. Results are matched against the module catalog and filtered by vendor/model. The IEEE OUI database (`routerxpl/data/oui.txt`) resolves MAC addresses to vendors with online-first lookup and local fallback. When a host exposes WiFi capabilities, the tool recommends [WirelessXPL-Forge](https://github.com/mrhenrike/WirelessXPL-Forge) for wireless-specific attacks.

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
rxf > sessions list

# Full history for one host: tested modules, findings, timestamps
rxf > sessions show 192.168.1.1

# Export session as JSON
rxf > sessions export 192.168.1.1

# Delete one session
rxf > sessions delete 192.168.1.1

# Purge all sessions
rxf > sessions purge
```

Sessions are stored in `~/.rxf_sessions/` as JSON, keyed by SHA-256 of IP+MAC. On re-discovery of a known host, already-tested modules are shown as `[Tested]` and skipped by default.

### AutoPwn Scanner

```
rxf > use scanners/autopwn
rxf (AutoPwn) > set target 192.168.1.0/24
rxf (AutoPwn) > run
```

## Module Structure

```
routerxpl/modules/
├── creds/             # Credential testing (FTP, SSH, Telnet, HTTP, SNMP)
│   ├── generic/       # Protocol-agnostic bruteforce and defaults
│   └── routers/       # Vendor-specific default credentials
├── exploits/          # Vulnerability exploitation
│   ├── generic/       # Cross-vendor (Heartbleed, ShellShock, GPON)
│   ├── routers/       # Router exploits by vendor (incl. Huawei EG8145X6 chain)
│   ├── switches/      # Switch exploits (Cisco, D-Link, NETGEAR)
│   └── soho_edge/     # SOHO edge device exploits
├── scanners/          # Network scanning and AutoPwn
├── payloads/          # Reverse/bind shells (multi-arch)
├── encoders/          # Payload encoding (Base64, Hex)
└── generic/           # CVE lookup, SNMP, UPnP SSDP, UPnP IGD exploit, wordlist tools
```

## Architecture Diagrams

Mermaid diagrams for all supported device categories are in [`docs/diagrams/architecture/`](docs/diagrams/architecture/). Rendered PNGs are in [`docs/img/architecture/`](docs/img/architecture/).

| SOHO Router | ISP CPE / GPON ONT |
|:-----------:|:------------------:|
| ![SOHO router](docs/img/architecture/rxf_arch_router_soho.png) | ![ISP CPE](docs/img/architecture/rxf_arch_isp_cpe.png) |

| NGFW / UTM | Mixed Edge |
|:----------:|:----------:|
| ![NGFW](docs/img/architecture/rxf_arch_ngfw_utm.png) | ![Mixed edge](docs/img/architecture/rxf_arch_edge_mixed.png) |

| GPON ONT Full Attack Map |
|:------------------------:|
| ![GPON ONT attack map](docs/img/architecture/rxf_arch_gpon_ont_attack.png) |

## Requirements

- Python 3.8+
- Optional: `nmap` (binary) for enhanced network discovery
- Dependencies: `requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `colorama`, `rich`, `python-nmap`

Full list: [`requirements.txt`](requirements.txt)

## Legal Disclaimer

RouterXPL-Forge is intended for authorized security testing and research only. Use this tool exclusively on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## License

BSD License — see [LICENSE](LICENSE) for details.

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
