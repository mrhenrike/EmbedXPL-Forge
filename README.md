# RouterXPL-Forge

**Network Device Security Assessment Framework**

RouterXPL-Forge is an open-source exploitation framework designed for security professionals to audit routers, switches, TAPs, and SOHO edge devices. It provides 271 modules covering credential testing, vulnerability exploitation, network scanning, payload generation, and encoding.

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Features

- **125 exploit modules** — RCE, auth bypass, path traversal, info disclosure, DNS hijacking
- **88 credential modules** — dictionary attacks against FTP, SSH, Telnet, HTTP, SNMP, SFTP
- **5 scanner modules** — AutoPwn, device-specific scanners
- **32 payload modules** — reverse/bind TCP shells for x86, x64, ARM, MIPS, Python, Perl, PHP
- **13 encoder modules** — Base64 and hex encoding for Python, PHP, Perl
- **8 generic modules** — Heartbleed, ShellShock, UPnP SSDP, SNMP, CVE lookup
- **23 vendor-specific wordlists** — externalized default credentials per vendor

## Supported Device Types

| Type | Coverage | Description |
|------|----------|-------------|
| **Routers** | 187 modules | SOHO routers, enterprise gateways, CPE |
| **Switches L2/L3** | 3 modules | Managed and unmanaged switches |
| **SOHO Edge** | 7 modules | Travel routers, NAS, wireless APs, smart plugs |
| **TAPs** | Planned | Network TAP devices |

## Supported Vendors

2Wire · 3Com · Asmax · ASUS · Belkin · BHU · Billion · Cisco · Comtrend · D-Link · HooToo · Huawei · IPFire · Juniper · LG · Linksys · MikroTik · Movistar · Netcore · NETGEAR · Netsys · Shuttle · Technicolor · Thomson · TP-Link · Ubiquiti · ZTE · ZyXEL

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
│   ├── generic/       # Cross-vendor (Heartbleed, ShellShock)
│   ├── routers/       # Router exploits by vendor
│   ├── switches/      # Switch exploits (Cisco, D-Link, NETGEAR)
│   └── soho_edge/     # SOHO edge device exploits
├── scanners/          # Network scanning and AutoPwn
├── payloads/          # Reverse/bind shells (multi-arch)
├── encoders/          # Payload encoding (Base64, Hex)
└── generic/           # CVE lookup, SNMP, UPnP, wordlist tools
```

## Requirements

- Python 3.8+
- Dependencies: `requests`, `paramiko`, `pysnmp`, `pycryptodome`, `scapy`, `colorama`

## Legal Disclaimer

RouterXPL-Forge is intended for authorized security testing and research only. Use this tool exclusively on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## License

BSD License — see [LICENSE](LICENSE) for details.

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)