# EmbedXPL-Forge Documentation Hub (en-US)

**Version:** 3.1.0 | Default documentation language: `en-US`

Portuguese version available at `../pt-BR/README.md`.

## Framework Architecture (v3.1.0)

### Component Architecture

<p align="center">
  <img src="../assets/embedxpl_architecture.png" width="920" alt="EmbedXPL-Forge Component Architecture v3.1.0"/>
</p>

### Audit and Exploitation Flow

<p align="center">
  <img src="../assets/embedxpl_flow.png" width="920" alt="EmbedXPL-Forge Exploitation Flow v3.1.0"/>
</p>


## What is new in v3.1.0

- **54 new modules** across printers, embedded OS, ICS/OT, smart home, maritime IoT, and 2026 Pwn2Own chains
- **Printer domain enabled** (185+ printer modules now active)
- **7 automated quality gates** via `tools/phase_gate.py`
- New CVEs: wolfSSL CVE-2026-5194 (CVSS 9.3), PAN-OS CVE-2026-0300 (CVSS 9.8), CUPS CVE-2026-34477/78/79/80 (CVSS 9.9), UR PolyScope5 CVE-2026-8153 (CVSS 9.8), Cisco IOS XE CVE-2025-20188 (CVSS 10.0), and 30+ more
- New vendors: EnGenius, Universal Robots, Metis Maritime, eNet SMART HOME, OpenRemote

## Scope

This documentation set covers:

- installation and execution flows;
- interactive and non-interactive usage;
- expected inputs and outputs for common commands;
- module and protocol references;
- hardware and architecture guidance for audits.

Primary repository guides:

- Root `README.md` (en-US default);
- Root `README.pt-BR.md` (Portuguese translation);
- Wiki `../wiki/en-US/README.md` and `../wiki/pt-BR/README.md`.

## Installation

### PyPI

```bash
pip install embedxpl
embedxpl
```

Expected output:

```text
EmbedXPL-Forge vX.Y.Z
exf >
```

### Source

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
pip install -r requirements.txt
python exf.py
```

Expected output:

```text
[*] Loading modules...
[+] Modules loaded: <count>
exf >
```

## Interactive Usage

### 1) Discover modules

```text
exf > search huawei
```

Expected output:

```text
[+] Found <n> module(s)
...
```

### 2) Select module

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
```

Expected output:

```text
exf (EG8145X6 Info Disclosure) >
```

### 3) Show required options

```text
exf (EG8145X6 Info Disclosure) > show options
```

Expected output:

```text
Name    Current Value  Required  Description
target                 yes       Target IPv4/IPv6
port    80             no        HTTP port
```

### 4) Set inputs

```text
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > set port 80
```

### 5) Validate and execute

```text
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Expected output:

```text
[+] Target appears vulnerable
[*] Collecting metadata...
[+] ProductName: ...
```

## Non-Interactive Usage

### Direct module execution

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s target 192.168.18.1 -s port 80
```

Expected output:

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ...
```

### Discovery command

```bash
embedxpl -c "discover 192.168.1.0/24 --timing T3"
```

Expected output:

```text
[*] Discovery started
[+] Hosts discovered: <n>
[+] Suggested modules: <n>
```

## Input/Output Conventions

- Input values are configured using module options (`set <name> <value>`) or `-s key value`.
- `check` returns a pre-exploitation status:
  - positive: target likely matches exploit conditions;
  - negative: target not applicable, patched, or unreachable.
- `run` executes exploitation or scanner logic and prints findings.

Status markers:

- `[*]` runtime status;
- `[+]` positive finding or success;
- `[-]` negative result, blocked exploit path, or missing condition.

## Documentation Map

| Path | Description |
|------|-------------|
| `architecture.md` | framework architecture and execution model |
| `hardware-requirements.md` | adapters, monitor mode, and capture prerequisites |
| `../wiki/en-US/` | complete usage wiki with command references |
| `../wiki/pt-BR/` | Portuguese wiki translation |
| `../modules/` | module-level generated docs |
| `../diagrams/architecture/` | Mermaid source and architecture diagrams |

## Security and Legal Notes

- Use only in authorized environments.
- Validate legal authorization before scanning or exploitation.
- Follow disclosure and incident response procedures for findings.

## License

See repository `LICENSE` file.
