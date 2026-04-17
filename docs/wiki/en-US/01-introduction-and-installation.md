# Introduction, Scope, and Installation

**Language:** English (en-US). **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

## What EmbedXPL-Forge is

**EmbedXPL-Forge** is a modular **Python** framework for **authorized** security testing of routers, GPON ONTs, CPE devices, and SOHO edge equipment. It bundles credential checks, vulnerability-oriented modules, scanners, payloads, and supporting utilities.

- **647** modules organized by role and vendor (500 exploits, 88 creds, 9 generic, 5 scanners, 32 payloads, 13 encoders).
- **49** vendor families covered, **338 CVEs** mapped.
- **Network discovery** with T0–T5 timing profiles, OUI lookup, and session management.
- **Chained autopwn modules** — multi-phase exploitation chains for validated vendors (e.g. Huawei GPON ONT series).

## Supported Device Classes

| Class | Coverage |
|-------|----------|
| **Routers / GPON ONT / CPE** | Primary focus — 580+ modules, 49 vendors |
| **Managed Switches L2/L3** | Limited — 3 exploit modules (Cisco, D-Link, NETGEAR) |
| **SOHO Edge** (NAS, APs, travel routers) | 9 exploit modules |

## Requirements

- **Python 3.8–3.13**
- Optional: `nmap` binary for enhanced network discovery
- Install dependencies from `requirements.txt` after cloning the repository.

## Install

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
python3 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
python3 -m pip install -r requirements.txt
```

## Diagnostics

Run the environment check:

```bash
python tools/env_doctor.py
```

## Start the interactive shell

```bash
python exf.py
```

## Log file and history

- **Log file:** `embedxpl.log` (created in the current working directory).
- **Command history:** typically `~/.exf_history`.
- **Session data:** `~/.exf_sessions/` — persistent scan history per host.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
