# Introduction, Scope, and Installation

**Language:** English (en-US). **pt-BR:** [../pt-BR/01-introducao-e-instalacao.md](../pt-BR/01-introducao-e-instalacao.md)

## What RouterXPL-Forge is

**RouterXPL-Forge** is a modular **Python** framework for **authorized** security testing of routers, switches, TAPs, and SOHO edge devices. It bundles credential checks, vulnerability-oriented modules, scanners, payloads, and supporting utilities.

- **271** modules organized by role and vendor.
- **28+** vendor-oriented families plus generic building blocks.

## Requirements

- **Python 3.8–3.13**
- Install dependencies from `requirements.txt` after cloning the repository.

## Install

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
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
python rxf.py
```

## Log file and history

- **Log file:** `routerxpl.log` (created in the current working directory).
- **Command history:** typically `~/.rxf_history`.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
