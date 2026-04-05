# Security Policy — RouterXPL-Forge

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Language:** **English (en-US)** — default. **Português (pt-BR):** [SECURITY.pt-BR.md](SECURITY.pt-BR.md)

## Supported scope

- **In scope:** flaws in **RouterXPL-Forge itself** (Python code, declared dependencies, `tools/` scripts) affecting the **operator** (RCE on the analyst machine, unsafe input handling, etc.).
- **Out of scope:** “0-day” on third-party **devices** found while using the framework; report through vendor or their bug bounty.
- **Functional scope:** routers, switches, TAPs, firewalls, NGFW. Camera/printer/DVR-primary modules are not the focus of this fork.

## Reporting a vulnerability

1. Use GitHub **private vulnerability reporting**: **Security → Report a vulnerability** on `mrhenrike/RouterXPL-Forge`.
2. Do not file a public issue with a full exploit before triage.
3. Include:
   - Affected commit or tag
   - Minimal reproduction steps
   - Impact (confidentiality, integrity, availability)
   - Suggested patch (optional)
   - Logs without third-party secrets

## Response targets (best effort)

| Phase | Target |
|-------|--------|
| Acknowledgement | ~72 hours |
| Initial triage | ~7 business days |
| Fix | depends on severity and complexity |

## Coordinated disclosure

We prefer **coordinated disclosure**: keep details private until a fix or agreed timeline. Immediate public PoC may be discouraged when it puts users at risk.

## Safe use (operator responsibility)

### Safe testing rules

- Use only on assets you **own** or with **written authorization**.
- Third-party production requires contract and clear rules of engagement.
- Do not submit customer data, credentials, or dumps to this repository.
- Modules may be destructive in lab environments — isolate test networks.

## Conduct

Harassment or abuse in project channels: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and use private reporting where appropriate.

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
