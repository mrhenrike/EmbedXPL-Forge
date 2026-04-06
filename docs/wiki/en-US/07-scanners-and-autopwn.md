# Scanners and AutoPwn

**Language:** English (en-US). **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

## AutoPwn

**AutoPwn** orchestrates fingerprinting and module selection workflows. Load the AutoPwn module with `use`, set `target` (and interface options if required), then `run`—behavior is defined inside the module’s `run()` implementation.

## Device-oriented scanners

| Module | Role |
|--------|------|
| `router_scan` | Router-focused discovery / chaining entry point |
| `hootoo_scan` | Hootoo-oriented scanner workflow |

## Typical options

| Option | Role |
|--------|------|
| `target` | Host or network under test |
| `port` | Service port when not implied |
| `threads` | Concurrency for network-heavy phases |

Always confirm scope and rate limits before running scanners on live networks.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
