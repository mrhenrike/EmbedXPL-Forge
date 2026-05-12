# EmbedXPL-Forge Wiki (en-US)

**Language:** English (en-US). **Português (pt-BR):** [../pt-BR/README.md](../pt-BR/README.md)

**Maintainer:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| União Geek

Official usage documentation for the framework. Read on GitHub or copy into the **GitHub Wiki** (separate Git repository).

## Architecture Diagrams (device classes)

PNG gallery. Mermaid sources: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

| SOHO Router | Managed Switch |
|:-----------:|:--------------:|
| ![SOHO](../../img/architecture/exf_arch_router_soho.png) | ![Switch](../../img/architecture/exf_arch_switch_l2l3.png) |

| ISP CPE / GPON ONT | Mixed Edge |
|:------------------:|:----------:|
| ![ISP CPE](../../img/architecture/exf_arch_isp_cpe.png) | ![Mixed edge](../../img/architecture/exf_arch_edge_mixed.png) |

| GPON ONT Full Attack Map |
|:------------------------:|
| ![GPON ONT attack map](../../img/architecture/exf_arch_gpon_ont_attack.png) |

## Table of Contents

| Doc | Topics |
|-----|--------|
| [01-introduction-and-installation.md](01-introduction-and-installation.md) | Introduction, scope, Python, install, diagnostics, logs |
| [02-interactive-shell-commands.md](02-interactive-shell-commands.md) | Interactive commands, discover, sessions |
| [03-search-and-listing.md](03-search-and-listing.md) | `search`, `show`, listing modules and devices |
| [04-non-interactive-mode.md](04-non-interactive-mode.md) | `exf.py -m` / `-s`, automation |
| [05-creds-modules.md](05-creds-modules.md) | Credential modules and options |
| [06-exploits-modules.md](06-exploits-modules.md) | Exploit modules, `check`, layout |
| [07-scanners-and-autopwn.md](07-scanners-and-autopwn.md) | Scanners and AutoPwn |
| [08-generic-modules.md](08-generic-modules.md) | Generic cross-vendor modules (UPnP IGD, SSDP, SNMP, etc.) |
| [09-payloads-and-encoders.md](09-payloads-and-encoders.md) | Payloads and encoders |
| [10-catalogs-and-tools.md](10-catalogs-and-tools.md) | JSON catalogs and `tools/` scripts |
| [11-troubleshooting.md](11-troubleshooting.md) | Common failures and fixes |
| [Module path index (all locales)](../ANEXO-INDICE-MODULOS.md) | Full module path list |

## End-to-End Example (input and expected output)

Input:

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Expected output (example):

```text
[+] Target appears vulnerable
[*] Collecting metadata...
[+] ProductName: EG8145X6-10
[+] APPVersion: ...
```

Automation mode input:

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s target 192.168.18.1 -s port 80
```

Expected output (example):

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ...
```

## See also

- [README.md](../../../README.md)
- [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- [docs/COVERAGE_MATRIX.md](../../COVERAGE_MATRIX.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
