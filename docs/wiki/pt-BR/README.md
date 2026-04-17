# Wiki EmbedXPL-Forge (pt-BR)

**Idioma: Português (pt-BR)**. **English (en-US):** [../en-US/README.md](../en-US/README.md)

**Mantenedor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| União Geek

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

## Ver também

- [README.md](../../../README.md)
- [CONTRIBUTING.md](../../../CONTRIBUTING.md)
- [docs/COVERAGE_MATRIX.md](../../COVERAGE_MATRIX.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
