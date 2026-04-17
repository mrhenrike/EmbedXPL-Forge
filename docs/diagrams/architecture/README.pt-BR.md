# Diagramas de arquitetura — EmbedXPL-Forge

**Idioma:** pt-BR. **English (en-US):** [README.md](README.md)

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

O estilo replica o hub-and-spoke do **MikrotikAPI-BF** (`mikrotik_full_attack_surface.png`, `mikrotik_access_vectors.png`): núcleo do dispositivo, vetores de acesso em volta, legenda de cobertura.

## Legenda de cobertura

| Símbolo | Significado |
|---------|-------------|
| ✓ (verde) | Coberto por módulos `creds`, `exploits`, `scanners` ou `generic` no EmbedXPL-Forge |
| ◐ (amarelo) | Cobertura parcial ou só genérica (banner, CVE lookup, rede IP) |
| ✗ / ausente | Fora do foco do projeto ou sem módulo dedicado |

## Ficheiros Mermaid (fonte)

Os `.mmd` em esta pasta podem ser renderizados com Mermaid CLI ou colados no GitHub.

## PNGs gerados

Caminhos em `docs/img/architecture/`. Galeria:

| Router SOHO | Switch |
|:---:|:---:|
| ![SOHO](../../img/architecture/exf_arch_router_soho.png) | ![Switch](../../img/architecture/exf_arch_switch_l2l3.png) |

| CPE ISP / GPON ONT | Edge misto |
|:---:|:---:|
| ![CPE](../../img/architecture/exf_arch_isp_cpe.png) | ![Edge misto](../../img/architecture/exf_arch_edge_mixed.png) |

| Mapa de ataque GPON ONT |
|:---:|
| ![GPON ONT](../../img/architecture/exf_arch_gpon_ont_attack.png) |

**Diagrama GPON ONT:** ver [07-gpon-ont-attack.mmd](07-gpon-ont-attack.mmd) — validado contra Huawei EG8145X6-10 (OptiXstar, Loga Internet) e EG8145V5-V2 (EchoLife, Sumicity/Giga+). Mapeia todos os 11 módulos específicos com seus vetores de ataque.

Ver também [README.md](README.md) (en-US).

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
