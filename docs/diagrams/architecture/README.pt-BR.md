# Diagramas de arquitetura — RouterXPL-Forge

**Idioma:** pt-BR. **English (en-US):** [README.md](README.md)

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

O estilo replica o hub-and-spoke do **MikrotikAPI-BF** (`mikrotik_full_attack_surface.png`, `mikrotik_access_vectors.png`): núcleo do dispositivo, vetores de acesso em volta, legenda de cobertura.

## Legenda de cobertura

| Símbolo | Significado |
|---------|-------------|
| ✓ (verde) | Coberto por módulos `creds`, `exploits`, `scanners` ou `generic` no RouterXPL-Forge |
| ◐ (amarelo) | Cobertura parcial ou só genérica (banner, CVE lookup, rede IP) |
| ✗ / ausente | Fora do foco do projeto ou sem módulo dedicado |

## Ficheiros Mermaid (fonte)

Os `.mmd` em esta pasta podem ser renderizados com Mermaid CLI ou colados no GitHub.

## PNGs gerados

Caminhos em `docs/img/architecture/`. Galeria:

| Router SOHO | Switch |
|:---:|:---:|
| ![SOHO](../../img/architecture/rxf_arch_router_soho.png) | ![Switch](../../img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | CPE ISP |
|:---:|:---:|
| ![NGFW](../../img/architecture/rxf_arch_ngfw_utm.png) | ![CPE](../../img/architecture/rxf_arch_isp_cpe.png) |

| Edge misto |
|:---:|
| ![Edge misto](../../img/architecture/rxf_arch_edge_mixed.png) |

Ver também [README.md](README.md) (en-US).

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
