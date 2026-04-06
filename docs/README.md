# Documentation — RouterXPL-Forge

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** Files below are primarily **English (en-US)**. **Português (pt-BR)** hub: [README.pt-BR.md](README.pt-BR.md). Wiki: [wiki/pt-BR/README.md](wiki/pt-BR/README.md).

## Contents

| Path | Language | Description |
|------|----------|-------------|
| [wiki/README.md](wiki/README.md) | bilingual hub | Wiki index (en-US + pt-BR) |
| [diagrams/architecture/README.md](diagrams/architecture/README.md) | en-US + pt-BR | Attack-surface architecture diagrams (Mermaid) |
| [img/architecture/](img/architecture/) | en-US labels | Exported architecture PNGs |
| [modules/](modules/) | en-US | Per-module documentation |

## Attack-Surface Architecture (PNGs)

Mermaid sources: [diagrams/architecture/](diagrams/architecture/). Gallery:

| SOHO Router | Switch |
|:---:|:---:|
| ![SOHO router](img/architecture/rxf_arch_router_soho.png) | ![Switch](img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW](img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](img/architecture/rxf_arch_isp_cpe.png) |

| Mixed Edge |
|:---:|
| ![Mixed edge](img/architecture/rxf_arch_edge_mixed.png) |

## Wiki Locales

- **English (default):** [wiki/en-US/README.md](wiki/en-US/README.md)
- **Português (Brazil):** [wiki/pt-BR/README.md](wiki/pt-BR/README.md)

## Regeneration

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/gen_wiki_module_index.py
```

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)