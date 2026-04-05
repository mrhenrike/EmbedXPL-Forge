# Documentation folder — `docs/`

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** Files below are primarily **English (en-US)**. **Português (pt-BR)** hub for this folder: [README.pt-BR.md](README.pt-BR.md). User wiki: [wiki/pt-BR/README.md](wiki/pt-BR/README.md).

## Contents / Conteúdo

| File | Language | Description |
|------|----------|-------------|
| [COVERAGE_MATRIX.md](COVERAGE_MATRIX.md) | en-US | Coverage matrix, external intel tables |
| [FULL_CATALOG.md](FULL_CATALOG.md) | en-US | Full module catalog snapshot |
| [wiki/README.md](wiki/README.md) | bilingual hub | Wiki index (en-US + pt-BR) |
| [diagrams/architecture/README.md](diagrams/architecture/README.md) | en-US + pt-BR | **Attack-surface architecture** (MikrotikAPI-BF style) |
| [img/architecture/](img/architecture/) | en-US labels on PNG | Exported architecture PNGs |

## Attack-surface architecture (PNGs)

Same visual language as MikrotikAPI-BF hub-and-spoke diagrams. **Mermaid:** [diagrams/architecture/](diagrams/architecture/). **Gallery:**

| SOHO router | Switch |
|:---:|:---:|
| ![SOHO router](img/architecture/rxf_arch_router_soho.png) | ![Switch](img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW](img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](img/architecture/rxf_arch_isp_cpe.png) |

| Mixed edge |
|:---:|
| ![Mixed edge](img/architecture/rxf_arch_edge_mixed.png) |

## Wiki locales

- **English (default):** [wiki/en-US/README.md](wiki/en-US/README.md)
- **Português (Brazil):** [wiki/pt-BR/README.md](wiki/pt-BR/README.md)

## Regeneration hints

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/refresh_cve_extended_catalog.py
python tools/gen_wiki_module_index.py
```

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
