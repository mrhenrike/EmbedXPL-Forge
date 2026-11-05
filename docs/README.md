---
nav_exclude: true
---

# EmbedXPL-Forge — Documentation

## Contents

| Path | Description |
|------|-------------|
| [wiki/README.md](wiki/README.md) | Wiki index |
| [wiki/en-US/](wiki/en-US/) | Full wiki (23 chapters) |
| [diagrams/architecture/README.md](diagrams/architecture/README.md) | Attack-surface architecture diagrams (Mermaid) |
| [img/architecture/](img/architecture/) | Exported architecture PNGs |
| [modules/](modules/) | Per-module documentation |

## Attack-Surface Architecture

Mermaid sources: [diagrams/architecture/](diagrams/architecture/). Gallery:

| SOHO Router | Switch |
|:---:|:---:|
| ![SOHO router](img/architecture/exf_arch_router_soho.png) | ![Switch](img/architecture/exf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW](img/architecture/exf_arch_ngfw_utm.png) | ![ISP CPE](img/architecture/exf_arch_isp_cpe.png) |

| Mixed Edge |
|:---:|
| ![Mixed edge](img/architecture/exf_arch_edge_mixed.png) |

## Regeneration

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/gen_wiki_module_index.py
```
