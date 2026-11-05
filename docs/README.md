---
nav_exclude: true
---

# EmbedXPL-Forge Documentation

**Diagram baseline:** source version `v7.0.0`, aligned with the current `main` documentation (November 2026). Note that the latest published GitHub Release may lag behind the versioned source tag.

## Documentation index

| Location | Description |
|---|---|
| [Wiki](wiki/README.md) | User and module documentation |
| [Architecture diagrams](diagrams/architecture/README.md) | Technical attack-surface maps and editable Mermaid sources |
| [Architecture assets](assets/embedxpl_architecture.svg) | v7 component architecture |
| [Assessment flow](assets/embedxpl_flow.svg) | Authorized assessment lifecycle |
| [Device gallery](img/architecture/README.md) | Device-specific SVG coverage maps |
| [Modules](modules/) | Per-module documentation |

## Device attack-surface gallery

| SOHO Router | L2/L3 Switch |
|:---:|:---:|
| ![SOHO gateway surface](img/architecture/rxf_arch_router_soho.svg) | ![Managed switch surface](img/architecture/rxf_arch_switch_l2l3.svg) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW surface](img/architecture/rxf_arch_ngfw_utm.svg) | ![ISP CPE surface](img/architecture/rxf_arch_isp_cpe.svg) |

| Mixed Edge | GPON ONT |
|:---:|:---:|
| ![Mixed edge](img/architecture/rxf_arch_edge_mixed.svg) | ![GPON ONT research](img/architecture/rxf_arch_gpon_ont_attack.svg) |

These are architecture and research illustrations, **not proof of exploitability** on a particular device. Match model, firmware, configuration, ROE and scope before any active testing.

## Regeneration of documentation indexes

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/gen_wiki_module_index.py
```

The new SVG visual assets are human-curated from the documented v7 capabilities; older PNGs are kept for backward compatibility with external links.
