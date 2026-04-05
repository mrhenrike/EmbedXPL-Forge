# Catalogs and `tools/`

**Language:** English (en-US). **pt-BR:** [../pt-BR/10-catalogos-e-ferramentas.md](../pt-BR/10-catalogos-e-ferramentas.md)

## `routerxpl/resources/catalogs/`

| File | Role |
|------|------|
| `market_priority_devices_2010_2026.json` | Market device pool + yearly lists |
| `module_target_scope.json` | AutoPwn scope policy |
| `cve_extended_catalog.json` | CVE DB extension (merged static + intel + modules + tg12 PoC refs for in-scope IDs) |
| `discord_requested_devices.json` | Community requests |
| `external_tool_intel_sources.json` | External intel URLs (incl. MSF / Exploit-DB bridges) |
| `external_framework_clones.json` | Curated official clone URLs + license notes; pairs with `generic/external/*` bridges |
| `incorporated_third_party_index.json` | Index of vendored PoC mirrors under `arsenal/pocs/incorporated_third_party/` |
| `soho_catalog_js_index.json` | Build stamp / mapping for the bundled SOHO HTML catalog |
| `third_party_upstream_open_work.json` | Upstream PR/issue tracking snapshot for third-party mirrors |
| `deep_intel_backlog.json` | Intel backlog items |

## Architecture diagrams

Device-class attack-surface PNGs and Mermaid sources: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

## Generated docs

- `docs/COVERAGE_MATRIX.md`
- `docs/FULL_CATALOG.md`

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
```

## Useful scripts

| Script | Role |
|--------|------|
| `tools/env_doctor.py` | Dependency smoke |
| `tools/compat_smoke.py` | Compatibility smoke |
| `tools/validate_market_priority_minimums.py` | Market catalog validation |
| `tools/report_market_priority_gaps.py` | Gap CSV |
| `tools/gen_wiki_module_index.py` | Regenerate [../ANEXO-INDICE-MODULOS.md](../ANEXO-INDICE-MODULOS.md) |
| `tools/phase6_sync_external_intel.py` | External intel snapshot (environment-dependent) |
| `tools/generate_full_catalog.py` | Regenerate [../../FULL_CATALOG.md](../../FULL_CATALOG.md) / `.txt` (footprint + stats) |
| `tools/refresh_cve_extended_catalog.py` | Regenerate `cve_extended_catalog.json` (merge + tg12 PoC URLs) |
| `tools/embed_local_third_party_poc_intel.py` | Refresh embedded PoC intel JSON from local mirrors |
| `tools/incorporate_third_party_poc_tree.py` | Copy/sync third-party PoC trees into `incorporated_third_party/` |
| `tools/build_soho_catalog_js_index.py` | Rebuild SOHO catalog JS index metadata |
| `tools/compile_first_party.py` | Packaging helper for first-party artifacts |

---

[Wiki hub](../README.md)
