# Catalogs and Tools

**Language:** English (en-US). **pt-BR:** [../pt-BR/10-catalogos-e-ferramentas.md](../pt-BR/10-catalogos-e-ferramentas.md)

## JSON catalogs

| File | Purpose |
|------|---------|
| `market_priority_devices_2010_2026.json` | Market-priority device coverage matrix input |
| `module_target_scope.json` | Module ↔ target scope metadata |
| `cve_extended_catalog.json` | Extended CVE reference data |
| `arsenal_layout.json` | Arsenal layout description for tooling |

## Tools (`tools/`)

| Script | Role |
|--------|------|
| `env_doctor.py` | Environment diagnostics |
| `compat_smoke.py` | Compatibility smoke checks |
| `gen_wiki_module_index.py` | Regenerate wiki annex |
| `generate_coverage_matrix.py` | Build coverage matrix artifacts |
| `generate_full_catalog.py` | Generate full catalog outputs |
| `refresh_cve_extended_catalog.py` | Refresh CVE extended catalog |
| `validate_market_priority_minimums.py` | Validate market-priority minimums |
| `build_arsenal_index.py` | Build arsenal index |
| `sync_scope_wordlists.py` | Sync scope-related wordlists |

Run scripts from the repository root unless a tool documents otherwise.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
