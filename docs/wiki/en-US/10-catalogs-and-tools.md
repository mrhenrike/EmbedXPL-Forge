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
| `phase_gate.py` | **Automated quality gate system** — validates modules before release (new in v3.1.0) |
| `env_doctor.py` | Environment diagnostics |
| `compat_smoke.py` | Compatibility smoke checks |
| `gen_wiki_module_index.py` | Regenerate wiki annex |
| `generate_coverage_matrix.py` | Build coverage matrix artifacts |
| `generate_full_catalog.py` | Generate full catalog outputs |
| `refresh_cve_extended_catalog.py` | Refresh CVE extended catalog |
| `validate_market_priority_minimums.py` | Validate market-priority minimums |
| `build_arsenal_index.py` | Build arsenal index |
| `sync_scope_wordlists.py` | Sync scope-related wordlists |
| `audit_modules.py` | Audit module metadata completeness |
| `run_scoped_tests.py` | Run scoped test suite |

Run scripts from the repository root unless a tool documents otherwise.

## Quality Gate Usage (phase_gate.py)

```bash
# Run all 7 gates in sequence
python tools/phase_gate.py --all

# Run a specific gate
python tools/phase_gate.py --phase A1A2
python tools/phase_gate.py --phase B
python tools/phase_gate.py --phase C
python tools/phase_gate.py --phase A3
python tools/phase_gate.py --phase D
python tools/phase_gate.py --phase E
python tools/phase_gate.py --phase final
```

Each gate validates: module importability, `__info__` completeness (name, description, authors, references with URL, devices, cvss), `check()` and `run()` with non-stub bodies, anti-false-positive on closed port 63994, no prohibited strings (em-dash, TODO, PLACEHOLDER, hardcoded IPs), flake8/bandit clean, full indexing by `index_modules()`.


[Wiki hub](../README.md)
