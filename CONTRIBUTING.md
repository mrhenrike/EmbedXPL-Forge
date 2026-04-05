# Contributing — RouterXPL-Forge

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Language:** **English (en-US)** — default. **Português (pt-BR):** [CONTRIBUTING.pt-BR.md](CONTRIBUTING.pt-BR.md)

Thanks for considering a contribution. This document summarizes scope, workflow, and expected checks.

## Documentation and wiki

**Documentation is bilingual:** default **en-US**; **pt-BR** lives in parallel paths (see repository root and `docs/wiki/`).

- README: [README.md](README.md) · [README.pt-BR.md](README.pt-BR.md)
- Wiki hub: [docs/wiki/README.md](docs/wiki/README.md)
- Wiki **en-US:** [docs/wiki/en-US/README.md](docs/wiki/en-US/README.md)
- Wiki **pt-BR:** [docs/wiki/pt-BR/README.md](docs/wiki/pt-BR/README.md)
- Before opening an issue, check the wiki and [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md).

## Repository scope

| In scope | Not the focus of this fork |
|----------|----------------------------|
| Routers, switches, TAPs, firewalls, NGFW | Modules whose primary target is IP camera, printer, or DVR |

Out-of-scope proposals may be declined or redirected to a specialized fork.

## How to contribute

- **Issues:** bugs, compatibility regressions, module ideas aligned with scope
- **Pull requests:** focused fixes, new scanners/exploits/creds with references (CVE, advisory, PoC)
- **Catalogs:** updates under `routerxpl/resources/catalogs/` with rationale and sources

## PR best practices

1. One PR should address **one coherent** topic.
2. Include **risk notes** (operational impact, security surface).
3. **Do not** commit secrets, `.env`, credentials, or customer data.
4. Preserve upstream `authors` in inherited modules; add `subcredits` when adapting.
5. Update **both locales** when you change user-visible behavior (en-US + pt-BR wiki sections as applicable).

## Bug reports

Include:

- Module path (e.g. `exploits/routers/dlink/dir_815_850l_rce`)
- Exact command sequence (interactive or `rxf.py -m ... -s ...`)
- OS, Python version, venv vs global
- Expected vs actual behavior
- Traceback or `routerxpl.log` excerpt **without** real third-party IPs/tokens

## Validation expectations

PRs should pass the suggested local validation below when the change touches runtime code, modules, or catalogs. Documentation-only edits may skip parts that do not apply, but **describe what you ran** in the PR.

## Suggested local validation

```bash
python tools/env_doctor.py
python tools/compile_first_party.py
python tools/compat_smoke.py
python tools/validate_market_priority_minimums.py
python tools/generate_coverage_matrix.py
```

Adjust for your PR (documentation-only changes may need less).

If you add or remove Python modules under `routerxpl/modules/`, also run:

```bash
python tools/gen_wiki_module_index.py
```

This refreshes [docs/wiki/ANEXO-INDICE-MODULOS.md](docs/wiki/ANEXO-INDICE-MODULOS.md) (language-neutral path index).

## Security and conduct

- Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities in **this framework’s code**.
- Interactions follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Commit messages

Prefer clear, imperative messages with enough context for the changelog (e.g. `fix(snmp): handle timeout on Windows`).

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
