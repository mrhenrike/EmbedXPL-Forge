## Status
**READY / IN DEVELOPMENT / HOLD**

**Languages / Idiomas:** PR descriptions **English (en-US)** preferred; Portuguese acceptable if the change is pt-BR-only docs. Prefer **en-US + pt-BR** when editing user-facing docs. | PRs: texto preferencialmente em **inglês (en-US)**; português aceitável se for só documentação pt-BR. Documentação de utilizador: ideal **en-US e pt-BR**.

## Description
Explain the change and why. Link issues: `closes #`.

## Scope
- [ ] In scope (router/switch/TAP/fw/NGFW)
- [ ] Does not introduce camera/printer/DVR as primary focus

## Verification
Reproducible steps and outcome.

1.
2.
3.

## Required local checks

- [ ] `python tools/env_doctor.py`
- [ ] `python tools/compile_first_party.py`
- [ ] `python tools/compat_smoke.py`
- [ ] `python tools/validate_market_priority_minimums.py` (if catalogs changed)
- [ ] `python tools/generate_coverage_matrix.py` (if modules/docs matrix affected)
- [ ] `python tools/gen_wiki_module_index.py` (if modules added/removed)

## Risk notes
- Operational:
- Security:
- Rollback:

---

Governance: [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) · [CONTRIBUTING.md](../CONTRIBUTING.md) · [CONTRIBUTING.pt-BR.md](../CONTRIBUTING.pt-BR.md)
