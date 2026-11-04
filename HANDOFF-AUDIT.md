# HANDOFF-AUDIT - submodules/Uniao-Geek/EmbedXPL-Forge

Gerado: 2026-06-24 01:26

## Remoto
- URL: https://github.com/mrhenrike/EmbedXPL-Forge.git
- Remote: ok
- Branch default: master
- HEAD local: 6ee10a2a
- Update: reset-to-origin/master

## Autores no historico
- Andre Henrique <henrique.santos@uniaogeek.com.br>
- André Henrique <henrique.santos@uniaogeek.com.br>
- mrhenrike <henrique.santos@uniaogeek.com.br>

## Issues abertas (0)
_nenhuma issue aberta_

## Pull Requests abertos (0)
_nenhum PR aberto_
## [Malware Research Integration] — 2026-09-23 14:30

### Novos modulos de malware research adicionados

| Modulo | Familia | TTP |
|--------|---------|-----|
| `mirai_telnet_spray.py` | Mirai | T1110.001 |
| `mirai_ddos_resilience.py` | Mirai/Bashlite | T1498.001 |
| `equation_router_implant.py` | EquationGroup | T1542.001 |
| `juniper_netscreen_backdoor_cve_2015_7755.py` | EquationGroup.FEEDTROUGH | T1190 |
| `dino_icmp_covert.py` | Dino (Animal Farm) | T1095 |
| `synful_knock_ios.py` | SYNful Knock Cisco | T1542.001 |

Recursos gerados:
- `embedxpl/resources/creds/default_creds_iot_mirai.json` (62 pares Mirai)
- `embedxpl/resources/signatures/bashlite_attack_methods.json`



---

## Audit — 2026-11-04

### Bootstrap fix (fix/bootstrap-module-not-found branch)

**Root cause fixed:** 	ools/venv_bootstrap.py and 	ools/xpl_cli.py had been deleted from
the repo but were still imported by xf.py and mbedxpl/__main__.py, causing
ModuleNotFoundError: No module named 'tools' for every pip-installed user.

**Changes:**
- mbedxpl/tools/venv_bootstrap.py — recreated (PEP 668-safe venv bootstrapper)
- mbedxpl/tools/xpl_cli.py — recreated (ProductInfo dataclass + bootstrap() dispatcher)
- mbedxpl/__main__.py — import fixed to mbedxpl.tools.venv_bootstrap with source-checkout fallback
- xf.py — same dual-import pattern for both modules
- .gitignore — /tools/ corrected so only top-level dev-tools dir is ignored

### Smoke tests

| Check | Result |
|-------|--------|
| import embedxpl | PASS |
| rom embedxpl.tools.venv_bootstrap import ensure_runtime | PASS |
| rom embedxpl.tools.xpl_cli import ProductInfo, bootstrap | PASS |
| rom embedxpl.nse.__main__ import main | PASS |
| Python syntax (py_compile) — new files | PASS |
| Ruff — new files (13 F541 auto-fixed in xpl_cli.py) | PASS |
| Mypy — venv_bootstrap.py + xpl_cli.py | PASS (0 issues) |

### NSE audit (41 scripts)

Ran scripts/audit_nse.py against all .nse files in 
se/ and 
se/printers/.

**Result:** All 41 NSE scripts pass basic structural validation (description, author, license, categories, action fields present; balanced [[ ]]; action function detected).

The user-reported "parsing errors" on NSE scripts appear to have been runtime Nmap errors
rather than structural syntax issues. NSE scripts require Nmap to execute — they cannot be
tested without it. Recommend installing nmap and running:
`
nmap --script-help nse/embedxpl-router-vuln.nse
`

### Pre-commit hook

- .git/hooks/pre-commit — bash hook: py_compile + ruff + smoke import + untested-file warning
- .pre-commit-config.yaml — pre-commit framework config (4 hooks)
- scripts/audit_nse.py — NSE structural validator (runs in pre-commit)

### pytest

Full test suite running (> 1800 tests). Excluding 	est_xpl_bridge.py (requires private
xpl-core package, only available in CI with XPL_CORE_TOKEN).
