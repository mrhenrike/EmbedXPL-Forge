# WAVE2 CI/Coverage Exclusions and Python 2 Audit

**Data:** 2026-10-20
**Autor:** Andre Henrique (@mrhenrike) | Uniao Geek

## 1. Auditoria de exclusoes no CI (Task 2.6)

### 1.1 Ruff (linting)

Exclusoes em `pyproject.toml` `[tool.ruff.lint]`:

| Path excluido | Justificativa | Status |
|---|---|---|
| `embedxpl/malware_research/**` | Codigo de pesquisa, decompiled, Python 2 | OK |
| `embedxpl/engines/fingerprint/tenable/**` | Adaptacoes de terceiros (Tenable/Nessus) | OK |
| `embedxpl/modules/exploits/**` | Modulos de exploit com padroes nao convencionais | OK |

**Achado:** As exclusoes do ruff estao adequadas. Per-file-ignores adicionais cobrem modules, engines, libs, core, nse, tools, intel e scripts com regras especificas.

### 1.2 Mypy (type-checking)

Config em `pyproject.toml` `[tool.mypy]`:

- **Sem `exclude` configurado.** O mypy nao tem glob de exclusao.
- No CI (`ci.yml`), mypy roda apenas em 3 arquivos especificos: `embedxpl/__init__.py`, `embedxpl/core/config.py`, `embedxpl/core/pool.py`. Isso mitiga o problema na pratica, mas a config local nao protege desenvolvedores rodando `mypy embedxpl/`.

**Problema P1:** Se um desenvolvedor rodar `mypy embedxpl/` localmente, o mypy tentara analisar `malware_research/` (Python 2/decompiled) e `modules/exploits/`, gerando falsos erros massivos.

**Fix aplicado:** Adicionado `exclude` ao `[tool.mypy]` com os mesmos paths excluidos pelo ruff.

### 1.3 Coverage (`.coveragerc`)

Exclusoes em `[report] omit`:

| Path excluido | Justificativa | Status |
|---|---|---|
| `*/modules/*` | Modulos de exploit/ataque (nao testados unitariamente) | OK |
| `*/malware_research/*` | Codigo de pesquisa/decompiled | OK |
| `*/native_src/*` | Codigo nativo (C/ASM) | OK |
| `*/nse/*` | Scripts NSE (Nmap) | OK |
| `*/resources/*` | Recursos estaticos | OK |
| `*/tests/*` | Testes nao medem a propria cobertura | OK |
| `*/venv*/*`, `*/.venv/*`, `*/site-packages/*` | Ambientes virtuais | OK |

**Achado:** Exclusoes de coverage estao adequadas. `engines/` nao esta excluido, o que e correto (engines sao codigo testavel do projeto).

### 1.4 CI Workflows

#### ci.yml
- `ruff check .` roda na raiz: depende das exclusoes do pyproject.toml (OK).
- `mypy` roda apenas em 3 arquivos especificos (OK, mas ver P1 acima).
- `pytest tests/` roda so no diretorio tests (OK).

#### compat-matrix.yml
- **Problema P2:** `python -m compileall -q embedxpl tools` compila TODOS os .py dentro de `embedxpl/`, incluindo `malware_research/ics_apt/trisis/decompiled_code/` que e Python 2. Isso pode gerar falhas de SyntaxError em Python 3.
- `flake8 tools exf.py` roda apenas em `tools` e `exf.py` (OK, nao toca malware_research).
- `bandit -q -r tools -lll` roda apenas em `tools` (OK).

**Fix aplicado:** Adicionado `-x embedxpl/malware_research` ao comando `compileall` no compat-matrix.yml.

#### publish.yml
- Sem linting ou testes diretos; apenas build/publish (OK, sem problemas de exclusao).

#### release.yml
- `pytest tests/` (OK).
- `grep -rl "theoretical" embedxpl/modules/` (OK, apenas modulos).

### 1.5 Paths que NAO devem ser excluidos

Os seguintes paths estao corretamente incluidos no CI/linting:
- `embedxpl/core/` : nucleo do framework
- `embedxpl/engines/` : engines de scan/fingerprint (exceto tenable no ruff)
- `embedxpl/libs/` : bibliotecas internas
- `embedxpl/intel/` : modulos de inteligencia
- `embedxpl/runtime/` : runtime do framework
- `embedxpl/tools/` : ferramentas auxiliares
- `tests/` : suite de testes

## 2. Codigo Python 2 / Decompiled (Task 2.7)

### 2.1 Diretorios identificados

| Diretorio | Tipo | Arquivos .py | Python 2? |
|---|---|---|---|
| `embedxpl/malware_research/ics_apt/trisis/decompiled_code/` | Decompiled | 211 | Sim (stdlib Python 2 decompilada) |
| `embedxpl/malware_research/ics_apt/trisis/decompiled_code/library/` | Decompiled | ~210 | Sim |
| `embedxpl/malware_research/ics_apt/trisis/symbolic_execution/` | Pesquisa | 3 | Sim (shebang `#!/usr/bin/env python2`) |
| `embedxpl/malware_research/ics_apt/blackenergy/v2/Scripts/` | Pesquisa | 3 | Misto (Python 2/3 compativel) |
| `embedxpl/malware_research/ics_apt/` (raiz) | Pesquisa | 1 | Python 3 (`greyenergy_unpacker.py`) |

### 2.2 Status de exclusao por ferramenta

| Ferramenta | malware_research excluido? | Detalhe |
|---|---|---|
| Ruff | Sim | `embedxpl/malware_research/**` em exclude |
| Mypy | Nao (antes do fix) | Sem exclude (fix aplicado nesta auditoria) |
| Coverage | Sim | `*/malware_research/*` em omit |
| compileall (CI) | Nao (antes do fix) | Compilava tudo (fix aplicado nesta auditoria) |
| pytest | N/A | Roda apenas em `tests/` |
| flake8 (CI) | N/A | Roda apenas em `tools exf.py` |
| bandit (CI) | N/A | Roda apenas em `tools` |

### 2.3 Sumario de fixes

1. **pyproject.toml** `[tool.mypy]`: adicionado `exclude` para `malware_research`, `modules/exploits` e `engines/fingerprint/tenable`.
2. **compat-matrix.yml**: adicionado `-x embedxpl/malware_research` ao `compileall` para evitar SyntaxError com codigo Python 2 decompilado.
