# Catálogos e Ferramentas

**Idioma:** Português (pt-BR). **English:** [../en-US/10-catalogs-and-tools.md](../en-US/10-catalogs-and-tools.md)

---

## Visão geral

O EmbedXPL-Forge inclui um conjunto de ferramentas de desenvolvedor e CI no diretório `tools/` e um conjunto de catálogos de dados JSON/YAML em `embedxpl/resources/`. Essas ferramentas suportam validação de módulos, manutenção do catálogo de CVEs, geração de wiki e diagnósticos de ambiente.

---

## Catálogos de Dados (`embedxpl/resources/`)

### `firmware_sources.yaml`

Registro de download de firmware de vendors. As chaves são identificadores de vendor em minúsculas; cada entrada mapeia para URL do portal, categoria, requisito de login e notas.

```yaml
vendors:
  hikvision:
    name: "Hikvision"
    category: "ip-cameras"
    portal_url: "https://www.hikvision.com/en/support/download/firmware/"
    requires_login: false
    notes: "Direct download links available for most models."
  tplink:
    name: "TP-Link"
    category: "routers"
    portal_url: "https://www.tp-link.com/en/support/download/"
    requires_login: false
  cisco:
    name: "Cisco"
    category: "routers-switches"
    portal_url: "https://software.cisco.com/download/home"
    requires_login: true
    notes: "Requires Cisco account with entitlement."
```

Consumido pela CLI `firmware-dl` (`embedxpl/tools/firmware_downloader.py`).

---

### `infra_profiles.yaml`

Taxonomia de contexto de infraestrutura para o modo orquestrador `--infra` / `--context`. Mapeia tuplas `(infra, contexto)` para prefixos de caminho de módulo.

| Infra | Contexto | Rótulo | Caminhos de módulo mapeados |
|-------|---------|--------|---------------------------|
| `ot` | `ics` | ICS / SCADA | `exploits/ics/`, `scanners/ics/`, `creds/ics/`, `exploits/firewalls/siemens/`, `exploits/firewalls/moxa/`, `exploits/firewalls/hirschmann/`, `exploits/firewalls/schneider/`, `exploits/firewalls/phoenix/` |
| `ot` | `energy` | Energia / Medidores Inteligentes | `exploits/smart_meters/`, `scanners/smart_meters/` |
| `ot` | `building` | Automação Predial (BACnet/HVAC) | `scanners/ics/`, `creds/ics/`, `exploits/bms/` |
| `it` | `enterprise_network` | Perímetro de Rede Corporativa | `exploits/firewalls/`, `exploits/switches/`, `exploits/vpn/`, `exploits/appliances/`, `exploits/ngfw/`, `exploits/network_os/`, `scanners/firewalls/`, `creds/firewalls/` |
| `it` | `hypervisor` | Hypervisors / Virtualização | `exploits/hypervisors/`, `creds/hypervisors/`, `scanners/hypervisors/` |
| `it` | `bmc_ipmi` | BMC / IPMI / Gerenciamento Out-of-Band | `exploits/bmc/`, `scanners/bmc/`, `creds/bmc/` |
| `it` | `ups_power` | UPS / Gerenciamento de Energia | `exploits/ups/`, `scanners/ups/`, `creds/ups/` |
| `iot` | `home` | Residencial / SOHO | `exploits/routers/`, `exploits/soho_edge/` |

---

### Recursos `catalogs/`

| Arquivo | Finalidade |
|---------|-----------|
| `market_priority_devices_2010_2026.json` | Matriz de cobertura de dispositivos prioritários no mercado — modelos classificados por volume de implantação e densidade de CVE |
| `module_target_scope.json` | Mapeamento de módulo para escopo de alvo — especifica quais classes de dispositivos alvo cada módulo endereça |
| `cve_extended_catalog.json` | Dados de referência CVE estendidos — pontuações CVSS, CWE, versões de firmware afetadas, técnicas MITRE ATT&CK e caminhos de módulo EmbedXPL associados |
| `arsenal_layout.json` | Descritor de layout do arsenal — descreve o agrupamento visual de módulos por fase de ataque para a ferramenta de índice do arsenal |

---

## Ferramentas (`tools/`)

| Script | Função |
|--------|--------|
| `phase_gate.py` | Gate de qualidade automatizado — valida módulos antes do release em 7 fases sequenciais de gate |
| `env_doctor.py` | Diagnóstico de ambiente — reporta versão Python, status de dependências, opcionais ausentes |
| `compat_smoke.py` | Verificações de compatibilidade — importação rápida e teste de interface para todos os módulos |
| `gen_wiki_module_index.py` | Regenerar índice de módulos da wiki a partir de metadados ao vivo do módulo |
| `generate_coverage_matrix.py` | Construir artefatos de matriz de cobertura HTML/JSON a partir do catálogo de dispositivos |
| `generate_full_catalog.py` | Gerar saídas completas de catálogo (JSON + Markdown) para todos os módulos |
| `refresh_cve_extended_catalog.py` | Buscar e atualizar catálogo CVE estendido de feeds NVD/MITRE |
| `validate_market_priority_minimums.py` | Assegurar que modelos de dispositivos de alta prioridade tenham pelo menos um módulo |
| `build_arsenal_index.py` | Construir JSON de índice do arsenal a partir de metadados de módulo |
| `sync_scope_wordlists.py` | Sincronizar wordlists relacionadas ao escopo com o catálogo de dispositivos |
| `audit_modules.py` | Auditar completude de metadados dos módulos — reporta campos `__info__` ausentes |
| `run_scoped_tests.py` | Executar suite de testes com escopo para categorias específicas de módulos |
| `validate_governance.py` | Validador de governança — verifica cabeçalhos de licença, campos de autor, docstrings |
| `validate_arsenal_architecture.py` | Assegurar que o layout do arsenal corresponda à árvore de arquivos real dos módulos |
| `build_osi_tcpip_attack_matrix.py` | Gerar matriz de superfície de ataque OSI/TCP-IP |
| `deep_intel_backlog.py` | Reportar módulos no backlog de pesquisa de inteligência aprofundada |
| `sync_mibs.py` | Sincronizar arquivos MIB SNMP de fontes de vendor para `resources/mibs/` |

Execute todos os scripts a partir da **raiz do repositório** a menos que a ferramenta documente o contrário.

---

## Gate de Qualidade (`phase_gate.py`)

### Sequência completa de gates

```bash
# Executar todos os 7 gates em sequência (recomendado para CI/CD)
python tools/phase_gate.py --all
```

### Gates individuais

```bash
python tools/phase_gate.py --phase A1A2    # Validação de importação + __info__
python tools/phase_gate.py --phase B       # Validação do corpo check() e run()
python tools/phase_gate.py --phase C       # Anti-falso-positivo na porta 63994
python tools/phase_gate.py --phase A3      # Verificação de string proibida
python tools/phase_gate.py --phase D       # Gate de linting flake8
python tools/phase_gate.py --phase E       # Gate de segurança bandit
python tools/phase_gate.py --phase final   # Verificação completa de indexação index_modules()
```

### Saída de exemplo `--all`

```
$ python tools/phase_gate.py --all

EmbedXPL-Forge Phase Gate v3.1.0
=================================

[A1/A2] Import and __info__ Validation
---------------------------------------
  Checking 143 modules...
  [OK]  exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
  [OK]  exploits/routers/cisco/rv320_command_injection
  [OK]  exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
  ...
  [OK]  143/143 modules import cleanly
  [OK]  143/143 modules have complete __info__ (name, description, authors, references, devices, cvss)

[B]    check() and run() Body Validation
-----------------------------------------
  [OK]  143/143 modules have non-stub check() bodies
  [OK]  143/143 modules have non-stub run() bodies

[C]    Anti-False-Positive Gate (port 63994)
---------------------------------------------
  [OK]  143/143 modules return False / None against closed port 63994

[A3]   Prohibited String Check
--------------------------------
  Checking for: em-dash, TODO, PLACEHOLDER, hardcoded IPs (192.168.x.x, 10.x.x.x)...
  [OK]  No prohibited strings found

[D]    flake8 Linting Gate
----------------------------
  [OK]  flake8 passed — 0 violations

[E]    bandit Security Gate
-----------------------------
  [OK]  bandit passed — 0 high-severity findings
  [INFO] 3 low-severity findings (eval, subprocess) — permitted by policy

[FINAL] index_modules() Full Indexing
---------------------------------------
  [OK]  index_modules() returned 143 modules
  [OK]  All modules appear in global index

=================================
GATE RESULT: PASS (7/7 gates)
Time: 12.4 s
=================================
```

### Exemplo de falha de gate (A1/A2)

```
[A1/A2] Import and __info__ Validation
  [FAIL] exploits/routers/acme/new_module — ImportError: cannot import name 'OptString'
  [FAIL] exploits/cameras/brand/cve_test — __info__ missing required fields: ['cvss', 'references']

GATE RESULT: FAIL (0/7 gates — stopped at A1/A2)
Fix the 2 error(s) above and re-run.
```

---

## Diagnóstico de Ambiente (`env_doctor.py`)

```bash
python tools/env_doctor.py
```

**Saída de exemplo:**

```
EmbedXPL-Forge — Environment Doctor
=====================================
Python          3.12.3          [OK]
pip             24.0            [OK]
requests        2.31.0          [OK]
paramiko        3.4.0           [OK]
yaml            6.0.1           [OK]
rich            13.7.0          [OK]
pysnmp          6.1.1           [OK]
telnetlib3      2.0.1           [OK]   (required for Python 3.13+)
impacket        0.11.0          [OK]
pymodbus        3.7.0           [OK]
torch           2.2.1+cu121     [OK]   (optional — GPU compute)
tensorflow      MISSING         [WARN] (optional — install with pip install tensorflow)
binwalk         MISSING         [WARN] (optional — firmware analysis; install with apt-get install binwalk)
nmap            7.95            [OK]   (required for NSE scripts)

GPU / Compute
  CUDA available  : True  (driver 555.85, CUDA 12.1)
  torch backend   : cuda
  Visible devices : NVIDIA GeForce RTX 4070 (8192 MB)

Summary: 13/14 required deps OK | 1 optional missing | 0 errors
```

---

## Verificação de Compatibilidade (`compat_smoke.py`)

```bash
python tools/compat_smoke.py
```

**Saída de exemplo:**

```
EmbedXPL-Forge — Compatibility Smoke
=======================================
[OK] embedxpl.interpreter imports cleanly
[OK] embedxpl.core.exploit.exploit imports cleanly
[OK] embedxpl.core.hw_profiler imports cleanly
[OK] embedxpl.core.session imports cleanly
[OK] embedxpl.core.apt_catalog imports cleanly
[OK] embedxpl.core.orchestrator imports cleanly
[OK] embedxpl.nse.manager imports cleanly
[OK] embedxpl.tools.firmware_downloader imports cleanly
[OK] embedxpl.tools.firmware_analyzer imports cleanly
[OK] 9/9 critical imports passed

Module scan:
[OK] 143 modules indexed by index_modules()

Smoke result: PASS
```

---

## Auditoria de Módulos (`audit_modules.py`)

```bash
python tools/audit_modules.py
```

**Saída de exemplo:**

```
EmbedXPL-Forge Module Audit
============================
Scanning 143 modules...

Field coverage:
  name          143/143 (100%)
  description   143/143 (100%)
  authors       143/143 (100%)
  references    143/143 (100%)
  devices       143/143 (100%)
  cvss          141/143 (98.6%)  -- 2 missing
  cwe           128/143 (89.5%)  -- 15 missing
  date          143/143 (100%)

Modules missing 'cvss':
  exploits/generic/snmp/snmp_bruteforce
  generic/dns_hijack_detector

Audit complete: 2 warnings
```

---

## Índice de Módulos da Wiki (`gen_wiki_module_index.py`)

Regenera o índice de módulos a partir dos metadados ao vivo dos módulos. Execute após adicionar novos módulos:

```bash
python tools/gen_wiki_module_index.py
```

A saída é escrita em `docs/wiki/en-US/ANNEX-module-index.md` e `docs/wiki/pt-BR/ANNEX-module-index.md`.

---

## Gerador de Catálogo Completo (`generate_full_catalog.py`)

Gera `docs/catalog.json` e `docs/catalog.md` a partir de todos os metadados `__info__` dos módulos:

```bash
python tools/generate_full_catalog.py
# Saída:
#   docs/catalog.json    -- catálogo completo legível por máquina
#   docs/catalog.md      -- tabela Markdown legível por humanos
#   docs/catalog.html    -- renderização HTML
```

**Exemplo de entrada `catalog.json`:**

```json
{
  "path": "exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684",
  "name": "FortiOS Authentication Bypass (CVE-2022-40684)",
  "description": "HTTP/HTTPS authentication bypass on FortiOS management interface allowing full admin access.",
  "authors": ["@mrhenrike"],
  "cvss": 9.8,
  "cves": ["CVE-2022-40684"],
  "mitre": ["T1190"],
  "devices": ["FortiGate", "FortiProxy", "FortiSwitch Manager"],
  "references": [
    "https://www.fortiguard.com/psirt/FG-IR-22-377"
  ]
}
```

---

[Hub da Wiki](../README.md)
