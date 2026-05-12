# Catálogos e ferramentas

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/10-catalogs-and-tools.md](../en-US/10-catalogs-and-tools.md)

## Catálogos JSON

| Arquivo | Função |
|---------|--------|
| `market_priority_devices_2010_2026.json` | Entrada para matriz de cobertura de devices prioritários de mercado |
| `module_target_scope.json` | Metadados módulo ↔ escopo de target |
| `cve_extended_catalog.json` | Dados estendidos de referência CVE |
| `arsenal_layout.json` | Descrição de layout do arsenal para ferramentas |

## Ferramentas (`tools/`)

| Script | Função |
|--------|--------|
| `phase_gate.py` | **Sistema de gates de qualidade automatizados** - valida modulos antes do release (novo em v3.1.0) |
| `env_doctor.py` | Diagnostico de ambiente |
| `compat_smoke.py` | Smoke de compatibilidade |
| `gen_wiki_module_index.py` | Regenerar anexo da wiki |
| `generate_coverage_matrix.py` | Gerar artefatos da matriz de cobertura |
| `generate_full_catalog.py` | Gerar saidas de catalogo completo |
| `refresh_cve_extended_catalog.py` | Atualizar catalogo estendido CVE |
| `validate_market_priority_minimums.py` | Validar minimos de prioridade de mercado |
| `build_arsenal_index.py` | Construir indice do arsenal |
| `sync_scope_wordlists.py` | Sincronizar wordlists relacionadas ao escopo |
| `audit_modules.py` | Auditar completude de metadados dos modulos |
| `run_scoped_tests.py` | Executar suite de testes scopado |

Execute os scripts a partir da raiz do repositorio salvo indicacao contraria na documentacao da ferramenta.

## Uso do Quality Gate (phase_gate.py)

```bash
# Executar todos os 7 gates em sequencia
python tools/phase_gate.py --all

# Executar um gate especifico
python tools/phase_gate.py --phase A1A2   # valida ports do PrinterXPL
python tools/phase_gate.py --phase B      # valida lote CVE 2026 primario
python tools/phase_gate.py --phase C      # valida CVE 2026 estendido
python tools/phase_gate.py --phase A3     # valida modulos research de impressoras
python tools/phase_gate.py --phase D      # valida backlog CVEs 2025/2024
python tools/phase_gate.py --phase E      # valida referencias e CHANGELOG
python tools/phase_gate.py --phase final  # gate final + working tree
```

Cada gate verifica: importabilidade, `__info__` completo (name, description, authors, references com URL, devices, cvss), `check()` e `run()` com corpo real, anti-falso-positivo em porta 63994 fechada, sem strings proibidas, flake8/bandit limpos, indexacao completa.


[Hub wiki](../README.md)
