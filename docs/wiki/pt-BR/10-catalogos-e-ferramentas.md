# Catálogos, matrizes e ferramentas (`tools/`)

**Idioma:** pt-BR. **English (en-US):** [../en-US/10-catalogs-and-tools.md](../en-US/10-catalogs-and-tools.md)

## Catálogos em `routerxpl/resources/catalogs/`

| Ficheiro | Conteúdo |
|----------|----------|
| `market_priority_devices_2010_2026.json` | *Device pool* e listas anuais (Brasil/global) |
| `module_target_scope.json` | Política de escopo e mapeamento *device class* para AutoPwn |
| `cve_extended_catalog.json` | Extensão do `CVEDatabase` (merge matriz + intel + módulos + URLs PoC tg12 para IDs em âmbito) |
| `discord_requested_devices.json` | Pedidos da comunidade / Discord |
| `external_tool_intel_sources.json` | Fontes externas para roadmap (RouterPwn, EDB, Metasploit, …) |
| `external_framework_clones.json` | URLs oficiais para clonar Metasploit / Exploit-DB / MikrotikAPI-BF (licenças e pontes `generic/external/*`) |
| `incorporated_third_party_index.json` | Índice dos espelhos PoC em `arsenal/pocs/incorporated_third_party/` |
| `soho_catalog_js_index.json` | Metadados da *build* do catálogo SOHO HTML/JS |
| `third_party_upstream_open_work.json` | *Snapshot* de PRs/issues abertos nos *mirrors* upstream |
| `deep_intel_backlog.json` | Itens de intel pendentes de triagem |

## Diagramas de arquitetura

PNG por classe de dispositivo e fontes Mermaid: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

## Documentação gerada

- `docs/COVERAGE_MATRIX.md` — matriz de cobertura e tabelas de intel externa
- `docs/FULL_CATALOG.md` — catálogo textual ampliado

Regeneração da matriz:

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
```

## Scripts úteis

| Script | Função |
|--------|--------|
| `tools/env_doctor.py` | Dependências base |
| `tools/compat_smoke.py` | Fumo de compatibilidade |
| `tools/validate_market_priority_minimums.py` | Valida catálogo de prioridade |
| `tools/report_market_priority_gaps.py` | Gera `.log/market_priority_gaps.csv` |
| `tools/gen_wiki_module_index.py` | Regenera `docs/wiki/ANEXO-INDICE-MODULOS.md` |
| `tools/phase6_sync_external_intel.py` | *Snapshots* de intel externa (rede / `gh` conforme ambiente) |
| `tools/generate_full_catalog.py` | Regenera `docs/FULL_CATALOG.*` (pegada em disco + estatísticas) |
| `tools/refresh_cve_extended_catalog.py` | Regenera `cve_extended_catalog.json` (merge + URLs PoC tg12) |
| `tools/embed_local_third_party_poc_intel.py` | Actualiza JSON de intel PoC embutido |
| `tools/incorporate_third_party_poc_tree.py` | Copia/sincroniza árvores PoC para `incorporated_third_party/` |
| `tools/build_soho_catalog_js_index.py` | Reconstrói índice JS do catálogo SOHO |
| `tools/compile_first_party.py` | Helper de empacotamento (*first-party*) |

---

[Wiki hub](../README.md)
