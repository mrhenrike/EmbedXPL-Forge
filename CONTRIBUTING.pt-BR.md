# Guia de contribuição — RouterXPL-Forge

**Idioma:** **Português (pt-BR).** **English (en-US, padrão):** [CONTRIBUTING.md](CONTRIBUTING.md)

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

Obrigado por considerar contribuir. A documentação é **bilíngue**: **en-US** como padrão; **pt-BR** em ficheiros paralelos e em `docs/wiki/pt-BR/`.

## Documentação e wiki

- README: [README.pt-BR.md](README.pt-BR.md) · [README.md](README.md)
- Hub da wiki: [docs/wiki/README.md](docs/wiki/README.md)
- Uso detalhado **pt-BR:** [docs/wiki/pt-BR/README.md](docs/wiki/pt-BR/README.md)
- Detailed usage **en-US:** [docs/wiki/en-US/README.md](docs/wiki/en-US/README.md)
- Antes de abrir issue: wiki e [docs/COVERAGE_MATRIX.md](docs/COVERAGE_MATRIX.md)

## Escopo do repositório

| Incluído | Não é foco deste fork |
|----------|------------------------|
| Roteadores, switches, TAPs, firewalls, NGFW | Módulos cujo alvo principal é câmera IP, impressora, DVR |

## Formas de contribuir

- **Issues:** bugs, regressões, ideias alinhadas ao escopo
- **Pull requests:** correções focadas, novos módulos com referências (CVE, advisory, PoC)
- **Catálogos:** `routerxpl/resources/catalogs/` com justificativa e fontes

## Boas práticas em PRs

1. Um PR = **um tema** coerente.
2. Notas de **risco**.
3. Sem segredos, `.env` ou dados de clientes.
4. Preserve `authors` upstream; use `subcredits` nas adaptações.
5. Atualize **en-US e pt-BR** quando alterar comportamento visível (README/wiki conforme aplicável).

## Relatório de bugs

- Caminho do módulo
- Comandos exatos (interativo ou `rxf.py -m ...`)
- SO, Python, *venv*
- Esperado vs observado
- Log **sanitizado**

## Validação local sugerida

```bash
python tools/env_doctor.py
python tools/compile_first_party.py
python tools/compat_smoke.py
python tools/validate_market_priority_minimums.py
python tools/generate_coverage_matrix.py
```

Ao adicionar/remover módulos em `routerxpl/modules/`:

```bash
python tools/gen_wiki_module_index.py
```

Mantém [docs/wiki/ANEXO-INDICE-MODULOS.md](docs/wiki/ANEXO-INDICE-MODULOS.md) (índice neutro quanto ao idioma).

## Segurança e conduta

- [SECURITY.pt-BR.md](SECURITY.pt-BR.md) / [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.pt-BR.md](CODE_OF_CONDUCT.pt-BR.md) / [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Commits

Mensagens claras, imperativas (ex.: `fix(snmp): timeout no Windows`).

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
