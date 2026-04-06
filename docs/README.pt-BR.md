# Documentação — RouterXPL-Forge

**Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Idiomas:** Arquivos neste diretório são primariamente **English (en-US)**. **Português (pt-BR)** Wiki: [wiki/pt-BR/README.md](wiki/pt-BR/README.md).

## Conteúdo

| Caminho | Idioma | Descrição |
|---------|--------|-----------|
| [wiki/README.md](wiki/README.md) | hub bilíngue | Índice da wiki (en-US + pt-BR) |
| [diagrams/architecture/README.md](diagrams/architecture/README.md) | en-US + pt-BR | Diagramas de arquitetura de superfície de ataque (Mermaid) |
| [img/architecture/](img/architecture/) | labels en-US | PNGs exportados de arquitetura |
| [modules/](modules/) | en-US | Documentação por módulo |

## Arquitetura de Superfície de Ataque (PNGs)

Fontes Mermaid: [diagrams/architecture/](diagrams/architecture/). Galeria:

| Roteador SOHO | Switch |
|:---:|:---:|
| ![Roteador SOHO](img/architecture/rxf_arch_router_soho.png) | ![Switch](img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW](img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](img/architecture/rxf_arch_isp_cpe.png) |

| Edge Misto |
|:---:|
| ![Edge misto](img/architecture/rxf_arch_edge_mixed.png) |

## Idiomas da Wiki

- **English (padrão):** [wiki/en-US/README.md](wiki/en-US/README.md)
- **Português (Brasil):** [wiki/pt-BR/README.md](wiki/pt-BR/README.md)

## Regeneração

```bash
python tools/generate_coverage_matrix.py
python tools/generate_full_catalog.py
python tools/gen_wiki_module_index.py
```

---

> **Autor:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)