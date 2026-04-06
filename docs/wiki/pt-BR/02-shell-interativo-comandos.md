# Comandos do shell interativo

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/02-interactive-shell-commands.md](../en-US/02-interactive-shell-commands.md)

## Referência de comandos

| Comando | Função |
|---------|--------|
| `use` | Carrega um módulo pelo caminho |
| `back` | Sai do contexto do módulo atual |
| `show options` | Lista opções do módulo |
| `show info` | Mostra metadados do módulo |
| `show devices` | Lista devices / visão de catálogo quando aplicável |
| `set` | Define opção local ao módulo |
| `setg` | Define opção global |
| `unset` | Remove opção local |
| `unsetg` | Remove opção global |
| `check` | Executa checagem de disponibilidade quando implementada |
| `run` / `exploit` | Executa o módulo carregado |
| `search` | Busca módulos por palavra-chave |
| `help` | Ajuda integrada |
| `exit` | Encerra o shell |

## Exemplo de sessão

```text
RouterXPL-Forge > use exploits/routers/dlink/dir_300_600_rce
RouterXPL-Forge (dir_300_600_rce) > show options
RouterXPL-Forge (dir_300_600_rce) > set target 192.168.0.1
RouterXPL-Forge (dir_300_600_rce) > check
RouterXPL-Forge (dir_300_600_rce) > run
```

**Tab completion** está disponível para comandos e caminhos de módulo quando a camada readline está ativa.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
