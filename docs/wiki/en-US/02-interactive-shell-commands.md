# Interactive Shell Commands

**Language:** English (en-US). **pt-BR:** [../pt-BR/02-shell-interativo-comandos.md](../pt-BR/02-shell-interativo-comandos.md)

## Command reference

| Command | Purpose |
|---------|---------|
| `use` | Load a module by path |
| `back` | Leave the current module context |
| `show options` | List module options |
| `show info` | Show module metadata |
| `show devices` | List known devices / targets catalog view (when applicable) |
| `set` | Set an option for the current module |
| `setg` | Set a global option |
| `unset` | Clear a module-local option |
| `unsetg` | Clear a global option |
| `check` | Run a module-specific availability check when implemented |
| `run` / `exploit` | Execute the loaded module |
| `search` | Search modules by keyword |
| `help` | Built-in help |
| `exit` | Quit the shell |

## Example session

```text
RouterXPL-Forge > use exploits/routers/dlink/dir_300_600_rce
RouterXPL-Forge (dir_300_600_rce) > show options
RouterXPL-Forge (dir_300_600_rce) > set target 192.168.0.1
RouterXPL-Forge (dir_300_600_rce) > check
RouterXPL-Forge (dir_300_600_rce) > run
```

**Tab completion** is available for commands and module paths where the readline layer is active.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
