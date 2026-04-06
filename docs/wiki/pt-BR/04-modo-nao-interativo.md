# Modo não interativo

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/04-non-interactive-mode.md](../en-US/04-non-interactive-mode.md)

## Uso

```bash
python rxf.py -m <module_path> -s <option> <value> [-s <option> <value> ...]
```

## Exemplos

```bash
python rxf.py -m creds/routers/dlink/telnet_default -s target 192.168.1.1
python rxf.py -m exploits/routers/dlink/dir_300_600_rce -s target 192.168.0.1 -s port 80
```

Repita `-s` para cada opção. Este modo serve a **automação**, checagens tipo smoke em CI e scripts em alvos autorizados.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
