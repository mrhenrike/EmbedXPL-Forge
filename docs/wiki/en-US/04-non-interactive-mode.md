# Non-Interactive Mode

**Language:** English (en-US). **pt-BR:** [../pt-BR/04-modo-nao-interativo.md](../pt-BR/04-modo-nao-interativo.md)

## Usage

```bash
python rxf.py -m <module_path> -s <option> <value> [-s <option> <value> ...]
```

## Examples

```bash
python rxf.py -m creds/routers/dlink/telnet_default -s target 192.168.1.1
python rxf.py -m exploits/routers/dlink/dir_300_600_rce -s target 192.168.0.1 -s port 80
```

Repeat `-s` for each option. This mode suits **automation**, CI-style smoke checks, and scripted assessments on systems you are allowed to test.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
