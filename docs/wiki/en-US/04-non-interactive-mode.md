# Non-Interactive Mode

**Language:** English (en-US). **pt-BR:** [../pt-BR/04-modo-nao-interativo.md](../pt-BR/04-modo-nao-interativo.md)

## Usage

Recommended (after `pip install embedxpl`):

```bash
embedxpl -m <module_path> -s <option> <value> [-s <option> <value> ...]
```

Equivalents when running from a repository clone:

```bash
python -m embedxpl -m <module_path> -s <option> <value> ...
python exf.py     -m <module_path> -s <option> <value> ...   # legacy bootstrap
```

## Examples

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds -s target 192.168.1.1
embedxpl -m exploits/routers/dlink/dir_300_600_rce   -s target 192.168.0.1 -s port 80
embedxpl -m exploits/printers/hp/hp_printing_shellz_rce -s target 192.168.1.50 -s port 631
```

Repeat `-s` for each option. This mode suits **automation**, CI-style smoke checks, and scripted assessments on systems you are explicitly allowed to test. Always operate with written authorization from the asset owner.


[Wiki hub](../README.md)
