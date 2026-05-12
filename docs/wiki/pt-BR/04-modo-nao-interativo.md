# Modo não interativo

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/04-non-interactive-mode.md](../en-US/04-non-interactive-mode.md)

## Uso

Recomendado (apos `pip install embedxpl`):

```bash
embedxpl -m <module_path> -s <option> <value> [-s <option> <value> ...]
```

Equivalentes (rodando do clone do repositorio):

```bash
python -m embedxpl -m <module_path> -s <option> <value> ...
python exf.py     -m <module_path> -s <option> <value> ...   # bootstrap legacy
```

## Exemplos

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds -s target 192.168.1.1
embedxpl -m exploits/routers/dlink/dir_300_600_rce   -s target 192.168.0.1 -s port 80
embedxpl -m exploits/printers/hp/hp_printing_shellz_rce -s target 192.168.1.50 -s port 631
```

Repita `-s` para cada opcao. Este modo serve a **automacao**, checagens tipo smoke em CI e scripts em alvos autorizados. Sempre opere com autorizacao escrita do dono do ativo.


[Hub wiki](../README.md)
