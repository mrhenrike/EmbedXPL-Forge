# Solucao de Problemas

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/11-troubleshooting.md](../en-US/11-troubleshooting.md)

---

## Problemas de inicializacao

### `ImportError` ou `ModuleNotFoundError` ao iniciar

```bash
pip install -r requirements.txt   # reinstala todas as dependencias
pip install embedxpl[all]          # ou reinstala com todos os extras
python tools/env_doctor.py         # diagnostico completo
```

### Erro de TTY / modo nao-interativo falha

```text
[-] EmbedXPL-Forge requer terminal interativo para o modo shell.
    Use a flag -m para execucao nao-interativa.
```

Solucao: use a flag `-m` para modo nao-interativo, ou garanta que o terminal tenha um TTY real.

---

## Problemas de versao do Python

### Telnet no Python 3.13+

`telnetlib` foi removido no Python 3.13. Instale `telnetlib3`:

```bash
pip install telnetlib3
```

---

## Problemas de rede e SO

### Erros do Scapy / acesso a raw socket

```bash
sudo embedxpl
# ou (Linux):
sudo setcap cap_net_raw+eip $(which python3)
```

No **Windows**, instale o **Npcap** para suporte a raw socket.

### Sem cores no Windows

```bash
pip install colorama
```

### Permissao negada no Linux (NSE ou raw sockets)

```bash
sudo embedxpl-nse install
sudo embedxpl
```

---

## Problemas com Shell Stager

### Listener ativo mas sem conexao

1. Verifique se `lhost` e o IP do atacante acessivel a partir do alvo.
2. Verifique regras de firewall: `lport` deve estar aberta para entrada.
3. Aumente `listener_timeout`.
4. Tente outro `shell_type` (`python`, `nc_mkfifo`, `socat`).

### Terminal corrompido apos fechar o shell

```bash
reset         # restaura o estado do terminal
stty sane     # alternativa
```

### Stager Meterpreter falha

1. Verifique se `msfvenom` esta instalado (`metasploit-framework`).
2. O modulo imprime o comando `msfvenom` -- execute manualmente.
3. Inicie o handler: `msfconsole -r .tmp/msf_handler_<porta>.rc`

---

## Problemas com scripts NSE

### Scripts nao encontrados pelo Nmap apos instalacao

```bash
sudo nmap --script-updatedb
```

### `embedxpl-nse install` retorna erro de permissao

```bash
sudo embedxpl-nse install
# ou especifique um diretorio gravavel:
embedxpl-nse install --nse-dir ~/.nmap/scripts
```

---

## Problemas com modulos especificos

### `check()` retorna "nao foi possivel verificar"

```text
exf (nome_modulo) > set force_exploit true
exf (nome_modulo) > run
```

### `[WARN] Alvo pode estar corrigido`

O alvo pode estar corrigido, atras de um WAF ou usando configuracao nao-padrao. Use `force_exploit=true` para tentar mesmo assim.

---

## Dependencias

Reinstalar todas as dependencias:

```bash
pip install -r requirements.txt --upgrade
```

---

## Obtendo ajuda

- **Issues no GitHub:** https://github.com/mrhenrike/EmbedXPL-Forge/issues
- **Diagnostico:** `python tools/env_doctor.py`
- **Teste de compatibilidade:** `python tools/compat_smoke.py`


[Hub da wiki](../README.md)
