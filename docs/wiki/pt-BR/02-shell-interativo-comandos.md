# Comandos do Shell Interativo

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/02-interactive-shell-commands.md](../en-US/02-interactive-shell-commands.md)

---

## Iniciando o shell

```bash
embedxpl           # recomendado (apos pip install)
exf                # alias
python -m embedxpl # ponto de entrada do modulo
python exf.py      # bootstrap legado (git clone)
```

O prompt muda conforme o modulo carregado:

```text
exf >                          # sem modulo carregado
exf (dir_300_600_rce) >        # com modulo carregado
```

Completacao por Tab disponivel para todos os comandos e caminhos de modulo.

---

## Referencia completa de comandos

### Comandos globais (sempre disponiveis)

| Comando | Sintaxe | Descricao |
|---------|---------|-----------|
| `help` | `help` | Imprime a referencia de comandos |
| `use` | `use <caminho>` | Carrega um modulo pelo caminho |
| `search` | `search [termo] [filtros]` | Busca modulos por palavra-chave, CVE ou fabricante |
| `show` | `show <sub>` | Exibe listagens |
| `exec` | `exec <comando shell>` | Executa um comando no SO |
| `sysinfo` | `sysinfo` | Exibe CPU, RAM, GPU, modo de computacao |
| `compute` | `compute <modo>` | Define o backend de computacao |
| `discover` | `discover [alvo] [opcoes]` | Descoberta e fingerprinting de rede |
| `sessions` | `sessions [sub]` | Gerencia sessoes de scan persistentes |
| `apt` | `apt [sub]` | Catalogo de cadeias de ataque APT |
| `exit` | `exit` | Sai do shell |

### Comandos de contexto de modulo (requerem `use` primeiro)

| Comando | Sintaxe | Descricao |
|---------|---------|-----------|
| `run` | `run` | Executa o modulo carregado |
| `exploit` | `exploit` | Alias de `run` |
| `check` | `check` | Executa a verificacao de vulnerabilidade do modulo |
| `set` | `set <opcao> <valor>` | Define uma opcao do modulo |
| `setg` | `setg <opcao> <valor>` | Define uma opcao global (persiste entre modulos) |
| `unset` | `unset <opcao>` | Limpa uma opcao do modulo |
| `unsetg` | `unsetg <opcao>` | Limpa uma opcao global |
| `show options` | `show options` | Lista todas as opcoes do modulo |
| `show advanced` | `show advanced` | Lista opcoes avancadas |
| `show info` | `show info` | Exibe metadados do modulo |
| `show devices` | `show devices` | Lista dispositivos alvo do modulo |
| `back` | `back` | Descarrega o modulo atual |

---

## `set` / `setg` -- configurar opcoes

```text
exf (dir_300_600_rce) > set target 192.168.0.1
[+] target => 192.168.0.1

exf (dir_300_600_rce) > set port 8080
[+] port => 8080

exf (dir_300_600_rce) > set ssl true
[+] ssl => true

# Opcao global que persiste entre modulos:
exf (dir_300_600_rce) > setg target 192.168.0.1
[+] target => 192.168.0.1 (global)
```

**Tipos de dados das opcoes:**

| Tipo | Entrada no shell | Exemplo |
|------|-----------------|---------|
| `OptIP` | IPv4, IPv6 ou `file://caminho` (multi-alvo) | `192.168.1.1`, `file:///tmp/hosts.txt` |
| `OptPort` | Inteiro 1-65535 | `443`, `9100` |
| `OptBool` | Exatamente `true` ou `false` | `true`, `false` |
| `OptString` | Qualquer string | `admin`, `id`, `whoami` |
| `OptInteger` | Inteiro decimal ou hexadecimal | `10`, `0x1F` |
| `OptFloat` | Numero decimal | `2.0`, `0.5` |
| `OptMAC` | Endereco MAC | `aa:bb:cc:dd:ee:ff` |
| `OptWordlist` | `file://caminho` ou `usuario:senha,...` | `file:///usr/share/wordlists/rockyou.txt` |

---

## `check` e `run`

```text
exf (dir_300_600_rce) > check
[*] Verificando vulnerabilidade...
[+] Alvo e vulneravel

exf (dir_300_600_rce) > run
[*] Executando modulo dir_300_600_rce...
[+] Saida do comando: uid=0(root) gid=0(root)
```

| Retorno de `check` | Mensagem no shell |
|-------------------|------------------|
| `True` | `[+] Alvo e vulneravel` |
| `False` | `[-] Alvo nao e vulneravel` |
| Outro / excecao | `[*] Nao foi possivel verificar o alvo` |

**Opcoes do Shell Stager** (disponiveis em todos os modulos de exploit armados):

| Opcao | Tipo | Padrao | Descricao |
|-------|------|--------|-----------|
| `lhost` | `OptString` | `""` | IP do atacante para shells reversos |
| `lport` | `OptPort` | `4444` | Porta TCP do listener |
| `shell_type` | `OptString` | `auto` | Tipo de shell: `bash`, `nc`, `python`, `perl`, `ruby`, `php`, `powershell`, `meterpreter_linux`, `meterpreter_windows`, `auto`, entre outros |
| `force_exploit` | `OptBool` | `false` | Pula `check()` e vai direto ao exploit |
| `ask_on_fail` | `OptBool` | `true` | Pergunta ao usuario se `check()` retornar False |
| `pty_upgrade` | `OptBool` | `true` | Envia automaticamente `python3 pty.spawn()` ao conectar |
| `listener_timeout` | `OptPort` | `60` | Segundos para aguardar conexao reversa |

---

## `search` -- buscar modulos

```text
exf > search dlink
exf > search CVE-2021-36260
exf > search hikvision
exf > search fortinet
exf > search type=exploits cisco
exf > search vendor=sonicwall
exf > search device=routers netgear
```

**Filtros de busca:**

| Filtro | Valores | Exemplo |
|--------|---------|---------|
| `type=` | `exploits`, `creds`, `scanners`, `payloads`, `encoders`, `generic` | `type=exploits` |
| `device=` | Subdiretorio de `exploits/` | `device=cameras` |
| `vendor=` | Qualquer segmento de caminho | `vendor=paloalto` |
| `language=` | Subdiretorio de `encoders/` | `language=python` |
| `payload=` | Subdiretorio de `payloads/` | `payload=python` |

---

## `discover` -- descoberta de rede

```text
exf > discover 192.168.1.0/24
exf > discover 192.168.1.0/24 --timing T4
exf > discover -T /tmp/alvos.txt
exf > discover 192.168.1.0/24 --fresh
```

**Perfis de timing:**

| Perfil | Atraso | Caso de uso |
|--------|--------|-------------|
| `T0` | 300 s/probe | Evasao extrema de IDS |
| `T1` | 15 s/probe | Auditorias silenciosas |
| `T2` | 2 s/probe | Impacto minimo na rede |
| `T3` | 0,5 s/probe | **Padrao** -- normal |
| `T4` | 0,1 s/probe | Scans rapidos em LAN |
| `T5` | 0 s/probe | Somente CTF / lab isolado |

---

## `sessions` -- gerenciar historico de scan

```text
exf > sessions list
exf > sessions show 192.168.1.1
exf > sessions export 192.168.1.1
exf > sessions delete 192.168.1.1
exf > sessions purge           # solicita confirmacao: digite "yes"
```

---

## Convencoes de prefixo de saida

| Prefixo | Cor | Significado |
|---------|-----|-------------|
| `[+]` | Verde | Sucesso / descoberta |
| `[-]` | Vermelho | Erro / falha |
| `[*]` | Azul | Status / progresso |
| `[!]` | Amarelo | Aviso |
| (nenhum) | Branco | Informativo |


[Hub da wiki](../README.md)
