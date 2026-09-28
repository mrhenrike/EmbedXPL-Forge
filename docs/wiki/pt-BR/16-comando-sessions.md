# Comando sessions

**Idioma:** Português (pt-BR). **English:** [../en-US/16-sessions-command.md](../en-US/16-sessions-command.md)

---

## Visão geral

`sessions` gerencia o histórico de sessões de varredura. Toda vez que `discover` ou um módulo executa contra um alvo, o EmbedXPL-Forge registra o resultado em um arquivo de sessão por host (`~/.exf_sessions/`). As sessões persistem entre reinicializações e funcionam como o `--restore` do John the Ripper — retomando de onde a última varredura parou.

---

## Sintaxe

```
sessions                        Listar todas as sessões salvas
sessions list                   Igual ao anterior
sessions show <ip>              Exibir sessão detalhada de um host
sessions delete <ip>            Excluir sessão de um host específico
sessions export <ip>            Exportar sessão como JSON
sessions purge                  Excluir TODAS as sessões (solicita confirmação)
```

---

## `sessions` / `sessions list` — listar todas as sessões

### Saída (sessões existem)

```
exf> sessions

┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    Saved Sessions (4)                                        │
├───┬─────────────────┬───────────────────┬──────────────────┬──────────────────┬───────┬─────┤
│ # │ IP              │ MAC               │ Vendor           │ Model            │ Scans │...  │
├───┼─────────────────┼───────────────────┼──────────────────┼──────────────────┼───────┼─────┤
│ 1 │ 192.168.1.1     │ EC:08:6B:1A:2C:40 │ TP-Link          │ TL-WR841N        │   3   │...  │
│ 2 │ 192.168.1.100   │ AC:CC:8E:5A:10:F2 │ Hikvision        │ DS-7608NI-K2     │   2   │...  │
│ 3 │ 192.168.1.200   │ 00:09:0F:AA:00:01 │ Fortinet         │ FortiGate-200F   │   1   │...  │
│ 4 │ 10.0.0.1        │ 00:1A:2B:3C:4D:5E │ Cisco            │ IOS XE           │   1   │...  │
└───┴─────────────────┴───────────────────┴──────────────────┴──────────────────┴───────┴─────┘

Use 'sessions show <ip>' for details
```

### Descrições das colunas

| Coluna | Descrição |
|--------|-----------|
| `#` | Índice da linha |
| `IP` | Endereço IP do alvo |
| `MAC` | Endereço MAC (do ARP) |
| `Vendor` | Vendor do dispositivo detectado |
| `Model` | Modelo do dispositivo detectado |
| `Scans` | Número total de vezes que este host foi varrido |
| `Tested` | Número de módulos de exploit executados contra este host |
| `Pending` | Módulos correspondentes ainda não testados |
| `Vulns` | Número de vulnerabilidades confirmadas |
| `Last Scan` | Timestamp da varredura mais recente |
| `ID` | Primeiros 8 caracteres do ID de host da sessão (baseado em SHA) |

### Saída (sem sessões)

```
exf> sessions

[*] No saved sessions. Run 'discover <target>' to create one.
```

---

## `sessions show <ip>` — detalhe da sessão

### Saída

```
exf> sessions show 192.168.1.100

╔══════════════════════════════════════════════════════════════╗
║                      Session Detail                          ║
╠══════════════════════════════════════════════════════════════╣
║ 192.168.1.100 (AC:CC:8E:5A:10:F2)                           ║
║ Vendor: Hikvision  Model: DS-7608NI-K2                      ║
║ First seen: 2026-05-28 10:14  Last scan: 2026-05-29 14:32   ║
║ Total scans: 2  Ports: 80,443,554,8000,37777                ║
║ WiFi: No                                                     ║
╚══════════════════════════════════════════════════════════════╝

Module Execution Summary:
  Matched:  14
  Tested:    9
  Pending:   5
  Vuln:      2
  Safe:      6
  Errored:   1

Confirmed Vulnerabilities:
  • exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  • exploits/cameras/hikvision/info_disclosure_cve_2017_7921

Pending Modules (not yet tested):
  • exploits/cameras/hikvision/psh_challenge_predictor
  • exploits/cameras/hikvision/nvr_dvr_serial_privesc
  • exploits/cameras/hikvision/r0_intercom_gpio_door_unlock
  • exploits/cameras/hikvision/r0_intercom_ssh_default_bypass
  • exploits/cameras/hikvision/firmware_crypto_key_extract

Execution History (last 20):
┌───────────────────────────────────────────────────┬───────────────┬─────────────┬─────────┐
│ Module                                            │ Result        │ Time        │ Elapsed │
├───────────────────────────────────────────────────┼───────────────┼─────────────┼─────────┤
│ rtsp_rce_cve_2021_36260                           │ VULNERABLE    │ 05-29 14:28 │   3.2s  │
│ info_disclosure_cve_2017_7921                     │ VULNERABLE    │ 05-29 14:25 │   1.8s  │
│ psh_command_injection                             │ safe          │ 05-29 14:22 │   2.1s  │
│ psh_debug_rsa1024_bypass                          │ safe          │ 05-29 14:20 │   1.4s  │
│ nas_auth_bypass_cve_2023_28808                    │ safe          │ 05-29 14:18 │   2.9s  │
│ r0_intercom_3des_decrypt                          │ safe          │ 05-29 14:15 │   1.1s  │
│ r0_intercom_developer_nfs                         │ safe          │ 05-29 14:12 │   0.8s  │
│ r0_intercom_ssh_mitm                              │ safe          │ 05-29 14:10 │   3.5s  │
│ r0_intercom_suid_privesc                          │ error         │ 05-28 10:20 │   0.5s  │
└───────────────────────────────────────────────────┴───────────────┴─────────────┴─────────┘
```

### Erro — sessão não encontrada

```
exf> sessions show 192.168.99.99

[WARN] No session found for 192.168.99.99
```

### Erro — argumento ausente

```
exf> sessions show

[-] Usage: sessions show <ip>
```

---

## `sessions delete <ip>` — excluir uma sessão

```
exf> sessions delete 192.168.1.100

[+] Session for 192.168.1.100 deleted
```

### Não encontrada

```
exf> sessions delete 192.168.99.99

[WARN] No session found for 192.168.99.99
```

### Argumento ausente

```
exf> sessions delete

[-] Usage: sessions delete <ip>
```

---

## `sessions export <ip>` — exportar sessão como JSON

Exporta o registro completo da sessão como um objeto JSON impresso no stdout.

```
exf> sessions export 192.168.1.100

{
  "host_id": "c7e2d4a1b3f92e8a1c7d4e5f6a0b1c2d",
  "ip": "192.168.1.100",
  "mac": "AC:CC:8E:5A:10:F2",
  "vendor": "Hikvision",
  "model": "DS-7608NI-K2",
  "hostname": "DVR-001",
  "first_seen": 1748428440.0,
  "last_scanned": 1748514720.0,
  "total_scans": 2,
  "open_ports": [80, 443, 554, 8000, 37777],
  "banners": {
    "80": "Server: App-webs/",
    "554": "RTSP/1.0 401 Unauthorized"
  },
  "fingerprint_confidence": 0.88,
  "matched_modules": [
    "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260",
    "exploits/cameras/hikvision/info_disclosure_cve_2017_7921",
    ...
  ],
  "module_results": [
    {
      "module_path": "embedxpl.modules.exploits.cameras.hikvision.rtsp_rce_cve_2021_36260",
      "vulnerable": true,
      "error": null,
      "elapsed_s": 3.2,
      "port": 554,
      "timestamp": 1748514708.0
    },
    ...
  ],
  "vulns_found": [
    "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260",
    "exploits/cameras/hikvision/info_disclosure_cve_2017_7921"
  ],
  "has_wireless": false,
  "wireless_ssids": [],
  "notes": []
}
```

### Salvar em arquivo

```bash
# Redirecionar para arquivo (do shell, não do prompt EmbedXPL)
python -m embedxpl -m sessions -s "export 192.168.1.100" > session_192.168.1.100.json
```

### Não encontrada

```
exf> sessions export 192.168.99.99

[WARN] No session found for 192.168.99.99
```

---

## `sessions purge` — excluir TODAS as sessões

Requer confirmação explícita.

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: yes

[+] Purged 4 session(s)
```

### Cancelado

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: no

[*] Cancelled
```

### Interrupção de teclado (Ctrl+C)

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: ^C
[*] Cancelled
```

---

## Subcomando desconhecido

```
exf> sessions foo

[-] Unknown sub-command 'foo'. Use: list, show, delete, export, purge
```

---

## Local de armazenamento de sessão

As sessões são armazenadas como arquivos JSON em `~/.exf_sessions/` (um arquivo por host, nomeado por ID de host baseado em SHA):

```
~/.exf_sessions/
  a3f9b21c...json      # 192.168.1.1
  c7e2d4a1...json      # 192.168.1.100
  f1b8c392...json      # 192.168.1.200
  8d3c1a2b...json      # 10.0.0.1
```

O ID do host é derivado de um hash de `ip:mac` (ou apenas `ip` se MAC estiver indisponível), tornando as sessões estáveis entre reatribuições de IP quando o MAC persiste.

---

## Como as sessões interagem com `discover`

Quando `discover` é executado e encontra um host varrido anteriormente:

1. Carrega a sessão existente
2. Exibe a idade da sessão, contagem de testados e vulnerabilidades conhecidas
3. Mostra quais módulos foram testados (verde), vulneráveis (vermelho) e pendentes (esmaecido)
4. Mescla novos dados de descoberta (portas atualizadas, banners, confiança)
5. Salva a sessão atualizada

Use `--fresh` para resetar: `discover 192.168.1.0/24 --fresh`

Use `sessions delete 192.168.1.100` para excluir uma sessão de host específico e começar do zero.

---

[Hub da Wiki](../README.md)
