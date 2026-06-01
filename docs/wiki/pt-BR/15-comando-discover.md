# Comando discover

**Idioma:** Português (pt-BR). **English:** [../en-US/15-discover-command.md](../en-US/15-discover-command.md)

---

## Visão geral

`discover` realiza descoberta de rede em uma subnet ou host individual, faz fingerprint dos dispositivos ativos e os combina com o catálogo de exploits do EmbedXPL. É ciente de sessão: se um host foi varrido antes, os achados anteriores são exibidos e a varredura retoma de onde parou.

---

## Sintaxe

```
discover <subnet/CIDR>
discover <IP>
discover <subnet/CIDR> --fresh
discover -T <targets.txt>
discover -T <targets.txt> --fresh
```

---

## Parâmetros

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `<subnet/CIDR>` | string | Endereço IPv4 ou notação CIDR (ex.: `192.168.1.0/24`, `10.0.0.1`) |
| `--fresh` | flag | Ignorar dados de sessão salvos; realizar uma varredura completa do zero |
| `-T <arquivo>` | string | Caminho para arquivo de texto simples com um IP ou CIDR por linha |

---

## Descoberta padrão — CIDR único

```
exf> discover 192.168.1.0/24

[*] Starting network discovery on 192.168.1.0/24
[*] [arp_ping] Sending ARP broadcast to 192.168.1.0/24
[*] [port_scan] Scanning live hosts: 80,443,23,22,554,8080,8443,7547,37777,9100,631
[*] [banner_grab] Grabbing HTTP/RTSP/Telnet banners
[*] [fingerprint] Matching vendor OUI and HTTP fingerprints
[*] [catalog_match] Matching hosts to exploit catalog
[*] [wireless_check] Checking for wireless SSIDs

┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  Discovered Hosts (5)                                  │
├─────────────────┬───────────────────┬──────────────────┬────────────────┬──────────────┤
│ IP              │ MAC               │ Hostname         │ Ports          │ Vendor       │
├─────────────────┼───────────────────┼──────────────────┼────────────────┼──────────────┤
│ 192.168.1.1     │ EC:08:6B:1A:2C:40 │ -                │ 80,443,22      │ TP-Link      │
│ 192.168.1.100   │ AC:CC:8E:5A:10:F2 │ DVR-001          │ 80,554,8000,37777│ Hikvision  │
│ 192.168.1.101   │ 00:E0:4C:3B:12:AA │ -                │ 80,37777       │ Dahua        │
│ 192.168.1.200   │ 00:09:0F:AA:00:01 │ fw-perimeter     │ 80,443,8443    │ Fortinet     │
│ 192.168.1.254   │ 18:E8:29:01:B4:CC │ router-main      │ 80,443,22,23   │ Cisco        │
└─────────────────┴───────────────────┴──────────────────┴────────────────┴──────────────┘

[+]
[+] 5 host(s) matched against the exploit catalog:

  192.168.1.1 [TP-Link] TL-WR841N -- 6 exploit module(s)
    use exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224  [pending]
    use exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377    [pending]
    use exploits/routers/tplink/multi_dns_hijack_apt28                       [pending]
    use creds/routers/tplink/ssh_default_creds                               [pending]
    use creds/routers/tplink/telnet_default_creds                            [pending]
    use creds/routers/tplink/http_default_creds                              [pending]

  192.168.1.100 [Hikvision] DS-7608NI-K2 -- 14 exploit module(s)
    use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260                   [pending]
    use exploits/cameras/hikvision/info_disclosure_cve_2017_7921             [pending]
    use exploits/cameras/hikvision/psh_command_injection                     [pending]
    use exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808            [pending]
    use exploits/cameras/hikvision/firmware_crypto_key_extract               [pending]
    ... e mais 9

  192.168.1.101 [Dahua] IPC-HDW2831T -- 8 exploit module(s)
    use exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044               [pending]
    use exploits/cameras/dahua/cctv_rce_cve_2021_36260                       [pending]
    ... e mais 6

  192.168.1.200 [Fortinet] FortiGate-200F -- 12 exploit module(s)
    use exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684       [pending]
    use exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762        [pending]
    ... e mais 10

╔════════════════════════════════════════════════════════════════════╗
║ WirelessXPL-Forge  COMPLEMENTARY                                   ║
║ 192.168.1.1 (TP-Link TL-WR841N)  SSIDs: HomeNet_5G, HomeNet_2G    ║
║                                                                    ║
║ Este dispositivo tem interfaces wireless. WirelessXPL-Forge pode testar:  ║
║  - Captura de handshake WPA2/WPA3 e cracking offline              ║
║  - Ataques Deauth e PMKID                                          ║
║  - Enumeração de SSID e detecção de redes ocultas                 ╚
```

---

## Descoberta com `--fresh` (ignorar histórico de sessão)

```
exf> discover 192.168.1.0/24 --fresh

[*] Starting network discovery on 192.168.1.0/24
[*] --fresh flag: ignoring saved session data

... (saída completa de descoberta, igual à acima) ...

[*] 5 new session(s) created
```

---

## Comportamento de retomada de sessão (sem `--fresh`)

Quando `discover` encontra um host que foi varrido antes, mostra a sessão anterior e retoma a partir dos módulos pendentes:

```
exf> discover 192.168.1.0/24

[*] Starting network discovery on 192.168.1.0/24
...

SESSION FOUND for 192.168.1.100 (AC:CC:8E:5A:10:F2) — last scan: 2026-05-29 14:32, tested: 9, vulns: 2
  9 module(s) already tested, 5 pending — resuming from where it stopped
  Previous vulns:
    • exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
    • exploits/cameras/hikvision/info_disclosure_cve_2017_7921

SESSION FOUND for 192.168.1.200 (00:09:0F:AA:00:01) — last scan: 2026-05-30 09:15, tested: 4, vulns: 0
  4 module(s) already tested, 8 pending — resuming from where it stopped

[+]
[+] 2 host(s) resumed from session history, 3 new
Use 'discover 192.168.1.0/24 --fresh' to ignore history and rescan from zero

  192.168.1.100 [Hikvision] DS-7608NI-K2 -- 14 exploit module(s)
    use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260     VULN
    use exploits/cameras/hikvision/info_disclosure_cve_2017_7921  VULN
    use exploits/cameras/hikvision/psh_command_injection        tested
    use exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808  tested
    use exploits/cameras/hikvision/psh_challenge_predictor      pending
    use exploits/cameras/hikvision/nvr_dvr_serial_privesc       pending
```

---

## Descoberta de host único

```
exf> discover 10.0.0.1

[*] Starting network discovery on 10.0.0.1
[*] [arp_ping] Checking 10.0.0.1...
[*] [port_scan] Scanning: 80,443,22,23,8080,8443
[*] [banner_grab] HTTP banner: Cisco IOS XE 17.3.4
[*] [fingerprint] Matched vendor: Cisco | model: IOS XE router
[*] [catalog_match] Matching against exploit catalog...

┌────────────────────────────────────────────────────────────┐
│             Discovered Hosts (1)                           │
├───────────┬─────────────────┬────────┬───────────┬─────────┤
│ IP        │ MAC             │ Ports  │ Vendor    │ Model   │
├───────────┼─────────────────┼────────┼───────────┼─────────┤
│ 10.0.0.1  │ 00:1A:2B:3C:4D:5E│443,22 │ Cisco     │IOS XE   │
└───────────┴─────────────────┴────────┴───────────┴─────────┘

[+] 1 host(s) matched against the exploit catalog:
  10.0.0.1 [Cisco] IOS XE router -- 3 exploit module(s)
    use exploits/network_os/cisco/ios_xe_webui_privesc_cve_2023_20198  [pending]
    use exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452  [pending]
    use creds/routers/cisco/ssh_default_creds                          [pending]
```

---

## Descoberta a partir de arquivo de alvos (`-T`)

### Formato do arquivo de alvos

```
# targets.txt
# Um IP ou CIDR por linha, linhas em branco e comentários # são ignorados
192.168.1.0/24
10.0.0.1
172.16.0.0/23
# 192.168.2.0/24   (comentado)
```

### Uso no shell interativo

```
exf> discover -T /caminho/para/targets.txt

[*] Multi-target scan from file: /caminho/para/targets.txt
[*] [192.168.1.0/24] [arp_ping] Sending ARP broadcast...
[*] [10.0.0.1] [port_scan] Scanning ports...
[*] [172.16.0.0/23] [arp_ping] Sending ARP broadcast...
[+] [192.168.1.0/24] done — 5 host(s) found
[+] [10.0.0.1] done — 1 host(s) found
[+] [172.16.0.0/23] done — 12 host(s) found

Scan complete — 3 target(s), 18 total host(s) found

  192.168.1.0/24 — 5 host(s):
    192.168.1.1    TP-Link TL-WR841N  ports=[80,443,22]  conf=92%  modules=6
    192.168.1.100  Hikvision DS-7608NI-K2  ports=[80,554,37777]  conf=88%  modules=14
    192.168.1.101  Dahua IPC-HDW2831T  ports=[80,37777]  conf=81%  modules=8
    192.168.1.200  Fortinet FortiGate  ports=[80,443,8443]  conf=95%  modules=12
    192.168.1.254  Cisco RV325  ports=[80,22,23]  conf=90%  modules=5

  10.0.0.1 — 1 host(s):
    10.0.0.1  Cisco IOS XE  ports=[443,22]  conf=87%  modules=3

  172.16.0.0/23 — 12 host(s):
    172.16.0.1   ... (12 entradas) ...
```

### Modo não interativo (`-T` como flag CLI)

```bash
python -m embedxpl -T /caminho/para/targets.txt
```

A saída é idêntica. A ferramenta varre todos os alvos em paralelo (até 4 workers de arquivo) e encerra após a conclusão.

---

## Nenhum host ativo encontrado

```
exf> discover 10.255.0.0/24

[*] Starting network discovery on 10.255.0.0/24
[*] [arp_ping] Sending ARP broadcast to 10.255.0.0/24
[WARN] No live hosts found on 10.255.0.0/24
```

---

## Alvo inválido

```
exf> discover not-an-ip

[-] Invalid target: 'not-an-ip'. Use IP or CIDR notation.

exf> discover 999.0.0.0/24

[-] Invalid target: '999.0.0.0/24'. Use IP or CIDR notation.
```

---

## Argumento ausente

```
exf> discover

[-] Usage: discover <subnet/CIDR>  |  discover -T <targets.txt>
```

---

## Dados de descoberta armazenados por host

Para cada host descoberto, `discover` armazena na sessão:

| Campo | Descrição |
|-------|-----------|
| `ip` | Endereço IP |
| `mac` | Endereço MAC (se determinável via ARP) |
| `hostname` | Nome de host DNS ou registro PTR |
| `vendor` | Suposição de vendor a partir de OUI + fingerprint HTTP |
| `model` | Suposição de modelo a partir de banner/cabeçalhos HTTP |
| `open_ports` | Lista de portas TCP abertas |
| `banners` | Strings de banner HTTP/Telnet/RTSP por porta |
| `fingerprint_confidence` | Float 0.0–1.0, % de certeza da correspondência vendor/modelo |
| `matched_modules` | Lista de caminhos de módulo EmbedXPL que correspondem a este host |
| `has_wireless` | True se interfaces/SSIDs wireless foram detectados |
| `wireless_ssids` | Lista de nomes de SSID se detectados |
| `wireless_recommendation` | Mensagem de referência cruzada para WirelessXPL-Forge |

Use `sessions show <ip>` para inspecionar os dados armazenados. Consulte [16-comando-sessions.md](16-comando-sessions.md).

---

## Referência cruzada com WirelessXPL-Forge

Quando `discover` encontra um dispositivo com interfaces wireless, exibe um painel recomendando WirelessXPL-Forge:

```
╔══════════════════════════════════════════════════════════════════════╗
║ WirelessXPL-Forge  RECOMMENDED                                        ║
║ 192.168.1.1 (TP-Link Unknown)  SSIDs: HomeNet_5G, HomeNet_2G         ║
║                                                                       ║
║ Nenhum módulo de exploit com fio correspondeu a este host. WirelessXPL-Forge pode    ║
║ testar a interface wireless independentemente:                         ║
║  - Captura de handshake WPA2/WPA3 com hashcat/aircrack-ng            ║
║  - Ataque PMKID (sem cliente)                                         ║
║  - Ataques de deautenticação e evil twin                              ║
║  pip install wirelessxpl && wfx                                       ╚
```

O painel é `RECOMMENDED` (borda magenta) quando nenhum módulo de exploit com fio correspondeu, ou `COMPLEMENTARY` (borda ciano) quando módulos com fio também corresponderam.

---

## Referência de temporização

| Tamanho da rede | Tempo típico de varredura |
|---|---|
| Host único | 3–8 segundos |
| /30 (4 hosts) | 5–12 segundos |
| /24 (256 hosts) | 30–90 segundos |
| /22 (1024 hosts) | 2–5 minutos |
| /16 (65536 hosts) | 20–60 minutos |

A temporização depende da latência de resposta ARP, contagem de portas abertas e timeouts de captura de banner.

---

[Hub da Wiki](../README.md)
