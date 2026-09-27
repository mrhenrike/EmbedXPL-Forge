# Busca e Listagem

**Idioma:** Português (pt-BR). **English:** [../en-US/03-search-and-listing.md](../en-US/03-search-and-listing.md)

---

## `search` — encontrar módulos

O comando `search` realiza correspondência de substring sem distinção de maiúsculas/minúsculas em todos os caminhos de módulos. Suporta busca por palavra-chave e filtros estruturados. Os resultados são exibidos com palavras correspondentes destacadas em vermelho/negrito.

### Sintaxe

```
search [palavra-chave] [filtro=valor ...]
```

**Parâmetros:**

| Parâmetro | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-----------|------|-------------|--------|-----------------|-----------|
| `palavra-chave` | string | Não* | `""` | Qualquer texto | Substring correspondida ao caminho completo do módulo |
| `type=` | filtro | Não | — | `exploits`, `creds`, `scanners`, `payloads`, `encoders`, `generic` | Restringir a uma categoria de módulo |
| `device=` | filtro | Não | — | Subdiretório de `exploits/` (ex.: `cameras`, `routers`, `firewalls`) | Restringir a uma classe de dispositivo em módulos de exploit |
| `vendor=` | filtro | Não | — | Qualquer segmento de caminho (ex.: `hikvision`, `dlink`, `cisco`) | Restringir a um subdiretório de vendor |
| `language=` | filtro | Não | — | Subdiretório de `encoders/` (ex.: `python`, `php`, `perl`) | Restringir à linguagem do encoder |
| `payload=` | filtro | Não | — | Subdiretório de `payloads/` (ex.: `python`, `x86`, `armle`) | Restringir a uma arquitetura de payload |

\* Pelo menos uma palavra-chave ou filtro deve ser fornecido.

**Erro quando chamado sem argumentos:**

```text
exf > search
[-] Please specify at least search keyword. e.g. 'search cisco'
[-] You can specify options. e.g. 'search type=exploits device=routers vendor=linksys WRT100 rce'
```

---

### Busca apenas por palavra-chave

Busque por nome de vendor, identificador CVE, família de dispositivo, protocolo ou qualquer substring de um caminho de módulo:

**Sessão de terminal — busca por vendor:**

```text
exf > search dlink
exploits/cameras/dlink/dcs_930l_932l_auth_bypass
exploits/cameras/dlink/dcs_931l_file_upload_rce_cve_2015_2049
creds/cameras/dlink/ftp_default_creds
creds/cameras/dlink/ssh_default_creds
creds/cameras/dlink/telnet_default_creds
creds/routers/dlink/telnet_default_creds
...
```

**Sessão de terminal — busca por CVE:**

```text
exf > search CVE-2021-36260
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exploits/cameras/dahua/cctv_rce_cve_2021_36260
```

**Sessão de terminal — busca por família de dispositivo:**

```text
exf > search herospeed
exploits/cameras/herospeed/herospeed_nvr_camera_creds_decrypt
exploits/cameras/herospeed/herospeed_nvr_config_export_cred_recovery
exploits/cameras/herospeed/herospeed_nvr_ftp_diagnostic_rce
exploits/cameras/herospeed/herospeed_nvr_ftp_sqlite_injection_rce
exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash
exploits/cameras/herospeed/herospeed_nvr_paramconfig_bypass
exploits/cameras/herospeed/herospeed_nvr_rce
exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor
exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce
exploits/cameras/herospeed/herospeed_nvr_v6_db_decryptor
exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure
scanners/cameras/herospeed_longsee_nvr_scan
```

**Sessão de terminal — busca por palavra-chave múltipla (lógica AND):**

```text
exf > search hikvision rce
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
```

Todas as palavras-chave separadas por espaço devem aparecer no caminho do módulo (lógica AND).

---

### Busca filtrada

Combine palavra-chave com um ou mais filtros `chave=valor`:

**Sessão de terminal — filtro `type=`:**

```text
exf > search type=exploits cisco
exploits/cameras/cisco/video_surv_path_traversal
exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171
```

**Sessão de terminal — filtro `device=`:**

```text
exf > search type=exploits device=cameras auth_bypass
exploits/cameras/dahua/auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044
exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117
exploits/cameras/dlink/dcs_930l_932l_auth_bypass
exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808
exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655
```

**Sessão de terminal — filtro `vendor=`:**

```text
exf > search vendor=hikvision
exploits/cameras/hikvision/firmware_crypto_key_extract
exploits/cameras/hikvision/info_disclosure_cve_2017_7921
exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808
exploits/cameras/hikvision/nvr_dvr_serial_privesc
exploits/cameras/hikvision/psh_challenge_predictor
exploits/cameras/hikvision/psh_command_injection
exploits/cameras/hikvision/psh_debug_rsa1024_bypass
exploits/cameras/hikvision/r0_intercom_3des_decrypt
exploits/cameras/hikvision/r0_intercom_developer_nfs
exploits/cameras/hikvision/r0_intercom_gpio_door_unlock
exploits/cameras/hikvision/r0_intercom_ssh_default_bypass
exploits/cameras/hikvision/r0_intercom_ssh_mitm
exploits/cameras/hikvision/r0_intercom_suid_privesc
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
scanners/cameras/hikvision/boot_permission_audit
...
creds/cameras/hikvision/ftp_default_creds
creds/cameras/hikvision/ssh_default_creds
creds/cameras/hikvision/telnet_default_creds
```

**Sessão de terminal — filtro `language=` (encoders):**

```text
exf > search type=encoders language=python
encoders/python/base64
encoders/python/hex
```

**Sessão de terminal — filtro `payload=`:**

```text
exf > search type=payloads payload=python
payloads/python/bind_tcp
payloads/python/bind_udp
payloads/python/reverse_tcp
payloads/python/reverse_udp
```

---

## Subcomandos `show` — listagem

O comando `show` lista módulos ou exibe dados específicos do módulo.

### `show all`

Lista todos os caminhos de módulos em todo o arsenal, de todas as categorias.

```text
exf > show all
exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781
exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986
...
creds/cameras/hikvision/ftp_default_creds
...
scanners/autopwn
...
payloads/armbe/reverse_tcp
...
encoders/php/base64
...
generic/cve/cve_lookup
generic/upnp/igd_exploit
```

---

### `show exploits`

Lista todos os caminhos de módulos de exploit.

```text
exf > show exploits
exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781
exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exploits/aps/mediatek/mt7622_heap_overflow_preauth
exploits/aps/mediatek/mt7622_heap_overflow_postauth
exploits/bmc/asus/asmb8_default_creds_ipmi
exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300
exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786
exploits/bms/abb/cylon_aspect_default_creds
exploits/cameras/acti/acm_5611_rce
...
```

---

### `show scanners`

Lista todos os caminhos de módulos de scanner.

```text
exf > show scanners
scanners/aruba/papi_service_scanner
scanners/autopwn
scanners/bmc/bmc_discover
scanners/bms/bms_discover
scanners/cameras/camera_scan
scanners/cameras/dahua/cctv_discover
scanners/cameras/herospeed_longsee_nvr_scan
scanners/cameras/hikvision/boot_permission_audit
scanners/cameras/hikvision/firmware_version_fingerprint
scanners/cameras/rtsp_discover
scanners/cameras/rtsp_scanner
scanners/embedded_os/embedded_os_fingerprint
scanners/embedded_os/mdns_iot_discovery
scanners/embedded_os/mqtt_broker_scan
scanners/firewalls/fortinet/fortigate_sslvpn_scan
scanners/ics/bacnet_scanner
scanners/ics/cip_scanner
scanners/ics/dnp3_scanner
scanners/ics/enip_scanner
scanners/ics/modbus_id_fuzzer
scanners/ics/modbus_scanner
scanners/ics/s7_comm_scanner
...
```

---

### `show creds`

Lista todos os caminhos de módulos de credenciais.

```text
exf > show creds
creds/bmc/asus_asmb
creds/bmc/dell_idrac
creds/bmc/supermicro
creds/cameras/acti/ftp_default_creds
creds/cameras/acti/ssh_default_creds
creds/cameras/acti/telnet_default_creds
creds/cameras/acti/webinterface_http_form_default_creds
creds/cameras/axis/ftp_default_creds
creds/cameras/axis/ssh_default_creds
creds/cameras/dahua/ftp_default_creds
creds/cameras/dahua/ssh_default_creds
creds/cameras/dahua/telnet_default_creds
creds/cameras/dahua/webinterface_http_auth_default_creds
creds/cameras/hikvision/ftp_default_creds
creds/cameras/hikvision/ssh_default_creds
creds/cameras/hikvision/telnet_default_creds
...
```

---

### `show info` (contexto de módulo)

Exibe metadados completos para o módulo atualmente carregado.

```text
exf > use exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
exf (Herospeed/Longsee NVR Unauthenticated Account Enumeration) > show info

[*] Name:         Herospeed/Longsee NVR Unauthenticated Account Enumeration
[*] Description:  HSLS-2026-001 — Returns salt, challenge, and sessionID without authentication.
                  Reveals all user accounts on the target NVR.
[*] Devices:      Herospeed NVR N-series (all MC6830/FH6830 platform, 2023-2026)
                  TVT Digital TD-3000H1/TD-3300 — V21.1.x / V22.1.x
                  GISE V5 series (XVR/NVR) — V21.1.20.x - V21.1.27.x
                  Longse LSN-9836/LSN-9436 — Web v6.0 series (2021-2023)
[*] Authors:      c3l3r1on (discovery)
                  André Henrique (@mrhenrike) — EmbedXPL-Forge port
[*] References:   https://github.com/c3l3r1on/nvr
```

---

### `show options` (contexto de módulo)

Exibe todas as opções não avançadas para o módulo carregado.

```text
exf > use creds/cameras/dahua/telnet_default_creds
exf (telnet_default_creds) > show options

Target options:
┌────────┬──────────────────┬──────────────────────────────────────────────────────────────┐
│ Name   │ Current settings │ Description                                                  │
├────────┼──────────────────┼──────────────────────────────────────────────────────────────┤
│ target │                  │ Target IPv4 address or file://path for multi-target           │
│ port   │ 23               │ Target Telnet port                                           │
└────────┴──────────────────┴──────────────────────────────────────────────────────────────┘

Module options:
┌──────────────────┬──────────────────┬──────────────────────────────────────────────────────┐
│ Name             │ Current settings │ Description                                          │
├──────────────────┼──────────────────┼──────────────────────────────────────────────────────┤
│ threads          │ 8                │ Number of parallel connection threads                │
│ defaults         │ True             │ Try vendor-specific default credential pairs         │
│ stop_on_success  │ True             │ Stop after first successful credential               │
│ verbosity        │ False            │ Show every attempt in verbose mode                   │
│ timeout          │ 10               │ Per-connection timeout in seconds                    │
└──────────────────┴──────────────────┴──────────────────────────────────────────────────────┘
```

---

### `show advanced` (contexto de módulo)

Exibe todas as opções incluindo as avançadas (ocultas por padrão).

```text
exf > use scanners/autopwn
exf (AutoPwn) > show advanced

Module options:
┌─────────────────────────┬──────────────────┬───────────────────────────────────────────┐
│ Name                    │ Current settings │ Description                               │
├─────────────────────────┼──────────────────┼───────────────────────────────────────────┤
│ vendor                  │ any              │ Vendor filter (default: any)              │
│ target_device_class     │ multi            │ Device class filter                       │
│ timing_template         │ balanced         │ T0..T5 or name                            │
│ check_exploits          │ True             │ Run exploit checks                        │
│ check_creds             │ True             │ Run credential checks                     │
│ http_use                │ True             │ Check HTTP[s] service                     │
│ http_port               │ 80               │ Target HTTP port                          │
│ ftp_use                 │ True             │ Check FTP[s] service                      │
│ ssh_use                 │ True             │ Check SSH service                         │
│ telnet_use              │ True             │ Check Telnet service                      │
│ snmp_use                │ True             │ Check SNMP service                        │
│ snmp_community          │ public           │ SNMP community string                     │
│ threads                 │ 8                │ Thread count (1–300)                      │
│ ml_advisor              │ False            │ Enable ML/heuristic attack advisor        │
│ ml_auto_timing          │ False            │ Auto-set timing from ML suggestion        │
│ ml_use_gpu              │ False            │ Use GPU for ML scoring                    │
└─────────────────────────┴──────────────────┴───────────────────────────────────────────┘
```

---

### `show devices` (contexto de módulo)

Lista modelos exatos de dispositivos, versões de firmware e marcas alvo do módulo carregado.

```text
exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf (Herospeed/Longsee NVR Scanner) > show devices

Target devices:
   0 - Herospeed NVR N-series (9CH-64CH, firmware v2.0.4-v2.1.x, SoC MC6830)
   1 - TVT Digital TD-3000H1/TD-3300 — V21.1.x / V22.1.x
   2 - GISE V5 series (XVR/NVR) — V21.1.20.x - V21.1.27.x
   3 - Longse LSN-9836/LSN-9436 — Web v6.0 series (2021-2023)
   4 - Zintronic P5/NVR — N9000 platform (BitVision)
   5 - Turing AI SMART series — N9000 platform
   6 - Speco ZIP series — OEM TVT
   7 - Alibi Security Vigilant series — OEM TVT
   8 - IRBIS MBD6804T-EL — V4.02.R11 (legacy)
```

---

### `show wordlists` (contexto de módulo)

Lista wordlists embutidas disponíveis no diretório `embedxpl/resources/wordlists/`.

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) > show wordlists

┌────────────────────────┬──────────────────────────────────────────────────────────────────────┐
│ Wordlist               │ Path                                                                 │
├────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ dlink_defaults.txt     │ file:///usr/local/lib/python3.11/site-packages/embedxpl/resources/.. │
│ common_passwords.txt   │ file:///usr/local/lib/python3.11/site-packages/embedxpl/resources/.. │
│ router_defaults.txt    │ file:///usr/local/lib/python3.11/site-packages/embedxpl/resources/.. │
└────────────────────────┴──────────────────────────────────────────────────────────────────────┘
```

---

### `show encoders` (contexto de módulo de payload)

Lista módulos de encoder compatíveis com o payload carregado.

```text
exf > use payloads/python/reverse_tcp
exf (python/reverse_tcp) > show encoders

┌────────────────────┬──────────────────────────────────┬────────────────────────────────────────┐
│ Encoder            │ Name                             │ Description                            │
├────────────────────┼──────────────────────────────────┼────────────────────────────────────────┤
│ encoders/python/base64 │ Python Base64 Encoder       │ Wrap payload in Python base64.b64decode│
│ encoders/python/hex    │ Python Hex Encoder          │ Wrap payload in Python hex bytes decode│
└────────────────────┴──────────────────────────────────┴────────────────────────────────────────┘
```

---

## Tabela de referência rápida de busca

| Objetivo | Comando |
|----------|---------|
| Encontrar todos os módulos Hikvision | `search hikvision` |
| Encontrar todos os exploits de câmera | `search type=exploits device=cameras` |
| Encontrar módulos para CVE-2021-36260 | `search CVE-2021-36260` |
| Encontrar módulos para Fortinet | `search vendor=fortinet` |
| Encontrar todos os módulos de credenciais | `show creds` |
| Encontrar todos os módulos de scanner | `show scanners` |
| Encontrar payloads Python | `search type=payloads payload=python` |
| Encontrar encoders PHP | `search type=encoders language=php` |
| Encontrar todas as credenciais de câmera D-Link | `search type=creds device=cameras vendor=dlink` |
| Encontrar todos os payloads MIPS | `search mips` |
| Encontrar todos os módulos de auth bypass | `search auth_bypass` |
| Encontrar todos os módulos para Dahua | `search dahua` |
| Encontrar módulos com "rce" e "fortinet" | `search fortinet rce` |
| Listar arsenal completo | `show all` |

---

[Hub da Wiki](../README.md)
