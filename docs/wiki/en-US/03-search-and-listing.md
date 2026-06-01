# Search and Listing

**Language:** English (en-US) | **pt-BR:** [../pt-BR/03-busca-e-listagem.md](../pt-BR/03-busca-e-listagem.md)

---

## `search` — find modules

The `search` command performs case-insensitive substring matching across all module paths. It supports keyword search and structured filters. Results are printed with matched words highlighted in red/bold.

### Syntax

```
search [keyword] [filter=value ...]
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `keyword` | string | No* | `""` | Any text | Substring matched against the full module path |
| `type=` | filter | No | — | `exploits`, `creds`, `scanners`, `payloads`, `encoders`, `generic` | Restrict to a module category |
| `device=` | filter | No | — | Subdirectory of `exploits/` (e.g., `cameras`, `routers`, `firewalls`) | Restrict to a device class in exploit modules |
| `vendor=` | filter | No | — | Any path segment (e.g., `hikvision`, `dlink`, `cisco`) | Restrict to a vendor subdirectory |
| `language=` | filter | No | — | Subdirectory of `encoders/` (e.g., `python`, `php`, `perl`) | Restrict to encoder language |
| `payload=` | filter | No | — | Subdirectory of `payloads/` (e.g., `python`, `x86`, `armle`) | Restrict to a payload architecture |

\* At least one keyword or filter must be provided.

**Error when called with no arguments:**

```text
exf > search
[-] Please specify at least search keyword. e.g. 'search cisco'
[-] You can specify options. e.g. 'search type=exploits device=routers vendor=linksys WRT100 rce'
```

---

### Keyword-only search

Search by vendor name, CVE identifier, device family, protocol, or any substring of a module path:

**Terminal session — search by vendor:**

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

**Terminal session — search by CVE:**

```text
exf > search CVE-2021-36260
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exploits/cameras/dahua/cctv_rce_cve_2021_36260
```

**Terminal session — search by device family:**

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

**Terminal session — search by keyword (rce):**

```text
exf > search rce
exploits/cameras/acti/acm_5611_rce
exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941
exploits/cameras/axis/app_install_rce
exploits/cameras/axis/srv_parhand_rce_cve_2018_10660
exploits/cameras/beward/n100_rce
exploits/cameras/dahua/cctv_rce_cve_2021_36260
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
...
```

**Terminal session — search across multiple keywords (AND logic):**

```text
exf > search hikvision rce
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
```

All space-separated keywords must appear in the module path (AND logic).

---

### Filtered search

Combine keyword with one or more `key=value` filters:

**Terminal session — `type=` filter:**

```text
exf > search type=exploits cisco
exploits/cameras/cisco/video_surv_path_traversal
exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171
```

**Terminal session — `device=` filter:**

```text
exf > search type=exploits device=cameras auth_bypass
exploits/cameras/dahua/auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044
exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117
exploits/cameras/dlink/dcs_930l_932l_auth_bypass
exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808
exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655
```

**Terminal session — `vendor=` filter:**

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
scanners/cameras/hikvision/eglibc_version_check
scanners/cameras/hikvision/firmware_version_fingerprint
scanners/cameras/hikvision/nvr_binary_hardening_audit
scanners/cameras/hikvision/r0_intercom_firmware_audit
scanners/cameras/hikvision/r0_intercom_network_detect
creds/cameras/hikvision/ftp_default_creds
creds/cameras/hikvision/ssh_default_creds
creds/cameras/hikvision/telnet_default_creds
```

**Terminal session — `vendor=` with CVE keyword:**

```text
exf > search vendor=dahua CVE-2021
exploits/cameras/dahua/auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_rce_cve_2021_36260
exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078
```

**Terminal session — `cve=` style (keyword approach):**

```text
exf > search CVE-2022-40684
exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
```

**Terminal session — `language=` filter (encoders):**

```text
exf > search type=encoders language=python
encoders/python/base64
encoders/python/hex
```

**Terminal session — `payload=` filter:**

```text
exf > search type=payloads payload=python
payloads/python/bind_tcp
payloads/python/bind_udp
payloads/python/reverse_tcp
payloads/python/reverse_udp
```

**Error — unknown device type:**

```text
exf > search type=exploits device=unknown_device
[-] Unknown exploit type.
```

**Error — unknown encoder language:**

```text
exf > search type=encoders language=ruby
[-] Unknown encoder language.
```

---

## `show` subcommands — listing

The `show` command lists modules or displays module-specific data. See the full reference below.

### `show all`

Lists every module path in the entire arsenal, from all categories.

```
show all
```

**Terminal session (abbreviated):**

```text
exf > show all
exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781
exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986
exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388
exploits/aps/mediatek/mt7622_heap_overflow_postauth
exploits/aps/mediatek/mt7622_heap_overflow_preauth
...
creds/cameras/hikvision/ftp_default_creds
creds/cameras/hikvision/ssh_default_creds
...
scanners/autopwn
scanners/cameras/camera_scan
...
payloads/armbe/reverse_tcp
payloads/armle/bind_tcp
...
encoders/php/base64
...
generic/cve/cve_lookup
generic/upnp/igd_exploit
```

---

### `show exploits`

Lists all exploit module paths.

```
show exploits
```

**Terminal session (abbreviated):**

```text
exf > show exploits
exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781
exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exploits/aps/mediatek/mt7622_heap_overflow_postauth
exploits/aps/mediatek/mt7622_heap_overflow_preauth
exploits/bmc/asus/asmb8_default_creds_ipmi
exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300
exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786
exploits/bms/abb/cylon_aspect_default_creds
exploits/cameras/acti/acm_5611_rce
exploits/cameras/amcrest/amcrest_camera_unauth_info_disclosure_cve_2019_3950
exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941
exploits/cameras/avigilon/videoiq_camera_path_traversal
exploits/cameras/axis/app_install_rce
exploits/cameras/axis/srv_parhand_rce_cve_2018_10660
exploits/cameras/beward/n100_rce
exploits/cameras/brickcom/corp_network_cameras_conf_disclosure
exploits/cameras/brickcom/users_cgi_creds_disclosure
exploits/cameras/cisco/video_surv_path_traversal
exploits/cameras/dahua/auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_37777_credential_extraction
exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044
...
```

---

### `show scanners`

Lists all scanner module paths.

```
show scanners
```

**Terminal session (abbreviated):**

```text
exf > show scanners
scanners/aruba/papi_service_scanner
scanners/autopwn
scanners/bmc/bmc_discover
scanners/bms/bms_discover
scanners/cameras/camera_scan
scanners/cameras/dahua/cctv_discover
scanners/cameras/dahua/firmware_version_fingerprint
scanners/cameras/dahua/p2p_pppp_scan
scanners/cameras/herospeed_longsee_nvr_scan
scanners/cameras/hikvision/boot_permission_audit
scanners/cameras/hikvision/eglibc_version_check
scanners/cameras/hikvision/firmware_version_fingerprint
scanners/cameras/hikvision/nvr_binary_hardening_audit
scanners/cameras/hikvision/r0_intercom_firmware_audit
scanners/cameras/hikvision/r0_intercom_network_detect
scanners/cameras/intelbras_boa_detect
scanners/cameras/intelbras_cctv_discover
scanners/cameras/intelbras_onvif_scan
scanners/cameras/intelbras_p2p_uid_scan
scanners/cameras/intelbras_pvip_discover
scanners/cameras/rtsp_discover
scanners/cameras/rtsp_scanner
scanners/cameras/tvip_discover
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
scanners/ics/profinet_dcp_scanner
scanners/ics/rockwell_discover
scanners/ics/s7_comm_scanner
scanners/ics/s7comm_plus_scanner
scanners/ics/vxworks_scanner
...
```

---

### `show creds`

Lists all credential module paths.

```
show creds
```

**Terminal session (abbreviated):**

```text
exf > show creds
creds/bmc/asus_asmb
creds/bmc/dell_idrac
creds/bmc/supermicro
creds/cameras/acti/ftp_default_creds
creds/cameras/acti/ssh_default_creds
creds/cameras/acti/telnet_default_creds
creds/cameras/acti/webinterface_http_form_default_creds
creds/cameras/american_dynamics/ftp_default_creds
creds/cameras/arecont/ftp_default_creds
creds/cameras/arecont/ssh_default_creds
creds/cameras/arecont/telnet_default_creds
creds/cameras/arecont/webinterface_http_auth_default_creds
creds/cameras/axis/ftp_default_creds
creds/cameras/axis/ssh_default_creds
creds/cameras/axis/telnet_default_creds
creds/cameras/axis/webinterface_http_auth_default_creds
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

### `show info` (module context)

Displays full metadata for the currently loaded module.

```
show info
```

**Terminal session:**

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

### `show options` (module context)

Displays all non-advanced options for the loaded module.

```
show options
```

**Terminal session — credential module:**

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

### `show advanced` (module context)

Displays all options including advanced (hidden by default) ones.

```
show advanced
```

**Terminal session — AutoPwn advanced options:**

```text
exf > use scanners/autopwn
exf (AutoPwn) > show advanced

Target options:
┌────────┬──────────────────┬───────────────────────────────────────────┐
│ Name   │ Current settings │ Description                               │
├────────┼──────────────────┼───────────────────────────────────────────┤
│ target │                  │ Target IPv4 or IPv6 address               │
└────────┴──────────────────┴───────────────────────────────────────────┘

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
│ http_ssl                │ False            │ Use HTTPS                                 │
│ ftp_use                 │ True             │ Check FTP[s] service                      │
│ ftp_port                │ 21               │ Target FTP port                           │
│ ftp_ssl                 │ False            │ Use FTPS                                  │
│ ssh_use                 │ True             │ Check SSH service                         │
│ ssh_port                │ 22               │ Target SSH port                           │
│ telnet_use              │ True             │ Check Telnet service                      │
│ telnet_port             │ 23               │ Target Telnet port                        │
│ snmp_use                │ True             │ Check SNMP service                        │
│ snmp_community          │ public           │ SNMP community string                     │
│ snmp_version            │ 1                │ SNMP version (0=v1, 1=v2c)               │
│ snmp_port               │ 161              │ SNMP port                                 │
│ threads                 │ 8                │ Thread count (1–300)                      │
│ module_timeout_s        │ 20               │ Per-module timeout in seconds             │
│ verify_positive_twice   │ True             │ Re-verify positives to reduce false pos.  │
│ show_timing_help        │ True             │ Print timing table before scan            │
│ ml_advisor              │ False            │ Enable ML/heuristic attack advisor        │
│ ml_auto_timing          │ False            │ Auto-set timing from ML suggestion        │
│ ml_use_gpu              │ False            │ Use GPU for ML scoring                    │
└─────────────────────────┴──────────────────┴───────────────────────────────────────────┘
```

---

### `show devices` (module context)

Lists exact device models, firmware versions, and brands targeted by the loaded module.

```
show devices
```

**Terminal session — Herospeed NVR scanner:**

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

**Terminal session — global `show devices` (no module loaded):**

```text
exf > show devices

┌──────────────────────┬───────────────────────────────────────────────┬───────────┐
│ Device Type          │ Description                                   │ Coverage  │
├──────────────────────┼───────────────────────────────────────────────┼───────────┤
│ Routers              │ SOHO routers, enterprise gateways, CPE        │ Primary   │
│ Switches L2/L3       │ Managed and unmanaged network switches        │ Expanding │
│ TAPs                 │ Network TAP devices                           │ Planned   │
│ SOHO Edge            │ Small office / home office edge appliances    │ Expanding │
└──────────────────────┴───────────────────────────────────────────────┴───────────┘
  Vendors covered: asus, axis, bmc, cameras, cisco, dahua, dlink, fortinet, herospeed, hikvision, ...
```

---

### `show wordlists` (module context)

Lists bundled wordlists available in the `embedxpl/resources/wordlists/` directory.

```
show wordlists
```

**Terminal session:**

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

### `show encoders` (payload module context)

Lists encoder modules compatible with the loaded payload.

```
show encoders
```

**Terminal session:**

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

**Error case — non-payload module:**

```text
exf (Hikvision Unauthenticated RCE) > show encoders
[-] No encoders available
```

---

## Quick search reference table

| Goal | Command |
|------|---------|
| Find all Hikvision modules | `search hikvision` |
| Find all camera exploits | `search type=exploits device=cameras` |
| Find modules for CVE-2021-36260 | `search CVE-2021-36260` |
| Find modules for Fortinet | `search vendor=fortinet` |
| Find all credential modules | `show creds` |
| Find all scanner modules | `show scanners` |
| Find Python payloads | `search type=payloads payload=python` |
| Find PHP encoders | `search type=encoders language=php` |
| Find all D-Link camera creds | `search type=creds device=cameras vendor=dlink` |
| Find all MIPS payloads | `search mips` |
| Find all auth bypass modules | `search auth_bypass` |
| Find all modules for Dahua | `search dahua` |
| Find modules with "rce" and "fortinet" | `search fortinet rce` |
| List full arsenal | `show all` |


[Wiki hub](../README.md)
