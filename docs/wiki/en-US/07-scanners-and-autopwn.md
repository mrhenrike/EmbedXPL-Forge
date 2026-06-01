# Scanners and AutoPwn

**Language:** English (en-US) | **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

---

## AutoPwn

**AutoPwn** orchestrates fingerprinting and module selection for a single target. It runs all applicable exploit modules and credential checks concurrently, reports confirmed vulnerabilities, and optionally uses an ML advisor to prioritize modules and suggest timing.

### Standard workflow

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.1
exf (AutoPwn) > set timing_template T4
exf (AutoPwn) > run
```

---

### `show options` — standard options

```text
exf (AutoPwn) > show options

Target options:
┌───────────────────┬──────────────────┬──────────────────────────────────────────────────────────────────────────┐
│ Name              │ Current settings │ Description                                                              │
├───────────────────┼──────────────────┼──────────────────────────────────────────────────────────────────────────┤
│ target            │                  │ Target IPv4 or IPv6 address                                              │
│ vendor            │ any              │ Vendor concerned (default: any)                                          │
│ timing_template   │ balanced         │ Timing template: T0..T5 or paranoid/sneaky/polite/balanced/aggressive/   │
│                   │                  │ insane                                                                   │
│ http_use          │ True             │ Check HTTP[s] service: true/false                                        │
│ ftp_use           │ True             │ Check FTP[s] service: true/false                                         │
│ ssh_use           │ True             │ Check SSH service: true/false                                            │
│ sftp_use          │ True             │ Check SFTP service: true/false                                           │
│ telnet_use        │ True             │ Check Telnet service: true/false                                         │
│ snmp_use          │ True             │ Check SNMP service: true/false                                           │
│ threads           │ 8                │ Number of threads (min: 1, max: 300)                                     │
└───────────────────┴──────────────────┴──────────────────────────────────────────────────────────────────────────┘
```

### `show advanced` — advanced options

```text
exf (AutoPwn) > show advanced

Advanced options:
┌──────────────────────┬──────────────────┬──────────────────────────────────────────────────────────────────────┐
│ Name                 │ Current settings │ Description                                                          │
├──────────────────────┼──────────────────┼──────────────────────────────────────────────────────────────────────┤
│ target_device_class  │ multi            │ Target class filter: multi|router|switch|tap|fw|ngfw|isp_cpe          │
│ check_exploits       │ True             │ Check exploits against target: true/false                             │
│ check_creds          │ True             │ Check factory credentials against target: true/false                  │
│ http_port            │ 80               │ Target Web Interface Port                                            │
│ http_ssl             │ False            │ HTTPS enabled: true/false                                            │
│ ftp_port             │ 21               │ Target FTP port (default: 21)                                        │
│ ftp_ssl              │ False            │ FTPS enabled: true/false                                             │
│ ssh_port             │ 22               │ Target SSH port (default: 22)                                        │
│ sftp_port            │ 22               │ Target SFTP port (default: 22)                                       │
│ telnet_port          │ 23               │ Target Telnet port (default: 23)                                     │
│ snmp_community       │ public           │ Target SNMP community name (default: public)                         │
│ snmp_version         │ 1                │ SNMP version for v1/v2 modules (0:v1, 1:v2c)                         │
│ snmp_port            │ 161              │ Target SNMP port (default: 161)                                      │
│ tcp_use              │ True             │ Check custom TCP services                                            │
│ udp_use              │ True             │ Check custom UDP services                                            │
│ verify_positive_twice│ True             │ Re-check positive exploit result to reduce false positives           │
│ show_timing_help     │ True             │ Show timing template help before scan: true/false                     │
│ module_timeout_s     │ 20               │ Per-module timeout in seconds for check/check_default (0 disables)   │
│ ml_advisor           │ False            │ Enable ML/heuristic advisor: prioritizes modules, suggests timing     │
│ ml_auto_timing       │ False            │ When ml_advisor true: overwrite timing_template with advisor          │
│ ml_use_gpu           │ False            │ When ml_advisor true: run timing logits on PyTorch CUDA if installed  │
└──────────────────────┴──────────────────┴──────────────────────────────────────────────────────────────────────┘
```

---

### Typed option table

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 / IPv6 | Single target host to scan |
| `vendor` | `OptString` | No | `any` | vendor name or `any` | Restrict modules to a specific vendor subfolder |
| `timing_template` | `OptString` | No | `balanced` | `T0`–`T5`, `paranoid`, `sneaky`, `polite`, `balanced`, `aggressive`, `insane` | Nmap-style timing profile |
| `target_device_class` | `OptString` (adv) | No | `multi` | `multi`, `router`, `switch`, `tap`, `fw`, `ngfw`, `isp_cpe` | Scope filter — skips out-of-class modules |
| `check_exploits` | `OptBool` (adv) | No | `True` | `true/false` | Run exploit modules |
| `check_creds` | `OptBool` (adv) | No | `True` | `true/false` | Run credential modules |
| `http_use` | `OptBool` | No | `True` | `true/false` | Include HTTP modules |
| `http_port` | `OptPort` (adv) | No | `80` | 1-65535 | Override HTTP port |
| `http_ssl` | `OptBool` (adv) | No | `False` | `true/false` | Use HTTPS instead of HTTP |
| `ftp_use` | `OptBool` | No | `True` | `true/false` | Include FTP modules |
| `ftp_port` | `OptPort` (adv) | No | `21` | 1-65535 | Override FTP port |
| `ftp_ssl` | `OptBool` (adv) | No | `False` | `true/false` | Use FTPS |
| `ssh_use` | `OptBool` | No | `True` | `true/false` | Include SSH modules |
| `ssh_port` | `OptPort` (adv) | No | `22` | 1-65535 | Override SSH port |
| `sftp_use` | `OptBool` | No | `True` | `true/false` | Include SFTP modules |
| `sftp_port` | `OptPort` (adv) | No | `22` | 1-65535 | Override SFTP port |
| `telnet_use` | `OptBool` | No | `True` | `true/false` | Include Telnet modules |
| `telnet_port` | `OptPort` (adv) | No | `23` | 1-65535 | Override Telnet port |
| `snmp_use` | `OptBool` | No | `True` | `true/false` | Include SNMP modules |
| `snmp_community` | `OptString` (adv) | No | `public` | string | SNMP community string |
| `snmp_version` | `OptInteger` (adv) | No | `1` | `0` (v1), `1` (v2c) | SNMP version |
| `snmp_port` | `OptPort` (adv) | No | `161` | 1-65535 | Override SNMP port |
| `tcp_use` | `OptBool` (adv) | No | `True` | `true/false` | Include custom TCP modules |
| `udp_use` | `OptBool` (adv) | No | `True` | `true/false` | Include custom UDP modules |
| `threads` | `OptInteger` | No | `8` | 1–300 | Concurrent threads (overridden by timing profile if at default 8) |
| `verify_positive_twice` | `OptBool` (adv) | No | `True` | `true/false` | Re-run `check()` on positives to reduce false positives |
| `show_timing_help` | `OptBool` (adv) | No | `True` | `true/false` | Print timing profile table before scan |
| `module_timeout_s` | `OptInteger` (adv) | No | `20` | 0–∞ | Per-module execution timeout in seconds (0 = disable) |
| `ml_advisor` | `OptBool` (adv) | No | `False` | `true/false` | Enable ML heuristic module prioritization |
| `ml_auto_timing` | `OptBool` (adv) | No | `False` | `true/false` | Let ML advisor overwrite timing template |
| `ml_use_gpu` | `OptBool` (adv) | No | `False` | `true/false` | Run ML scoring on CUDA GPU (requires PyTorch + CUDA) |

---

### Timing templates T0–T5

AutoPwn uses Nmap-style timing profiles. Each profile controls thread count, confirmation passes, retry behavior for inconclusive results, and inter-probe delay.

| Template | Alias | Threads | Confirm passes | Inconclusive retries | Delay (s) | Use case |
|----------|-------|---------|----------------|----------------------|-----------|----------|
| T0 | paranoid | 1 | 3 | 2 | 1.0 | Slow/stealthy — evade IDS, fragile targets |
| T1 | sneaky | 2 | 2 | 2 | 0.5 | Low-profile — minimal network noise |
| T2 | polite | 4 | 2 | 1 | 0.2 | Careful — reduced load on target |
| T3 | balanced | 8 | 2 | 1 | 0.0 | Default — good accuracy vs. speed tradeoff |
| T4 | aggressive | 16 | 1 | 0 | 0.0 | Fast — lab/authorized pentest environments |
| T5 | insane | 32 | 1 | 0 | 0.0 | Maximum speed — may miss flaky results |

**Terminal session — T0 (paranoid, stealthy single thread):**

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (AutoPwn) > set timing_template T0
[+] timing_template => T0
exf (AutoPwn) > run
[*] AutoPwn timing profiles (Nmap-style -T0..-T5):
┌──────────┬──────────┬─────────┬─────────┬──────────────────────┬──────────┐
│ Template │ Alias    │ Threads │ Confirm │ Retry(Inconclusive)  │ Delay(s) │
├──────────┼──────────┼─────────┼─────────┼──────────────────────┼──────────┤
│ T0       │ paranoid │ 1       │ 3       │ 2                    │ 1.0      │
│ T1       │ sneaky   │ 2       │ 2       │ 2                    │ 0.5      │
│ T2       │ polite   │ 4       │ 2       │ 1                    │ 0.2      │
│ T3       │ balanced │ 8       │ 2       │ 1                    │ 0.0      │
│ T4       │ aggressive│ 16     │ 1       │ 0                    │ 0.0      │
│ T5       │ insane   │ 32      │ 1       │ 0                    │ 0.0      │
└──────────┴──────────┴─────────┴─────────┴──────────────────────┴──────────┘
[*] Default profile: balanced (T3). Use: set timing_template T4 or set timing_template aggressive
[*] AutoPwn timing template T0 (paranoid) active: threads=1, confirm_passes=3, inconclusive_retries=2, delay=1.0s

[*] 192.168.1.1 Starting vulnerability check...
[!] 192.168.1.1:80 http exploits/routers/zte/zxhn_h168n_rce_auth_bypass Could not be verified
[+] 192.168.1.1:23 telnet exploits/routers/zte/telnet_cmd_injection is vulnerable
[+] 192.168.1.1:23 telnet exploits/routers/zte/telnet_cmd_injection is vulnerable   (confirm pass 2/3)
[+] 192.168.1.1:23 telnet exploits/routers/zte/telnet_cmd_injection is vulnerable   (confirm pass 3/3)

[*] 192.168.1.1 Starting default credentials check...
[+] 192.168.1.1:23 telnet creds/routers/zte/telnet_default_creds is vulnerable

[*] 192.168.1.1 Could not verify exploitability:
 - 192.168.1.1:80 http exploits/routers/zte/zxhn_h168n_rce_auth_bypass

[+] 192.168.1.1 Device is vulnerable:
┌─────────────┬──────┬─────────┬───────────────────────────────────────────────┐
│ Target      │ Port │ Service │ Exploit                                        │
├─────────────┼──────┼─────────┼───────────────────────────────────────────────┤
│ 192.168.1.1 │ 23   │ telnet  │ exploits/routers/zte/telnet_cmd_injection      │
└─────────────┴──────┴─────────┴───────────────────────────────────────────────┘

[+] 192.168.1.1 Found default credentials:
┌─────────────┬──────┬─────────┬──────────┬──────────┐
│ Target      │ Port │ Service │ Username │ Password │
├─────────────┼──────┼─────────┼──────────┼──────────┤
│ 192.168.1.1 │ 23   │ telnet  │ admin    │ admin    │
└─────────────┴──────┴─────────┴──────────┴──────────┘
```

**Terminal session — T3 (balanced, default) with full discovery workflow:**

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (AutoPwn) > set vendor huawei
[+] vendor => huawei
exf (AutoPwn) > run
[*] AutoPwn timing template T3 (balanced) active: threads=8, confirm_passes=2, inconclusive_retries=1, delay=0.0s
[*] Device class filter active: multi (all modules in scope)

[*] 10.0.0.1 Starting vulnerability check...
[-] 10.0.0.1:80 http exploits/routers/huawei/eg8145x6_csrf_static_token is not vulnerable
[+] 10.0.0.1:80 http exploits/routers/huawei/eg8145x6_info_disclosure is vulnerable
[+] 10.0.0.1:80 http exploits/routers/huawei/eg8145x6_info_disclosure is vulnerable   (confirm pass 2/2)

[*] 10.0.0.1 Starting default credentials check...
[+] 10.0.0.1:80 http creds/routers/huawei/webinterface_http_auth_default_creds is vulnerable

[+] 10.0.0.1 Device is vulnerable:
┌──────────┬──────┬─────────┬──────────────────────────────────────────────────────┐
│ Target   │ Port │ Service │ Exploit                                               │
├──────────┼──────┼─────────┼──────────────────────────────────────────────────────┤
│ 10.0.0.1 │ 80   │ http    │ exploits/routers/huawei/eg8145x6_info_disclosure      │
└──────────┴──────┴─────────┴──────────────────────────────────────────────────────┘

[+] 10.0.0.1 Found default credentials:
┌──────────┬──────┬─────────┬──────────┬──────────┐
│ Target   │ Port │ Service │ Username │ Password │
├──────────┼──────┼─────────┼──────────┼──────────┤
│ 10.0.0.1 │ 80   │ http    │ admin    │ HuaWei12 │
└──────────┴──────┴─────────┴──────────┴──────────┘
```

**Terminal session — T4 (aggressive) with NGFW class filter:**

```text
exf (AutoPwn) > set target 10.0.0.5
[+] target => 10.0.0.5
exf (AutoPwn) > set timing_template aggressive
[+] timing_template => aggressive
exf (AutoPwn) > set target_device_class ngfw
[+] target_device_class => ngfw
exf (AutoPwn) > run
[*] AutoPwn timing template T4 (aggressive) active: threads=16, confirm_passes=1, inconclusive_retries=0, delay=0.0s
[*] Device class filter active: ngfw (modules outside module_target_scope.json rules are skipped)

[*] 10.0.0.5 Starting vulnerability check...
[+] 10.0.0.5:443 https exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 is vulnerable
[-] 10.0.0.5:443 https exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379 is not vulnerable
[!] 10.0.0.5:443 https exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762 Could not be verified

[*] 10.0.0.5 Starting default credentials check...
[-] 10.0.0.5:443 https creds/firewalls/fortinet/webinterface_http_auth_default_creds is not vulnerable

[+] 10.0.0.5 Device is vulnerable:
┌──────────┬──────┬───────┬──────────────────────────────────────────────────────────────────────┐
│ Target   │ Port │ Svc   │ Exploit                                                               │
├──────────┼──────┼───────┼──────────────────────────────────────────────────────────────────────┤
│ 10.0.0.5 │ 443  │ https │ exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684        │
└──────────┴──────┴───────┴──────────────────────────────────────────────────────────────────────┘
[*] Skipped 12 module(s) not permitted for target_device_class=ngfw
```

**Terminal session — T5 (insane) with ML advisor:**

```text
exf (AutoPwn) > set target 192.168.50.1
[+] target => 192.168.50.1
exf (AutoPwn) > set timing_template T5
[+] timing_template => T5
exf (AutoPwn) > set ml_advisor true
[+] ml_advisor => True
exf (AutoPwn) > set ml_auto_timing true
[+] ml_auto_timing => True
exf (AutoPwn) > run
[*] AutoPwn timing template T5 (insane) active: threads=32, confirm_passes=1, inconclusive_retries=0, delay=0.0s
[*] ML advisor enabled (CVSS + CVE recency + attack type scoring).
[*] ML advisor suggests timing: T4 (probabilities: T4=54.2%, T3=28.1%, T5=17.7%)
[*] ml_auto_timing: overwriting timing_template from T5 to T4
[*] AutoPwn timing template T4 (aggressive) active: threads=16, confirm_passes=1, inconclusive_retries=0, delay=0.0s

[*] 192.168.50.1 Starting vulnerability check...
[*] ML advisor reordered 87 exploit modules (higher expected yield first).
[+] 192.168.50.1:8291 tcp exploits/firewalls/mikrotik/mikrotik_winbox_cred_bypass_cve_2018_14847 is vulnerable
[-] 192.168.50.1:443 https exploits/firewalls/mikrotik/mikrotik_routeros_rce_cve_2022_45315 is not vulnerable

[+] 192.168.50.1 Device is vulnerable:
┌─────────────┬──────┬────────┬──────────────────────────────────────────────────────────────────────┐
│ Target      │ Port │ Svc    │ Exploit                                                               │
├─────────────┼──────┼────────┼──────────────────────────────────────────────────────────────────────┤
│ 192.168.50.1│ 8291 │ tcp    │ exploits/firewalls/mikrotik/mikrotik_winbox_cred_bypass_cve_2018_14847│
└─────────────┴──────┴────────┴──────────────────────────────────────────────────────────────────────┘
```

**Terminal session — T2 (polite) targeting firewall class only:**

```text
exf (AutoPwn) > set target 10.10.10.1
[+] target => 10.10.10.1
exf (AutoPwn) > set timing_template polite
[+] timing_template => polite
exf (AutoPwn) > set target_device_class fw
[+] target_device_class => fw
exf (AutoPwn) > set check_creds false
[+] check_creds => False
exf (AutoPwn) > run
[*] AutoPwn timing template T2 (polite) active: threads=4, confirm_passes=2, inconclusive_retries=1, delay=0.2s
[*] Device class filter active: fw

[*] 10.10.10.1 Starting vulnerability check...
[+] 10.10.10.1:443 https exploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919 is vulnerable
[+] 10.10.10.1:443 https exploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919 is vulnerable   (confirm 2/2)

[+] 10.10.10.1 Device is vulnerable:
┌────────────┬──────┬───────┬───────────────────────────────────────────────────────────────────────┐
│ Target     │ Port │ Svc   │ Exploit                                                                │
├────────────┼──────┼───────┼───────────────────────────────────────────────────────────────────────┤
│ 10.10.10.1 │ 443  │ https │ exploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919  │
└────────────┴──────┴───────┴───────────────────────────────────────────────────────────────────────┘
[*] Skipped 247 module(s) not permitted for target_device_class=fw
```

**Error cases — AutoPwn:**

```text
[!] ALERT: 250 threads configured. This may consume high CPU/RAM and impact scan host stability.
```

```text
[!] Invalid thread count 0. Minimum is 1. Applying minimum.
```

```text
[!] Unknown timing template 'turbo'. Falling back to balanced (T3).
```

```text
[-] 192.168.1.1 During this AutoPwn run, no exploitable weakness was confirmed by the current EmbedXPL-Forge
    module base. This does not mean the target is secure, does not exclude unknown vectors/zero-days,
    and does not replace broader assessment methods.
[-] 192.168.1.1 During this AutoPwn run, no valid default credential was confirmed with the current
    credential datasets and checks.
```

---

## Discover integration

AutoPwn integrates with the `discover` command for pre-scan OUI-based vendor fingerprinting. Run `discover` first to identify vendors and get module suggestions, then use AutoPwn with `vendor` set for focused scanning.

```text
exf > discover 192.168.1.0/24
[*] ARP sweep on 192.168.1.0/24...
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY COMMUNICATION (Mercusys/TP-Link)
[+] 192.168.1.1   — TP-Link (Mercusys)
    Suggested: exploits/routers/tplink/*, creds/routers/tplink/*
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[+] 192.168.1.2   — ZTE
    Suggested: exploits/routers/zte/zxhn_h168n_rce_auth_bypass
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[+] 192.168.1.3   — Huawei
    Suggested: exploits/routers/huawei/*, creds/routers/huawei/*
[*] OUI lookup: 2c:6f:51 -> HIKVISION DIGITAL TECHNOLOGY CO.,LTD
[+] 192.168.1.60  — Hikvision (camera)
    Suggested: exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (AutoPwn) > set vendor hikvision
[+] vendor => hikvision
exf (AutoPwn) > set timing_template T4
[+] timing_template => T4
exf (AutoPwn) > run
[*] AutoPwn timing template T4 (aggressive) active: threads=16, confirm_passes=1, inconclusive_retries=0, delay=0.0s
[*] 192.168.1.60 Starting vulnerability check...
[+] 192.168.1.60:80 http exploits/cameras/hikvision/info_disclosure_cve_2017_7921 is vulnerable
[+] 192.168.1.60:80 http exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 is vulnerable
[+] 192.168.1.60 Device is vulnerable (2 modules confirmed)
```

---

## Device-oriented scanners

| Module | Path | Role |
|--------|------|------|
| `autopwn` | `scanners/autopwn` | Full vulnerability + credentials scan for a single target |
| `router_scan` | `scanners/router_scan` | Router-focused discovery with chaining entry point |
| `hootoo_scan` | `scanners/hootoo_scan` | Hootoo-oriented scanner workflow |
| `soho_discover` | `scanners/soho_discover` | Universal SOHO HTTP discovery (12+ vendor signatures) |
| `bmc_discover` | `scanners/bmc/bmc_discover` | BMC/IPMI/iDRAC service discovery |
| `bms_discover` | `scanners/bms/bms_discover` | Building Management System discovery |
| `camera_scan` | `scanners/cameras/camera_scan` | Generic IP camera discovery and fingerprinting |
| `rtsp_discover` | `scanners/cameras/rtsp_discover` | RTSP stream discovery (see [21-rtsp-camera-engine.md](21-rtsp-camera-engine.md)) |
| `rtsp_scanner` | `scanners/cameras/rtsp_scanner` | RTSP full port scan + credential testing |
| `dahua_dvr_scanner` | `scanners/cameras/dahua_dvr_scanner` | Dahua DVR/NVR discovery |
| `herospeed_longsee_nvr_scan` | `scanners/cameras/herospeed_longsee_nvr_scan` | Herospeed/Longsee NVR discovery |
| `hp_rawprint_9100` | `scanners/printers/hp_rawprint_9100` | HP PJL scanner via port 9100 |
| `wsd_printer_enum` | `exploits/printers/generic/wsd_printer_enum` | WSD/mDNS printer discovery |
| `upnp_ssdp_scan` | `scanners/protocols/iot/upnp_ssdp_scan` | UPnP/SSDP device enumeration |
| `mdns_iot_discovery` | `scanners/embedded_os/mdns_iot_discovery` | mDNS/Bonjour IoT device discovery |
| `mqtt_broker_scan` | `scanners/embedded_os/mqtt_broker_scan` | MQTT broker discovery and fingerprinting |
| `embedded_os_fingerprint` | `scanners/embedded_os/embedded_os_fingerprint` | Embedded OS fingerprinting |
| `mirai_default_creds_sweep` | `scanners/threat_detection/mirai_default_creds_sweep` | Mirai botnet default credential sweep |
| `gpon_exploitation_scan` | `scanners/threat_detection/gpon_exploitation_scan` | GPON vulnerability scanner |
| `fortigate_sslvpn_scan` | `scanners/firewalls/fortinet/fortigate_sslvpn_scan` | FortiGate SSL-VPN scanner |
| `misc_scan` | `scanners/firewalls/misc_scan` | Generic firewall misconfiguration scanner |
| `proxmox_discover` | `scanners/hypervisors/proxmox_discover` | Proxmox VE management interface discovery |
| `papi_service_scanner` | `scanners/aruba/papi_service_scanner` | Aruba PAPI service scanner |
| **ICS scanners** | — | — |
| `modbus_scanner` | `scanners/ics/modbus_scanner` | Modbus TCP device discovery and register read |
| `modbus_id_fuzzer` | `scanners/ics/modbus_id_fuzzer` | Modbus unit ID fuzzer |
| `bacnet_scanner` | `scanners/ics/bacnet_scanner` | BACnet/IP device discovery |
| `cip_scanner` | `scanners/ics/cip_scanner` | Ethernet/IP + CIP scanner |
| `dnp3_scanner` | `scanners/ics/dnp3_scanner` | DNP3 device scanner |
| `enip_scanner` | `scanners/ics/enip_scanner` | EtherNet/IP (Rockwell CIP) scanner |
| `profinet_dcp_scanner` | `scanners/ics/profinet_dcp_scanner` | PROFINET DCP scanner (Siemens) |

---

## RTSP scanner

```text
exf > use scanners/cameras/rtsp_scanner
exf (RTSP Scanner) > show options

Target options:
┌──────────┬──────────────────┬──────────────────────────────────────────────────────┐
│ Name     │ Current settings │ Description                                          │
├──────────┼──────────────────┼──────────────────────────────────────────────────────┤
│ target   │                  │ Target IP or CIDR network                            │
│ port     │ 554              │ RTSP port (default: 554)                             │
│ timeout  │ 5                │ Per-probe timeout in seconds                         │
│ threads  │ 8                │ Concurrent scan threads                              │
│ creds    │ True             │ Test default credentials after discovery             │
└──────────┴──────────────────┴──────────────────────────────────────────────────────┘

exf (RTSP Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (RTSP Scanner) > run
[*] Running module ...
[*] Scanning 254 hosts on port 554...
[+] 192.168.1.60  — RTSP service detected (Hikvision DS-2CD2143G2-I, firmware 5.7.16)
[+] 192.168.1.61  — RTSP service detected (Dahua IPC-HDW2831T-AS, firmware 2.840.0005.0.R)
[+] 192.168.1.62  — RTSP service detected (generic H.265 NVR)
[*] Testing default credentials on discovered RTSP services...
[+] 192.168.1.60 — credentials found: admin:(empty)    rtsp://192.168.1.60/Streaming/Channels/101
[+] 192.168.1.61 — credentials found: admin:admin      rtsp://192.168.1.61/cam/realmonitor?channel=1&subtype=0
[-] 192.168.1.62 — no default credentials matched
```

> Full RTSP engine documentation: [21-rtsp-camera-engine.md](21-rtsp-camera-engine.md)

---

## ICS protocol scanners

```text
exf > use scanners/ics/modbus_scanner
exf (Modbus Scanner) > show options

Target options:
┌──────────┬──────────────────┬──────────────────────────────────────────────┐
│ Name     │ Current settings │ Description                                  │
├──────────┼──────────────────┼──────────────────────────────────────────────┤
│ target   │                  │ Target IP or CIDR                            │
│ port     │ 502              │ Modbus TCP port                              │
│ timeout  │ 3                │ Connection timeout (seconds)                 │
│ read_regs│ True             │ Read holding registers 0–9 from each device  │
└──────────┴──────────────────┴──────────────────────────────────────────────┘

exf (Modbus Scanner) > set target 10.0.50.0/24
[+] target => 10.0.50.0/24
exf (Modbus Scanner) > run
[*] Running module ...
[*] Scanning 254 hosts on Modbus TCP port 502...
[+] 10.0.50.10  — Modbus device responding (unit_id=1)
    Device ID: Schneider Electric Modicon M340
    Holding registers [0..9]: [100, 0, 4096, 1, 0, 0, 0, 0, 0, 0]
[+] 10.0.50.11  — Modbus device responding (unit_id=1)
    Device ID: Siemens S7-1200 PLC (Modbus emulation)
    Holding registers [0..9]: [0, 0, 1500, 245, 0, 0, 0, 0, 0, 0]
[-] 10.0.50.12  — No Modbus response (port closed or filtered)
```

> Full ICS/OT exploit modules: [20-ics-ot-modules.md](20-ics-ot-modules.md)

---

## Printer scanners

```text
exf > use exploits/printers/generic/wsd_printer_enum
exf (WSD Printer Enum) > set target 239.255.255.250
[+] target => 239.255.255.250
exf (WSD Printer Enum) > set timeout 8
[+] timeout => 8
exf (WSD Printer Enum) > run
[*] Running module ...
[*] WSD probe on 239.255.255.250:3702 (8s timeout)...
[+] Discovered 3 WSD device(s):

IP              Endpoint                      Types          XAddrs
192.168.1.100   urn:uuid:a1b2c3d4-e5f6...    wsdl:Service   http://192.168.1.100:80/
192.168.1.101   urn:uuid:b2c3d4e5-f6a7...    d:Device       http://192.168.1.101:631/
192.168.1.102   urn:uuid:c3d4e5f6-a7b8...    d:Device       http://192.168.1.102:80/
```

---

## Phase Gate Tool

`tools/phase_gate.py` is the internal quality gate system that validates all modules are importable, have required metadata, and pass count checks.

```bash
# List available gates
python tools/phase_gate.py --list

# Validate specific track
python tools/phase_gate.py --phase A1A2   # printer EDB/MSF ports
python tools/phase_gate.py --phase B      # 2026 CVE primary batch
python tools/phase_gate.py --phase C      # 2026 CVE extended
python tools/phase_gate.py --phase A3     # printer research modules
python tools/phase_gate.py --phase D      # 2025/2024 backlog CVEs

# Run all gates
python tools/phase_gate.py --all
```

Expected output:

```text
============================================================
  GATE B
============================================================
  [ PASS ] import:cisco_sdwan_dtls_auth_bypass_cve_2026_20182
  [ PASS ] import:cisco_fmc_auth_bypass_rce_cve_2026_20079
  [ PASS ] import:globalprotect_auth_bypass_cve_2026_0257
  [ PASS ] cvss_present
  [ PASS ] sdwan_dtls_stages      (6 .run() stages confirmed)
  [ PASS ] indexed                (All 14 modules indexed)
  [ PASS ] total_module_count     (2760 modules indexed)

Results: 27/27 passed  (all passed)
Gate B PASSED.
```

> Always confirm scope and rate limits before running scanners on live networks.

[Wiki hub](../README.md)
