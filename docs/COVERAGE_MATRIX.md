# RouterXPL-Forge — Coverage Matrix

> Auto-generated from module metadata.
> **Version:** 0.4.0-beta | **Modules:** 271 | **CVEs:** 23 | **Vendors:** 28+
>
> Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Summary

| Metric | Count |
|---|---|
| Total modules | 271 |
| Exploit modules | 125 |
| Credential modules | 88 |
| Payload modules | 32 |
| Encoder modules | 13 |
| Generic modules | 8 |
| Scanner modules | 5 |
| Unique CVEs | 23 |
| Hardware vendors (exploits + creds) | 28 |
| Unique device models affected | 444+ |

---

## Attack Capabilities

### Exploit Categories (125 modules)

| Attack Type | Modules |
|---|---|
| RCE / Command Injection | 55 |
| Credential Recovery / Disclosure | 19 |
| Authentication Bypass / Backdoor | 13 |
| Information Disclosure | 13 |
| Path / Directory Traversal | 11 |
| DNS Hijacking / Change | 4 |
| ShellShock (CGI) | 2 |
| Buffer Overflow | 2 |
| Heartbleed (TLS) | 1 |
| UPnP / SSDP Abuse | 1 |

### Credential Testing Protocols (88 modules)

| Protocol | Modules |
|---|---|
| FTP (default + bruteforce) | 26 |
| SSH (default + bruteforce) | 26 |
| Telnet (default + bruteforce) | 26 |
| HTTP Basic/Digest/Form | 5 |
| SFTP | 2 |
| SNMP / SNMPv3 | 2 |
| MikroTik API | 1 |

### Payload Generation (32 modules)

| Architecture | Modules | Type |
|---|---|---|
| CMD (Shell) | 14 | reverse_tcp, bind_tcp |
| Python | 4 | reverse_tcp, bind_tcp |
| ARM (LE) | 2 | reverse_tcp, bind_tcp |
| MIPS (BE) | 2 | reverse_tcp, bind_tcp |
| MIPS (LE) | 2 | reverse_tcp, bind_tcp |
| Perl | 2 | reverse_tcp, bind_tcp |
| PHP | 2 | reverse_tcp, bind_tcp |
| x64 | 2 | reverse_tcp, bind_tcp |
| x86 | 2 | reverse_tcp, bind_tcp |

### Encoding (13 modules)

| Language | Modules | Formats |
|---|---|---|
| Python | 5 | base64, hex (encoder + decoder) |
| Perl | 4 | base64, hex (encoder + decoder) |
| PHP | 4 | base64, hex (encoder + decoder) |

### Scanners (5 modules)

| Scanner | Target |
|---|---|
| AutoPwn | Auto-detect and exploit multiple device types |
| D-Link Scanner | D-Link device-specific scanning |
| Netgear Scanner | Netgear device-specific scanning |
| Multi-vendor Scanner | Generic multi-vendor discovery |
| CVE Lookup | CVE database lookup tool |

### Generic Modules (8 modules)

| Module | Scope |
|---|---|
| Heartbleed | OpenSSL TLS memory disclosure (any TLS target) |
| ShellShock | Bash CGI remote code execution (any CGI target) |
| HTTP Form Char-by-Char Oracle | Login form oracle timing attack |
| UPnP SSDP Discovery | UPnP/SSDP device discovery and enumeration |
| SNMP Enumeration | SNMP community string enumeration |
| CVE Lookup | Query CVE database for vulnerability info |
| Wordlist Generator | Generate targeted credential wordlists |
| External / Misc | Additional generic utilities |

---

## CVE Coverage (23 unique)

| CVE | Year | Vendor | Module | Attack Type |
|---|---|---|---|---|
| CVE-2001-0537 | 2001 | Cisco | `ios_http_authorization_bypass` | Authentication Bypass |
| CVE-2008-0403 | 2008 | Belkin | `g_plus_info_disclosure` | Information Disclosure |
| CVE-2012-2765 | 2012 | Belkin | `g_n150_password_disclosure` | Credential Disclosure |
| CVE-2013-3568 | 2013 | Linksys | `wrt100_110_rce` | RCE |
| CVE-2014-1635 | 2014 | Belkin | `n750_rce` | RCE |
| CVE-2014-6271 | 2014 | Generic | `shellshock` | RCE (ShellShock) |
| CVE-2014-7169 | 2014 | Generic | `shellshock` | RCE (ShellShock) |
| CVE-2014-8243 | 2014 | Linksys | `smartwifi_password_disclosure` | Credential Disclosure |
| CVE-2014-9222 | 2014 | Multi | `misfortune_cookie` | Authentication Bypass |
| CVE-2017-3881 | 2017 | Cisco | `catalyst_2960_rocem` | RCE (Switch) |
| CVE-2017-5521 | 2017 | Netgear | `multi_password_disclosure-2017-5521` | Credential Disclosure |
| CVE-2017-6077 | 2017 | Netgear | `dgn2200_ping_cgi_rce` | RCE |
| CVE-2017-6334 | 2017 | Netgear | `dgn2200_dnslookup_cgi_rce`, `dgn2200_rce` | RCE |
| CVE-2017-11519 | 2017 | TP-Link | `archer_c9_admin_password_reset` | Credential Reset |
| CVE-2017-17215 | 2017 | Huawei | `hg532_rce` | RCE |
| CVE-2018-5999 | 2018 | ASUS | `asuswrt_lan_rce` | RCE |
| CVE-2018-6000 | 2018 | ASUS | `asuswrt_lan_rce` | RCE |
| CVE-2019-1652 | 2019 | Cisco | `rv320_command_injection` | Command Injection |
| CVE-2019-1663 | 2019 | Cisco | `rv130w_rce` | RCE (Buffer Overflow) |
| CVE-2019-6971 | 2019 | TP-Link | `wr1043nd_auth_bypass` | Authentication Bypass |
| CVE-2019-16920 | 2019 | D-Link | `dir_655_866_652_rce` | RCE |
| CVE-2022-30075 | 2022 | TP-Link | `ax50_rce` | RCE (Authenticated) |
| CVE-2023-1389 | 2023 | TP-Link | `archer_ax21_rce` | RCE (Unauthenticated) |

---

## Vendor Coverage

### 2Wire

| Type | Count | Details |
|---|---|---|
| Exploits | 2 | Info disclosure, password disclosure |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** 2Wire 2701HGV-W, 3800HGV-B, 3801HGV, 4011G, 5012NV

---

### 3Com

| Type | Count | Details |
|---|---|---|
| Exploits | 5 | RCE, info disclosure, path traversal |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** 3Com AP8760, OfficeConnect, Intelligent Management Center

---

### Asmax

| Type | Count | Details |
|---|---|---|
| Exploits | 2 | DNS change, info disclosure |
| Creds | 4 | FTP, SSH, Telnet, MikroTik API |

**Affected devices:** Asmax AR 804 gu, AR 1004g

---

### ASUS

| Type | Count | Details |
|---|---|---|
| Exploits | 3 | RCE (CVE-2018-5999/6000), info disclosure, password disclosure |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 2 | CVE-2018-5999, CVE-2018-6000 |

**Affected devices (17):** RT-AC55U, RT-AC66R, RT-AC66U, RT-AC68U, RT-AC87U, RT-N10U, RT-N12HP_B1, RT-N15U, RT-N16, RT-N53, RT-N56U, RT-N66U, DSL-AC68U, DSL-N55U, AsusWRT < v3.0.0.4.384.10007

---

### Belkin

| Type | Count | Details |
|---|---|---|
| Exploits | 6 | RCE (CVE-2014-1635), info disclosure, password disclosure, auth bypass |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 3 | CVE-2008-0403, CVE-2012-2765, CVE-2014-1635 |

**Affected devices (11):** G, N150, N300 (F7D7301), N750, N900 (F9K1104), AC1200, F5D8633, Play Max (F7D4401)

---

### BHU

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | RCE |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** BHU uRouter

---

### Billion

| Type | Count | Details |
|---|---|---|
| Exploits | 2 | Password disclosure, auth bypass |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Billion 5200W-T, 7700NR4

---

### Cisco

| Type | Count | Details |
|---|---|---|
| Exploits | 5 | RCE (CVE-2019-1663), command injection (CVE-2019-1652), auth bypass (CVE-2001-0537), switch RCE (CVE-2017-3881) |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 4 | CVE-2001-0537, CVE-2017-3881, CVE-2019-1652, CVE-2019-1663 |

**Affected devices (9):** Catalyst 2960, DPC2420, RV110W, RV130W, RV215W, RV320, RV325, IOS 11.3–12.2

---

### Comtrend

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | Info disclosure |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Comtrend CT 5361T (CT 536X family)

---

### D-Link

| Type | Count | Details |
|---|---|---|
| Exploits | 28 | RCE, info disclosure, password disclosure, path traversal, DNS change, auth bypass, backdoor |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 1 | CVE-2019-16920 |

**Affected devices (76+):** DIR-300, DIR-320, DIR-600, DIR-601, DIR-615, DIR-645, DIR-815, DIR-825, DIR-850L, DIR-860L, DIR-865L, DIR-880L, DIR-655, DIR-866, DIR-652, DSL-2520U, DSL-2640B, DSL-2730B/U, DSL-2740R, DSL-2750B/U/E, DSL-2780B, DSL-526B, DWR-932/B, DCS-930L, DAP-1650, AP-1522, DGS-1510 series (switches), DNS-320L, DNS-327L, DSP-W110, DVG-N5402SP, DWL-3200AP, TEW-733GR, TEW-751DR

---

### HooToo

| Type | Count | Details |
|---|---|---|
| Exploits | 3 | RCE, path traversal, auth bypass |
| Creds | 0 | — |

**Affected devices (6):** TripMate HT-TM01, TripMate Nano HT-TM02, TripMate Mini HT-TM03, TripMate Elite HT-TM04, TripMate Titan HT-TM05, TripMate Elite U HT-TM06

---

### Huawei

| Type | Count | Details |
|---|---|---|
| Exploits | 7 | RCE (CVE-2017-17215), info disclosure, password disclosure, DNS change |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 1 | CVE-2017-17215 |

**Affected devices (9):** HG520/b, HG530, HG532, HG866, EchoLife HG8240 V1, EchoLife HG8245 V1/Q, E5331 MiFi

---

### IPFire

| Type | Count | Details |
|---|---|---|
| Exploits | 3 | RCE, shellshock, command injection |
| Creds | 0 | — |

**Affected devices:** IPFire <= 2.15 Core 82, < 2.19 Core 101, < 2.19 Core 110

---

### Juniper

| Type | Count | Details |
|---|---|---|
| Exploits | 0 | — |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Juniper routers (default credential testing)

---

### LG

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | RCE |
| Creds | 0 | — |

**Affected devices:** LG N1A1 NAS (3718.510.a0)

---

### Linksys

| Type | Count | Details |
|---|---|---|
| Exploits | 6 | RCE (CVE-2013-3568, RE6500), password disclosure (CVE-2014-8243), info disclosure |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 2 | CVE-2013-3568, CVE-2014-8243 |

**Affected devices (26+):** E900, E1000, E1200, E1500, E1550, E2000, E2100L, E2500, E3000, E3200, E4200/v2, EA2700, EA3500, EA4500, EA6200, EA6300, EA6400, EA6500, EA6700, EA6900, RE6500, WRT100, WRT110, WRT300N, WRT350N v2, WAG120N, WAG160n, WAG200G, WAG320N, WAG54G2, WAG54GS, WAP54Gv3

---

### MikroTik

| Type | Count | Details |
|---|---|---|
| Exploits | 2 | RCE (Chimay Red, WinBox) |
| Creds | 4 | FTP, SSH, Telnet, MikroTik API |

**Affected devices:** RouterOS 2.9.8–6.41rc56 (WinBox), RouterOS 6.29–6.42 (Chimay Red)

---

### Movistar

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | Info disclosure |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Movistar ADSL Router BHS_RTA

---

### Netcore / Netis

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | Backdoor RCE |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Netcore/Netis routers (UDP backdoor)

---

### Netgear

| Type | Count | Details |
|---|---|---|
| Exploits | 12 | RCE (CVE-2017-6077/6334), password disclosure (CVE-2017-5521), path traversal, auth bypass |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 3 | CVE-2017-5521, CVE-2017-6077, CVE-2017-6334 |

**Affected devices (62+):** DG834, DGN1000, DGN2000B, DGN2200 (v1-v4), DGN3500, DGND3300/Bv2, DM111Pv2, D6220, D6400, JNR1010/v2, JNR2010, JNR3000/3210, JWNR2000v5, JWNR2010v5, N300, R3250, R6200v2, R6250, R6300v2, R6400, R6700, R6900, R7000, R7100LG, R7300DST, R7900, R8000, R8300, R8500, RAX30, WG102, WG103, WN370, WN604, WNAP210, WNAP320, WND930, WNDAP350/360/380R/620/660, WNDR3400v2/v3, WNDR4500v2, WNR500, WNR612v3, WNR614, WNR618, WNR2020, WNR3500Lv2, ProSafe WC7520/WC7600/WC9500

---

### Netsys

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | Password disclosure |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Multiple Netsys models

---

### Shuttle

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | DNS change |
| Creds | 0 | — |

**Affected devices:** Shuttle Tech ADSL Modem-Router 915 WM

---

### Technicolor

| Type | Count | Details |
|---|---|---|
| Exploits | 4 | RCE, password disclosure, info disclosure |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** TC7200, TG784n-v3, DWG-855

---

### Thomson

| Type | Count | Details |
|---|---|---|
| Exploits | 2 | Password disclosure, auth bypass |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Thomson TWG849, TWG850

---

### TP-Link

| Type | Count | Details |
|---|---|---|
| Exploits | 8 | RCE (CVE-2023-1389, CVE-2022-30075), auth bypass (CVE-2019-6971), password reset (CVE-2017-11519), path traversal |
| Creds | 3 | FTP, SSH, Telnet |
| CVEs | 4 | CVE-2017-11519, CVE-2019-6971, CVE-2022-30075, CVE-2023-1389 |

**Affected devices (10+):** Archer AX21 (AX1800), Archer AX50, Archer C2, Archer C9, Archer C20i, Archer C60, TL-WR1043ND V2, WDR740N, WDR740ND, WDR842ND, TD-8840T

---

### Ubiquiti

| Type | Count | Details |
|---|---|---|
| Exploits | 1 | Auth bypass |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** AirOS 6.x

---

### ZTE

| Type | Count | Details |
|---|---|---|
| Exploits | 4 | RCE, info disclosure, config download |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** ZTE F460, F660, ZXHN H108N, ZXV10 H108L, ZXV10 W812N V2

---

### Zyxel

| Type | Count | Details |
|---|---|---|
| Exploits | 4 | RCE, password disclosure, DNS change |
| Creds | 3 | FTP, SSH, Telnet |

**Affected devices:** Zyxel P660HN-T v1/v2, EIR D1000

---

## Multi-Vendor Modules (5 exploit modules)

These modules target vulnerabilities affecting devices from multiple vendors simultaneously:

| Module | CVE | Affected Vendors | Devices |
|---|---|---|---|
| Misfortune Cookie | CVE-2014-9222 | Cisco, D-Link, Huawei, Linksys, TP-Link, ZTE, Zyxel + more | 42+ devices with RomPager < 4.34 |
| DNS Change (Generic) | — | D-Link, Linksys, TP-Link, Comtrend, Billion, others | Multiple ADSL/DSL routers |
| Multi Info Disclosure | — | Various | CPE/SOHO gateways |
| Multi Path Traversal | — | Various | Web-managed devices |
| Multi Password Disclosure | — | Netgear | 30+ Netgear models |

---

## Device Type Distribution

| Device Type | Exploit Modules | Cred Modules | Total |
|---|---|---|---|
| Routers | 112 | 72 | 184 |
| SOHO Edge / CPE | 4 | 3 | 7 |
| Switches (L2/L3) | 1 | 0 | 1 |
| Multi / Generic | 8 + 4 generic | 14 generic | 26 |

---

## Credential Wordlists (23 vendor-specific files)

Externalized default credentials for dictionary attacks:

| Vendor | Wordlist File | Protocols |
|---|---|---|
| 2Wire | `2wire_defaults.txt` | FTP, SSH, Telnet |
| 3Com | `3com_defaults.txt` | FTP, SSH, Telnet |
| Asmax | `asmax_defaults.txt` | FTP, SSH, Telnet, API |
| ASUS | `asus_defaults.txt` | FTP, SSH, Telnet |
| Belkin | `belkin_defaults.txt` | FTP, SSH, Telnet |
| BHU | `bhu_defaults.txt` | FTP, SSH, Telnet |
| Billion | `billion_defaults.txt` | FTP, SSH, Telnet |
| Cisco | `cisco_defaults.txt` | FTP, SSH, Telnet |
| Comtrend | `comtrend_defaults.txt` | FTP, SSH, Telnet |
| D-Link | `dlink_defaults.txt` | FTP, SSH, Telnet |
| Huawei | `huawei_defaults.txt` | FTP, SSH, Telnet |
| Juniper | `juniper_defaults.txt` | FTP, SSH, Telnet |
| Linksys | `linksys_defaults.txt` | FTP, SSH, Telnet |
| MikroTik | `mikrotik_defaults.txt` | FTP, SSH, Telnet, API |
| Movistar | `movistar_defaults.txt` | FTP, SSH, Telnet |
| Netcore | `netcore_defaults.txt` | FTP, SSH, Telnet |
| Netgear | `netgear_defaults.txt` | FTP, SSH, Telnet |
| Netsys | `netsys_defaults.txt` | FTP, SSH, Telnet |
| Technicolor | `technicolor_defaults.txt` | FTP, SSH, Telnet |
| Thomson | `thomson_defaults.txt` | FTP, SSH, Telnet |
| TP-Link | `tplink_defaults.txt` | FTP, SSH, Telnet |
| Ubiquiti | `ubiquiti_defaults.txt` | FTP, SSH, Telnet |
| ZTE | `zte_defaults.txt` | FTP, SSH, Telnet |
| Zyxel | `zyxel_defaults.txt` | FTP, SSH, Telnet |

---

## Full Capability Summary

| Capability | Description |
|---|---|
| **Exploitation** | 125 modules covering RCE, auth bypass, info disclosure, path traversal, DNS hijacking, credential disclosure, buffer overflow, ShellShock, Heartbleed, UPnP/SSDP |
| **Credential Testing** | 88 modules for dictionary attacks via FTP, SSH, Telnet, HTTP, SFTP, SNMP, MikroTik API against 24+ vendors |
| **Payload Generation** | 32 modules generating reverse/bind TCP shells for x86, x64, ARM, MIPS (BE/LE), Python, Perl, PHP, CMD |
| **Encoding** | 13 modules for Base64/Hex encoding in Python, Perl, PHP |
| **Scanning** | 5 modules including AutoPwn (auto-detect + exploit), vendor-specific scanners, CVE lookup |
| **Generic Tools** | 8 modules for Heartbleed, ShellShock, HTTP oracle attacks, UPnP/SSDP discovery, SNMP enumeration |
| **Wordlists** | 23 vendor-specific default credential files + generic wordlists |
| **Target Scope** | Routers, Switches L2/L3, SOHO Edge/CPE devices, TAPs |

---

*Generated from RouterXPL-Forge v0.4.0-beta module metadata.*
