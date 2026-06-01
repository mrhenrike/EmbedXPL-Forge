# Scanners and AutoPwn

**Language:** English (en-US) | **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

---

## Overview

Scanner modules perform network reconnaissance, device fingerprinting, protocol discovery, and automated vulnerability assessment. The flagship scanner is **AutoPwn**, which orchestrates a full scan-and-check cycle against a target using all applicable exploit and credential modules.

---

## AutoPwn

**AutoPwn** loads all exploit and credential modules for the applicable device class and runs their `check()` methods concurrently against a target. It is the closest equivalent to a fully automated "scan everything" operation.

### Module path

```
scanners/autopwn
```

### Complete options reference

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 or IPv6 | Target host IP address |
| `vendor` | `OptString` | No | `any` | Any vendor name or `any` | Restrict to a specific vendor's modules |
| `target_device_class` | `OptString` | No | `multi` | `multi`, `router`, `switch`, `tap`, `fw`, `ngfw`, `isp_cpe` | Device class filter (skips non-applicable modules) |
| `timing_template` | `OptString` | No | `balanced` | T0–T5 or name aliases | Controls thread count, confirm passes, retries, and inter-probe delay |
| `check_exploits` | `OptBool` | No | `True` | `true`, `false` | Whether to run exploit check() methods |
| `check_creds` | `OptBool` | No | `True` | `true`, `false` | Whether to run credential check_default() methods |
| `http_use` | `OptBool` | No | `True` | `true`, `false` | Enable HTTP service checks |
| `http_port` | `OptPort` | No | `80` | 1–65535 | HTTP port |
| `http_ssl` | `OptBool` | No | `False` | `true`, `false` | Use HTTPS for HTTP modules |
| `ftp_use` | `OptBool` | No | `True` | `true`, `false` | Enable FTP service checks |
| `ftp_port` | `OptPort` | No | `21` | 1–65535 | FTP port |
| `ftp_ssl` | `OptBool` | No | `False` | `true`, `false` | Use FTPS |
| `ssh_use` | `OptBool` | No | `True` | `true`, `false` | Enable SSH checks |
| `ssh_port` | `OptPort` | No | `22` | 1–65535 | SSH port |
| `sftp_use` | `OptBool` | No | `True` | `true`, `false` | Enable SFTP checks |
| `sftp_port` | `OptPort` | No | `22` | 1–65535 | SFTP port |
| `telnet_use` | `OptBool` | No | `True` | `true`, `false` | Enable Telnet checks |
| `telnet_port` | `OptPort` | No | `23` | 1–65535 | Telnet port |
| `snmp_use` | `OptBool` | No | `True` | `true`, `false` | Enable SNMP checks |
| `snmp_community` | `OptString` | No | `public` | Any string | SNMP community string |
| `snmp_version` | `OptInteger` | No | `1` | `0` (v1) or `1` (v2c) | SNMP protocol version |
| `snmp_port` | `OptPort` | No | `161` | 1–65535 | SNMP port |
| `threads` | `OptInteger` | No | `8` | 1–300 | Number of concurrent module check threads |
| `module_timeout_s` | `OptInteger` | No | `20` | 0–3600 | Per-module timeout in seconds (0 = disabled) |
| `verify_positive_twice` | `OptBool` | No | `True` | `true`, `false` | Re-confirm positive results to reduce false positives |
| `show_timing_help` | `OptBool` | No | `True` | `true`, `false` | Print timing profile table before scan |
| `ml_advisor` | `OptBool` | No | `False` | `true`, `false` | Enable ML heuristic module prioritization |
| `ml_auto_timing` | `OptBool` | No | `False` | `true`, `false` | Let ML advisor override timing_template |
| `ml_use_gpu` | `OptBool` | No | `False` | `true`, `false` | Use GPU for ML scoring |

---

### Timing templates

AutoPwn uses Nmap-style `-T0` through `-T5` timing profiles:

| Template | Alias | Threads | Confirm passes | Inconclusive retries | Delay (s/probe) | Use case |
|----------|-------|---------|----------------|----------------------|----------------|---------|
| `T0` | `paranoid` | 1 | 3 | 2 | 1.0 | IDS evasion, maximum stealth |
| `T1` | `sneaky` | 2 | 2 | 2 | 0.5 | Quiet audits, minimal network footprint |
| `T2` | `polite` | 4 | 2 | 1 | 0.2 | Low-bandwidth links, careful scans |
| `T3` | `balanced` / `normal` | 8 | 2 | 1 | 0.0 | **Default** — works well for most scenarios |
| `T4` | `aggressive` | 16 | 1 | 0 | 0.0 | Fast LAN scans, reliable network |
| `T5` | `insane` | 32 | 1 | 0 | 0.0 | CTF / isolated lab only — very noisy |

**"Confirm passes"**: when a module returns `True`, AutoPwn calls `check()` again this many times total. This reduces false positives.

**"Inconclusive retries"**: when `check()` returns `None`/inconclusive, AutoPwn retries up to this many times.

**Thread limit:** minimum 1, maximum 300. Setting `threads >= 200` prints a warning about CPU/RAM impact.

---

### AutoPwn terminal session (balanced T3, default)

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (AutoPwn) > run

[*] AutoPwn timing profiles (Nmap-style -T0..-T5):

┌──────────┬───────────┬─────────┬─────────┬────────────────────┬──────────┐
│ Template │ Alias     │ Threads │ Confirm │ Retry(Inconclusive)│ Delay(s) │
├──────────┼───────────┼─────────┼─────────┼────────────────────┼──────────┤
│ T0       │ paranoid  │ 1       │ 3       │ 2                  │ 1.0      │
│ T1       │ sneaky    │ 2       │ 2       │ 2                  │ 0.5      │
│ T2       │ polite    │ 4       │ 2       │ 1                  │ 0.2      │
│ T3       │ balanced  │ 8       │ 2       │ 1                  │ 0.0      │
│ T4       │ aggressive│ 16      │ 1       │ 0                  │ 0.0      │
│ T5       │ insane    │ 32      │ 1       │ 0                  │ 0.0      │
└──────────┴───────────┴─────────┴─────────┴────────────────────┴──────────┘
[*] Default profile: balanced (T3). Use: set timing_template T4 or set timing_template aggressive

[*] AutoPwn timing template T3 (balanced) active: threads=8, confirm_passes=2, inconclusive_retries=1, delay=0.0s

[*] 192.168.1.1 Starting vulnerability check...
[+] 192.168.1.1:80 http dir_300_600_rce is vulnerable
[-] 192.168.1.1:22 ssh ssh_default_creds is not vulnerable
[-] 192.168.1.1:80 http admin_panel_default is not vulnerable
[*] 192.168.1.1:161 snmp snmp_rocommunity Could not be verified
[+] 192.168.1.1:80 http telnet_default_creds is vulnerable

[*] 192.168.1.1 Starting default credentials check...
[-] 192.168.1.1:22 ssh ssh_default is not vulnerable
[+] 192.168.1.1:23 telnet telnet_default is vulnerable

[*]
[+] 192.168.1.1 Device is vulnerable:
┌───────────────┬──────┬──────────┬───────────────────────────────────┐
│ Target        │ Port │ Service  │ Exploit                           │
├───────────────┼──────┼──────────┼───────────────────────────────────┤
│ 192.168.1.1   │ 80   │ http     │ dir_300_600_rce                   │
│ 192.168.1.1   │ 80   │ http     │ telnet_default_creds              │
└───────────────┴──────┴──────────┴───────────────────────────────────┘

[*]
[+] 192.168.1.1 Found default credentials:
┌───────────────┬──────┬──────────┬────────────┬────────────┐
│ Target        │ Port │ Service  │ Username   │ Password   │
├───────────────┼──────┼──────────┼────────────┼────────────┤
│ 192.168.1.1   │ 23   │ telnet   │ admin      │ admin      │
└───────────────┴──────┴──────────┴────────────┴────────────┘
```

---

### AutoPwn terminal session (T4 aggressive, vendor filter)

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (AutoPwn) > set timing_template T4
[+] timing_template => T4
exf (AutoPwn) > set vendor hikvision
[+] vendor => hikvision
exf (AutoPwn) > run

[*] AutoPwn timing template T4 (aggressive) active: threads=16, confirm_passes=1, inconclusive_retries=0, delay=0.0s

[*] 192.168.1.100 Starting vulnerability check...
[+] 192.168.1.100:80 http rtsp_rce_cve_2021_36260 is vulnerable
[+] 192.168.1.100:80 http info_disclosure_cve_2017_7921 is vulnerable
[-] 192.168.1.100:80 http nas_auth_bypass_cve_2023_28808 is not vulnerable

[+] 192.168.1.100 Device is vulnerable:
┌───────────────┬──────┬──────────┬──────────────────────────────────────┐
│ Target        │ Port │ Service  │ Exploit                              │
├───────────────┼──────┼──────────┼──────────────────────────────────────┤
│ 192.168.1.100 │ 80   │ http     │ rtsp_rce_cve_2021_36260              │
│ 192.168.1.100 │ 80   │ http     │ info_disclosure_cve_2017_7921        │
└───────────────┴──────┴──────────┴──────────────────────────────────────┘
```

---

### AutoPwn terminal session (T0 paranoid, IDS-evasion mode)

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 10.0.0.50
[+] target => 10.0.0.50
exf (AutoPwn) > set timing_template paranoid
[+] timing_template => paranoid
exf (AutoPwn) > set check_creds false
[+] check_creds => false
exf (AutoPwn) > run

[*] AutoPwn timing template T0 (paranoid) active: threads=1, confirm_passes=3, inconclusive_retries=2, delay=1.0s

[*] 10.0.0.50 Starting vulnerability check...
[*] 10.0.0.50:80 http — testing rtsp_rce_cve_2021_36260 (probe delay: 1.0s)
[-] 10.0.0.50:80 http rtsp_rce_cve_2021_36260 is not vulnerable
[*] 10.0.0.50:80 http — testing info_disclosure_cve_2017_7921 (probe delay: 1.0s)
[+] 10.0.0.50:80 http info_disclosure_cve_2017_7921 is vulnerable (confirmed 3x)
...
```

---

### AutoPwn terminal session (ML advisor enabled)

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (AutoPwn) > set ml_advisor true
[+] ml_advisor => true
exf (AutoPwn) > set ml_auto_timing true
[+] ml_auto_timing => true
exf (AutoPwn) > run

[*] ML advisor enabled (CVSS + CVE recency + attack type scoring).
[*] ML advisor suggests timing: T4 (probabilities: T4=42.3%, T3=31.1%, T5=18.7%)
[*] ML advisor reordered 847 exploit modules (higher expected yield first).

[*] AutoPwn timing template T4 (aggressive) active: threads=16, ...
```

---

### AutoPwn error cases

**No target specified:**

```text
exf (AutoPwn) > run
[-] target is required but not set
```

**Invalid timing template (falls back to T3):**

```text
exf (AutoPwn) > set timing_template T9
[+] timing_template => T9
exf (AutoPwn) > run
[-] Unknown timing template 'T9'. Falling back to balanced (T3).
[*] AutoPwn timing template T3 (balanced) active...
```

**Thread count out of range:**

```text
exf (AutoPwn) > set threads 500
[+] threads => 500
exf (AutoPwn) > run
[-] Invalid thread count 500. Maximum is 300. Applying maximum.
[!] ALERT: 300 threads configured. This may consume high CPU/RAM and impact scan host stability.
```

**Target class filter active:**

```text
exf (AutoPwn) > set target_device_class router
[+] target_device_class => router
exf (AutoPwn) > run
[*] Device class filter active: router (modules outside module_target_scope.json rules are skipped)
...
[*] Skipped 124 module(s) not permitted for target_device_class=router
```

---

## Device-oriented scanner modules

### Network discovery scanners

| Module | Path | Description |
|--------|------|-------------|
| SOHO device discovery | `scanners/routers/soho_discover` | Fingerprints 12+ vendor HTTP signatures |
| Router scan | `scanners/routers/router_scan` | Router-focused discovery and chaining |
| HooToo scan | `scanners/soho_edge/hootoo_scan` | HooToo travel router detection |
| Misc scan | `scanners/misc/misc_scan` | Generic device scan |

### Camera-specific scanners

| Module | Path | Description |
|--------|------|-------------|
| Camera scan | `scanners/cameras/camera_scan` | Generic IP camera discovery |
| RTSP discover | `scanners/cameras/rtsp_discover` | Discover RTSP streams on a network |
| RTSP scanner | `scanners/cameras/rtsp_scanner` | Scan for open RTSP ports |
| Herospeed/Longsee NVR scan | `scanners/cameras/herospeed_longsee_nvr_scan` | Detect Herospeed/Longsee/TVT/GISE NVRs |
| Dahua CCTV discover | `scanners/cameras/dahua/cctv_discover` | Dahua device discovery |
| Dahua DVR 37777 | `scanners/cameras/dahua_dvr_37777` | Scan Dahua port 37777 |
| Dahua DVR scanner | `scanners/cameras/dahua_dvr_scanner` | Dahua DVR scanner |
| Dahua firmware fingerprint | `scanners/cameras/dahua/firmware_version_fingerprint` | Version fingerprinting |
| Dahua P2P/PPPP scan | `scanners/cameras/dahua/p2p_pppp_scan` | P2P PPPP protocol scan |
| Hikvision firmware fingerprint | `scanners/cameras/hikvision/firmware_version_fingerprint` | Firmware version detection |
| Hikvision boot permission audit | `scanners/cameras/hikvision/boot_permission_audit` | Audit boot permissions |
| Hikvision eglibc version check | `scanners/cameras/hikvision/eglibc_version_check` | eglibc version analysis |
| Hikvision NVR binary hardening | `scanners/cameras/hikvision/nvr_binary_hardening_audit` | Binary hardening audit |
| Hikvision R0 intercom firmware | `scanners/cameras/hikvision/r0_intercom_firmware_audit` | Intercom firmware audit |
| Hikvision R0 intercom network | `scanners/cameras/hikvision/r0_intercom_network_detect` | Intercom network detect |
| Intelbras BOA detect | `scanners/cameras/intelbras_boa_detect` | Intelbras BOA server detect |
| Intelbras CCTV discover | `scanners/cameras/intelbras_cctv_discover` | Intelbras device discovery |
| Intelbras ONVIF scan | `scanners/cameras/intelbras_onvif_scan` | ONVIF protocol scan |
| Intelbras P2P UID scan | `scanners/cameras/intelbras_p2p_uid_scan` | P2P UID extraction |
| Intelbras PVIP discover | `scanners/cameras/intelbras_pvip_discover` | PVIP protocol discovery |
| TVT/Intelbras CCTV discover | `scanners/cameras/tvip_discover` | TVT/TVIP discovery |

**Terminal session — Herospeed/Longsee NVR scan:**

```text
exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf (Herospeed/Longsee NVR Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (Herospeed/Longsee NVR Scanner) > run
[*] Running module ...
[*] Scanning 192.168.1.0/24 for Herospeed/Longsee NVR signatures...
[*] Probe 192.168.1.60: HTTP 200, signature match (statics/js/variable.js)
[+] Found: 192.168.1.60 [Herospeed NVR v2.0.6, 9CH, MC6830]
[*] Checking backdoor port (9999)... open
[*] Checking default credentials admin:admin... FAIL
[*] Checking default credentials admin:12345... SUCCESS
[+] Default creds valid: admin:12345
[*] Probe 192.168.1.61: HTTP 200, signature match (statics/js/variable.js)
[+] Found: 192.168.1.61 [TVT Digital TD-3000H1, V21.1.23.3]
...
Summary: 2 Herospeed/Longsee NVR device(s) found on 192.168.1.0/24
  use exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
  use exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor
```

---

### ICS / OT protocol scanners

| Module | Path | Protocol | Description |
|--------|------|----------|-------------|
| Modbus scanner | `scanners/ics/modbus_scanner` | Modbus TCP/502 | Modbus device discovery |
| Modbus ID fuzzer | `scanners/ics/modbus_id_fuzzer` | Modbus | Unit ID fuzzing |
| BACnet scanner | `scanners/ics/bacnet_scanner` | BACnet/IP | BACnet device discovery |
| S7 comm scanner | `scanners/ics/s7_comm_scanner` | S7comm | Siemens S7 PLC scanner |
| S7comm+ scanner | `scanners/ics/s7comm_plus_scanner` | S7comm+ | S7comm+ (TIA Portal) |
| EtherNet/IP scanner | `scanners/ics/enip_scanner` | EtherNet/IP | Rockwell/AB device scan |
| DNP3 scanner | `scanners/ics/dnp3_scanner` | DNP3 | DNP3 SCADA scan |
| CIP scanner | `scanners/ics/cip_scanner` | CIP | CIP protocol scan |
| Profinet DCP scanner | `scanners/ics/profinet_dcp_scanner` | PROFINET | Profinet DCP discovery |
| Rockwell discover | `scanners/ics/rockwell_discover` | EtherNet/IP | Rockwell device discovery |
| VxWorks scanner | `scanners/ics/vxworks_scanner` | Various | VxWorks RTOS detection |

**Terminal session — Modbus scanner:**

```text
exf > use scanners/ics/modbus_scanner
exf (Modbus Scanner) > set target 192.168.100.0/24
[+] target => 192.168.100.0/24
exf (Modbus Scanner) > run
[*] Running module ...
[*] Scanning 192.168.100.0/24 for Modbus TCP (port 502)...
[+] 192.168.100.10:502 — Modbus device responding
    Device ID: 1, Vendor: Schneider Electric, Product: Modicon M340
[+] 192.168.100.15:502 — Modbus device responding
    Device ID: 1, Vendor: Siemens, Product: S7-300 series
Summary: 2 Modbus device(s) found
```

---

### Protocol IoT scanners

| Module | Protocol | Description |
|--------|----------|-------------|
| `scanners/protocols/iot/mqtt_protocol_scan` | MQTT | MQTT broker discovery |
| `scanners/protocols/iot/coap_protocol_scan` | CoAP | CoAP endpoint scan |
| `scanners/protocols/iot/upnp_ssdp_scan` | UPnP/SSDP | UPnP device enumeration |
| `scanners/protocols/iot/ble_scan` | BLE | Bluetooth Low Energy scan |
| `scanners/protocols/iot/wifi_scan` | Wi-Fi | Wi-Fi AP discovery |
| `scanners/protocols/iot/zigbee_scan` | Zigbee | Zigbee network scan |
| `scanners/protocols/iot/zwave_scan` | Z-Wave | Z-Wave device scan |
| `scanners/protocols/iot/lorawan_scan` | LoRaWAN | LoRa network scan |
| `scanners/protocols/iot/dds_rtps_scan` | DDS/RTPS | DDS middleware scan |
| `scanners/protocols/ot/modbus_scan` | Modbus | OT/ICS Modbus scan (OT profile) |
| `scanners/protocols/ot/s7comm_scan` | S7comm | OT/ICS Siemens S7 scan |
| `scanners/protocols/ot/can_scan` | CAN | CAN bus scan |
| `scanners/protocols/ot/ethernetip_scan` | EtherNet/IP | OT EtherNet/IP scan |
| `scanners/protocols/ot/hartip_scan` | HART-IP | HART-IP field device scan |

**Terminal session — MQTT broker scan:**

```text
exf > use scanners/embedded_os/mqtt_broker_scan
exf (MQTT Broker Scanner) > set target 192.168.1.0/24
[+] target => 192.168.1.0/24
exf (MQTT Broker Scanner) > run
[*] Scanning for MQTT brokers on 192.168.1.0/24 (port 1883/8883)...
[+] 192.168.1.5:1883 — MQTT broker (anonymous access allowed)
    Client ID: connected as anonymous
    Subscriptions: #, $SYS/#
[!] Broker allows unauthenticated connections — HIGH RISK
```

---

### Threat detection scanners

| Module | Path | Description |
|--------|------|-------------|
| Mirai default creds sweep | `scanners/threat_detection/mirai_default_creds_sweep` | Sweep for Mirai IoT botnet default creds |
| Mirai C2 beacon detect | `scanners/threat_detection/mirai_c2_beacon_detect` | Detect Mirai C2 beaconing |
| Mirai infection scan | `scanners/threat_detection/mirai_infection_scan` | Detect Mirai-infected hosts |
| GPON exploitation scan | `scanners/threat_detection/gpon_exploitation_scan` | GPON vulnerability scanner |
| Botnet C2 port scan | `scanners/threat_detection/botnet_c2_port_scan` | Scan for botnet C2 ports |
| Mozi DHT presence scan | `scanners/threat_detection/mozi_dht_presence_scan` | Detect Mozi DHT nodes |

---

### Other specialized scanners

| Module | Path | Description |
|--------|------|-------------|
| BMC discover | `scanners/bmc/bmc_discover` | Baseboard management controller discovery |
| BMS discover | `scanners/bms/bms_discover` | Building management system discovery |
| Embedded OS fingerprint | `scanners/embedded_os/embedded_os_fingerprint` | Identify embedded OS type and version |
| mDNS IoT discovery | `scanners/embedded_os/mdns_iot_discovery` | mDNS/Bonjour IoT device discovery |
| FortiGate SSL-VPN scan | `scanners/firewalls/fortinet/fortigate_sslvpn_scan` | FortiGate SSL-VPN endpoint scan |
| Aruba PAPI scanner | `scanners/aruba/papi_service_scanner` | Aruba PAPI service detection |
| Proxmox discover | `scanners/hypervisors/proxmox_discover` | Proxmox VE discovery |
| NAS discover | `scanners/nas/nas_discover` | NAS device discovery |
| NAS scan | `scanners/nas/nas_scan` | NAS vulnerability scan |
| HP raw print 9100 | `scanners/printers/hp_rawprint_9100` | HP PJL raw print port scan |
| SOHO exploit catalog server | `scanners/misc/soho_exploit_catalog_server` | Catalog matching server |
| Smart home assistant scan | `scanners/smart_home/smart_home_assistant_scan` | Smart home hub discovery |
| Wattrout discover | `scanners/smart_meters/wattrout_discover` | Smart meter discovery |
| Smart TV discover | `scanners/smart_tv/smart_tv_discover` | Generic smart TV discovery |
| ADB mass scan | `scanners/smart_tv/adb_mass_scan` | ADB TCP/5555 mass scan |
| ADB TCP/IP discover | `scanners/smart_tv/adb_tcpip_discover` | Android Debug Bridge discovery |
| Bravia discover | `scanners/smart_tv/bravia_discover` | Sony Bravia TV discovery |
| Wearable BLE scan | `scanners/wearables/wearable_ble_scan` | Wearable BLE device scan |

---

## OUI vendor lookup (inside `discover`)

The `discover` command resolves MAC addresses to vendors using a 3-tier lookup:

1. **Session cache** — instant lookup from prior scans
2. **Online APIs** — `macvendors.com`, `maclookup.app` (live queries)
3. **Local IEEE database** — `embedxpl/data/oui.txt` (39,000+ entries, offline fallback)

```text
exf > discover 192.168.1.0/24
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD (Mercusys/TP-Link)
[*] OUI lookup: 44:19:b6 -> Hangzhou Hikvision Digital Technology Co.,Ltd
[+] Suggested modules for 192.168.1.50 (Hikvision):
    use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
    use exploits/cameras/hikvision/info_disclosure_cve_2017_7921
    use creds/cameras/hikvision/telnet_default_creds
```

---

## Phase Gate validation tool

`tools/phase_gate.py` is the internal quality gate system that validates all modules after development:

```bash
# List available gates
python tools/phase_gate.py --list

# Validate specific gates
python tools/phase_gate.py --phase A1A2   # printer EDB/MSF ports
python tools/phase_gate.py --phase B      # 2026 CVE primary batch
python tools/phase_gate.py --phase C      # 2026 CVE extended batch
python tools/phase_gate.py --phase A3     # printer research modules
python tools/phase_gate.py --phase D      # 2025/2024 backlog CVEs

# Run full validation suite
python tools/phase_gate.py --all
```

**Expected output (all pass):**

```text
============================================================
  GATE B
============================================================
  [ PASS ] import:globalprotect_auth_bypass_cve_2026_0257
  [ PASS ] import:cups_pwn2own_chain_cve_2026_34480
  [ PASS ] cvss_present
  [ PASS ] cups_chain_stages    (3 .run() calls confirmed)
  [ PASS ] indexed              (All 11 modules indexed)
  [ PASS ] total_module_count   (2807 modules indexed)

Results: 27/27 passed  (all passed)
Gate B PASSED.
```

**Expected output (failure):**

```text
  [ FAIL ] import:new_module_with_syntax_error
  Error: SyntaxError in new_module_with_syntax_error.py line 42

Results: 26/27 passed  (1 failed)
Gate B FAILED.
```


[Wiki hub](../README.md)
