# discover Command

**Language:** English (en-US) | **pt-BR:** [../pt-BR/15-comando-discover.md](../pt-BR/15-comando-discover.md)

---

## Overview

`discover` performs network discovery on a subnet or individual host, fingerprints live devices, and matches them against the EmbedXPL exploit catalog. It is session-aware: if a host was scanned before, previous findings are displayed and the scan resumes from where it stopped.

---

## Syntax

```
discover <subnet/CIDR>
discover <IP>
discover <subnet/CIDR> --fresh
discover -T <targets.txt>
discover -T <targets.txt> --fresh
```

---

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `<subnet/CIDR>` | string | IPv4 address or CIDR notation (e.g. `192.168.1.0/24`, `10.0.0.1`) |
| `--fresh` | flag | Ignore saved session data; perform a full rescan from zero |
| `-T <file>` | string | Path to a plain-text file with one IP or CIDR per line |

---

## Standard discovery — single CIDR

```
exf> discover 192.168.1.0/24

[*] Starting network discovery on 192.168.1.0/24
[*] [arp_ping] Sending ARP broadcast to 192.168.1.0/24
[*] [port_scan] Scanning live hosts: 80,443,23,22,554,8080,8443,7547,37777,9100,631
[*] [banner_grab] Grabbing HTTP/RTSP/Telnet banners
[*] [fingerprint] Matching vendor OUI and HTTP fingerprints
[*] [catalog_match] Matching hosts to exploit catalog
[*] [wireless_check] Checking for wireless SSIDs

┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       Discovered Hosts (5)                                                                 │
├─────────────────┬───────────────────┬──────────────────┬───────────────────────────┬──────────────────┬────────────────────┤
│ IP              │ MAC               │ Hostname         │ Ports                     │ Vendor           │ Model              │
├─────────────────┼───────────────────┼──────────────────┼───────────────────────────┼──────────────────┼────────────────────┤
│ 192.168.1.1     │ EC:08:6B:1A:2C:40 │ -                │ 80,443,22                 │ TP-Link          │ TL-WR841N          │
│ 192.168.1.100   │ AC:CC:8E:5A:10:F2 │ DVR-001          │ 80,554,8000,37777         │ Hikvision        │ DS-7608NI-K2       │
│ 192.168.1.101   │ 00:E0:4C:3B:12:AA │ -                │ 80,37777                  │ Dahua            │ IPC-HDW2831T       │
│ 192.168.1.200   │ 00:09:0F:AA:00:01 │ fw-perimeter     │ 80,443,8443               │ Fortinet         │ FortiGate-200F     │
│ 192.168.1.254   │ 18:E8:29:01:B4:CC │ router-main      │ 80,443,22,23              │ Cisco            │ RV325              │
└─────────────────┴───────────────────┴──────────────────┴───────────────────────────┴──────────────────┴────────────────────┘

(continued with Confidence, Modules, Tested, Pending, WiFi columns)
┌─────────────────┬────────────┬─────────┬─────────┬────────┬──────┐
│ IP              │ Confidence │ Modules │ Tested  │ Pending│ WiFi │
├─────────────────┼────────────┼─────────┼─────────┼────────┼──────┤
│ 192.168.1.1     │ 92%        │ 6       │ 0       │ 6      │ Yes  │
│ 192.168.1.100   │ 88%        │ 14      │ 0       │ 14     │ -    │
│ 192.168.1.101   │ 81%        │ 8       │ 0       │ 8      │ -    │
│ 192.168.1.200   │ 95%        │ 12      │ 0       │ 12     │ -    │
│ 192.168.1.254   │ 90%        │ 5       │ 0       │ 5      │ Yes  │
└─────────────────┴────────────┴─────────┴─────────┴────────┴──────┘

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
    ... and 9 more

  192.168.1.101 [Dahua] IPC-HDW2831T -- 8 exploit module(s)
    use exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044               [pending]
    use exploits/cameras/dahua/cctv_rce_cve_2021_36260                       [pending]
    use exploits/cameras/dahua/auth_bypass_cve_2021_33044                    [pending]
    use exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078       [pending]
    use exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117                 [pending]
    ... and 3 more

  192.168.1.200 [Fortinet] FortiGate-200F -- 12 exploit module(s)
    use exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684       [pending]
    use exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762        [pending]
    use exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997 [pending]
    use exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379   [pending]
    use exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575    [pending]
    ... and 7 more

  192.168.1.254 [Cisco] RV325 -- 5 exploit module(s)
    use exploits/routers/cisco/rv320_command_injection                       [pending]
    use exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653  [pending]
    ... and 3 more

╔════════════════════════════════════════════════════════════════════╗
║ WirelessXPL-Forge  COMPLEMENTARY                                   ║
║ 192.168.1.1 (TP-Link TL-WR841N)  SSIDs: HomeNet_5G, HomeNet_2G    ║
║                                                                    ║
║ This device has wireless interfaces. WirelessXPL-Forge can test:   ║
║  - WPA2/WPA3 handshake capture and offline cracking               ║
║  - Deauth and PMKID attacks                                        ║
║  - SSID enumeration and hidden network detection                   ╚
```

---

## Discovery with `--fresh` (ignore session history)

```
exf> discover 192.168.1.0/24 --fresh

[*] Starting network discovery on 192.168.1.0/24
[*] --fresh flag: ignoring saved session data

... (full discovery output, same as above) ...

[*] 5 new session(s) created
```

---

## Session resume behavior (without `--fresh`)

When `discover` finds a host that was scanned before, it shows the previous session and resumes from pending modules:

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
[dim]Use 'discover 192.168.1.0/24 --fresh' to ignore history and rescan from zero

... (results table) ...

  192.168.1.100 [Hikvision] DS-7608NI-K2 -- 14 exploit module(s)
    use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260     VULN
    use exploits/cameras/hikvision/info_disclosure_cve_2017_7921  VULN
    use exploits/cameras/hikvision/psh_command_injection        tested
    use exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808  tested
    use exploits/cameras/hikvision/firmware_crypto_key_extract  tested
    use exploits/cameras/hikvision/psh_challenge_predictor      pending
    use exploits/cameras/hikvision/nvr_dvr_serial_privesc       pending
    ... and 5 more (pending)
```

---

## Discover single host

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

## Discover from targets file (`-T`)

### Targets file format

```
# targets.txt
# One IP or CIDR per line, blank lines and # comments ignored
192.168.1.0/24
10.0.0.1
172.16.0.0/23
# 192.168.2.0/24   (commented out)
```

### Interactive shell usage

```
exf> discover -T /path/to/targets.txt

[*] Multi-target scan from file: /path/to/targets.txt
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
    172.16.0.1   ... (12 entries) ...
```

### Non-interactive (`-T` as CLI flag)

```bash
python -m embedxpl -T /path/to/targets.txt
```

Output is identical. The tool scans all targets in parallel (up to 4 file workers) and exits after completion.

---

## No live hosts found

```
exf> discover 10.255.0.0/24

[*] Starting network discovery on 10.255.0.0/24
[*] [arp_ping] Sending ARP broadcast to 10.255.0.0/24
[WARN] No live hosts found on 10.255.0.0/24
```

---

## Invalid target

```
exf> discover not-an-ip

[-] Invalid target: 'not-an-ip'. Use IP or CIDR notation.

exf> discover 999.0.0.0/24

[-] Invalid target: '999.0.0.0/24'. Use IP or CIDR notation.
```

---

## Missing argument

```
exf> discover

[-] Usage: discover <subnet/CIDR>  |  discover -T <targets.txt>
```

---

## Discovery data stored per host

For each discovered host, `discover` stores in the session:

| Field | Description |
|-------|-------------|
| `ip` | IP address |
| `mac` | MAC address (if determinable via ARP) |
| `hostname` | DNS hostname or PTR record |
| `vendor` | Vendor guess from OUI + HTTP fingerprint |
| `model` | Model guess from banner/HTTP headers |
| `open_ports` | List of open TCP ports |
| `banners` | HTTP/Telnet/RTSP banner strings per port |
| `fingerprint_confidence` | 0.0–1.0 float, % certainty of vendor/model match |
| `matched_modules` | List of EmbedXPL module paths that match this host |
| `has_wireless` | True if wireless interfaces/SSIDs were detected |
| `wireless_ssids` | List of SSID names if detected |
| `wireless_recommendation` | Cross-reference message for WirelessXPL-Forge |

Use `sessions show <ip>` to inspect the stored data. See [16-sessions-command.md](16-sessions-command.md).

---

## WirelessXPL-Forge cross-reference

When `discover` finds a device with wireless interfaces, it prints a panel recommending WirelessXPL-Forge:

```
╔══════════════════════════════════════════════════════════════════════╗
║ WirelessXPL-Forge  RECOMMENDED                                        ║
║ 192.168.1.1 (TP-Link Unknown)  SSIDs: HomeNet_5G, HomeNet_2G         ║
║                                                                       ║
║ No wired exploit modules matched this host. WirelessXPL-Forge can    ║
║ test the wireless interface independently:                            ║
║  - WPA2/WPA3 handshake capture with hashcat/aircrack-ng              ║
║  - PMKID attack (clientless)                                          ║
║  - Deauthentication and evil twin attacks                             ║
║  pip install wirelessxpl && wfx                                       ╚
```

The panel is `RECOMMENDED` (magenta border) when no wired exploit modules matched, or `COMPLEMENTARY` (cyan border) when wired modules also matched.

---

## Timing reference

| Network size | Typical scan time |
|---|---|
| Single host | 3–8 seconds |
| /30 (4 hosts) | 5–12 seconds |
| /24 (256 hosts) | 30–90 seconds |
| /22 (1024 hosts) | 2–5 minutes |
| /16 (65536 hosts) | 20–60 minutes |

Timing depends on ARP response latency, open port count, and banner grab timeouts.
