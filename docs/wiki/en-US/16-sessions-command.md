# sessions Command

**Language:** English (en-US) | **pt-BR:** [../pt-BR/16-comando-sessions.md](../pt-BR/16-comando-sessions.md)

---

## Overview

`sessions` manages scan session history. Every time `discover` or a module runs against a target, EmbedXPL-Forge records the result in a per-host session file (`~/.exf_sessions/`). Sessions persist between restarts and work like John the Ripper's `--restore` — resuming from where the last scan stopped.

---

## Syntax

```
sessions                        List all saved sessions
sessions list                   Same as above
sessions show <ip>              Show detailed session for a host
sessions delete <ip>            Delete session for a specific host
sessions export <ip>            Export session as JSON
sessions purge                  Delete ALL sessions (asks confirmation)
```

---

## `sessions` / `sessions list` — list all sessions

### Output (sessions exist)

```
exf> sessions

┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                      Saved Sessions (4)                                                                │
├───┬─────────────────┬───────────────────┬──────────────────┬──────────────────┬───────┬────────┬─────────┬───────┬────────────────────┬──────────┐
│ # │ IP              │ MAC               │ Vendor           │ Model            │ Scans │ Tested │ Pending │ Vulns │ Last Scan          │ ID       │
├───┼─────────────────┼───────────────────┼──────────────────┼──────────────────┼───────┼────────┼─────────┼───────┼────────────────────┼──────────┤
│ 1 │ 192.168.1.1     │ EC:08:6B:1A:2C:40 │ TP-Link          │ TL-WR841N        │   3   │   4    │    2    │   1   │ 2026-06-01 14:30   │ a3f9b21c │
│ 2 │ 192.168.1.100   │ AC:CC:8E:5A:10:F2 │ Hikvision        │ DS-7608NI-K2     │   2   │   9    │    5    │   2   │ 2026-05-29 14:32   │ c7e2d4a1 │
│ 3 │ 192.168.1.200   │ 00:09:0F:AA:00:01 │ Fortinet         │ FortiGate-200F   │   1   │   4    │    8    │   0   │ 2026-05-30 09:15   │ f1b8c392 │
│ 4 │ 10.0.0.1        │ 00:1A:2B:3C:4D:5E │ Cisco            │ IOS XE           │   1   │   2    │    1    │   0   │ 2026-05-28 11:00   │ 8d3c1a2b │
└───┴─────────────────┴───────────────────┴──────────────────┴──────────────────┴───────┴────────┴─────────┴───────┴────────────────────┴──────────┘

[dim]Use 'sessions show <ip>' for details
```

### Column descriptions

| Column | Description |
|--------|-------------|
| `#` | Row index |
| `IP` | Target IP address |
| `MAC` | MAC address (from ARP) |
| `Vendor` | Detected device vendor |
| `Model` | Detected device model |
| `Scans` | Total number of times this host was scanned |
| `Tested` | Number of exploit modules run against this host |
| `Pending` | Matched modules not yet tested |
| `Vulns` | Number of confirmed vulnerabilities |
| `Last Scan` | Timestamp of the most recent scan |
| `ID` | First 8 characters of the session host ID (SHA-based) |

### Output (no sessions)

```
exf> sessions

[*] No saved sessions. Run 'discover <target>' to create one.
```

---

## `sessions show <ip>` — session detail

### Output

```
exf> sessions show 192.168.1.100

╔══════════════════════════════════════════════════════════════╗
║                      Session Detail                          ║
╠══════════════════════════════════════════════════════════════╣
║ 192.168.1.100 (AC:CC:8E:5A:10:F2)                           ║
║ Vendor: Hikvision  Model: DS-7608NI-K2                      ║
║ First seen: 2026-05-28 10:14  Last scan: 2026-05-29 14:32   ║
║ Total scans: 2  Ports: 80,443,554,8000,37777                ║
║ WiFi: No                                                     ║
╚══════════════════════════════════════════════════════════════╝

Module Execution Summary:
  Matched:  14
  Tested:    9
  Pending:   5
  Vuln:      2
  Safe:      6
  Errored:   1

Confirmed Vulnerabilities:
  • exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  • exploits/cameras/hikvision/info_disclosure_cve_2017_7921

Pending Modules (not yet tested):
  • exploits/cameras/hikvision/psh_challenge_predictor
  • exploits/cameras/hikvision/nvr_dvr_serial_privesc
  • exploits/cameras/hikvision/r0_intercom_gpio_door_unlock
  • exploits/cameras/hikvision/r0_intercom_ssh_default_bypass
  • exploits/cameras/hikvision/firmware_crypto_key_extract

Execution History (last 20):
┌───────────────────────────────────────────────────┬───────────────┬─────────────┬─────────┐
│ Module                                            │ Result        │ Time        │ Elapsed │
├───────────────────────────────────────────────────┼───────────────┼─────────────┼─────────┤
│ rtsp_rce_cve_2021_36260                           │ VULNERABLE    │ 05-29 14:28 │   3.2s  │
│ info_disclosure_cve_2017_7921                     │ VULNERABLE    │ 05-29 14:25 │   1.8s  │
│ psh_command_injection                             │ safe          │ 05-29 14:22 │   2.1s  │
│ psh_debug_rsa1024_bypass                          │ safe          │ 05-29 14:20 │   1.4s  │
│ nas_auth_bypass_cve_2023_28808                    │ safe          │ 05-29 14:18 │   2.9s  │
│ r0_intercom_3des_decrypt                          │ safe          │ 05-29 14:15 │   1.1s  │
│ r0_intercom_developer_nfs                         │ safe          │ 05-29 14:12 │   0.8s  │
│ r0_intercom_ssh_mitm                              │ safe          │ 05-29 14:10 │   3.5s  │
│ r0_intercom_suid_privesc                          │ error         │ 05-28 10:20 │   0.5s  │
└───────────────────────────────────────────────────┴───────────────┴─────────────┴─────────┘
```

### Error — session not found

```
exf> sessions show 192.168.99.99

[WARN] No session found for 192.168.99.99
```

### Error — missing argument

```
exf> sessions show

[-] Usage: sessions show <ip>
```

---

## `sessions delete <ip>` — delete one session

```
exf> sessions delete 192.168.1.100

[+] Session for 192.168.1.100 deleted
```

### Not found

```
exf> sessions delete 192.168.99.99

[WARN] No session found for 192.168.99.99
```

### Missing argument

```
exf> sessions delete

[-] Usage: sessions delete <ip>
```

---

## `sessions export <ip>` — export session as JSON

Exports the full session record as a JSON object printed to stdout.

```
exf> sessions export 192.168.1.100

{
  "host_id": "c7e2d4a1b3f92e8a1c7d4e5f6a0b1c2d",
  "ip": "192.168.1.100",
  "mac": "AC:CC:8E:5A:10:F2",
  "vendor": "Hikvision",
  "model": "DS-7608NI-K2",
  "hostname": "DVR-001",
  "first_seen": 1748428440.0,
  "last_scanned": 1748514720.0,
  "total_scans": 2,
  "open_ports": [80, 443, 554, 8000, 37777],
  "banners": {
    "80": "Server: App-webs/",
    "554": "RTSP/1.0 401 Unauthorized"
  },
  "fingerprint_confidence": 0.88,
  "matched_modules": [
    "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260",
    "exploits/cameras/hikvision/info_disclosure_cve_2017_7921",
    "exploits/cameras/hikvision/psh_command_injection",
    "exploits/cameras/hikvision/psh_debug_rsa1024_bypass",
    "exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808",
    "exploits/cameras/hikvision/r0_intercom_3des_decrypt",
    "exploits/cameras/hikvision/r0_intercom_developer_nfs",
    "exploits/cameras/hikvision/r0_intercom_ssh_mitm",
    "exploits/cameras/hikvision/r0_intercom_suid_privesc",
    "exploits/cameras/hikvision/psh_challenge_predictor",
    "exploits/cameras/hikvision/nvr_dvr_serial_privesc",
    "exploits/cameras/hikvision/r0_intercom_gpio_door_unlock",
    "exploits/cameras/hikvision/r0_intercom_ssh_default_bypass",
    "exploits/cameras/hikvision/firmware_crypto_key_extract"
  ],
  "module_results": [
    {
      "module_path": "embedxpl.modules.exploits.cameras.hikvision.rtsp_rce_cve_2021_36260",
      "vulnerable": true,
      "error": null,
      "elapsed_s": 3.2,
      "port": 554,
      "timestamp": 1748514708.0
    },
    {
      "module_path": "embedxpl.modules.exploits.cameras.hikvision.info_disclosure_cve_2017_7921",
      "vulnerable": true,
      "error": null,
      "elapsed_s": 1.8,
      "port": 80,
      "timestamp": 1748514684.0
    },
    ...
  ],
  "vulns_found": [
    "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260",
    "exploits/cameras/hikvision/info_disclosure_cve_2017_7921"
  ],
  "has_wireless": false,
  "wireless_ssids": [],
  "notes": []
}
```

### Save to file

```bash
# Pipe to file (from shell, not EmbedXPL prompt)
python -m embedxpl -m sessions -s "export 192.168.1.100" > session_192.168.1.100.json
```

### Not found

```
exf> sessions export 192.168.99.99

[WARN] No session found for 192.168.99.99
```

---

## `sessions purge` — delete ALL sessions

Requires explicit confirmation.

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: yes

[+] Purged 4 session(s)
```

### Cancelled

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: no

[*] Cancelled
```

### Keyboard interrupt (Ctrl+C)

```
exf> sessions purge

WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: ^C
[*] Cancelled
```

---

## Unknown subcommand

```
exf> sessions foo

[-] Unknown sub-command 'foo'. Use: list, show, delete, export, purge
```

---

## Session storage location

Sessions are stored as JSON files in `~/.exf_sessions/` (one file per host, named by SHA-based host ID):

```
~/.exf_sessions/
  a3f9b21c...json      # 192.168.1.1
  c7e2d4a1...json      # 192.168.1.100
  f1b8c392...json      # 192.168.1.200
  8d3c1a2b...json      # 10.0.0.1
```

The host ID is derived from a hash of `ip:mac` (or just `ip` if MAC is unavailable), making sessions stable across IP re-assignments when MAC persists.

---

## How sessions interact with `discover`

When `discover` runs and finds a previously-scanned host:

1. Loads the existing session
2. Displays the session age, tested count, and known vulnerabilities
3. Shows which modules are tested (green), vulnerable (red), and pending (dim)
4. Merges new discovery data (updated ports, banners, confidence)
5. Saves the updated session

Use `--fresh` to reset: `discover 192.168.1.0/24 --fresh`

Use `sessions delete 192.168.1.100` to delete a specific host session and start clean.
