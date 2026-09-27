# Credential Modules

**Language:** English (en-US) | **pt-BR:** [../pt-BR/05-modulos-creds.md](../pt-BR/05-modulos-creds.md)

---

## Overview

Credential modules test **SSH**, **Telnet**, **FTP**, **HTTP Basic/Digest/Form**, **SNMP**, and vendor-specific login interfaces against **authorized** targets using built-in default credential lists or custom wordlists.

Each credential module inherits from a generic protocol base class and adds vendor-specific default credential pairs. All modules run dictionary attacks with configurable concurrency and behavior.

> **Authorization required.** Use only on systems you own or have explicit written permission to test.

---

## Module directory structure

```
embedxpl/modules/creds/
├── cameras/        IP cameras, NVRs, DVRs — 40+ camera vendor folders
│   ├── acti/           ftp_default_creds, ssh_default_creds, telnet_default_creds, webinterface_http_form_default_creds
│   ├── american_dynamics/
│   ├── arecont/
│   ├── avigilon/
│   ├── avtech/
│   ├── axis/           + webinterface_http_auth_default_creds
│   ├── basler/         + webinterface_http_form_default_creds
│   ├── bosch/          + webinterface_http_auth_default_creds
│   ├── brickcom/       + webinterface_http_auth_default_creds
│   ├── canon/          + webinterface_http_auth_default_creds
│   ├── cbc_ganz/       + webinterface_http_auth_default_creds
│   ├── cisco/
│   ├── dahua/          + webinterface_http_auth_default_creds
│   ├── dlink/
│   ├── dvtel/          + webinterface_http_auth_default_creds
│   ├── dynacolor/      + webinterface_http_auth_default_creds
│   ├── everfocus/      + webinterface_http_auth_default_creds
│   ├── flir/           + webinterface_http_auth_default_creds
│   ├── foscam/         + webinterface_http_auth_default_creds
│   ├── geovision/
│   ├── grandstream/
│   ├── hikvision/      ftp, ssh, telnet
│   ├── honeywell/
│   ├── intelbras/      webinterface_default_creds
│   └── ...many more...
│
├── bmc/            Baseboard Management Controllers
│   ├── asus_asmb/
│   ├── dell_idrac/
│   └── supermicro/
│
└── (routers, firewalls, switches, nas, printers — many vendor subfolders)
```

---

## Common options (all credential modules)

| Option | Type | Required | Default | Accepted values | Description |
|--------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4, IPv6, hostname, `file://path` | Target host or file with IPs (one per line for multi-target) |
| `port` | `OptPort` | No | Protocol default | 1–65535 | Service port to test |
| `threads` | `OptInteger` | No | `8` | 1–300 | Number of parallel connection threads |
| `defaults` | `OptWordlist` | No | Vendor-specific | `user:pass`, comma-separated pairs, or `file://path` | Credential list to try |
| `stop_on_success` | `OptBool` | No | `True` | `true`, `false` | Stop testing after first successful credential |
| `verbosity` | `OptBool` | No | `True` | `true`, `false` | Show each credential attempt in the output |
| `timeout` | `OptInteger` | No | `10` | 1–120 | Per-connection timeout in seconds |

**Protocol default ports:**

| Protocol | Default port |
|----------|-------------|
| Telnet | 23 |
| SSH | 22 |
| FTP | 21 |
| HTTP Basic/Digest | 80 |
| HTTP Form / HTTPS | 443 |
| SNMP | 161 |

---

## Module types by protocol

### `telnet_default_creds` — Telnet

Tests Telnet login with vendor default credentials. Uses `telnetlib3` on Python 3.13+ and `telnetlib` on earlier versions.

**Terminal session (Hikvision camera):**

```text
exf > use creds/cameras/hikvision/telnet_default_creds
exf (Hikvision Camera Default Telnet Creds) > show options

Target options:
┌────────┬──────────────────┬───────────────────────────────────────────────────┐
│ Name   │ Current settings │ Description                                       │
├────────┼──────────────────┼───────────────────────────────────────────────────┤
│ target │                  │ Target IPv4, IPv6 address or file with ip:port    │
│ port   │ 23               │ Target Telnet port                                │
└────────┴──────────────────┴───────────────────────────────────────────────────┘

Module options:
┌──────────────────┬──────────────────┬────────────────────────────────────────────────────┐
│ Name             │ Current settings │ Description                                        │
├──────────────────┼──────────────────┼────────────────────────────────────────────────────┤
│ threads          │ 8                │ Number of threads                                  │
│ defaults         │ admin:12345      │ User:Pass or file with default credentials (file://)│
│ stop_on_success  │ True             │ Stop on first valid authentication attempt         │
│ verbosity        │ True             │ Display authentication attempts                    │
└──────────────────┴──────────────────┴────────────────────────────────────────────────────┘

exf (Hikvision Camera Default Telnet Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[+] SUCCESS: admin:12345 — telnet session obtained
```

**Terminal session (all credentials fail):**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[-] FAIL: admin:12345
[-] No valid credentials found
```

**Terminal session (Dahua camera — multiple defaults):**

```text
exf > use creds/cameras/dahua/telnet_default_creds
exf (Dahua Camera/DVR/NVR Default Telnet Creds) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua Camera/DVR/NVR Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:admin on 192.168.1.50:23
[-] FAIL: admin:admin
[*] Trying 888888:888888 on 192.168.1.50:23
[+] SUCCESS: 888888:888888 — telnet session obtained
```

---

### `ssh_default_creds` — SSH

Tests SSH login with vendor default credentials using Paramiko.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Target IP or file:// |
| `port` | `OptPort` | `22` | SSH port |
| `threads` | `OptInteger` | `8` | Concurrency |
| `defaults` | `OptWordlist` | Vendor-specific | Default credential pairs |
| `stop_on_success` | `OptBool` | `True` | Stop on first success |
| `verbosity` | `OptBool` | `True` | Show attempts |

**Terminal session (Hikvision camera SSH):**

```text
exf > use creds/cameras/hikvision/ssh_default_creds
exf (Hikvision Camera Default SSH Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default SSH Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:22
[-] FAIL: admin:12345
[*] Trying root:hikadmin on 192.168.1.100:22
[+] SUCCESS: root:hikadmin — SSH session opened
```

**Terminal session (Axis camera SSH):**

```text
exf > use creds/cameras/axis/ssh_default_creds
exf (Axis Camera Default SSH Creds) > set target 192.168.1.110
[+] target => 192.168.1.110
exf (Axis Camera Default SSH Creds) > run
[*] Running module ...
[*] Trying root: on 192.168.1.110:22
[+] SUCCESS: root: (empty password) — SSH session opened
```

---

### `ftp_default_creds` — FTP

Tests FTP login using vendor default credentials.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Target IP or file:// |
| `port` | `OptPort` | `21` | FTP port |
| `threads` | `OptInteger` | `8` | Concurrency |
| `defaults` | `OptWordlist` | Vendor-specific | Default credential pairs |
| `stop_on_success` | `OptBool` | `True` | Stop on first success |
| `verbosity` | `OptBool` | `True` | Show attempts |

**Terminal session:**

```text
exf > use creds/cameras/hikvision/ftp_default_creds
exf (Hikvision Camera Default FTP Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default FTP Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:21
[+] SUCCESS: admin:12345 — FTP session opened
230 Login successful.
```

---

### `webinterface_http_auth_default_creds` — HTTP Basic/Digest Auth

Tests HTTP Basic authentication or Digest authentication endpoints with vendor default credentials.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Target IP |
| `port` | `OptPort` | `80` | HTTP port |
| `ssl` | `OptBool` | `False` | Use HTTPS |
| `threads` | `OptInteger` | `8` | Concurrency |
| `defaults` | `OptWordlist` | Vendor-specific | Default credential pairs |
| `stop_on_success` | `OptBool` | `True` | Stop on first success |

**Terminal session (Dahua camera web interface):**

```text
exf > use creds/cameras/dahua/webinterface_http_auth_default_creds
exf (Dahua Camera/DVR/NVR Default HTTP Auth Creds) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua Camera/DVR/NVR Default HTTP Auth Creds) > set port 80
[+] port => 80
exf (Dahua Camera/DVR/NVR Default HTTP Auth Creds) > run
[*] Running module ...
[*] Trying admin:admin on http://192.168.1.50:80
[-] FAIL: admin:admin (HTTP 401)
[*] Trying admin:888888 on http://192.168.1.50:80
[+] SUCCESS: admin:888888 (HTTP 200)
```

**Terminal session (Axis camera HTTP auth):**

```text
exf > use creds/cameras/axis/webinterface_http_auth_default_creds
exf (Axis Camera Default HTTP Auth Creds) > set target 192.168.1.110
[+] target => 192.168.1.110
exf (Axis Camera Default HTTP Auth Creds) > run
[*] Running module ...
[*] Trying root: on http://192.168.1.110:80
[+] SUCCESS: root: (empty password) — HTTP 200
```

---

### `webinterface_http_form_default_creds` — HTTP Form Login

Tests vendor-specific HTTP login form endpoints (POST-based authentication).

**Terminal session (ACTi camera):**

```text
exf > use creds/cameras/acti/webinterface_http_form_default_creds
exf (ACTi Camera Default HTTP Form Creds) > set target 192.168.1.120
[+] target => 192.168.1.120
exf (ACTi Camera Default HTTP Form Creds) > run
[*] Running module ...
[*] Trying admin:123456 on http://192.168.1.120:80/cgi-bin/encoder?USER=admin&PWD=123456
[+] SUCCESS: admin:123456 — HTTP form login successful
```

---

### `webinterface_default_creds` — Intelbras cameras

Intelbras cameras use a combined web interface module:

```text
exf > use creds/cameras/intelbras/webinterface_default_creds
exf (Intelbras Camera Default Creds) > set target 192.168.1.130
[+] target => 192.168.1.130
exf (Intelbras Camera Default Creds) > run
[*] Running module ...
[*] Trying admin:admin on 192.168.1.130:80
[+] SUCCESS: admin:admin — web session obtained
```

---

## Vendor coverage (cameras)

The following camera vendors have at least one credential module (`ftp_default_creds`, `ssh_default_creds`, `telnet_default_creds`, and/or `webinterface_*_default_creds`):

| Vendor | ftp | ssh | telnet | webinterface |
|--------|-----|-----|--------|--------------|
| ACTi | Yes | Yes | Yes | form |
| American Dynamics | Yes | Yes | Yes | — |
| Arecont | Yes | Yes | Yes | auth |
| Avigilon | Yes | Yes | Yes | — |
| AVTech | Yes | Yes | Yes | — |
| Axis | Yes | Yes | Yes | auth |
| Basler | Yes | Yes | Yes | form |
| Bosch | Yes | Yes | Yes | auth |
| Brickcom | Yes | Yes | Yes | auth |
| Canon | Yes | Yes | Yes | auth |
| CBC/GANZ | Yes | Yes | Yes | auth |
| Cisco (cameras) | Yes | Yes | Yes | — |
| Dahua | Yes | Yes | Yes | auth |
| D-Link (cameras) | Yes | Yes | Yes | — |
| DVTel | Yes | Yes | Yes | auth |
| Dynacolor | Yes | Yes | Yes | auth |
| EverFocus | Yes | Yes | Yes | auth |
| FLIR | Yes | Yes | Yes | auth |
| Foscam | Yes | Yes | Yes | auth |
| GeoVision | Yes | Yes | Yes | — |
| Grandstream | Yes | Yes | Yes | — |
| Hikvision | Yes | Yes | Yes | — |
| Honeywell | Yes | Yes | Yes | — |
| Intelbras | — | — | — | combined |

---

## Multi-target credential testing

Use `file://` protocol for the `target` option to test multiple hosts from a file:

```text
exf > use creds/cameras/hikvision/telnet_default_creds
exf (Hikvision Camera Default Telnet Creds) > set target file:///tmp/hikvision_hosts.txt
[+] target => file:///tmp/hikvision_hosts.txt
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[*] Trying admin:12345 on 192.168.1.101:23
[*] Trying admin:12345 on 192.168.1.102:23
[+] SUCCESS: admin:12345 on 192.168.1.100:23
[+] SUCCESS: admin:12345 on 192.168.1.102:23
[-] FAIL: all credentials exhausted for 192.168.1.101
```

`/tmp/hikvision_hosts.txt` format:

```text
192.168.1.100
192.168.1.101
192.168.1.102:23
```

---

## Custom wordlist

Override the built-in defaults with a custom wordlist file:

```text
exf (Hikvision Camera Default Telnet Creds) > set defaults file:///tmp/custom_creds.txt
[+] defaults => file:///tmp/custom_creds.txt
```

Wordlist format — one credential pair per line, colon-separated:

```text
admin:admin
admin:password
admin:12345
admin:
root:root
root:
guest:guest
service:service
```

---

## Non-interactive examples

### Telnet scan (D-Link router)

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds -s "target 192.168.1.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.1.1:23
[-] FAIL: admin:admin
[*] Trying admin:1234 on 192.168.1.1:23
[+] SUCCESS: admin:1234 — telnet session obtained
```

### SSH scan (TP-Link router)

```bash
embedxpl -m creds/routers/tplink/ssh_default_creds -s "target 192.168.0.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.0.1:22
[-] FAIL: admin:admin
[*] Trying admin:tplink on 192.168.0.1:22
[+] SUCCESS: admin:tplink — SSH session opened
```

### HTTPS web interface (Dahua camera)

```bash
embedxpl \
    -m creds/cameras/dahua/webinterface_http_auth_default_creds \
    -s "target 192.168.1.50" \
    -s "port 443" \
    -s "ssl true"
```

```text
[*] Running module ...
[*] Trying admin:admin on https://192.168.1.50:443
[-] FAIL: admin:admin (HTTP 401)
[*] Trying admin:888888 on https://192.168.1.50:443
[+] SUCCESS: admin:888888 (HTTP 200)
```

### Multi-target from file

```bash
embedxpl \
    -m creds/cameras/hikvision/telnet_default_creds \
    -s "target file:///tmp/hosts.txt" \
    -s "threads 16" \
    -s "stop_on_success false"
```

```text
[*] Multi-target mode: file:///tmp/hosts.txt
[*] Trying admin:12345 on 192.168.1.100:23
[*] Trying admin:12345 on 192.168.1.101:23
[+] SUCCESS: admin:12345 on 192.168.1.100:23
[-] FAIL on 192.168.1.101 — no valid credentials
```

---

## Viewing bundled wordlists

```text
exf (telnet_default_creds) > show wordlists

┌────────────────────────┬──────────────────────────────────────────────────────────────────────┐
│ Wordlist               │ Path                                                                 │
├────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ hikvision_defaults.txt │ file:///usr/local/lib/python3.11/site-packages/embedxpl/resources/.. │
│ common_passwords.txt   │ file:///usr/local/lib/python3.11/site-packages/embedxpl/resources/.. │
└────────────────────────┴──────────────────────────────────────────────────────────────────────┘
```

---

## Error cases

**Target not specified:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[-] target is required but not set
```

**Connection refused:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Trying admin:12345 on 192.168.1.100:23
[-] Connection refused: 192.168.1.100:23
```

**Connection timeout:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Trying admin:12345 on 192.168.1.100:23
[-] Connection timed out after 10s: 192.168.1.100:23
```

**Invalid file path:**

```text
exf (Hikvision Camera Default Telnet Creds) > set target file:///nonexistent/hosts.txt
[+] target => file:///nonexistent/hosts.txt
exf (Hikvision Camera Default Telnet Creds) > run
[-] File not found: /nonexistent/hosts.txt
```

---

## SNMP community bruteforce (generic)

SNMP community string testing is available via:
- `generic/snmp/snmp_bruteforce` — standalone generic SNMP bruteforcer
- `creds/generic/snmp_community_bruteforce` (if present)

See [08-generic-modules.md](08-generic-modules.md#snmp-modules) for the SNMP module reference.

---

## Tips

1. Set `verbosity false` to suppress per-attempt output when running batch scans.
2. Set `threads 16` for faster scanning on LAN targets (default 8).
3. Use `stop_on_success false` to collect all valid credentials (e.g., when multiple accounts have default passwords).
4. Combine with `discover` to find hosts and then target them: discover → get IPs → feed to creds module via `file://`.
5. For routers with SNMP: always try `public` and `private` community strings — they are embedded defaults across most vendors.


[Wiki hub](../README.md)
