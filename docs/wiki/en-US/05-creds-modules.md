# Credential Modules

**Language:** English (en-US) | **pt-BR:** [../pt-BR/05-modulos-creds.md](../pt-BR/05-modulos-creds.md)

---

## Overview

Credential modules test **SSH**, **Telnet**, **FTP**, **HTTP Basic/Digest**, **SNMP**, and vendor-specific login interfaces against **authorized** targets using default or custom credential lists.

---

## Module locations

```
embedxpl/modules/creds/
├── routers/       # 1200+ modules — 85+ vendor folders
├── cameras/       # Hikvision, Dahua, Reolink, Axis...
├── firewalls/     # Fortinet, Cisco, Palo Alto, SonicWall...
├── printers/      # HP, Canon, Lexmark...
├── switches/      # Cisco, D-Link, NETGEAR...
├── nas/           # QNAP, Synology...
├── iot/           # Generic IoT services
├── generic/       # Protocol-level credential modules
└── ...
```

---

## Typical workflow

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) > set target 192.168.1.1
[+] target => 192.168.1.1

exf (telnet_default_creds) > set port 23
exf (telnet_default_creds) > set threads 5
exf (telnet_default_creds) > set stop_on_success true
exf (telnet_default_creds) > run

[*] Running telnet_default_creds against 192.168.1.1:23
[*] Trying admin:admin
[*] Trying admin:1234
[+] SUCCESS: admin:1234 -- telnet shell obtained
```

---

## Common options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Target hostname or IP; also `file://path` for multi-target |
| `port` | `OptPort` | (protocol default) | Service port |
| `threads` | `OptInteger` | `8` | Number of parallel connection threads |
| `defaults` | `OptBool` | `true` | Try vendor-specific default credential pairs |
| `stop_on_success` | `OptBool` | `true` | Stop after first successful credential |
| `verbosity` | `OptBool` | `false` | Show every attempt (verbose mode) |
| `timeout` | `OptInteger` | `10` | Per-connection timeout in seconds |

---

## Protocol-specific defaults

| Protocol | Default port | Module path pattern |
|----------|-------------|---------------------|
| Telnet | 23 | `creds/routers/<vendor>/telnet_default_creds` |
| SSH | 22 | `creds/routers/<vendor>/ssh_default_creds` |
| FTP | 21 | `creds/routers/<vendor>/ftp_default_creds` |
| HTTP | 80 | `creds/routers/<vendor>/webinterface_default_creds` |
| HTTPS | 443 | `creds/routers/<vendor>/webinterface_default_creds` |
| SNMP | 161 | `creds/generic/snmp_community_bruteforce` |

---

## Wordlists

Bundled wordlists are in `embedxpl/resources/wordlists/vendors/`, one per vendor:

```text
exf (telnet_default_creds) > show wordlists

 Wordlist         URI
─────────────────────────────────────────────────
 dlink_defaults   file:///...embedxpl/resources/wordlists/vendors/dlink_defaults.txt
```

Use a custom wordlist with:

```text
exf (telnet_default_creds) > set defaults file:///path/to/my_wordlist.txt
```

Wordlist format — one entry per line, colon-separated:

```
admin:admin
admin:password
admin:1234
root:root
user:user
```

---

## Examples

### SSH credential test (TP-Link router)

```text
exf > use creds/routers/tplink/ssh_default_creds
exf (ssh_default_creds) > set target 192.168.0.1
exf (ssh_default_creds) > run
[*] Trying admin:admin on 192.168.0.1:22
[-] FAIL: admin:admin
[*] Trying admin:tplink on 192.168.0.1:22
[+] SUCCESS: admin:tplink -- SSH session opened
```

### HTTP credential test (Hikvision camera)

```text
exf > use creds/cameras/hikvision/webinterface_default_creds
exf (webinterface_default_creds) > set target 192.168.1.100
exf (webinterface_default_creds) > set port 80
exf (webinterface_default_creds) > run
[*] Trying admin:12345 on http://192.168.1.100:80
[+] SUCCESS: admin:12345 (HTTP 200)
```

### SNMP community string test

```text
exf > use creds/generic/snmp_community_bruteforce
exf (snmp_community_bruteforce) > set target 192.168.1.1
exf (snmp_community_bruteforce) > run
[*] Testing community: public
[+] VALID: public (SNMPv1 get-request succeeded)
[*] Testing community: private
[+] VALID: private
```

### Multi-target credential test

```bash
# hosts.txt:
# 192.168.1.1
# 192.168.1.2
# 192.168.1.3
embedxpl -m creds/routers/dlink/telnet_default_creds -s "target file:///tmp/hosts.txt"
```

---

## Generic credential modules

| Module | Path | Protocols |
|--------|------|-----------|
| SNMP community bruteforce | `creds/generic/snmp_community_bruteforce` | SNMP |
| Telnet default | `creds/generic/telnet_default` | Telnet |
| SSH generic | `creds/generic/ssh_default` | SSH |
| HTTP basic auth | `creds/generic/http_basic_auth_bruteforce` | HTTP |
| FTP default | `creds/generic/ftp_default` | FTP |


[Wiki hub](../README.md)
