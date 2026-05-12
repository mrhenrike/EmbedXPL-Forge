# Scanners and AutoPwn

**Language:** English (en-US). **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

## AutoPwn

**AutoPwn** orchestrates fingerprinting and module selection workflows. Load the AutoPwn module with `use`, set `target` (and interface options if required), then `run` - behavior is defined inside the module's `run()` implementation.

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.0/24
exf (AutoPwn) > run
[*] Discovery phase: scanning 254 hosts
[+] Discovered: 192.168.1.1 (Huawei EG8145X6)
[*] Testing 9 modules for this target...
[+] VULNERABLE: eg8145x6_csrf_static_token (CVSS 9.1)
[+] VULNERABLE: eg8145x6_info_disclosure (pre-auth)
```

## Device-oriented scanners

| Module | Role |
|--------|------|
| `router_scan` | Router-focused discovery / chaining entry point |
| `hootoo_scan` | Hootoo-oriented scanner workflow |
| `soho_discover` | Universal SOHO HTTP discovery (fingerprints 12+ vendor signatures) |
| `scanners/printers/hp_rawprint_9100` | HP PJL scanner via port 9100 |
| `scanners/protocols/iot/upnp_ssdp_scan` | UPnP/SSDP device enumeration |
| `scanners/embedded_os/mdns_iot_discovery` | mDNS/Bonjour IoT device discovery |
| `scanners/threat_detection/mirai_default_creds_sweep` | Mirai botnet default credential sweep |
| `scanners/threat_detection/gpon_exploitation_scan` | GPON vulnerability scanner |

### Printer-specific scanners (new in v3.1.0)

Use `exploits/printers/generic/wsd_printer_enum` for WSD/mDNS printer discovery:

```text
exf > use exploits/printers/generic/wsd_printer_enum
exf (WSD Printer Enum) > set target 239.255.255.250
exf (WSD Printer Enum) > set timeout 8
exf (WSD Printer Enum) > run
[*] WSD probe on 239.255.255.250:3702 (8s)
[+] Discovered 3 WSD device(s):
IP              Endpoint            Types              XAddrs
192.168.1.100   urn:uuid:abc123...  wsdl:Service       http://192.168.1.100:80/
192.168.1.101   urn:uuid:def456...  d:Device           http://192.168.1.101:631/
192.168.1.102   urn:uuid:ghi789...  d:Device           http://192.168.1.102:80/
```

## OUI Vendor Lookup

The `discover` command resolves MAC addresses to vendors using:

1. Session cache (instant)
2. Online APIs (`macvendors.com`, `maclookup.app`)
3. Local IEEE database (`embedxpl/data/oui.txt` - 39,000+ entries)

```text
exf > discover 192.168.1.0/24
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY COMMUNICATION (Mercusys/TP-Link)
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[+] Suggested modules for 192.168.1.1:
    - exploits/routers/zte/zxhn_h168n_rce_auth_bypass
    - creds/routers/zte/ftp_default_creds
```

## Typical options

| Option | Role |
|--------|------|
| `target` | Host or network under test |
| `port` | Service port when not implied |
| `threads` | Concurrency for network-heavy phases |
| `timeout` | Per-probe timeout in seconds |

Always confirm scope and rate limits before running scanners on live networks.

## Phase Gate Tool (new in v3.1.0)

`tools/phase_gate.py` is the automated quality gate system used internally to validate all modules:

```bash
# List available gates
python tools/phase_gate.py --list

# Validate specific track
python tools/phase_gate.py --phase A1A2   # printer EDB/MSF ports
python tools/phase_gate.py --phase B      # 2026 CVE primary batch
python tools/phase_gate.py --phase C      # 2026 CVE extended
python tools/phase_gate.py --phase A3     # printer research modules
python tools/phase_gate.py --phase D      # 2025/2024 backlog CVEs

# Run all gates (full validation suite)
python tools/phase_gate.py --all
```

Expected output (pass):

```text
============================================================
  GATE B
============================================================
  [ PASS ] import:gnu_inetutils_telnetd_auth_bypass
  [ PASS ] import:cups_pwn2own_chain_cve_2026_34480
  [ PASS ] cvss_present
  [ PASS ] cups_chain_stages    (3 .run() calls confirmed)
  [ PASS ] indexed              (All 11 modules indexed)
  [ PASS ] total_module_count   (2760 modules indexed)

Results: 27/27 passed  (all passed)
Gate B PASSED.
```


[Wiki hub](../README.md)
