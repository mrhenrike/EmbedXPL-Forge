# Generic Modules

**Language:** English (en-US). **pt-BR:** [../pt-BR/08-modulos-generic.md](../pt-BR/08-modulos-generic.md)

Generic modules operate across vendors and device classes — they target common protocols and services rather than vendor-specific vulnerabilities.

## Module Map

| Module | Path | Role |
|--------|------|------|
| `cve_lookup` | `generic/cve/cve_lookup` | Map CVE identifiers to local metadata |
| `snmp_bruteforce` | `generic/snmp/snmp_bruteforce` | SNMP community string guessing |
| `ssdp_msearch` | `generic/upnp/ssdp_msearch` | SSDP M-SEARCH discovery (basic) |
| `igd_exploit` | `generic/upnp/igd_exploit` | UPnP IGD full exploitation suite |
| `heartbleed` | `generic/heartbleed` | OpenSSL Heartbleed-oriented check |
| `shellshock` | `generic/shellshock` | CGI / Bash shellshock pattern tests |
| `wordlists` | `generic/wordlist` | Helpers around bundled wordlists |

## UPnP IGD Full Exploitation

`igd_exploit` is the most comprehensive UPnP module. It chains:

1. **SSDP M-SEARCH** — discovers all IGD services on the target
2. **Device description XML parsing** — extracts model, serial number, service list
3. **SCPD enumeration** — lists all available SOAP actions per service
4. **GetExternalIPAddress** — discloses WAN/external IP without authentication
5. **GetGenericPortMappingEntry** — enumerates all existing NAT port mappings
6. **AddPortMapping** — adds firewall bypass rules without authentication (CRITICAL)
7. **DeletePortMapping** — removes NAT rules
8. **GetStatusInfo / GetNATRSIPStatus** — WAN connection status and uptime
9. **WANCommonInterfaceConfig** — traffic statistics (bytes/packets sent/received, link type)
10. **ForceTermination** — WAN disconnect capability (DoS) — skipped by default
11. **Event SUBSCRIBE** — monitors WAN events in real-time

```text
EmbedXPL-Forge > use generic/upnp/igd_exploit
EmbedXPL-Forge (igd_exploit) > set target 192.168.1.1
EmbedXPL-Forge (igd_exploit) > show options
EmbedXPL-Forge (igd_exploit) > run

# Skip dangerous actions (ForceTermination):
EmbedXPL-Forge (igd_exploit) > set skip_dangerous yes
EmbedXPL-Forge (igd_exploit) > run

# Test specific external port for AddPortMapping:
EmbedXPL-Forge (igd_exploit) > set test_port 31337
EmbedXPL-Forge (igd_exploit) > run
```

## UPnP SSDP Discovery (basic)

```text
EmbedXPL-Forge > use generic/upnp/ssdp_msearch
EmbedXPL-Forge (ssdp_msearch) > set target 192.168.1.1
EmbedXPL-Forge (ssdp_msearch) > run
```

## CVE Lookup

```text
EmbedXPL-Forge > use generic/cve/cve_lookup
EmbedXPL-Forge (cve_lookup) > set cve CVE-2014-0160
EmbedXPL-Forge (cve_lookup) > run
```

## SNMP Bruteforce

```text
EmbedXPL-Forge > use generic/snmp/snmp_bruteforce
EmbedXPL-Forge (snmp_bruteforce) > set target 192.168.1.1
EmbedXPL-Forge (snmp_bruteforce) > run
```

Adjust options with `show options` before execution.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
