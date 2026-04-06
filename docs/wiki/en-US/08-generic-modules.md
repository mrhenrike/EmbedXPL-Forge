# Generic Modules

**Language:** English (en-US). **pt-BR:** [../pt-BR/08-modulos-generic.md](../pt-BR/08-modulos-generic.md)

## Module map

| Module | Role |
|--------|------|
| `cve_lookup` | Map CVE identifiers to local metadata |
| `snmp_bruteforce` | SNMP community guessing |
| `ssdp_msearch` | SSDP `M-SEARCH` discovery |
| `heartbleed` | OpenSSL Heartbleed-oriented check |
| `shellshock` | CGI / Bash `shellshock` pattern tests |
| `wordlists` | Helpers around bundled wordlists |

## CVE lookup example

```text
RouterXPL-Forge > use generic/cve_lookup
RouterXPL-Forge (cve_lookup) > set cve CVE-2014-0160
RouterXPL-Forge (cve_lookup) > run
```

## UPnP discovery example

```text
RouterXPL-Forge > use generic/ssdp_msearch
RouterXPL-Forge (ssdp_msearch) > run
```

Adjust options with `show options` before execution.

---

[Wiki hub](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
