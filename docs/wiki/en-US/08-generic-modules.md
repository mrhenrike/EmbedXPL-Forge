# `generic` modules (CVE, wordlist, SNMP, UPnP, external)

**Language:** English (en-US). **pt-BR:** [../pt-BR/08-modulos-generic.md](../pt-BR/08-modulos-generic.md)

## CVE — `generic/cve/cve_lookup`

Queries the **embedded** CVE database.

```text
use generic/cve/cve_lookup
set vendor cisco
set product rv320
run
```

Options: `banner`, `product`, `version`, `remote_only`, `show_physical`.

## Exploit-DB (offline CSV) — `generic/external/exploitdb_embedded_lookup`

Searches **`files_exploits.csv`** inside the bundled `exploit-database__exploitdb` tree under `routerxpl/resources/arsenal/pocs/incorporated_third_party/`. **No** `searchsploit` or external Exploit-DB CLI. Preserve GPLv2 notices when redistributing mirror contents.

## 802.11 / BLE / PCAP (moved)

All **offline Wi‑Fi PCAP**, **WPA/WPA3 analysis**, and **Bluetooth LE** modules live in [**WirelessXPL-Forge**](https://github.com/mrhenrike/WirelessXPL-Forge) (private lab repo). RouterXPL keeps router/switch-oriented `generic` utilities only.

## Wordlist — `wordlist_generator`

Parameterized list generation for feeding bruteforce modules.

## SNMP — `snmp_trap_listener`

Trap listener for lab scenarios.

## UPnP — `ssdp_msearch`

SSDP discovery on LAN.

---

[Wiki hub](../README.md)
