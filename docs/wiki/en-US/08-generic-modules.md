# `generic` modules (PCAP, CVE, wordlist, SNMP, UPnP, Bluetooth)

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

## PCAP / Wi‑Fi offline — `generic/pcap/*`

Requires **Scapy**. Lab / authorized forensic use.

| Module | Role |
|--------|------|
| `pcap_ap_station_mapper` | Map APs/stations |
| `pcap_handshake_extractor` | Extract WPA handshake |
| `pcap_offline_wpa_crack` | Offline cracking workflow |
| `pcap_wep_crack` | WEP statistical attacks |
| `pcap_pmkid_attack` | PMKID extraction/workflow |
| `pcap_tkip_downgrade` | TKIP / Michael analysis |
| `pcap_dragonblood` | WPA3/SAE-related signals |
| `pcap_wpe_harvest` | EAP/MSCHAPv2 harvest style |
| `pcap_credential_sniffer` | Credential patterns from capture |

Set **PCAP file paths** per `show options`.

## Wordlist — `wordlist_generator`

Parameterized list generation for feeding bruteforce modules.

## SNMP — `snmp_trap_listener`

Trap listener for lab scenarios.

## UPnP — `ssdp_msearch`

SSDP discovery on LAN.

## Bluetooth LE — `generic/bluetooth/*`

Typically **Linux** + optional `bluepy`; needs suitable permissions.

---

[Wiki hub](../README.md)
