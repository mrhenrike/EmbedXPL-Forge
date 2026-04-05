# Módulos `generic` — CVE, wordlist, SNMP, UPnP, external

**Idioma:** pt-BR. **English (en-US):** [../en-US/08-generic-modules.md](../en-US/08-generic-modules.md)

Área de **utilitários** transversais ao ecossistema de testes.

## CVE — `generic/cve/cve_lookup`

Consulta **base embutida** (`routerxpl.core.cve`) com correspondência vendor/produto/versão/*banner*.

```text
use generic/cve/cve_lookup
set vendor cisco
set product rv320
run
```

Opções úteis: `banner`, `product`, `version`, `remote_only`, `show_physical`.

Ideal **após** obter *banner* por outro scanner ou serviço.

## Exploit-DB (CSV offline) — `generic/external/exploitdb_embedded_lookup`

Pesquisa o **`files_exploits.csv`** do espelho `exploit-database__exploitdb` em `routerxpl/resources/arsenal/pocs/incorporated_third_party/`. **Sem** `searchsploit` nem CLI externo. Respeite avisos GPLv2 ao redistribuir o espelho.

## 802.11 / BLE / PCAP (mudou de repositório)

Módulos **PCAP Wi‑Fi**, análise **WPA/WPA3** e **Bluetooth LE** estão em [**WirelessXPL-Forge**](https://github.com/mrhenrike/WirelessXPL-Forge).

## Wordlist — `generic/wordlist/wordlist_generator`

Gera *wordlists* parametrizáveis (perfil corporativo vs pessoal, variações). Integra-se conceitualmente com bruteforce (`ssh_bruteforce`, etc.) via export para ficheiro.

## SNMP — `generic/snmp/snmp_trap_listener`

*Listener* de traps para cenários de teste.

## UPnP — `generic/upnp/ssdp_msearch`

Descoberta SSDP / *M-SEARCH* em LAN.

---

[Wiki hub](../README.md)
