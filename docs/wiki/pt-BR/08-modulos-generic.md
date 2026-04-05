# Módulos `generic` — PCAP, CVE, wordlist, SNMP, UPnP, Bluetooth

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

## PCAP / Wi‑Fi offline — `generic/pcap/*`

Requer **Scapy**. Útil para laboratório e análise forense **autorizada**.

| Módulo | Função resumida |
|--------|-----------------|
| `pcap_ap_station_mapper` | Mapear AP/estações a partir de captura |
| `pcap_handshake_extractor` | Extrair *handshake* WPA para *crack* offline |
| `pcap_offline_wpa_crack` | Integração com quebra offline (ex.: *hashcat*) |
| `pcap_wep_crack` | Ataques estatísticos WEP |
| `pcap_pmkid_attack` | Extração / encaminhamento PMKID |
| `pcap_tkip_downgrade` | Análise TKIP / Michael |
| `pcap_dragonblood` | Deteção relacionada WPA3/SAE |
| `pcap_wpe_harvest` | Material MSCHAPv2 / EAP de capturas |
| `pcap_credential_sniffer` | Análise de credenciais em tráfego (âmbito lab) |

Configure sempre **caminho para ficheiro PCAP** conforme `show options` de cada módulo.

## Wordlist — `generic/wordlist/wordlist_generator`

Gera *wordlists* parametrizáveis (perfil corporativo vs pessoal, variações). Integra-se conceitualmente com bruteforce (`ssh_bruteforce`, etc.) via export para ficheiro.

## SNMP — `generic/snmp/snmp_trap_listener`

*Listener* de traps para cenários de teste.

## UPnP — `generic/upnp/ssdp_msearch`

Descoberta SSDP / *M-SEARCH* em LAN.

## Bluetooth LE — `generic/bluetooth/*`

`*btle_scan`, `btle_enumerate`, `btle_write` — em geral **Linux** com *stack* adequada; pode exigir `bluepy` e permissões de sistema.

---

[Wiki hub](../README.md)
