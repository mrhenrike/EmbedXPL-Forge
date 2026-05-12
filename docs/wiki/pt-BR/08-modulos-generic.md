# Módulos genéricos

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/08-generic-modules.md](../en-US/08-generic-modules.md)

Módulos genéricos operam entre vendors e classes de dispositivo — focam em protocolos e serviços comuns, não em vulnerabilidades específicas de vendor.

## Mapa de módulos

| Módulo | Caminho | Função |
|--------|---------|--------|
| `cve_lookup` | `generic/cve/cve_lookup` | Associa identificadores CVE a metadados locais |
| `snmp_bruteforce` | `generic/snmp/snmp_bruteforce` | Tentativa de community SNMP |
| `ssdp_msearch` | `generic/upnp/ssdp_msearch` | Descoberta SSDP M-SEARCH (básico) |
| `igd_exploit` | `generic/upnp/igd_exploit` | Exploração completa UPnP IGD |
| `heartbleed` | `generic/heartbleed` | Checagem orientada a OpenSSL Heartbleed |
| `shellshock` | `generic/shellshock` | Testes de padrão CGI / Bash shellshock |
| `wordlists` | `generic/wordlist` | Ajudantes sobre wordlists embutidas |

## UPnP IGD — Exploração Completa

`igd_exploit` é o módulo UPnP mais completo. Encadeia:

1. **SSDP M-SEARCH** — descobre todos os serviços IGD no alvo
2. **Parsing do XML de descrição** — extrai modelo, serial, lista de serviços
3. **Enumeração SCPD** — lista todas as ações SOAP por serviço
4. **GetExternalIPAddress** — expõe IP WAN/externo sem autenticação
5. **GetGenericPortMappingEntry** — enumera todos os mapeamentos NAT existentes
6. **AddPortMapping** — adiciona regras de bypass de firewall sem autenticação (CRÍTICO)
7. **DeletePortMapping** — remove regras NAT
8. **GetStatusInfo / GetNATRSIPStatus** — status da conexão WAN e uptime
9. **WANCommonInterfaceConfig** — estatísticas de tráfego (bytes/pacotes enviados/recebidos)
10. **ForceTermination** — capacidade de desconectar WAN (DoS) — ignorado por padrão
11. **Event SUBSCRIBE** — monitora eventos WAN em tempo real

```text
EmbedXPL-Forge > use generic/upnp/igd_exploit
EmbedXPL-Forge (igd_exploit) > set target 192.168.1.1
EmbedXPL-Forge (igd_exploit) > show options
EmbedXPL-Forge (igd_exploit) > run

# Pular ações perigosas (ForceTermination):
EmbedXPL-Forge (igd_exploit) > set skip_dangerous yes
EmbedXPL-Forge (igd_exploit) > run
```

## Descoberta SSDP (básico)

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

Ajuste opções com `show options` antes de executar.


[Hub wiki](../README.md)
