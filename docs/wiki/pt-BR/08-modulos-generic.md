# Módulos Generic

**Idioma:** Português (pt-BR). **English:** [../en-US/08-generic-modules.md](../en-US/08-generic-modules.md)

---

Os módulos generic operam entre vendors e classes de dispositivos — eles visam protocolos e serviços comuns em vez de vulnerabilidades específicas de vendor.

## Mapa de Módulos

| Módulo | Caminho | Função |
|--------|---------|--------|
| `cve_lookup` | `generic/cve/cve_lookup` | Mapear identificadores CVE para metadados locais |
| `snmp_bruteforce` | `generic/snmp/snmp_bruteforce` | Adivinhação de string de comunidade SNMP |
| `ssdp_msearch` | `generic/upnp/ssdp_msearch` | Descoberta SSDP M-SEARCH (básico) |
| `igd_exploit` | `generic/upnp/igd_exploit` | Suite completa de exploração UPnP IGD |
| `heartbleed` | `generic/heartbleed` | Verificação orientada ao OpenSSL Heartbleed |
| `shellshock` | `generic/shellshock` | Testes de padrão CGI / Bash shellshock |
| `wordlists` | `generic/wordlist` | Auxiliares para wordlists embutidas |

---

## Exploração Completa UPnP IGD

O `igd_exploit` é o módulo UPnP mais abrangente. Ele encadeia:

1. **SSDP M-SEARCH** — descobre todos os serviços IGD no alvo
2. **Parsing do XML de descrição do dispositivo** — extrai modelo, número de série, lista de serviços
3. **Enumeração SCPD** — lista todas as ações SOAP disponíveis por serviço
4. **GetExternalIPAddress** — divulga o IP WAN/externo sem autenticação
5. **GetGenericPortMappingEntry** — enumera todos os mapeamentos de porta NAT existentes
6. **AddPortMapping** — adiciona regras de bypass de firewall sem autenticação (CRÍTICO)
7. **DeletePortMapping** — remove regras NAT
8. **GetStatusInfo / GetNATRSIPStatus** — status da conexão WAN e tempo de atividade
9. **WANCommonInterfaceConfig** — estatísticas de tráfego (bytes/pacotes enviados/recebidos, tipo de link)
10. **ForceTermination** — capacidade de desconexão WAN (DoS) — ignorado por padrão
11. **Event SUBSCRIBE** — monitora eventos WAN em tempo real

```text
EmbedXPL-Forge > use generic/upnp/igd_exploit
EmbedXPL-Forge (igd_exploit) > set target 192.168.1.1
EmbedXPL-Forge (igd_exploit) > show options
EmbedXPL-Forge (igd_exploit) > run

# Ignorar ações perigosas (ForceTermination):
EmbedXPL-Forge (igd_exploit) > set skip_dangerous yes
EmbedXPL-Forge (igd_exploit) > run

# Testar porta externa específica para AddPortMapping:
EmbedXPL-Forge (igd_exploit) > set test_port 31337
EmbedXPL-Forge (igd_exploit) > run
```

---

## Descoberta SSDP UPnP (básico)

```text
EmbedXPL-Forge > use generic/upnp/ssdp_msearch
EmbedXPL-Forge (ssdp_msearch) > set target 192.168.1.1
EmbedXPL-Forge (ssdp_msearch) > run
```

---

## Lookup de CVE

```text
EmbedXPL-Forge > use generic/cve/cve_lookup
EmbedXPL-Forge (cve_lookup) > set cve CVE-2014-0160
EmbedXPL-Forge (cve_lookup) > run
```

---

## Brute-force SNMP

```text
EmbedXPL-Forge > use generic/snmp/snmp_bruteforce
EmbedXPL-Forge (snmp_bruteforce) > set target 192.168.1.1
EmbedXPL-Forge (snmp_bruteforce) > run
```

Use `show options` antes da execução para ajustar as opções.

---

[Hub da Wiki](../README.md)
