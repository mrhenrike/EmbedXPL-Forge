# Módulos genéricos

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/08-generic-modules.md](../en-US/08-generic-modules.md)

## Mapa de módulos

| Módulo | Função |
|--------|--------|
| `cve_lookup` | Associa identificadores CVE a metadados locais |
| `snmp_bruteforce` | Tentativa de community SNMP |
| `ssdp_msearch` | Descoberta SSDP `M-SEARCH` |
| `heartbleed` | Checagem orientada a OpenSSL Heartbleed |
| `shellshock` | Testes de padrão CGI / Bash `shellshock` |
| `wordlists` | Ajudantes sobre wordlists embutidas |

## Exemplo CVE lookup

```text
RouterXPL-Forge > use generic/cve_lookup
RouterXPL-Forge (cve_lookup) > set cve CVE-2014-0160
RouterXPL-Forge (cve_lookup) > run
```

## Exemplo descoberta UPnP

```text
RouterXPL-Forge > use generic/ssdp_msearch
RouterXPL-Forge (ssdp_msearch) > run
```

Ajuste opções com `show options` antes de executar.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
