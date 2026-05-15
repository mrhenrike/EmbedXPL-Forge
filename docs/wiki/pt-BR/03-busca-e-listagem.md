# Busca e listagem

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/03-search-and-listing.md](../en-US/03-search-and-listing.md)

## `search`

Pesquise por fabricante, tipo de módulo, protocolo, CVE ou palavra-chave. Correspondência substring sem distinção de maiúsculas/minúsculas em nomes e descrições de módulos.

```text
search dlink
search creds
search scanner
search herospeed
search longsee
search nvr
search rce
search CVE-2021-36260
```

## Listagens `show`

| Comando | Lista |
|---------|-------|
| `show all` | Todas as categorias de módulos |
| `show creds` | Módulos de credenciais |
| `show exploits` | Módulos de exploit |
| `show scanners` | Módulos scanner |
| `show payloads` | Módulos de payload |
| `show encoders` | Módulos encoder |

## `show devices` — cobertura de fabricantes e modelos de um módulo

Após carregar um módulo com `use`, execute `show devices` para ver exatamente quais fabricantes, modelos e versões de firmware ele cobre:

```text
exf > use exploits/cameras/herospeed/herospeed_nvr_rce
exf (Herospeed NVR RCE) > show devices
[*] Target devices:
    Herospeed NVR N-series (all MC6830/FH6830 platform, 2023-2025)
    All OEM re-brands: TVT Digital, GISE, Zintronic, Turing AI, Speco, Alibi Security, IRBIS

exf > use scanners/cameras/herospeed_longsee_nvr_scan
exf (Herospeed/Longsee NVR Scanner) > show devices
[*] Target devices:
    Herospeed NVR N-series (9CH-64CH, firmware v2.0.4-v2.1.x, SoC MC6830)
    TVT Digital TD-3000H1/TD-3300 — V21.1.x / V22.1.x
    GISE Série V5 (XVR/NVR) — V21.1.20.x - V21.1.27.x
    Longse LSN-9836/LSN-9436 — Web v6.0 series (2021-2023)
    Zintronic P5/NVR — plataforma N9000 (BitVision)
    Turing AI Série SMART — plataforma N9000
    Speco Série ZIP — OEM TVT
    Alibi Security Série Vigilant — OEM TVT
    IRBIS MBD6804T-EL — V4.02.R11 (legado)
```

## `show info` — metadados completos do módulo

```text
exf > use exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
exf > show info
[*] Name:        Herospeed/Longsee NVR Unauthenticated Account Enumeration
[*] CVSS:        9.1
[*] Authors:     c3l3r1on (discovery), Andre Henrique (@mrhenrike)
[*] References:  https://github.com/c3l3r1on/nvr
[*] Devices:     Herospeed NVR N-series ...
```

## Índice completo de caminhos

Para todos os caminhos de módulos na árvore, veja [Anexo: índice de módulos](../ANEXO-INDICE-MODULOS.md).


[Hub wiki](../README.md)
