# Search and Listing

**Language:** English (en-US). **pt-BR:** [../pt-BR/03-busca-e-listagem.md](../pt-BR/03-busca-e-listagem.md)

## `search`

Search by vendor, module type, protocol, CVE, or keyword. Case-insensitive substring match across module names and descriptions.

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

## `show` listings

| Command | Lists |
|---------|-------|
| `show all` | All module categories |
| `show creds` | Credential modules |
| `show exploits` | Exploit modules |
| `show scanners` | Scanner modules |
| `show payloads` | Payload modules |
| `show encoders` | Encoder modules |

## `show devices` — vendor and model coverage for a module

After loading a module with `use`, run `show devices` to see exactly which vendors, models, and firmware versions it covers:

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
    GISE V5 series (XVR/NVR) — V21.1.20.x - V21.1.27.x
    Longse LSN-9836/LSN-9436 — Web v6.0 series (2021-2023)
    Zintronic P5/NVR — N9000 platform (BitVision)
    Turing AI SMART series — N9000 platform
    Speco ZIP series — OEM TVT
    Alibi Security Vigilant series — OEM TVT
    IRBIS MBD6804T-EL — V4.02.R11 (legacy)
```

## `show info` — full module metadata

```text
exf > use exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
exf > show info
[*] Name:        Herospeed/Longsee NVR Unauthenticated Account Enumeration
[*] CVSS:        9.1
[*] Authors:     c3l3r1on (discovery), Andre Henrique (@mrhenrike)
[*] References:  https://github.com/c3l3r1on/nvr
[*] Devices:     Herospeed NVR N-series ...
```

## Full path index

For every module path in the tree, see [Module path index (all locales)](../ANEXO-INDICE-MODULOS.md).


[Wiki hub](../README.md)
