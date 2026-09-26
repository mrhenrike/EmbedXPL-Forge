# EmbedXPL v5.0.0 — XPL Suite Unified + Specialized Tools

---

## 🔒 PROTOCOLO DE PHASE GATES (obrigatório)

**Nenhuma fase inicia sem autorização explícita do usuário.**

### Fluxo de cada fase:

```
1. Executor executa a fase
2. Entrega RELATÓRIO DE CONCLUSÃO com:
   ├── Arquivos criados/modificados (lista completa)
   ├── Módulos integrados (count + lista)
   ├── Problemas encontrados e como foram resolvidos
   ├── Quality checks (testes passaram? avisos?)
   └── Preview do próximo trabalho (o que Phase N+1 fará)
3. PARA e aguarda resposta do usuário
4. Usuário revisa e responde com: "APROVADO: P<N+1>" ou "AJUSTE: <instrução>"
5. Só então a próxima fase executa
```

### Comando de aprovação:
```
APROVADO: P1   → libera Phase 1
APROVADO: P2   → libera Phase 2
...
APROVADO: P15  → libera o release final
```

Qualquer outra instrução é tratada como ajuste e a fase não avança.

---

## Paradigma de Domínios

**Cada ferramenta da XPL Suite é especialista no seu domínio e permanece ativa.**  
**EmbedXPL é o framework unificado que contém TUDO + conteúdo único.**

```
WirelessXPL  ─── wireless, WiFi, BLE, LoRaWAN, NFC, Sub-GHz, UWB, drones ─────────────┐
PrinterXPL   ─── printers, MFP, escâneres, plotters, PJL, PCL, PostScript ─────────────┤
IndustrialXPL─── ICS, OT, AT, SCADA, PLC, RTU, IED, gateways industriais, IIoT ───────┤──→ todos copiados para EmbedXPL
FirewallXPL  ─── firewall, ACL, NAC, NGFW, UTM, IDS, IPS, lb, vpn, waf ─────────────────┤
WordlistXPL  ─── wordlists, geração, fuzzing, credential combos ──────────────────────────┘

EmbedXPL     ─── TUDO acima + routers + cameras + mikrotik + malware + smart_tv
                  + mobile + nas + hardware + protocols + drones + baseband + ...
```

## Domínios Canônicos por Ferramenta

| Ferramenta | Domínio Canônico | Exemplos de Subcategorias |
|---|---|---|
| **WirelessXPL** | wireless + **drones** | WiFi/WPA/PMKID, BLE/SweynTooth, LoRaWAN, Sub-GHz 433/868/915MHz, UWB, NFC, TPMS, V2X, **MAVLink, DJI, FPV, Parrot, Holystone**, evil_twin, KRACK, fragattacks |
| **PrinterXPL** | printers + MFP | HP/Canon/Xerox/Ricoh/Kyocera/Brother/Lexmark/Samsung, PJL attacks, PostScript, PCL, SNMP printer, network printing protocols |
| **IndustrialXPL** | ICS + OT + **AT** + SCADA + **PLC** + **RTU** + **IED** + gateways industriais + sensores/atuadores + IoT + **IIoT** | Modbus TCP/RTU, S7comm, DNP3, IEC-104, IEC-61850, PROFIBUS, PROFINET, EtherCAT, BACnet, KNX, OPC-UA, FINS (Omron), CAN, Hart, Siemens/Rockwell/ABB/Schneider/Omron PLCs |
| **FirewallXPL** | firewall + **ACL** + **NAC** + **NGFW** + **UTM** + **IDS** + **IPS** + lb + vpn + waf | CheckPoint, Cisco ASA/FTD, Fortinet, Palo Alto, SonicWall, Sophos, WatchGuard, Juniper, F5 BIG-IP, Citrix NetScaler, Ivanti, lb: F5/Radware/HAProxy, NAC: Cisco ISE/ForeScout |
| **WordlistXPL** | wordlists engine | passwords, usernames, fuzzing, WPA dicts, AD wordlists, credential combos, custom generators |
| **EmbedXPL** | **tudo acima + routers + cameras + mikrotik + malware + smart_tv + mobile + nas + hardware + protocols + baseband + drones** | router exploits (958+), camera CVEs, MikroTik, Mirai, firmware attacks, embedded OS, SOHO, smart home, smart meters, wearables, crypto, VoIP |

## Estado Final de Todos os Repos

| Repo | Domínio | Estado | PyPI |
|---|---|---|---|
| **EmbedXPL-Forge** | tudo (unified) | público, ativo, **v5.0.0** | ✅ `embedxpl` |
| **WirelessXPL-Forge** | wireless + drones | público, ativo | ✅ `wirelessxpl` |
| **PrinterXPL-Forge** | printers + MFP | público, ativo | ✅ `printerxpl` |
| **IndustrialXPL-Forge** | ICS/OT/AT/SCADA/PLC/RTU/IED | público, ativo | ✅ `industrialxpl` |
| **FirewallXPL-Forge** | firewall/NGFW/UTM/IDS/IPS/NAC | público, ativo | ✅ `firewallxpl` |
| **WordlistXPL-Forge** | wordlists engine | público, ativo | ✅ `wordlistxpl` |
| **TupaXPL-Forge** | LLM/AI/ops/red team | **privado**, ativo | N/A |
| MikrotikAPI-BF | *(absorvido — sem domínio único)* | público + **archived** ⚠️ | ❌ yanked → `embedxpl` |

---

## Phase 0 — Multi-Language Runtime

Fundação do novo EmbedXPL. Todas as fases dependem disto.

```
embedxpl/runtime/
  executor.py        # orchestrator — detecta linguagem e roteia
  python_exec.py     # .py nativo (padrão, 95%+ dos módulos)
  c_exec.py          # gcc/clang + cross: arm-linux-gnueabi, aarch64, mips, mipsle
  cpp_exec.py        # g++/clang++
  go_exec.py         # go build → binary → execute + binary cache
  rust_exec.py       # rustc/cargo
  ruby_exec.py       # ruby .rb MSF-compatible
  toolchain.py       # auto-detect: gcc, g++, clang, go, rustc, ruby, cross-compilers
  crosscompile.py    # targets: ARM32, ARM64, MIPS BE, MIPS LE, x86/x64
  cache.py           # compiled binary cache (não recompila no segundo run)
```

Interface de módulo multi-linguagem:
```python
class CameradarRTSP(BaseExploit):
    native_language = "go"
    native_source   = "native_src/go/cameradar"
    native_arch     = ["amd64", "arm64"]

class MeltdownExploit(BaseExploit):
    native_language = "c"
    native_source   = "native_src/c/meltdown/meltdown.c"
    native_arch     = "x86_64"
    native_cflags   = ["-O2"]

class MsfEternalBlue(BaseExploit):
    native_language = "ruby"
    native_source   = "native_src/ruby/ms17_010.rb"
```

---

## Phase 1 — Deep Research Audit + Clone Rapid7 + Tenable

**Gate de entrada:** `APROVADO: P1`  
**Entrega:** Relatório completo com mapa de todos os repos + plano de mapeamento por módulo

Repos NUNCA analisados em profundidade + novos a clonar:

---

### 🦠 Malware Samples (malware para pesquisa de defesa + RE)

**`malware-samples/` — inventário:**

| Dir | Files | Conteúdo | Destino |
|---|---|---|---|
| `cube-maliot-2021/` | **47.931** | Dataset massivo IoT malware 2021 | `malware_research/iot/` |
| `IoT_ARM/` | 6.001 | Mirai source C+Go, `attack_app.c`, `attack_gre.c`, `attack_tcp.c`, `crosscompiler.bash`, wordlists | `malware_research/mirai/` + `native_src/c/mirai_iot/` |
| `iot-malware/` | 5.351 | IoT malware collection | `malware_research/iot/` |
| `TRISIS-TRITON-HATMAN/` | 228 | **ICS safety system attack malware** (infamous 2017) | `malware_research/ics_apt/trisis/` + IndustrialXPL |
| `Bashlite-ELF/` | 75 | Bashlite/Qbot IoT botnet ELF | `malware_research/botnets/` |
| `Mirai-ioT-Botnet/` | 77 | Mirai botnet research | `malware_research/mirai/` |
| `print-malware/` | 7 | Printer malware C# (`Program.cs`, `vars.cs`) + Python | `malware_research/printers/` + PrinterXPL |
| `ICS4U-Malware/` | 6 | ICS curriculum malware samples | `malware_research/ics_apt/` |
| `lisa/` | 93 | Unknown — audit needed | a definir |
| `akaja/` | 8 | Unknown — audit needed | a definir |

**`IoT_ARM/` destaque** — tem source code Mirai-style com:
- `crosscompiler.bash` → integrar em `runtime/crosscompile.py` (aproveitar scripts de cross-compile!)
- `attack_app.c`, `attack_gre.c`, `attack_tcp.c`, `attack_udp.c` → `native_src/c/mirai_iot/`
- `attack.go`, `bot.go` → `native_src/go/mirai_bot/`
- Wordlists: `Mirai Passwords.txt`, `Telnet Passwords.txt`, `SSH Passwords.txt` → `data/wordlists/iot/`

**`thezoo/` (1.455 files):**
- `Binaries/` — binários compilados de malware (estudar para IoT relevantes: botnet, rootkit, RAT)
- `Source/` — código fonte (prioridade: IoT botnets, Linux rootkits, network worms)
- Filtrar: relevantes para embedded/IoT/ICS → `malware_research/`

---

### Submodulos/OT (61.847 files)
- `BusPwn/` — bus attack toolkit → `ics/bus_attacks/`?
- `ics-tools/` — coleção de ferramentas ICS
- `modbus-tcp-auditor-tool/` → enriquecer IndustrialXPL + EmbedXPL `ics/modbus/`
- `s7comm-auditor-tool/` → enriquecer IndustrialXPL + EmbedXPL `ics/siemens/`
- `ixf-vendor/` — vendor-specific

### Submodulos/IoT (56.006 files)
- `_loose-root/` — coleção de root exploits IoT
- `aic8800-src/` — source code chipset AIC8800 (WiFi+BT chip usado em muitos dispositivos)
- `third-party-router-poc/` — pode ter centenas de CVEs de routers não catalogados

### Submodulos/Hacking (22.784 files, 26 ferramentas)
| Ferramenta | Descrição | Destino |
|---|---|---|
| `nuclei-templates/` | Scanner templates | EmbedXPL `engines/nuclei/` |
| `maigret/` | OSINT username hunt | EmbedXPL `intel/osint/` |
| `theHarvester/` | Email/domain OSINT | EmbedXPL `intel/osint/` |
| `spiderfoot/` | Automated OSINT | EmbedXPL `intel/osint/` |
| `shodan-python/` | Shodan API | EmbedXPL `intel/` |
| `flowsint/` | Network flow OSINT | EmbedXPL `intel/` |
| `turbosearch/` | Web discovery | EmbedXPL `intel/discovery/` |
| `knowsmore/` | AD credentials analytics | TupaXPL |
| `ad-autopwn/` | AD autopwn | TupaXPL |
| `crtdumper/` | Certificate dumper | TupaXPL / EmbedXPL `crypto/` |
| `hookchain/`, `godeclutter/` | Evasion | TupaXPL |
| `ARES/`, `artemis/`, `blackbird/` | Red team frameworks | TupaXPL |
| CVE-specific tools | Ubiquiti, Fortinet, Citrix | EmbedXPL + FirewallXPL |

### Submodulos/malware (1.601 files)
- `mirai-pcanyi/` + `mirai-rosgos/` → EmbedXPL `malware_research/mirai/` (IoT botnet study)
- `thezoo/` → TupaXPL (malware zoo)

### poc-harpia (red team ops platform)
- Framework de operações red team (abuse-framework, Mantis, operations, sentinelone)
- Destino: TupaXPL (ops platform, não device exploits)

---

### 🔴 Rapid7 — Clone + Integração

**Repos a clonar em `D:\Projects\Labs\rapid7\`:**

| Repo | Size estimado | Conteúdo | Destino |
|---|---|---|---|
| `rapid7/metasploit-framework` | ~4 GB | 6.000+ módulos Ruby (exploits, auxiliaries, post, payloads) | `native_src/ruby/msf/` → RubyExecutor |
| `rapid7/recog` | ~50 MB | XML fingerprinting patterns (serviços, apps, devices) | `engines/fingerprint/recog/` |
| `rapid7/metasploit-data` | ~200 MB | Wordlists, schemas, vulnerable VMs | `data/rapid7/` |
| `rapid7/vulnerability-feeds` | ~10 MB | Vuln feeds estruturados | `intel/vuln_feeds/` |
| CVE-specific repos | pequenos | PoCs Python/Ruby individuais | conforme target |

**Estratégia de integração do MSF** (via RubyExecutor):
```python
class MetasploitModule(BaseExploit):
    native_language = "ruby"
    native_source   = "native_src/ruby/msf/modules/exploits/linux/..."
    msf_module      = True  # indica que precisa de MSF libs
```

**Seleção de módulos MSF relevantes para EmbedXPL:**
- `modules/exploits/linux/` — Linux embedded exploits
- `modules/exploits/multi/` — multi-platform (muitos IoT)
- `modules/exploits/hardware/` — hardware specific
- `modules/auxiliary/scanner/` — scanners (muito útil)
- `modules/auxiliary/server/` — rogue servers

---

### 🟡 Tenable — Clone + Integração

**Repos a clonar em `D:\Projects\Labs\tenable\`:**

| Repo | Conteúdo | Destino |
|---|---|---|
| `tenable-labs/security-research` (ou similar) | CVE PoCs Python/Go | conforme target |
| `tenable/terrascan` | IaC security scanner | TupaXPL (CI/CD security) |
| `tenable/pyTenable` | Tenable API Python client | TupaXPL / intel/ |
| Tenable Research blog CVE disclosures | PoC links e writeups | mapear por CVE |

**Nota:** Tenable NASL plugins (Nessus Attack Scripting Language) são proprietários — não há repo público com plugins. O que existe são os CVE disclosures e PoC associados. Clonar os repos públicos da organização `tenable-labs` no GitHub.

---

### Pruva.dev 12 REPROs
- REPRO-2026-00365: CVE-2026-67276 MikroTik SSH RSA → `network_os/mikrotik/`
- REPRO-2026-00361: CVE-2026-15742 PostgreSQL OOB → TupaXPL
- 10 outros: catalogar targets e mapear

---

## Phase 2 — Sync Model

EmbedXPL recebe cópias dos módulos dos specialized tools. Para manter em sync:

```python
# embedxpl/tools/sync_from_suite.py
"""
Sync modules from specialized XPL Suite tools into EmbedXPL.
Run after any specialized tool release to keep EmbedXPL up-to-date.
"""
SYNC_MAP = {
    "../WirelessXPL-Forge/wirelessxpl/modules/": "modules/exploits/wireless/",
    "../PrinterXPL-Forge/printerxpl/modules/exploits/": "modules/exploits/printers/",
    "../FirewallXPL-Forge/firewallxpl/modules/exploits/": "modules/exploits/firewalls/",
    "../IndustrialXPL-Forge/industrialxpl/modules/exploits/": "modules/exploits/ics/",
    "../WordlistXPL-Forge/wfh_modules/": "engines/wordlists/",
    "../WordlistXPL-Forge/passwords/": "data/wordlists/passwords/",
}
```

Workflow:
```
Nova vuln impressora descoberta
    → módulo criado em PrinterXPL-Forge (canônico)
    → PrinterXPL released v6.6.0
    → sync_from_suite.py copia para EmbedXPL modules/exploits/printers/
    → EmbedXPL released v5.1.0
```

---

## Phase 3 — WirelessXPL → EmbedXPL Copy

WirelessXPL **permanece ativo, público, com PyPI.**

EmbedXPL recebe cópia completa de 518 py cobrindo:

**WiFi/wireless:** access_points, evil_twin, fragattacks, KRACK, wardrive, session_manager

**BLE/Bluetooth:** ble, bluetooth, sweyntooth, SweynTooth BLE stack vulns

**Protocolos RF:** LoRaWAN, sub-ghz (433/868/915 MHz), UWB, TPMS, V2X, DECT, NFC, matter

**Drones (CRÍTICO — sempre em WirelessXPL):**
- `dji/` — DJI drone protocol attacks
- `holystone/` + `parrot/` — consumer drone attacks
- `fpv/` — FPV racing drone attacks
- `px4/` — PX4 flight controller attacks
- `mavlink/` — MAVLink protocol attacks

**IoT wireless:** iot_proto, mdns, mediatek, cellular, SIM

**Wearables:** fitbit, garmin, samsung_gear

---

## Phase 4 — WordlistXPL → EmbedXPL Copy

WordlistXPL **permanece ativo, público, com PyPI.**

EmbedXPL recebe cópia completa:
- `wfh_modules/` → `engines/wordlists/`
- `passwords/` → `data/wordlists/passwords/`
- `usernames/` → `data/wordlists/usernames/`
- `fuzzing/` → `data/wordlists/fuzzing/`
- `labs/` → `data/wordlists/labs/`

---

## Phase 5 — PrinterXPL → EmbedXPL Copy

PrinterXPL **permanece ativo, público, com PyPI.**

EmbedXPL recebe 653 py (upgradar stubs com código real):
- `brother/`, `canon/`, `hp/`, `kyocera/`, `lexmark/`, `ricoh/`, `samsung/`, `xerox/`
- NSE scripts → `resources/nse/printers/`
- HP HPLIP mass CVE scanner
- PrinterXPL wordlists → `data/wordlists/printers/`

---

## Phase 6 — FirewallXPL → EmbedXPL Copy

FirewallXPL **permanece ativo, público, com PyPI.**

EmbedXPL recebe 434 py (firewalls/ já existe, upgradar):
- **Perimeter NGFW:** checkpoint, cisco, citrix, f5, fortinet, h3c, hillstone, huawei, ivanti, juniper, kerio, paloalto, pfsense, opnsense, radware, sangfor, sonicwall, sophos, stormshield, symantec, trellix, trendmicro, vyos, watchguard, zyxel
- **LB (Load Balancers):** `lb/` — F5, Radware, HAProxy, Nginx
- **NAC:** `nac/` — Cisco ISE, ForeScout, Aruba
- **VPN:** `vpn/` — OpenVPN, IPsec, WireGuard attacks
- **WAF:** `waf/` — ModSecurity, AWS WAF, Cloudflare bypass
- **UTM/IDS/IPS:** stormshield, trellix, symantec, trendmicro
- 13 novos módulos da sessão de hoje: SonicWall, Cisco ISE, F5, CheckPoint, Netscaler, Ivanti, WatchGuard, Juniper, FortiWeb, etc.

---

## Phase 7 — IndustrialXPL → EmbedXPL Copy

IndustrialXPL **permanece ativo, público, com PyPI.**

EmbedXPL recebe 2.361 py (ics/ e ot_iiot/ massivos):

**Protocolos OT embarcados:**
- `modbus/` — Modbus TCP/RTU attacks
- `s7comm/` + `s7comm_plus/` — Siemens S7 protocol
- `fins/` — Omron FINS protocol
- `dnp3/` — DNP3 (utilities SCADA)
- `iec104/` — IEC 60870-5-104
- `iec61850/` — IEC 61850 (substations)
- `profibus/` + `profinet/` — Siemens factory bus
- `ethercat/` — Beckhoff EtherCAT
- `bacnet/` — Building automation
- `knx/` — Smart building
- `lonworks/` — Echelon
- `hart/` — HART instruments
- `canopen/` + `can/` — CAN bus
- `enip/` + `ethernet_ip/` — Allen-Bradley EtherNet/IP
- `opc_ua/` + `opc_da/` — OPC protocols
- `modbus_mstp/` — BACnet MS/TP

**Vendors PLCs/HMIs/SCADA (300+ categorias):**
Siemens, Rockwell/Allen-Bradley, Schneider Electric, ABB, Omron, GE/GE Vernova, Honeywell, Beckhoff, WAGO, Phoenix Contact, Mitsubishi, Yaskawa, Fanuc, Keyence, Pilz, SEL, Emerson, Aveva/OSIsoft, Delta, Fuji Electric, LS Electric, Moxa, WAGO, Turck, Murr, ProSoft, etc.

---

## Phase 0 — Multi-Language Runtime
**Gate de entrada:** execução imediata (Phase 0 não precisa de gate, é a fundação)  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P1`

---

## Phase 8 — MikrotikAPI-BF Absorção (único que para)
**Gate de entrada:** `APROVADO: P8`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P9`

MikrotikAPI-BF **para desenvolvimento** — sem domínio único que justifique standalone.

55 py + 8 NSE → `embedxpl/modules/exploits/network_os/mikrotik/`:
- Attack core: `timing_oracle.py`, `winbox_auth.py` (CVE-2018-14847), `fingerprint.py`, `discovery.py`, `stealth.py`
- Security audit: `snmp.py`, `ssh_audit.py`, `privilege_escalation.py`, `hardening_check.py`, `web_security.py`
- Protocol: `ec_srp5_client.py`, `decoder.py`, `supout_codec.py`, `npk_decoder.py`, `npk_tools.py`
- PoC engine: `cve_db.py`, `exploits.py`, `jailbreak.py`, `poc_engine.py`, `poc_payloads.py`, `scanner.py`, `pywinbox_adapter.py`
- Novos: `mikrotik_ssh_rsa_forged_key_cve_2026_67276.py`, `mikrotik_ssh_minus2_username_chain.py`
- NSE (8 scripts) → `embedxpl/resources/nse/mikrotik/`

**MikrotikAPI-BF repo:** `archived: true, private: false` + README disclaimer + PyPI yank.

---

## Phase 9 — EmbedXPL Conteúdo Único: Cameras + RTSP
**Gate de entrada:** `APROVADO: P9`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P10`

Conteúdo específico de EmbedXPL (não existe em nenhuma ferramenta especializada):

**Ingram-Pro (74 py):**
- DahuaConsole library → `engines/dahua_console/`
- 20 CVE PoCs de câmeras (Hikvision CVE-2017-7921/2021-36260, Dahua CVE-2021-33044/33045/2022-30563/2023-28808, Reolink CVE-2024-39943, etc.)
- Novos vendors: `ezviz/`, `geovision/`, `hanwha/`, `instar/`, `netwave/`, `nuuo/`, `reecam/`

**Cameradar (Go nativo):**
```
embedxpl/native_src/go/cameradar/    ← source completo
embedxpl/data/rtsp_routes/           ← 300+ rotas RTSP
embedxpl/data/rtsp_creds.json        ← 300+ credenciais
```
Módulo Python usa `GoExecutor` → compila → cache.

---

## Phase 10 — Malware Research Integration
**Gate de entrada:** `APROVADO: P10`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P11`

**Fontes:**

**`IoT_ARM/` — Mirai Source (C + Go):**
- `attack_app.c`, `attack_gre.c`, `attack_tcp.c`, `attack_udp.c` → `native_src/c/mirai_iot/`
- `attack.go`, `bot.go`, `admin.go` → `native_src/go/mirai_bot/`
- `crosscompiler.bash` → extrair padrões para `runtime/crosscompile.py`
- Wordlists: `Mirai Passwords.txt`, `Telnet Passwords.txt` → `data/wordlists/iot/`

**`TRISIS-TRITON-HATMAN/` (228 files):**
- Infame malware ICS que atacou safety systems Triconex
- Analisar e documentar TTPs → `malware_research/ics_apt/trisis/`
- Extrair indicadores → IndustrialXPL `malware/` + EmbedXPL `ics/`

**`thezoo Source/` — filtrar IoT/Linux relevante:**
- Botnets IoT: Mirai variants, Bashlite, Tsunami, Kaiten
- Linux rootkits aplicáveis a embedded
- Network worm code
- → `malware_research/` por categoria

**`cube-maliot-2021/` (47.931 files):**
- Dataset massivo — analisar estrutura antes de copiar
- Extrair samples únicos relevantes para embedded
- → `malware_research/iot/`

**`print-malware/` (C# + Python):**
- `Program.cs`, `vars.cs` — C# printer malware → `malware_research/printers/`
- Python variants (`popup.py`, `smal2.0.py`) → `malware_research/printers/`
- Estudo para PrinterXPL defensive modules

---

## Phase 11 — Rapid7 + Tenable Integration
**Gate de entrada:** `APROVADO: P11`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P12`

**Rapid7:**
- Clonar `rapid7/metasploit-framework` → `D:\Projects\Labs\rapid7\metasploit-framework\`
- Catalogar módulos por categoria de interesse (linux, hardware, multi, scanner)
- Módulos mais relevantes → `native_src/ruby/msf/` (executáveis via RubyExecutor)
- Clonar `rapid7/recog` → `engines/fingerprint/recog/`

**Tenable:**
- Clonar repos públicos de `tenable-labs/` e `tenable/`
- Catalogar CVE PoCs e mapear para EmbedXPL/TupaXPL

---

## Phase 12 — Native Source Trees
**Gate de entrada:** `APROVADO: P12`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P13`

---

## Phase 11b (renumerada) — EmbedXPL Conteúdo Único: Routers + MikroTik

Após absorção do MikrotikAPI-BF, expandir:

**Ruijie RG-EW3000GX** → `routers/ruijie/`:
- Buffer Overflow `setAppEasyWizardConfig` (seed payload)
- Buffer Overflow `setWiFiMultipleConfig` (seed payload)
- RCE `setUnloadUserData` (seed payload)
- RCE `CloudACMunualUpdateUserdata` (seed payload)

**murrez CVE batch** (Studied → implementar):
CVE-2026-13355, 19658, 12227, 92229, 6433, 8181, 14281, 89055, 41940

**D-Link R95 BE9500** → `routers/dlink/`

**TP-LINK TL-WAR2600L** → `routers/tplink/`

**CheckPoint CVE-2026-50751** → `firewalls/checkpoint/` (e FirewallXPL)

---

## Phase 13 — Intel/OSINT + Arsenal CVEs Pendentes
**Gate de entrada:** `APROVADO: P13`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P14`

---

## Phase 13b (legacy) — EmbedXPL Conteúdo Único: Malware + Intel

**Malware Research** (pesquisa, não execução):
- `Submodulos/malware/mirai-pcanyi/` → `malware_research/mirai/`
- `Submodulos/malware/mirai-rosgos/` → `malware_research/mirai/`

**Intel/OSINT** (ferramentas de reconhecimento para ataques a devices):
- `nuclei-templates/` → `engines/nuclei/`
- `maigret/`, `theHarvester/`, `spiderfoot/` → `intel/osint/`
- `shodan-python/`, `flowsint/` → `intel/`

---

## Phase 12 — Native Source Trees (C/C++/Go/Ruby)
**Gate de entrada:** `APROVADO: P12`

```
embedxpl/native_src/
  go/
    cameradar/         Cameradar RTSP scanner (Go)
  c/
    meltdown/          9 arquivos C — hardware/spectre
    samsung_tv_root/   3 arquivos C — smart_tv root
  cpp/
    oboromi/           3 arquivos C++ — camera overflow
    cfc/               60C + 84cpp — toolkit completo
  ruby/
    msf_modules/       módulos MSF Ruby harvested
    atomic_red_team/   4 módulos Ruby ATT&CK
```

Cross-compile targets: `arm-linux-gnueabi`, `aarch64-linux-gnu`, `mips-linux-gnu`, `mipsel-linux-gnu`

---

## Phase 13 — Arsenal CVEs Pendentes + Submodulos OT/IoT
**Gate de entrada:** `APROVADO: P13`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P14`

Repos marcados como "Studied" no HANDOFF mas sem módulo ainda:
- **murrez batch**: 9 CVEs routers/IoT (CVE-2026-13355, 19658, 12227, 92229, 6433, 8181, 14281, 89055, 41940)
- **CheckPoint CVE-2026-50751**: → EmbedXPL `firewalls/checkpoint/` + FirewallXPL
- **Pruva.dev REPROs** (10 não identificados): catalogar targets e implementar

---

## Phase 14 — Intel/OSINT + Submodulos/OT e IoT Integration
**Gate de entrada:** `APROVADO: P14`  
**Gate de saída:** apresentar relatório → aguardar `APROVADO: P15`

**Submodulos/OT** → `ics/` + `ot_iiot/` (+ IndustrialXPL):
- `BusPwn/` → `ics/bus_attacks/`
- `modbus-tcp-auditor-tool/` → enriquecer `ics/modbus/`
- `s7comm-auditor-tool/` → enriquecer `ics/siemens/`
- `ics-tools/` → catalogar e distribuir

**Submodulos/IoT** → `routers/` + `hardware/`:
- `third-party-router-poc/` → catalogar vendors e CVEs, implementar por router brand
- `aic8800-src/` → `hardware/chipsets/aic8800/`
- `_loose-root/` → `hardware/root_exploits/`

---

## Phase 15 — Releases (FINAL)
**Gate de entrada:** `APROVADO: P15`  
**Nenhum gate de saída — esta é a fase final.**

**MikrotikAPI-BF:**
- `archived: true`, `private: false`
- README: banner `> [!WARNING] DEPRECATED — absorbed into EmbedXPL v5.0.0`
- PyPI: yank + deprecated notice pointing to `embedxpl`

**EmbedXPL v5.0.0:**
- README: "Unified XPL Suite Framework", "Absorbed Tools: MikrotikAPI-BF", "Sync Model", "Multi-Language Runtime"
- Push GitHub API (sem pyproject.toml)
- Release v5.0.0

**Specialized tools** (todos mantém versioning normal):
- WirelessXPL: bump menor
- PrinterXPL: bump menor
- FirewallXPL: bump menor
- IndustrialXPL: bump menor
- WordlistXPL: bump menor

---

## Arquitetura Final EmbedXPL v5.0.0

```
embedxpl/
  runtime/               NOVO — Python/C/C++/Go/Rust/Ruby engine
  native_src/            NOVO — Go/C/C++/Ruby source trees
    go/cameradar/
    c/meltdown/ samsung_tv/
    cpp/oboromi/ cfc/
    ruby/msf/ atomic/
  engines/               NOVO — shared engines
    dahua_console/       DahuaConsole (Dahua protocol)
    nuclei/              nuclei-templates scanner
    wordlists/           WordlistXPL copy
  intel/                 NOVO — OSINT + reconnaissance
    osint/               maigret, theHarvester, spiderfoot
  malware_research/      NOVO — IoT malware study
    mirai/               Mirai botnet source
  data/
    rtsp_routes/         Cameradar 300+ rotas
    rtsp_creds.json      Cameradar 300+ credenciais
    wordlists/           WordlistXPL copy
  resources/
    nse/mikrotik/        8 scripts NSE
    nse/printers/        PrinterXPL NSE
  modules/exploits/
    cameras/       ~230   (+ Ingram-Pro + novos vendors)
    drones/               cópia WirelessXPL drone modules
    firewalls/     ~450   (cópia FirewallXPL real + 13 novos)
    hardware/             (+ meltdown C + aic8800 + samsung_tv)
    ics/          ~2.500  (cópia IndustrialXPL 2.361 + Submod/OT)
    mobile/
    nas/
    network_os/
      mikrotik/    ~40    MikrotikAPI-BF absorvido
      moxa/
    ot_iiot/              cópia IndustrialXPL OT
    printers/      ~700   (cópia PrinterXPL 653 real)
    protocols/
    routers/      ~1.100  (+ Ruijie + murrez batch + Submod/IoT)
    smart_tv/
    wireless/      ~520   (cópia WirelessXPL 518 py)
    ...todos os outros existentes...
```
