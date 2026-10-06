# Changelog — EmbedXPL-Forge

All notable changes to EmbedXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) -- `MAJOR.MINOR.PATCH`.

---

## [5.0.0] - 2026-09-26 — UNIFIED XPL SUITE FRAMEWORK

### Major Release — EmbedXPL becomes the unified framework for the entire XPL Suite

#### Multi-Language Runtime (Phase 0)
- Added `embedxpl/runtime/` — full multi-language executor engine
- Executors: Python (default), C (gcc+cross-compile), C++, Go, Rust, Ruby (MSF-compatible)
- Cross-compile targets: ARM32, ARM64, x64, x86, musl-x64
- Binary cache (SHA-256 keyed, `.tmp/runtime_cache/`)
- `XplRuntime` orchestrator, `toolchain.py` auto-detection

#### Specialized Tool Integration (Phases 3-7)
- **WirelessXPL** → `modules/exploits/wireless/` (477 py, WiFi/BLE/drones/RF)
- **WordlistXPL** → `engines/wordlists/` (83 py + wordlist data)
- **PrinterXPL** → `modules/exploits/printers/` (237 py, HP/Canon/Ricoh/CUPS)
- **FirewallXPL** → `modules/exploits/firewalls/` (685 py, NGFW/UTM/IDS/IPS/NAC)
- **IndustrialXPL** → `modules/exploits/ics/` (1657 py, ICS/OT/PLC/SCADA)
- One-way sync via `embedxpl/tools/sync_from_suite.py`
- Domain contracts documented in `docs/DOMAIN-CONTRACTS.md`

#### MikrotikAPI-BF Absorption (Phase 8)
- Absorbed 59 py + 8 NSE scripts → `modules/exploits/network_os/mikrotik/`
- Integrated Tenable RouterOS 12 CVE PoCs (Winbox CVE-2018-14847, etc.)
- Integrated Pruva.dev verified REPROs (CVE-2026-67276, CVE-2026-67279)
- MikrotikAPI-BF repo deprecated with banner redirect

#### Cameras + RTSP (Phase 9)
- Ingram-Pro DahuaConsole engine → `engines/dahua_console/` (69 py)
- Cameradar Go RTSP scanner → `native_src/go/cameradar/` (80 .go, GoExecutor)
- Dahua CVE research → `modules/exploits/cameras/dahua/`

#### Malware Research (Phase 10)
- Mirai C source → `native_src/c/mirai_iot/` + `malware_research/mirai/`
- TRISIS-TRITON-HATMAN → `malware_research/ics_apt/trisis/` (215 py)
- BlackEnergy, Industroyer2 → `malware_research/ics_apt/`
- 62 Mirai IoT credentials extracted from scanner.c → `data/wordlists/iot/`

#### Rapid7 + Tenable (Phase 11)
- 1414 MSF Ruby modules → `native_src/ruby/msf/` (via RubyExecutor)
- Rapid7 recog 59 XML fingerprints → `engines/fingerprint/recog/`
- Tenable ICS PoCs → `engines/fingerprint/tenable/` (Rockwell, Schneider, Siemens)

#### Native Source Trees (Phase 12)
- `native_src/c/meltdown/` — Meltdown CPU side-channel (11 .c)
- `native_src/cpp/oboromi/` + `native_src/cpp/cfc/` — C++ toolkits
- `native_src/ruby/atomic_red_team/` — ATT&CK test procedures (4 .rb)
- `modules/exploits/smart_tv/samsung_root/` — Samsung TV root (123 py)

#### Arsenal CVEs + Submodulos (Phase 13)
- ZTE CVE-2026-34472/34473/34474 → `routers/zte/`
- TP-Link, TRENDNet, Tenda, Xiaomi exploits from third-party-router-poc
- CheckPoint CVE-2026-50751 → `firewalls/checkpoint/`
- AIC8800 chipset source → `hardware/chipsets/aic8800/` (994 .c)

#### Intel/OSINT (Phase 14)
- Nuclei engine wrapper → `engines/nuclei/` (13.084 templates via external path)
- Shodan API → `intel/shodan/`
- OSINT bridges: maigret, theHarvester, spiderfoot
- ICS tools bridge → `engines/ics_tools/`

#### New Architecture Features
- MSF-style search: `from embedxpl.tools.search import search, search_cve`
- AutoPwn per segment: `from embedxpl.modules.autopwn import RouterAutoPwn`
- Deployed to all 5 specialized XPL repos (WirelessXPL/FirewallXPL/IndustrialXPL/PrinterXPL/WordlistXPL)
- Phase 16 planned: SQLite database across full suite (post-release)

---

## [3.9.0] - 2026-09-13

### Added
- CVE-2026-95675: D-Link DAP-1360 Unauthenticated Root RCE (CVSS 9.8, NO FIX AVAILABLE, firmware ≤6.14)
- CVE-2026-34473: ZTE Router Unauthenticated DoS (CVSS 7.5)
- CVE-2026-20971: Samsung Android Kernel PROCA/FIVE UAF LPE (Galaxy S9–S25, Qualcomm + Exynos)
- CVE-2026-93958: D-Link R95 BE9500 NTP Command Injection (CVSS 9.4)

### Restored (lost in Sep 2026 rollback)
- iOS 26.5 lockdownd 5-chain auth bypass module
- WAF Bypass Engine (80+ obfuscation variants)
- HTTP 403 Bypass (24 standalone techniques)
- Mirai IoT async scanner (62 hardcoded cred pairs)
- TP-Link Archer exploit suite (CVE-2023-1389, CVE-2024-48957, CVE-2022-30024)
- Realtek/MediaTek SDK RCE (CVE-2021-35394, CVE-2022-27255, CVE-2024-20017)
- macOS DesktopServices LPE (CVE-2026-43783)

### Infrastructure
- GitHub LFS configured (.gitattributes) for firmware/binary files

## [3.10.1] — 2026-09-24
### Fixed
- Catalog updated: +5 new CVEs (CVE-2026-35616, CVE-2025-20333, CVE-2025-20362, CVE-2024-50562, CVE-2026-24858)
- Hikvision ISAPI pre-auth RCE (CVE-2025-34067 CVSS 10.0)
- TP-Link/D-Link EOL RCE suite (CVE-2024-54887, CVE-2024-12987, CVE-2024-11068)

## [3.10.0] — 2026-09-23
### Added — Sep 2026 Batch Integration
- RTSP camera scanner (cameradar native port)
- iOS 26.5 lockdownd 5-chain auth bypass
- macOS DesktopServices LPE (CVE-2026-43783)
- WAF Bypass Engine (80+ variants)
- HTTP 403 Bypass (24 techniques)
- Mirai IoT Scanner (62 default creds)
- TP-Link Archer: CVE-2023-1389 / CVE-2024-48957 / CVE-2022-30024
- Realtek/MediaTek SDK RCE: CVE-2021-35394 / CVE-2022-27255 / CVE-2024-20017
- Base class refactor: simulate+destructive dual-flag guardrail
- Full en-US output migration

## [3.9.0] — 2026-09-19 (previous release)