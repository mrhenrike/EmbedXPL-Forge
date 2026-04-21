# Changelog

All notable changes to EmbedXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`.

---

## [2.8.0] — 2026-04-21

### Added — Dahua CCTV Security Research Suite

**3 new scanners** (`scanners/cameras/dahua/`):
- `cctv_discover` — Multi-model discovery via HTTP, ONVIF, Dahua binary protocol (37777)
- `firmware_version_fingerprint` — Firmware version, platform (Hertz/Molec/Euler/Kant/Edison), SoC identification
- `p2p_pppp_scan` — PPPP/iLnkP2P cloud relay detection (CVE-2019-11219/11220)

**6 new exploit modules** (`exploits/cameras/dahua/`):
- `cctv_pem_key_extraction` — DAHUA-2026-001: PEM key material in firmware bootloaders (CVSS 7.5)
- `cctv_firmware_upload_no_verify` — DAHUA-2026-002: Firmware signature not enforced, 13/14 models (CVSS 8.1)
- `cctv_auth_bypass_cve_2021_33044` — DAHUA-2026-005: Auth bypass via RPC2_Login (CVSS 9.8)
- `cctv_rce_cve_2021_36260` — DAHUA-2026-006: RCE via configManager.cgi (CVSS 9.8)
- `cctv_username_disclosure_cve_2020_25078` — DAHUA-2026-007: Username leak via /current_config/passwd (CVSS 7.5)
- `cctv_37777_credential_extraction` — DAHUA-2026-008: TCP/37777 protocol credential extraction (CVSS 9.8)

### Research Coverage
- 14 Dahua firmware images analyzed (IP cameras, NVRs, PTZ — 2020 to 2025)
- Platforms: Hertz, Molec, Euler, Kant, Edison (HiSilicon, SigmaStar, Ingenic SoCs)
- 8 vulnerability findings documented with CVSSv3.1 scores and CWE classifications
- 32 PEM key extractions confirmed across 8/14 firmwares
- 13/14 firmwares lack signature verification in Install script

---

## [2.7.0] — 2026-04-18

### Added — Intelbras CCTV Security Research Suite

**4 new scanners** (`scanners/cameras/`):
- `intelbras_cctv_discover` — Multi-model discovery via HTTP, RTSP, Dahua protocol (37777)
- `intelbras_boa_detect` — Boa HTTP server (EOL 2005) detection via banner fingerprinting
- `intelbras_onvif_scan` — ONVIF endpoint discovery and SOAP GetDeviceInformation probe
- `intelbras_p2p_uid_scan` — P2P/iSIC cloud UID enumeration and predictability analysis

**8 new exploit modules** (`exploits/cameras/intelbras/`):
- `cctv_rsa_key_extraction` — INTELBRAS-2026-001: RSA key reuse across product lines (CVSS 9.8)
- `cctv_firmware_upload_no_verify` — INTELBRAS-2026-002: Firmware without integrity check (CVSS 8.1)
- `cctv_config_disclosure` — INTELBRAS-2026-005: Unauthenticated config dump, multi-model (CVSS 7.5)
- `cctv_onvif_auth_bypass` — INTELBRAS-2026-004: ONVIF auth bypass on NVR/DVR (CVSS 7.5)
- `cctv_telnet_default_creds` — INTELBRAS-2026-007: HiSilicon default creds via telnet (CVSS 6.5)
- `cctv_dahua_auth_bypass` — INTELBRAS-2026-008: Dahua CVE-2017-7921 on OEM models (CVSS 10.0)
- `cctv_dahua_rce_cve_2021_36260` — INTELBRAS-2026-008: Dahua command injection on OEM (CVSS 9.8)
- `cctv_dahua_username_disclosure_cve_2020_25078` — INTELBRAS-2026-008: Username leak (CVSS 7.5)

### Research Coverage
- 10 Intelbras firmware images analyzed (3 IP cameras, 4 DVRs, 3 NVRs)
- Models spanning 2019–2026: VIP 1130 D, VIP 3230 B SD, VIP S3020 G2, MHDX 1004-C, MHDX 1108-C, MHDX 3108, MHDX 1108 G3, NVD 1208 P, NVD 3316-P, NVD 1432-P
- 8 vulnerability findings documented with CVSSv3.1 scores and CWE classifications
- Forensic cross-analysis confirmed Dahua OEM heritage across all product lines

---

## [1.0.0] — 2026-04-17

### Changed (Breaking — Rebranding)
- **Project renamed**: RouterXPL-Forge → **EmbedXPL-Forge**
- **PyPI package**: `routerxpl` → **`embedxpl`** (`pip install embedxpl`)
- **CLI commands**: `routerxpl` → **`embedxpl`**; `exf` alias preserved
- **Python package**: `routerxpl/` → `embedxpl/` (all imports updated)
- **Classes**: `RouterXPLInterpreter` → `EmbedXPLInterpreter`, `RouterXPLException` → `EmbedXPLException`
- **Log file**: `routerxpl.log` → `embedxpl.log`
- **GitHub repo**: `mrhenrike/RouterXPL-Forge` → `mrhenrike/EmbedXPL-Forge`

### Changed (Scope)
- **Target scope expanded**: framework now explicitly covers Routers, Switches L2/L3, IP Cameras, GPON ONTs, ISP CPEs, and IoT/Embedded Edge devices
- Banner updated to reflect expanded scope
- `pyproject.toml`: added `embedded`, `firmware` keywords; description updated

### Infrastructure
- CI/CD guard conditions updated to `mrhenrike/EmbedXPL-Forge`
- PyPI OIDC Trusted Publisher re-bound to `embedxpl` project + `EmbedXPL-Forge` repo
- All 6 architecture PNG diagrams regenerated with EmbedXPL-Forge branding (v1.0.0)
- All 5 Mermaid source files updated
- All 26 wiki pages updated (en-US + pt-BR)

---

## [0.7.0] — 2026-04-08

### Added
- **Full RouterSploit parity** — 9 modules (4 new, 5 stubs upgraded with real exploit logic):
  - `cisco/secure_acs_5_x_unauthorized_password_change` — SOAP auth bypass
  - `cisco/ucm_tftp_info_disclosure_cve_2013_7030` — TFTP credential leak
  - `cisco/unified_multi_path_traversal_cve_2011_3315` — unauthenticated LFI
  - `zyxel/zywall_usg_config_hash_extraction` — config + hash download
  - Upgraded stubs: Firepower LFI/RCE (CVE-2016-6435/6433), UCS Shellshock (CVE-2014-6278), DGS-1510 (CVE-2017-6206), FortiGate SSH backdoor (CVE-2016-1909)
- **RouterPwn integration** — 13 high-value modules converted from routerpwn.com JS corpus:
  - D-Link: DIR-300/615 RCE, DSL-2750U auth bypass, DSL-320B config disclosure
  - Linksys: WRT54GL RCE, X2000 RCE
  - Netgear: DGN1000B RCE, WNDR3400 password disclosure
  - ASUS: RT-N16 password disclosure, RT-N66U/AC66U RCE
  - Cisco: EPC3925 CSRF password change
  - Ubiquiti: AirOS pre-auth RCE
  - Huawei: SmartAX MT880 admin add
  - TP-Link: TD-8840T password reset
- **Third-party CVE incorporation** — 3 priority modules:
  - `tplink/tl_wr820n_ssh_weak_crypto_cve_2025_14175` — SSH weak algo scanner
  - `xiaomi/mi_router_command_injection_cve_2023_26319` — post-auth smartcontroller RCE
  - `intelbras/nvd_9032_mfa_bypass_cve_2025_67070` — client-side MFA bypass
- **New vendor**: `xiaomi` (Mi Router family)
- CVE catalog: 338 → 343 entries (+5)

### Changed
- Module counts: 670 → 690 total, 520 → 540 exploits, 51 → 53 vendors
- `pyproject.toml` version bump to 0.7.0

## [0.6.3] — 2026-04-08

### Changed
- Removed generated artifacts from git tracking (COVERAGE_MATRIX.md/.txt, arsenal_index.json)
- Removed obsolete Travis CI configuration (.travis.yml, .travis/)
- MANIFEST.in: explicitly excludes tools/, docs/, .github/, .travis/ from sdist
- .gitignore: comprehensive exclusion of all generated and dev-only artifacts
- Package sdist now contains ONLY: embedxpl/ package + runtime resources + README/LICENSE/CHANGELOG

## [0.6.2] — 2026-04-08

### Added
- **2 new vendor families**: `dlink_dsl` (D-Link DSL modems), `juniper` (enterprise)
- **Exploit modules**:
  - `dlink_dsl/dsl_2750b_remote_code_execution_cve_2016_20017` — unauthenticated RCE (no auth)
  - `dlink_dsl/dsl_2640b_wps_rce_cve_2013_5223` — WPS PIN command injection
  - `juniper/junos_backdoor_cve_2015_7755` — NSA/GCHQ backdoor password (CVSS 10.0)
  - `juniper/junos_web_auth_bypass_cve_2023_36845` — J-Web PHP env RCE (CVSS 9.8)
  - `netgear/dgn1000_unauthenticated_rce` — setup.cgi syscmd no auth
  - `multi/netusb_kernel_stack_overflow_cve_2021_45388` — KCodes NetUSB crash/DoS (20+ brands)
- **Generic modules** (RouterSploit gaps):
  - `generic/snmp/snmp_bruteforce` — SNMP community string bruteforce
  - `generic/tcp_xmas` — TCP Xmas scan for firewall evasion testing
  - `generic/udp_amplification` — UDP amplification factor tester (DNS/NTP/SSDP/SNMP/CharGen)
- **CI scripts** (5 missing tools created):
  - `tools/run_scoped_tests.py` — module syntax + __info__ key validation gate
  - `tools/validate_market_priority_minimums.py` — coverage threshold checks
  - `tools/validate_governance.py` — governance file baseline check
  - `tools/deep_intel_backlog.py` — catalog enrichment report (non-gating)
  - `tools/phase6b_honeypot_validation.py` — honeypot ref snapshot (non-gating)
- `CONTRIBUTING.md` — governance baseline file

### Fixed
- `publish-pypi.yml` — added `PYPI_API_TOKEN` secret fallback for OIDC Trusted Publisher
  (configure on PyPI at https://pypi.org/manage/account/publishing/)

### Changed
- `pyproject.toml`: 0.6.1 → 0.6.2
- README.md: 657 → **666 modules**, 510 → **516 exploits**, 9 → **12 generic**, 49 → **51 vendors**
- COVERAGE_MATRIX.md: updated to v0.6.2

### Module Counts

| Category | 0.6.1 | 0.6.2 |
|----------|-------|-------|
| Exploits | 510 | **516** |
| Generic | 9 | **12** |
| **Total** | **657** | **666** |
| Vendors | 49 | **51** |

---

## [0.6.1] — 2026-04-08

### Added
- **4 new vendor families**: `actiontec`, `arcadyan`, `netis`, `pfsense`
- **10 new exploit modules** from third-party-router-poc analysis:
  - `actiontec/mi424wr_rce_cve_2014_9583` — Verizon FIOS traceroute cmd injection
  - `arcadyan/o2_box_6431_password_disclosure_cve_2015_7288` — pre-auth config/cred disclosure
  - `netis/mw5360_mw5370_rce_cve_2014_8572` — hardcoded UDP 53413 backdoor (no auth)
  - `pfsense/pfsense_2_2_6_command_injection_cve_2016_10709` — rrd_graph cmd injection
  - `trendnet/tew_827dru_ping_command_injection_cve_2019_13150`
  - `trendnet/tew_651br_tew_652brp_rce_cve_2019_13276`
  - `zte/f660_config_download_decrypt` — pre-auth ZTE F660 config download
  - `zyxel/vmg8825_ping_command_injection_cve_2019_9955`
  - `tplink/tl_wr841nd_password_disclosure_cve_2020_35575`
  - `multi/openwrt_luci_rce_cve_2021_22161` — CRLF injection + empty-password login
- **GitHub Wiki** — 19 pages (en-US complete + pt-BR core), sidebar, footer

### Fixed
- `tools/refresh_cve_extended_catalog.py` — `Optional` not imported (F821 flake8 error)
- `publish-pypi.yml` — auto-tag now checks for existing tag before creating
- Removed exclusive EG8145X6 wiki pages (12) — Huawei treated as regular vendor
- Removed NGFW/UTM and TAP architecture diagrams (no dedicated modules)

### Changed
- `pyproject.toml` version 0.6.0 → 0.6.1
- README.md: 647 → **657 modules**, 500 → **510 exploits**
- COVERAGE_MATRIX.md updated to v0.6.1

### Module Counts

| Category | 0.6.0 | 0.6.1 |
|----------|-------|-------|
| Exploits | 500 | **510** |
| Creds | 88 | 88 |
| **Total** | **647** | **657** |

---

## [0.6.0] — 2026-04-08

### Added
- **11 Huawei EG8145X6-10 exploit modules** — info disclosure, brute-force (rate-limit bypass), CSRF static token, pre-auth user enum, config AES decrypt, Epuser firewall bypass (CVE-2025-49599), MitM credential intercept, Telnet enable, CSRF payload generator, DNS poison via CSRF, WiFi credential extractor
- **`eg8145x6_autopwn`** — 9-phase chained exploitation: fingerprint → info disclosure → CSRF → user enum → brute-force → config decrypt → JS capture → port scan → report + generic fallback (v1.1.0)
- **`generic/upnp/igd_exploit`** — UPnP IGD full exploitation: SSDP discovery, GetExternalIPAddress, AddPortMapping (firewall bypass without auth), GetGenericPortMappingEntry, traffic stats, ForceTermination DoS check, event SUBSCRIBE
- **`core/oui.py`** — IEEE OUI database with online-first lookup and local fallback
- **`core/session.py`** — Persistent scan history per host (SHA-256 of IP+MAC), `~/.exf_sessions/`
- **`core/discovery.py`** — T0–T5 timing profiles, multi-method host discovery, wireless detection, WirelessXPL-Forge recommendations, session integration
- **`embedxpl/data/oui.txt`** — Full IEEE OUI database (39k+ entries)
- **`embedxpl/__main__.py`** — `python -m embedxpl` and `exf` / `embedxpl` console scripts
- **`pyproject.toml`** — PEP 517/518 packaging (replaces legacy setup.py)
- **GitHub Actions** — `publish-pypi.yml` for Trusted Publishing (OIDC, no API tokens)
- Wiki pages 01–12 (en-US + pt-BR)
- GPON ONT attack surface diagram (`07-gpon-ont-attack.mmd` + PNG)

### Changed
- `interpreter.py` — Added `discover` and `sessions` commands, WiFi recommendation panel
- `cve_extended_catalog.json` — 338 total CVEs (+8: RXPL-2026-HW-001..008, CVE-2025-49599 expanded)
- `huawei_defaults.txt` — 50+ credentials including ISP-specific Brazil (Sumicity, Loga, Vivo, Claro, Oi)
- `setup.py` — Reduced to a PEP 517 shim; all metadata in `pyproject.toml`
- README, diagrams, and wiki updated: removed NGFW/UTM and TAP (no dedicated modules), corrected module counts

### Removed
- `docs/diagrams/architecture/03-ngfw-utm.mmd` — no dedicated NGFW modules
- `docs/diagrams/architecture/06-network-tap.mmd` — TAP support was planned only
- `docs/img/architecture/exf_arch_ngfw_utm.png`

### Module Counts

| Category | 0.5.x | 0.6.0 |
|----------|-------|-------|
| Exploits | 429 | 500 |
| Creds | 88 | 88 |
| Scanners | 5 | 5 |
| Payloads | 32 | 32 |
| Encoders | 13 | 13 |
| Generic | 8 | 9 |
| **Total** | **575** | **647** |
| CVEs | 330 | **338** |

---

## [0.5.0] — 2026-04-04

### Added
- Machine Learning advisor (CVSS scoring, module prioritization)
- ML response classifier (TF-IDF + Logistic Regression)
- Banner fingerprinter (regex, substring, GPU-accelerated cosine similarity)
- System hardware profiler (CPU, RAM, GPU detection)
- GPU multi-backend: CUDA, AMD ROCm, OpenCL, CPU fallback
- SmartPool adaptive thread/process pool
- AsyncScanEngine with async HTTP client
- Rich-based TUI — all console output migrated from ANSI to Rich
- Network discovery engine (Nmap + Scapy + ARP + TCP fallback)

### Changed
- 60 new exploit modules imported from third-party-router-poc
- Module audit and enrichment across all 575 modules

---

## [0.4.0-beta] — 2026-04-03

### Added
- Major exploit incorporation: 575 modules, 330 CVEs, 49 vendors
- Architecture diagrams (Mermaid + PNG)
- Coverage matrix
- Bilingual documentation (en-US + pt-BR)

---

*Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)*
