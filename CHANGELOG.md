# Changelog

All notable changes to EmbedXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) -- `MAJOR.MINOR.PATCH`.

---

## [3.8.3] - 2026-06-25

### Fixed
- `bravia_upnp_audit`: fetch device descriptor from `/description.xml` (lab mock) with fallbacks; check uses GetVolume when XML paths fail.
- `hp_laserjet_ssrf_cve_2024_4479`: recognize IoT lab mock SSRF response.

---

## [3.8.2] - 2026-06-24

### Added
- Virtual environment bootstrap: `setup_venv.sh`, `setup_venv.ps1`, `run.sh`, `run.ps1`, and `tools/venv_bootstrap.py` ? `python exf.py` auto-reexecutes with `.venv` (PEP 668 safe).
- AutoPwn `https_use` option ? HTTP modules can probe both plain HTTP and HTTPS ports independently.

### Changed
- AutoPwn default service toggles: only HTTP, HTTPS, TCP, and UDP enabled; FTP, SSH, SFTP, Telnet, and SNMP disabled by default (default ports preserved).
- AutoPwn: configurable multi-port lists per protocol (`http_ports`, `https_ports`, `ftp_ports`, etc.) visible in `show options`.
- AutoPwn: custom/tcp modules infer service family (SSH, FTP, Telnet, SNMP) from module path and default port to respect service toggles.
- README / README.pt-BR: document venv setup and run scripts.

### Fixed
- AutoPwn threading: `DummyFile` missing `flush()` caused Rich console crashes in worker threads (`@mute` decorator).
- AutoPwn: safe `target_protocol` resolution prevents `AttributeError` during parallel checks.
- `uniview_nvr_unauth_rce_cve_2024_37630`: inherit `HTTPClient`, use `http_request()` API, lab port 8080.
- `upnp_unauth_volume_control` (Sony Bravia): minor compatibility fix.

---

## [3.8.1] - 2026-06-16

### Added - Rockwell Automation ICS Wave (ICSA-26-167-01 through 05)

**ICS / Rockwell Automation - June 2026 CISA Advisories:**
- `ics/rockwell/factorytalk_analytics_pavilionx_icsa_26_167_01.py` (CVE-2025-9364, CVE-2024-6435, CVE-2024-7961)
  Three-vector module: (1) unauthenticated Redis INFO/KEYS access in FactoryTalk Analytics
  LogixAI 3.00/3.01 (CVE-2025-9364 CVSS AV:A); (2) privilege escalation via incorrect
  privilege matrix in PavilionX 5.15-5.20 to create admin accounts (CVE-2024-6435 CVSS 8.8);
  (3) path traversal upload for RCE in PavilionX < 5.20 (CVE-2024-7961 CVSS 7.2).
- `ics/rockwell/rslinx_classic_dos_icsa_26_167_02.py` (CVE-2020-13573, CVSS 7.5)
  EtherNet/IP DoS against RSLinx Classic <= 4.50.00 via malformed packets (oversized,
  list_identity fuzz, register_fuzz variants). Crashes the RSLinx service disrupting
  SCADA/HMI to PLC communications.
- `ics/rockwell/logix_5370_5570_cip_dos_icsa_26_167_03.py` (CVE-2022-3157, CVE-2025-11743, CVE-2020-6998)
  Unified CIP ForwardOpen MNRF module for CompactLogix 5370 (fw <= 36.011) and
  ControlLogix 5570 (fw <= 33). Malformed ForwardOpen with invalid slot segment and
  multi-service fuzz trigger Major NonRecoverable Fault requiring controller restart.
- `ics/rockwell/compactlogix_icsa_26_167_04.py` (ICSA-26-167-04)
  CompactLogix 2026 multi-surface: (1) unauthenticated CIP tag write to alter process
  values; (2) embedded web server recon - firmware version, task list, tag names without
  auth; (3) FTP project exfiltration - extracts .ACD/.L5X controller project files.
- `ics/rockwell/flex_io_ethernetip_dos_icsa_26_167_05.py` (CVE-2026-0646, CVE-2026-0647)
  Two-vector DoS for Rockwell 1794-AENTR FLEX I/O EtherNet/IP Adapter V2.012:
  CVE-2026-0646 malformed ForwardOpen slot path triggers improper input validation
  (power cycle required); CVE-2026-0647 parallel connection flood exhausts adapter
  connection table causing I/O communication loss (power cycle required).

### Changed
- CVE catalog updated: 536 -> 545 entries (9 new Rockwell ICSA-26-167 records)

---

## [3.8.0] - 2026-06-15

### Added - CVE Wave 4 Jun 2026: 14 new modules across SIEM, backup, AI-infra, CI/CD, databases, ERP, cloud-SaaS, OS

**SIEM and Security Monitoring:**
- `siem/wazuh/wazuh_inventory_sync_ndjson_injection.py` (GHSA-ff9g-85jq-r3g3, CVSS 10.0)
  Unauthenticated NDJSON injection into Wazuh Manager 5.0.0-beta1 inventory_sync pipeline.
  Allows alert manipulation, evidence deletion, and arbitrary OpenSearch operations.
- `siem/splunk/splunk_postgres_sidecar_preauth_rce_cve_2026_20253.py` (CVE-2026-20253, CVSS 9.8)
  Pre-auth RCE via unauthenticated PostgreSQL sidecar backup/restore endpoints.
  Achieves arbitrary file write then Python script override for code execution.

**Firewall and VPN:**
- `firewalls/paloalto/panos_root_cmd_injection_cve_2026_0273.py` (CVE-2026-0273, HIGH)
  Authenticated PAN-OS command injection as root via CLI/WebUI on PA-Series, VM-Series, Panorama.
- `vpn/ivanti/ivanti_sentry_rce.py` (Ivanti Sentry Jun 2026, CRITICAL, actively exploited)
  Pre-auth RCE via Ivanti Sentry MICS administrative interface.

**Infrastructure and Backup:**
- `infrastructure/veeam/veeam_backup_domain_rce_cve_2026_44963.py` (CVE-2026-44963, CVSS 9.4)
  Any authenticated domain user can execute code on domain-joined Veeam Backup & Replication.

**Linux Kernel:**
- `linux/kernel/kvm_arm64_itscape_guest_host_escape_cve_2026_46316.py` (CVE-2026-46316, CRITICAL)
  ITScape: race condition in vGIC-ITS emulation on arm64 KVM. Guest-to-host kernel escape.
  Bridges ITScape PoC by Hyunwoo Kim (V4bel).

**AI Infrastructure:**
- `ai_infra/litellm/litellm_mcp_cmd_injection_cve_2026_42271.py` (CVE-2026-42271, CISA KEV)
  Pre-auth command injection in LiteLLM proxy MCP configuration endpoints.
  Exfiltrates AI provider API keys (OpenAI, Anthropic, etc.).

**CI/CD:**
- `ci_cd/jenkins/jenkins_deserialization_rce_cve_2026_53435.py` (CVE-2026-53435, CVSS 8.8)
  Deserialization in Jenkins enables user impersonation and Groovy RCE via Script Console.

**Databases:**
- `databases/mariadb/mariadb_rce_cve_2026_49261.py` (CVE-2026-49261, CVSS 10.0)
  Critical RCE in MariaDB < 11.8.8/11.4.12/10.11.18/10.6.27.
- `databases/oracle/oracle_ords_rce.py` (Oracle ORDS Jun 2026, CRITICAL)
  Critical vulnerability in Oracle REST Data Services requiring urgent patching.

**ERP:**
- `erp/oracle/oracle_peoplesoft_gadget_chain_rce.py` (active, ShinyHunters)
  Gadget chain RCE in Oracle PeopleSoft. Used by ShinyHunters in 300+ instance compromise.
  Includes ShinyHunters IOCs and lateral SSH spray with common PeopleSoft accounts.

**Cloud SaaS:**
- `cloud_saas/servicenow/servicenow_instance_access.py` (active exploitation)
  Unauthorized access to ServiceNow customer instances for data exfiltration.

**Cryptography:**
- `crypto/openssl/openssl_rce_cve_2025_15467.py` (CVE-2025-15467, HIGH)
  RCE in OpenSSL affecting Siemens Scalance/Simatic/Sinamics/Sinec and other products.

**Windows:**
- `windows/rdp/rdp_sensitive_data_exposure.py` (Microsoft June 2026 Patch Tuesday)
  Windows RDP sensitive data exposure via CredSSP/NTLM negotiation.

### Fixed - Module Health and Deduplication
- Removed 8 true duplicate modules across EmbedXPL (generic/, network_os/, misc/ leftover copies)
- Removed 1 FirewallXPL duplicate (fortimanager in routing/ - canonical is perimeter/)
- Added `check()` methods to 126 WirelessXPL modules missing the API contract
- WirelessXPL categories covered: bluetooth (21), wifi_lab (58), external (30), cellular (6), sim (6), pcap (4), cve (1)
- Updated cve_extended_catalog.json to 536 entries (was 522)

### Synced to specialized repos
- `panos_root_cmd_injection_cve_2026_0273.py` synced to FirewallXPL perimeter/paloalto/
- `ivanti_sentry_rce.py` synced to FirewallXPL vpn/ivanti/

## [3.7.0] - 2026-06-15

### Added - CVE Wave May-Jun 2026: ~30 new modules across 8 device categories

**Ubiquiti UniFi OS (new vendor modernization):**
- `routers/ubiquiti/unifi_os_rce_chain_cve_2026_34908.py` (CVE-2026-34908/34909/34910, CVSS 10.0, CISA KEV)
  Full three-stage unauthenticated root RCE chain on all UniFi OS appliances < 4.0.21.
  Stage 1: path traversal reads JWT secret; Stage 2: forges HS256 token; Stage 3: exec endpoint RCE.
- `routers/ubiquiti/unifi_os_path_traversal_cve_2026_34908.py` (Stage 1 individual module)
- `routers/ubiquiti/unifi_os_jwt_bypass_cve_2026_34909.py` (Stage 2 individual module)
- `routers/ubiquiti/unifi_os_rce_cve_2026_34910.py` (Stage 3 individual module)
- `routers/ubiquiti/unifi_network_path_traversal_cve_2026_22557.py` (CVE-2026-22557, CVSS 8.1)
  UniFi Network Application config-export path traversal.
- `routers/ubiquiti/unifi_os_path_traversal_cve_2026_47368.py` (CVE-2026-47368, CVSS 8.6)
  UniFi OS filemanager double-encoded traversal.

**Cisco SD-WAN (new 2026 modules):**
- `firewalls/cisco/cisco_sdwan_auth_bypass_cve_2026_20127.py` (CVE-2026-20127, CVSS 10.0)
  vManage REST API auth bypass via alg:none JWT. Full config R/W and CLI backdoor.
- `firewalls/cisco/cisco_sdwan_privesc_cve_2026_20245.py` (CVE-2026-20245, CVSS 7.8, CISA KEV)
  SD-WAN CLI shell injection for privilege escalation to root. SSH access required.

**Routers and Firewalls (new 2026):**
- `routers/dlink/di8400_unauth_rce_cve_2026_10206.py` (CVE-2026-10206, CVSS 9.8)
  D-Link DI-8400 unauthenticated command injection via wan.asp.
- `routers/kangda/dr300_hardcoded_telnet_cve_2026_10045.py` (CVE-2026-10045, CVSS 9.8)
  Kangda DR300 hardcoded Telnet credentials, no patch.
- `routers/acer/connect_m6e_5g_multi_cve_2026_49185.py` (CVE-2026-49185/49187/50213, CVSS 9.8)
  Acer Connect M6E auth bypass + info disclosure + ping injection RCE.
- `firewalls/fortinet/fortios_missing_auth_rce_cve_2025_53847.py` (CVE-2025-53847, CVSS 8.8)
  FortiOS secondary fgfmd socket missing auth RCE (complements CVE-2025-53844).

**Switches (new vendor folders + modules):**
- `switches/tplink/omada_unauth_rce_cve_2026_1668.py` (CVE-2026-1668, CVSS 9.8)
  TP-Link Omada auth bypass via model-string header + exec endpoint RCE.
- `switches/hikvision/poe_switch_auth_rce_cve_2026_3828.py` (CVE-2026-3828, CVSS 7.2, EOL)
  Hikvision DS-3E0318P-E/DS-3E0326P-E/DS-3E1318P-E ISAPI command injection.
- `switches/atop/ehg2408_stack_bof_cve_2026_3823.py` (CVE-2026-3823, CVSS 9.3)
  Atop EHG2408 industrial switch unauthenticated stack BOF.
- `switches/arista/eos_privesc_detection_cve_2026_7473.py` (CVE-2026-7473, CVSS 6.9, CISA KEV)
  Arista EOS privilege escalation detection + mitigation. No vendor patch available.

**UPS and PDU (new vendor folders: ups/vertiv, ups/dataprobe, ups/pduexperts):**
- `ups/vertiv/liebert_auth_bypass_cve_2025_46412.py` (CVE-2025-46412, CVSS 9.8)
  Vertiv Liebert NMC predictable session token auth bypass.
- `ups/vertiv/liebert_stack_bof_cve_2025_41426.py` (CVE-2025-41426, CVSS 9.8)
  Vertiv Liebert NMC HTTP Basic Auth decoder stack BOF.
- `ups/dataprobe/iboot_multi_cve_unauth_rce.py` (Claroty research, CVSS 9.8)
  Dataprobe iBoot PDU multi-CVE: XFF auth bypass + command injection RCE.
- `ups/pduexperts/smart_pdu_unauth_rce_icsr_2026_02_001.py` (ICSR-2026-02-001, CVSS 9.8)
  PDUExperts Smart PDU unauthenticated Python exec endpoint.

**Drones (new category: drones/dji/):**
- `drones/dji/mavic_auth_bypass_cve_2026_1743.py` (CVE-2026-1743, CVSS 8.1)
  DJI Mavic Mini/Air/Spark FlightHub API auth bypass via null-byte token.
- `drones/dji/wifi_dos_cve_2026_26673.py` (CVE-2026-26673, CVSS 6.5)
  DJI Wi-Fi RC mode 802.11 deauth DoS. Detection + mitigation module.
- `drones/dji/v2_sdk_oob_write_cve_2023_51454.py` (CVE-2023-51454, CVSS 9.8)
  DJI v2 SDK TCP/10000 out-of-bounds write. Ported from ByteMe1001/DJI-CatNect.

**Cameras:**
- `cameras/dahua/ipc_nvr_dvr_multi_cve_2026_29116.py` (CVE-2026-29116/29115/29114, CVSS 8.7)
  Dahua chain: unauth snapshot, session ID brute-force, recording IDOR.

**Printers:**
- `printers/hplip_unauth_rce_cve_2026_8631.py` (CVE-2026-8631, CVSS 9.3)
  HPLIP hpiod command injection via Device URI on TCP/2208.

**Smart TV:**
- `smart_tv/samsung_tizen/escargot_js_engine_bof_cve_2026_25205.py` (CVE-2026-25205/25207/47311/8915)
  Samsung Tizen Escargot JS engine multiple memory corruption bugs. Detection module.

**NSE Scripts (4 new):**
- `nse/embedxpl-unifi-vuln.nse` -- UniFi OS/Network App CVE fingerprint + traversal probes
- `nse/embedxpl-switch-vuln.nse` -- Omada/Hikvision/Atop/Arista CVE detection
- `nse/embedxpl-drone-vuln.nse` -- DJI drone AP CVE fingerprint (authorized use only)
- `nse/embedxpl-ups-pdu-vuln.nse` -- Vertiv/Dataprobe/PDUExperts CVE detection

### Changed
- `pyproject.toml`: synchronized version to 3.7.0 (was desynchronized at 3.4.1)
- `pyproject.toml`: updated description to reflect expanded scope (drones, switches, UPS/PDU)

---

## [3.6.0] - 2026-06-02

### Added - Critical historical CVEs, Pulse Secure coverage, 178 total modules

**Fortinet critical new modules:**
- ortios_format_string_rce_cve_2024_23113.py (CVE-2024-23113, CVSS 9.8, CISA KEV)
  FortiOS fgfmd pre-auth RCE via format string vulnerability
- ortios_stack_overflow_rce_cve_2025_32756.py (CVE-2025-32756, CVSS 9.6)
  FortiOS/FortiProxy SSL-VPN stack-based buffer overflow unauth RCE
- ortios_fgfm_preauth_rce_cve_2024_47575.py (CVE-2024-47575, CVSS 9.8, CISA KEV)
  FortiManager FGFM protocol pre-auth file write + RCE

**Citrix/NetScaler comprehensive coverage:**
- citrix_adc_path_traversal_rce_cve_2019_19781.py (CVE-2019-19781, CVSS 9.8)
  Most exploited CVE of 2020 -- path traversal + Perl template RCE
- citrix_adc_auth_bypass_cve_2022_27510.py (CVE-2022-27510, CVSS 9.8)
- citrix_adc_rce_cve_2022_27518.py (CVE-2022-27518, CVSS 9.8) SAML RCE

**New vpn/pulsesecure/ vendor folder:**
- pulse_connect_secure_rce_cve_2021_22893.py (CVE-2021-22893, CVSS 10.0, CISA KEV)
- pulse_connect_rce_cve_2019_11510.py (CVE-2019-11510, CVSS 10.0, CISA KEV)
  Both among the most exploited VPN CVEs historically (APT29/Cozy Bear)

**Cisco additional:**
- CVE-2023-20032 (FMC RCE), CVE-2022-20713 (FTD bypass), CVE-2020-3580 (XSS chain)

**Other vendors expanded:**
- F5 BIG-IP: CVE-2024-21793 iControl REST auth bypass
- SonicWall: CVE-2020-15778 SCP command injection
- Hillstone: CVE-2024-5829 web RCE (2nd module)
- Kerio: CVE-2022-24665 VPN cmd injection (2nd module)
- OPNsense: CVE-2022-0993 CSRF RCE (2nd module)
- Sangfor: CVE-2021-1782 SSL VPN RCE (2nd module)
- Stormshield: CVE-2023-23770 SNS privilege escalation (2nd module)
- Imperva: CVE-2023-28051 Cloud WAF bypass (new module)

### Summary (v3.6.0)
- Total firewall exploit modules: **178**
- CVE catalog: **495 entries** (0 gaps)
- Vendor folders: **34** (+ vpn/pulsesecure added)
- Zero HTTP scaffolds, zero catalog gaps

# Changelog

---

## [3.5.1] - 2026-06-02

### Added - CVE catalog completion: all 159 modules indexed (0 gaps)

- `cve_extended_catalog.json`: 411 -> **477 entries**
  Added 66 missing catalog entries so that every firewalls/ exploit module
  now has a corresponding CVE record. Zero gaps in module-catalog coverage.
- `embedxpl/modules/exploits/firewalls/lb/__init__.py`: created missing package init
- `embedxpl/modules/exploits/firewalls/waf/__init__.py`: created missing package init

### Summary (final state)
- Firewall exploit modules: **159** (all with real CVE-specific implementations)
- HTTP scaffolds remaining: **0** (zero)
- Vendor folders: **34**
- CVE catalog entries: **477** (covers all 159 modules)
- Wiki: **24 EN-US + 24 PT-BR pages** (all 47 functions documented with I/O samples)

---

## [3.5.0] - 2026-06-02

### Added - Scaffold elimination complete, 159 modules with real CVE primitives

**Final scaffold fixes (all modules now have real CVE implementations):**
- hirschmann/eagle_auth_bypass_cve_2020_6994.py: REST API auth bypass via empty
  session token, 3-stage config extraction chain
- schneider/connexium_ssh_hardcoded_cve_2017_6026.py: SSH credential sweep with
  8 hardcoded pairs via paramiko, enumeration, reverse shell staging
- phoenix/mguard_cmd_injection_cve_2024_43386.py: form-based auth + diagnostic
  cmd injection, synced to phoenix_contact/
- generic/modbus_dpi_bypass.py: Modbus TCP/502 raw socket, 5 bypass techniques
- generic/dnp3_firewall_evasion.py: DNP3 TCP/20000 raw socket, 4 evasion techniques
- generic/iec104_manipulation.py: IEC 60870-5-104 TCP/2404 raw socket, 5 APDU tests
- generic/ethernetip_cip_bypass.py: EtherNet/IP TCP/44818+UDP/2222, 4 CIP tests
- generic/opcua_firewall_bypass.py: OPC UA TCP/4840 binary transport, 5 bypass tests
- 
ac/__init__.py: created missing package init file

**Tier 3 additional modules (from parallel agents):**
- sophos x2, checkpoint x2, juniper x1, cisco x4, fortinet x2, aruba x2, meraki x1,
  pfSense x2, f5 x1, zyxel x1, sonicwall x1, watchguard x1, barracuda x1, citrix x2,
  ivanti x2, sangfor x1 — all with real exploitation chains

**CVE catalog:** 385 -> 411 entries (+26 from Tier 3)

### Summary
- Total firewall exploit modules: 159 (all with real CVE-specific implementations)
- Zero HTTP scaffolds remaining
- Vendor coverage: 34 folders
- CVE catalog: 411 entries
- Wiki: 24 EN-US + 24 PT-BR pages covering all 47 functions

All notable changes to EmbedXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`.



## [3.4.0] - 2026-06-02

### Added - Tier 3 CVE expansion: 27 new modules, Sangfor + Citrix vendors, wiki complete

**New vendor folder: sangfor/**
- `exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393.py` (CVE-2019-13393, CVSS 9.8)
  Sangfor NGFW unauthenticated RCE via management endpoint command injection

**New vendor folder: citrix/ (firewalls)**
- `exploits/firewalls/citrix/citrix_adc_gateway_rce_cve_2023_3519.py` (CVE-2023-3519, CVSS 9.8)
- `exploits/firewalls/citrix/citrix_bleed_info_disclosure_cve_2023_4966.py` (CVE-2023-4966, CVSS 9.4)

**New VPN sub-structure: vpn/ivanti/**
- `exploits/firewalls/vpn/ivanti/ivanti_connect_secure_ssrf_rce_cve_2024_21888.py` (CVE-2024-21888, CVSS 9.8)
- `exploits/firewalls/vpn/ivanti/ivanti_policy_secure_rce_cve_2024_22024.py` (CVE-2024-22024, CVSS 8.3)

**Sophos additional modules**
- `sophos_xg_rce_cve_2020_29583.py` (CVE-2020-29583, CVSS 9.8)  hardcoded PostgreSQL credentials
- `sophos_utm_rce_cve_2022_4934.py` (CVE-2022-4934, CVSS 8.8)  UTM web proxy cmd injection

**Check Point additional modules**
- `checkpoint_gaia_portal_sqli_cve_2021_30358.py` (CVE-2021-30358, CVSS 9.8)  Gaia portal SQLi
- `checkpoint_mobile_access_ssrf_cve_2020_6017.py` (CVE-2020-6017, CVSS 8.1)  Mobile Access SSRF

**Juniper additional**
- `juniper_ex_auth_bypass_cve_2019_0028.py` (CVE-2019-0028, CVSS 9.8)  EX J-Web auth bypass

**Cisco ASA historical CVEs**
- `cisco_asa_snmp_rce_cve_2016_6366.py` (CVE-2016-6366, CVSS 9.8)
- `cisco_asa_webvpn_rce_cve_2014_3390.py` (CVE-2014-3390, CVSS 10.0)
- `cisco_asa_path_traversal_cve_2018_0296.py` (CVE-2018-0296, CVSS 7.5)
- `cisco_ios_xe_csrf_rce_cve_2021_1442.py` (CVE-2021-1442, CVSS 8.8)

**Fortinet additional**
- `fortios_path_traversal_cve_2022_40685.py` (CVE-2022-40685, CVSS 7.5)
- `fortianalyzer_sql_inject_cve_2021_26103.py` (CVE-2021-26103, CVSS 9.8)

**Aruba NAC additional**
- `aruba_clearpass_rce_cve_2023_25594.py` (CVE-2023-25594, CVSS 9.8)
- `aruba_clearpass_sqli_cve_2022_37897.py` (CVE-2022-37897, CVSS 9.8)

**Cisco Meraki additional**
- `meraki_mx_config_api_bypass_cve_2023_20014.py` (CVE-2023-20014, CVSS 9.1)

**pfSense additional**
- `pfsense_sqli_cve_2021_41283.py` (CVE-2021-41283, CVSS 8.8)  SQLi in diag_backup.php

### Fixed
- `pfsense/pfblockerng_rce_cve_2022_31814.py`: replaced HTTP availability scaffold with real
  Host header injection chain (base64-encoded command, DNSBL endpoint targeting, output retrieval)

### Changed
- `cve_extended_catalog.json`: 383 -> 385 entries (CVE-2022-31814, CVE-2019-13393 added)
- Total firewall exploit modules: 126 -> 153
- Total firewall vendor folders: 31 -> 34 (sangfor, citrix, vpn added)

---

## [3.3.1] - 2026-06-02

### Added - Citrix VPN CVEs ported from FirewallXPL-Forge + gitignore hardening

**Citrix ADC/Gateway (ported from FirewallXPL-Forge vpn/citrix/)**
- `exploits/vpn/citrix/adc_rce_cve_2019_19781.py` (v2.0.0)
  - CVE-2019-19781 (CVSS 9.8, CISA KEV): directory traversal + Perl template injection RCE
  - Full E2E: SMB config file read, template write via newbm.pl, execution, ShellStagingMixin
- `exploits/vpn/citrix/netscaler_rce_cve_2023_3519.py` (v2.0.0)
  - CVE-2023-3519 (CVSS 9.8, CISA KEV): unauthenticated stack overflow RCE in NSPPE
  - Detection via OIDC endpoint (Gateway vserver required), overflow trigger, shell staging

### Changed
- `pyproject.toml`: bumped version 3.2.1 -> 3.3.0 -> 3.3.1; updated description (removed stale v3.1.0 reference)
- `embedxpl/resources/catalogs/cve_extended_catalog.json`: +2 entries (CVE-2019-19781, CVE-2023-3519), count 383->385
- `docs/wiki/en-US/README.md`: TOC now includes all 23 chapters (14-23 were missing)

### Fixed (FirewallXPL-Forge)
- `.gitignore`: added `.tmp/`, `.env`, `lab/`, generated artifacts patterns (aligned with EmbedXPL)

---

## [3.3.0] - 2026-06-01

### Added - Firewall CVE Expansion (30+ E2E Modules), 12 New Vendor Folders, Complete Wiki Rewrite

#### Firewall exploit modules (new)

**Cisco (3 new)**

- xploits/firewalls/cisco/cisco_sdwan_dtls_auth_bypass_cve_2026_20182.py
  - CVE-2026-20182, CVSS 10.0 -- SD-WAN vManage DTLS unauthenticated authentication bypass
- xploits/firewalls/cisco/cisco_fmc_auth_bypass_rce_cve_2026_20079.py
  - CVE-2026-20079, CVSS 10.0 -- Firepower Management Center authentication bypass + RCE
- xploits/firewalls/cisco/cisco_fmc_deserialization_rce_cve_2026_20131.py
  - CVE-2026-20131, CVSS 10.0 -- FMC Java deserialization remote code execution

**PAN-OS (3 new)**

- xploits/firewalls/paloalto/panos_dns_heap_rce_cve_2026_0264.py
  - CVE-2026-0264, CVSS 7.2 -- DNS proxy heap overflow RCE
- xploits/firewalls/paloalto/panos_ikev2_rce_cve_2026_0263.py
  - CVE-2026-0263, CVSS 7.2 -- IKEv2 daemon memory corruption RCE
- xploits/firewalls/paloalto/panos_cas_auth_bypass_cve_2026_0265.py
  - CVE-2026-0265, CVSS 7.2 -- Certificate Authentication Service auth bypass

**Fortinet (3 new)**

- xploits/firewalls/fortinet/fortios_heap_overflow_rce_cve_2026_25249.py
  - CVE-2026-25249, CVSS 9.6 -- FortiOS httpsd heap overflow unauthenticated RCE
- xploits/firewalls/fortinet/fortios_oob_write_rce_cve_2025_53844.py
  - CVE-2025-53844, CVSS 9.3 -- FortiOS out-of-bounds write memory corruption RCE
- xploits/firewalls/fortinet/fortiswitch_unauth_passwd_cve_2024_48887.py
  - CVE-2024-48887, CVSS 9.3 -- FortiSwitch unauthenticated admin password reset

**Check Point (2 new)**

- xploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919.py
  - CVE-2024-24919, CVSS 8.6 -- VPN Gateway LFI to credential extraction full chain
- xploits/firewalls/checkpoint/checkpoint_remote_code_exec_cve_2023_28461.py
  - CVE-2023-28461, CVSS 9.8 -- SSL Network Extender RFI remote code execution

**Juniper (2 new)**

- xploits/firewalls/juniper/juniper_srx_file_upload_rce_cve_2023_36851.py
  - CVE-2023-36851, CVSS 9.8 -- SRX J-Web unauthenticated file upload RCE
- xploits/firewalls/juniper/juniper_srx_unauth_rce_cve_2025_21590.py
  - CVE-2025-21590, CVSS 9.8 -- SRX session prediction unauthenticated RCE

#### New vendor coverage

New vendor folders added under xploits/firewalls/:
mikrotik (3 modules), huawei (2), opnsense (1), kerio (1), stormshield, hillstone, yos

#### Scaffold upgrades

Replaced HTTP-only check() stubs with CVE-specific network probes in:
- Siemens SCALANCE
- Siemens RUGGEDCOM
- Siemens SINEMA RC
- Moxa EDR-G9010
- Sophos Firewall
- WatchGuard Firebox
- Zyxel USG
- pfSense pfBlockerNG

#### Documentation

- Rewrote all 13 existing wiki pages EN-US with complete I/O samples for all 47 shell functions
- Created 10 new wiki pages EN-US (14-23) with full parameter tables and terminal examples
- Created 23 wiki pages PT-BR covering all commands and modules
- Updated wiki index README in both languages (en-US and pt-BR)

---
## [3.2.1] - 2026-06-01

### Added - CVE-2026-0257 PAN-OS GlobalProtect Authentication Override Cookie Bypass

**CVE-2026-0257 (CVSS 7.8 HIGH, CISA KEV 2026-05-29, Active exploitation)**
- `exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257.py`
  - Full E2E PoC: TLS certificate chain extraction -> RSA-PKCS1v15 cookie forge -> auth bypass -> VPN session
  - No credentials required; only HTTPS access to GlobalProtect portal/gateway
  - Requires auth override cookies enabled with cert shared with HTTPS service (common default)
  - CISA KEV deadline: 2026-06-19

**NSE Update**
- `nse/embedxpl-perimeter-vuln.nse`: added CVE-2026-0257 probe

**Catalog**
- `cve_extended_catalog.json`: +1 entry (CVE-2026-0257), count 354->355

---

## [3.2.0] - 2026-05-28

### Added - CVE-2026-35616 E2E Weaponization + GTFOBins + FIRESTARTER Chain + NSE Suite

#### Core: Shell Stager Framework

- New `shell_stager.py`: 26 shell types, PTY-aware listener (tty.setraw + select +
  SIGWINCH), Meterpreter RC generation, ShellStagingMixin (force_exploit, ask_on_fail)
- GTFOBins post-exploitation cheatsheet (35 entries): SUID/sudo/capabilities/BusyBox
  escape/NVRAM/cron persist/exfiltration -- printed automatically after shell session

#### CVE Modules Updated/Added

| CVE | Tool | Change |
|---|---|---|
| CVE-2026-35616 | FortiClient EMS | Rewritten v1.1.0->v4.0.0: correct X-SSL-CLIENT-VERIFY header spoofing, real X.509 cert forge (RSA-2048/SHA-256), fleet enumeration, shell staging |
| CVE-2022-40684 | FortiOS | v2.0.0: Forwarded header bypass, config dump, SSH key inject, CLI shell |
| CVE-2022-42475 | FortiOS | v2.0.0: Heap overflow trigger, crash detection, listener |
| CVE-2023-48788 | FortiClientEMS | v2.0.0: Time-based SQLi, xp_cmdshell, OS exec, shell |
| CVE-2024-55591 | FortiOS | v2.0.0: WebSocket bypass, admin inject, config dump, shell |
| CVE-2025-20362+20333 | Cisco ASA/FTD | New: FIRESTARTER chain (UAT4356/ArcaneDoor, CISA AR26-113A), shell staging |

#### NSE Scripts (10 total, 4 new)

- `embedxpl-perimeter-vuln.nse`: 15 firewall/VPN vendors, 19 CVEs, EmbedXPL+FirewallXPL refs
- `embedxpl-router-vuln.nse`: 15 SOHO router vendors, 14 CVEs, MikrotikAPI-BF + WirelessXPL refs
- `embedxpl-printer-vuln.nse`: 11 printer/MFP vendors, PJL+IPP+HTTP, PrinterXPL-Forge primary ref
- `embedxpl-suite-ref.nse`: full 5-tool suite install guide + GTFOBins quick reference
- All 7 existing NSEs: en-US corrected, full suite refs, GTFOBins links

#### CVE Catalog

- +4 entries: CVE-2026-35616, CVE-2026-24858, CVE-2025-20362, CVE-2025-20333

---

## [3.1.0] -- 2026-05-12

### Added — CVE 2026/2025/2024 Integration + PrinterXPL Port + Domain Enable

#### Core: Printer domain enabled

- Removed `DISABLED_MODULE_DOMAINS = ("printers",)` restriction in `embedxpl/core/exploit/utils.py`
- All 185+ existing printer modules now indexed and loadable
- New baseline: 2738+ modules

#### Track A1: PrinterXPL EDB/Research ports (8 new modules)

| Module | EDB Ref | Technique |
|--------|---------|-----------|
| `edb_15631_pjl_unrestricted_access` | EDB-15631 | PJL FSDIRLIST/FSDOWNLOAD unrestricted access |
| `edb_22319_hp_snmp_info_disclosure` | EDB-22319 | HP SNMP community string enumeration |
| `edb_45205_generic_printer_rce` | EDB-45205 | Generic firmware upload RCE |
| `edb_50498_lexmark_stored_xss` | EDB-50498 | Lexmark stored XSS via printer-name |
| `edb_51606_hp_ssrf_cve_2021_3441` | CVE-2021-3441 | HP FutureSmart SSRF via scan URL |
| `edb_51928_ricoh_auth_bypass` | EDB-51928 | Ricoh cookie-based auth bypass |
| `samsung_cve_2016_11061_xxe` | CVE-2016-11061 | Samsung SyncThru XXE injection |
| `xerox_cve_2023_3710_workcentre_rce` | CVE-2023-3710 | Xerox WorkCentre command injection |

#### Track A2: Native MSF implementations (3 new modules, no subprocess)

| Module | Technique |
|--------|-----------|
| `hp_laserjet_pjl_scan_native` | Full PJL scanner via raw socket port 9100 |
| `hp_laserjet_snmp_community_enum` | SNMP v1/v2c community brute via UDP |
| `canon_driver_privesc_cve_2021_38085` | Canon driver LPE via HTTP upload |

#### Track B: CVEs 2026 (user-requested, 11 new modules)

| Module | CVE | CVSS | Technique |
|--------|-----|------|-----------|
| `gnu_inetutils_telnetd_auth_bypass_cve_2026_24061` | CVE-2026-24061 | 9.8 | telnetd IAC bypass, unauth root |
| `cups_pwn2own_stage1_cve_2026_34477` | CVE-2026-34477 | 9.9 | CUPS cups-browsed UAF |
| `cups_pwn2own_stage2_cve_2026_34478` | CVE-2026-34478 | 9.9 | CUPS heap spray via IPP |
| `cups_pwn2own_stage3_cve_2026_34479` | CVE-2026-34479 | 9.9 | CUPS ROP chain LPE |
| `cups_pwn2own_chain_cve_2026_34480` | CVE-2026-34480 | 9.9 | CUPS chain orchestrator (stages 1-3) |
| `cve_2026_31602_unauth_rce` | CVE-2026-31602 | 9.8 | Embedded router unauth RCE |
| `cve_2026_40683_embedded_rce` | CVE-2026-40683 | 9.8 | Embedded OS RCE |
| `cve_2026_22812_cmd_injection` | CVE-2026-22812 | 9.8 | Router command injection |
| `cve_2026_0234_auth_bypass` | CVE-2026-0234 | 9.1 | Embedded device auth bypass |
| `cve_2026_21513_privesc` | CVE-2026-21513 | 8.8 | Embedded device privilege escalation |
| `cve_2026_21519_rce` | CVE-2026-21519 | 9.8 | Embedded device unauth RCE |

#### Track C: CVEs 2026 threat intel (12 new modules)

| Module | CVE | CVSS | Technique |
|--------|-----|------|-----------|
| `wolfssl_identity_forgery_cve_2026_5194` | CVE-2026-5194 | 9.3 | wolfSSL TLS identity forgery (~5B devices) |
| `panos_userid_bof_rce_cve_2026_0300` | CVE-2026-0300 | 9.8 | PAN-OS User-ID BOF unauth RCE |
| `ur_polyscope5_dashboard_cmd_injection_cve_2026_8153` | CVE-2026-8153 | 9.8 | UR PolyScope 5 OS command injection |
| `riot_sixlowpan_oob_read_cve_2026_25139` | CVE-2026-25139 | 9.1 | RIOT OS 6LoWPAN OOB read |
| `enet_smarthome_default_creds_cve_2026_26366` | CVE-2026-26366 | 9.8 | eNet SMART HOME default credentials |
| `metis_wic_unauth_rce_cve_2026_2248` | CVE-2026-2248 | 9.8 | Metis maritime WIC unauth shell |
| `metis_dfs_unauth_rce_cve_2026_2249` | CVE-2026-2249 | 9.8 | Metis maritime DFS unauth shell |
| `openremote_expr_injection_rce_cve_2026_39842` | CVE-2026-39842 | 9.8 | OpenRemote expression injection RCE |
| `a7000r_cmd_injection_cve_2026_1623` | CVE-2026-1623 | 9.8 | Totolink A7000R CGI command injection |
| `rauc_integer_overflow_cve_2026_34155` | CVE-2026-34155 | 8.1 | RAUC update integer overflow firmware bypass |
| `openwrt_hotplug_privesc_cve_2026_30874` | CVE-2026-30874 | 7.8 | OpenWrt hotplug_call env var LPE |
| `tuya_arduino_dns_bof_cve_2026_28519` | CVE-2026-28519 | 8.8 | Tuya arduino-tuyaopen DNS heap BOF |

#### Track A3: PrinterXPL research modules (20 new modules)

BOF modules: `lexmark_heap_bof_cve_2023_50734`, `lexmark_ps_bof_cve_2023_50736`,
`lexmark_pwn2own_2026_chain`, `ricoh_http_bof_cve_2024_34161`,
`xerox_http_bof_rce`, `xerox_ipp_bof_rce`, `hp_printing_shellz_rce`

Protocol modules: `brother_ldap_smb_passback`, `brother_wsd_dos`, `brother_wsd_ssrf`,
`canon_xps_bof_cve_2025_14237`, `ipp_anon_print_inject`, `ipp_purge_jobs_dos`,
`ms_rprn_ntlm_coerce`, `pjl_pwd_disclosure_cve_2011_4786`, `ps_infinite_loop_dos`,
`tftp_loop_dos`, `wsd_printer_enum`, `ssport_lpe`, `hp_fw_sig_bypass`

#### Track D: CVEs 2025/2024 (3 new modules)

| Module | CVE | CVSS | Technique |
|--------|-----|------|-----------|
| `ios_xe_wlc_jwt_rce_cve_2025_20188` | CVE-2025-20188 | 10.0 | Cisco WLC hardcoded JWT file upload RCE |
| `ews356_blind_cmd_injection_cve_2024_36061` | CVE-2024-36061 | 9.8 | EnGenius EWS356-FIT blind command injection |
| `enstation5_cmd_injection_cve_2024_31976` | CVE-2024-31976 | 9.8 | EnGenius EnStation5-AC command injection |

#### Quality Gates (automated, 100% automated, no manual review)

New `tools/phase_gate.py` with 7 gates (A1A2, B, C, A3, D, E, final).
Each gate verifies: imports, class Exploit, `__info__` completeness, references URLs,
`check()` and `run()` with real bodies, anti-false-positive on closed port,
no prohibited strings, flake8/bandit clean, module indexing.


## [3.0.0] — 2026-05-01

### Added - Embedded OS/OT/IoT/AT Arsenal Expansion (170+ new modules)

#### Exploit modules (130 new)

- **Embedded OS:** OpenWrt (6), Linux kernel LPE (5), Zephyr RTOS (4), RIOT OS (4), Contiki-NG (2), FreeRTOS (2), QNX Neutrino (3), VxWorks URGENT/11 (3)
- **OT/IIoT:** CODESYS (3), Siemens WinCC (3)
- **IoT protocols:** MQTT (4), CoAP (3), UPnP/SSDP (3), Zigbee (3), BLE (3), Wi-Fi (4), DDS/RTPS (2), LoRaWAN (2), TFTP (2), Z-Wave (2), mDNS (2)
- **OT protocols:** Modbus (3), OPC-UA (4), BACnet (3), EtherNet/IP (2), DNP3 (3), S7comm (2), PROFINET (3), IEC 60870-5-104 (2), IEC 61850 GOOSE/MMS (2), HART-IP (1), CAN/OBD-II (3), OPC DA (1)
- **Smart Home:** Amazon Echo (2), Google Home/Nest (2), Samsung SmartThings (1)
- **Wearables:** Xiaomi Mi Band (1), Garmin Connect IQ (1), Samsung Tizen Gear (1), Fitbit (1)
- **Specialized:** thermostats (3), medical devices (5), elevators (1), HVAC (4), access control (3), vehicles (3), electronic gates (2)
- **Lateral movement:** MQTT pivot, UART shell, ARP spoof, Zigbee passive, QNX CAN (5)

#### Scanner modules (24 new)

- Embedded OS fingerprint, mDNS discovery, MQTT broker scan
- OT/IIoT: Modbus, BACnet, DNP3, PROFINET, OPC-UA, ICS multi-protocol fingerprint
- Protocol scanners: MQTT, CoAP, UPnP, BLE, Zigbee, Wi-Fi, Z-Wave, LoRaWAN, DDS/RTPS, S7comm, EtherNet/IP, HART-IP, CAN bus
- Smart Home assistant scan, Wearable BLE scan

#### Core framework (19 new files)

- `ExploitOrchestrator`: CrossCompiler, ExploitRunner, TunnelManager, CompiledArtifact
- 8 shell engines: RawTCP, RawUDP, ICMP covert, DNS tunnel, MQTT C2, HTTP poll, Meterpreter bridge, InternalShell (ChaCha20-Poly1305 + X25519 ECDH)
- Hardware gate: `HWReq` class, `check_hardware_requirements()`, audit tool
- Registry: category-to-module mapping for selective PyPI installation
- PyPI optional-dependencies with 17 install categories


## [2.15.0] — 2026-04-25

### Added — Full Submodule Audit + Mass Integration

#### Audit scope
Complete audit of all submodules (`submodules/IoT`, `submodules/OT`, `submodules/Daryus`) and sibling frameworks (`FirewallXPL-Forge`, `PrinterXPL-Forge`, `WirelessXPL-Forge`) to identify and incorporate everything within EmbedXPL's device scope.

**83 new Firewall/Perimeter modules** (`embedxpl/modules/exploits/firewalls/`):

New vendors: `juniper/`, `moxa/`, `paloalto/`, `pfsense/`, `phoenix_contact/`, `schneider/`, `siemens/` (network appliances), `sonicwall/`, `sophos/`, `watchguard/`, `zyxel/`, `hirschmann/`

| Vendor | Notable modules |
|--------|----------------|
| SonicWall | sonicos_sslvpn_access CVE-2024-40766 (CVSS 9.3), sonicos_auth_bypass CVE-2024-53704, sma100_sqli CVE-2021-20016, sonicos_bof CVE-2020-5135, sslvpn_shellshock VisualDoor |
| Sophos | xg_auth_bypass CVE-2022-1040, xg_sqli_asnarok CVE-2020-12271, firewall_code_injection CVE-2022-3236 |
| Juniper | jweb_oob_write CVE-2024-21591 (CVSS 9.8), jweb_php_rce CVE-2023-36845 |
| Zyxel | buffer_overflow CVE-2023-33009, ike_cmd_injection CVE-2023-28771, usg_flex CVE-2022-30525 |
| WatchGuard | firebox_cyclops_blink CVE-2022-23176, xcs_9_rce |
| pfSense | pfblockerng_rce CVE-2022-31814, interfaces_cmd_injection CVE-2023-42326 |
| Palo Alto | panos_auth_bypass CVE-2025-0108, mgmt_auth_bypass CVE-2024-0012, privesc CVE-2024-9474, saml_bypass CVE-2020-2021 |
| Siemens | ruggedcom_web_rce CVE-2023-24845, scalance_cmd_injection CVE-2023-44373, sinema_rc CVE-2022-32257 |
| Moxa | edr_cmd_injection CVE-2024-9138, edr_jwt_hardcoded CVE-2024-9137 |

**27 new Printer exploitation modules** (`embedxpl/modules/exploits/printers/`):

New vendors: `linux/` (CUPS), `hp/`, `lexmark/`, `kyocera/`, `brother/`, `ricoh/`, `samsung/`, `xerox/`, `canon/`

| Module | CVE | CVSS |
|--------|-----|------|
| cups_browsed_rce | CVE-2024-47176 + CVE-2024-47076/47175/47177 | 9.9 CRITICAL |
| hp_laserjet_postscript_rce | CVE-2025-26506 | 9.8 CRITICAL |
| hp_laserjet_bof | CVE-2025-26508 | 9.8 CRITICAL |
| hp_jetdirect_rce | CVE-2017-2741 | 9.8 CRITICAL |
| brother_default_auth_bypass | CVE-2024-51977/51978 | 9.8 CRITICAL |
| lexmark_cmd_injection | CVE-2023-26067 | 9.0 HIGH |
| kyocera_soap_cred_dump | CVE-2022-1026 | HIGH |
| lexmark_rce | CVE-2024-6333 | HIGH |

**5 new Wireless/Bluetooth protocol attack modules** (`embedxpl/modules/exploits/ics/bluetooth_ble/`):

| Module | CVE | Description |
|--------|-----|-------------|
| blueborne_attack | CVE-2017-0781, CVE-2017-0785, CVE-2017-1000251 | BlueBorne BT/BLE RCE (Android/Linux IoT) |
| wifi_fragattacks | CVE-2020-24586/24587/24588/26140/26143/26144/26145/26146 | WiFi 802.11 fragmentation attacks |
| wifi_krack_attack | CVE-2017-13077..13088 | KRACK — WPA2 key reinstallation (IoT APs/clients) |
| wifi_kr00k_attack | CVE-2019-15126 | KR00K — Broadcom/Cypress WiFi chip decryption |
| ble_sweyntooth_bridge | SweynTooth CVEs (multiple) | BLE SweynTooth deadlock/overflow attacks |

**1 new OT/ICS scenario module** (`embedxpl/modules/exploits/ics/modbus/`):

| Module | Description |
|--------|-------------|
| modbus_ot_attack_scenarios | 6 OT attack scenarios (oil plant disruption, plant shutdown, fill line flood) via unauthenticated Modbus TCP register writes — ported from Daryus IoT Security Research lab |


## [2.14.0] — 2026-04-24

### Added — CVE Integration + Vendor Cleanup

**2 new CVE exploit modules:**

| Module | CVE | CVSS | Technique |
|--------|-----|------|-----------|
| `vpn/ivanti/connect_secure_ssrf_rce_cve_2024_21893.py` | CVE-2024-21893 + CVE-2024-21887 | 9.1 CRITICAL | Ivanti Connect Secure — unauthenticated SSRF via SAML SOAP envelope at `/dana-ws/saml20.ws`, chained with command injection in internal license API for pre-auth RCE (CISA KEV 2024-01-31). Actions: check \| ssrf \| rce \| shell |
| `routers/netgear/r6100_cgimain_bof_cve_2025_29044.py` | CVE-2025-29044 | 9.8 CRITICAL | Netgear R6100 cgiMain — QUERY_STRING `sprintf` stack overflow (offset 0x274), unauthenticated RCE via MIPS payload. Actions: check \| dos \| rce |

**4 new vendor modules (previously placeholder-only):**

| Module | Vendor | Technique |
|--------|--------|-----------|
| `routers/pirelli/pirelli_wpa_keygen.py` | Pirelli Broadband (A-226G, Dragonite) | Default WPA key derivation from serial suffix or BSSID MAC |
| `routers/sitel/sitel_default_credentials.py` | Sitel ADSL Modem/Router | HTTP Basic Auth brute-force (default creds) + info disclosure probe |
| `routers/smc/smc_config_disclosure.py` | SMC Networks (7904WBRA, 8014WG, D3GN) | Unauthenticated config export / ViewLog.asp / status.asp disclosure |
| `routers/xavi/xavi_csrf_dns_change.py` | Xavi Technologies (7868r, X7968) | CSRF DNS hijack via unauthenticated POST to DNS config endpoint + CSRF HTML PoC generator |

### Removed
- `routers/belkin_ext/` — empty duplicate of `routers/belkin/`; removed

### Fixed
- CVE-2025-30401 was an invalid/non-existent CVE ID in the pending list; replaced with CVE-2025-29044 (Netgear R6100, same device scope, CVSS 9.8, public PoC)


## [2.13.0] — 2026-04-22

### Added — routerpwn.com + routerPWN Gap Analysis: 27 New Exploit Modules

**Gap analysis performed against:**
- [`hkm/routerpwn.com`](https://github.com/hkm/routerpwn.com) — 44 vendor folders, 100+ HTML/JS exploits
- [`lilloX/routerPWN`](https://github.com/lilloX/routerPWN) — Netgear CVE-2017-5521, CVE-2016-5649, BID-72640 (all previously covered)

Both repositories cloned as `submodules/IoT/routerpwn.com` and `submodules/IoT/routerPWN`.

**19 new vendor packages created (previously zero coverage):**

| Vendor | Module | Technique |
|--------|--------|-----------|
| `alcatel_lucent` | `omnipcx_masterCGI_rce.py` | OmniPCX Enterprise — `/cgi-bin/masterCGI` command injection |
| `alcatel_lucent` | `omniswitch_add_admin_csrf.py` | OmniSwitch — CSRF add admin account |
| `alpha_networks` | `web_shell_cmd_rce.py` | `/web_shell_cmd.gch` backdoor RCE (Alpha Networks / ZTE OEM) |
| `alpha_networks` | `config_download.py` | `/manager_dev_config_t.gch` config download (no auth) |
| `astoria` | `astoria_password_reset.py` | `/cgi-bin/setup_pass.cgi` admin password reset (no auth) |
| `binatone` | `dt850w_change_admin.py` | DT850W `/Forms/tools_admin_1` CSRF password change |
| `ddwrt` | `ddwrt_info_disclosure.py` | `/Info.live.htm` (BID-35742) — WiFi PSK/PPPoE disclosure |
| `ddwrt` | `ddwrt_command_exec.py` | Diagnostics ping field command injection |
| `easybox` | `easybox_wpa_keygen.py` | WPA2 default key generator (MAC ? MD5 algorithm, Arcadyan EasyBox 802/803/804) |
| `ee` | `brightbox_config_disclosure.py` | `/cgi/cgi_status.js` EE BrightBox config disclosure |
| `freebox` | `freebox_auth_bypass_reboot.py` | `/system.cgi` forced reboot (no auth) |
| `mifi` | `mifi_config_backup.py` | Novatel MiFi `/config.xml.savefile` credential disclosure |
| `motorola` | `sbg6580_info_disclosure.py` | SBG6580 DNS CSRF + admin password change + reboot |
| `observa` | `observa_telecom_cred_disclosure.py` | JSON credential disclosure + DNS CSRF + FTP enable |
| `ruggedcom` | `ruggedcom_factory_password.py` | Factory "backdoor" account password generator (FD 2012/Apr/277) |
| `seagate` | `seagate_nas_php_backdoor.py` | "Ghost PHP" RCE backdoor — `d41d8cd98f...php` (CVE-2014-8684) |
| `sitecom` | `dc227_backdoor_password.py` | DC-227 hardcoded backdoor + WLR-4004 WPA key generator (eMaze 2014) |
| `starbridge` | `lynx526_password_reset.py` | Lynx 526 `/password.cgi?sysPassword=` (no auth) |
| `ubee` | `ubee_cablemas_bypass.py` | Cable modem operator credential bypass (Cablemas ISP) |
| `unicorn` | `wb3300nr_factory_reset.py` | WB-3300NR factory reset + DNS CSRF (no auth) |
| `utstarcom` | `utstar_ppp_password_disclosure.py` | `/ppppassword.html` PPPoE credential disclosure |
| `zoom` | `zoom_x4_x5_add_admin.py` | X4/X5 add admin via `PopOutUserAdd.htm` (EDB-26736) |

**Existing vendor gaps filled (5 new modules):**

| Vendor | Module | Technique |
|--------|--------|-----------|
| `belkin` | `dns_hijack_csrf.py` | DNS hijack + N300/N900 admin CSRF |
| `netgear` | `dg632_bypass_dos.py` | DG632 auth bypass (`saveconfig.html`) + DoS |
| `netgear` | `wg602_superman_backdoor.py` | WG602 hardcoded `super:5777364` / `superman:21241036` |
| `trendnet` | `tew827_backdoor_password.py` | TEW-827DRU `/backdoor?password=j78G-DFdg_24Mhw3` |
| `trendnet` | `camera_mjpeg_unauth.py` | `/anony/mjpg.cgi` MJPEG stream without auth (50,000+ cameras affected in 2012) |

**Validation:** All 27 modules pass `py_compile` validation (0 syntax errors).


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


## [1.0.0] — 2026-04-17

### Changed (Breaking - Rebranding)
- **Project renamed**: RouterXPL-Forge -> **EmbedXPL-Forge**
- **PyPI package**: `routerxpl` -> **`embedxpl`** (`pip install embedxpl`)
- **CLI commands**: `routerxpl` -> **`embedxpl`**; `exf` alias preserved
- **Python package**: `routerxpl/` -> `embedxpl/` (all imports updated)
- **Classes**: `RouterXPLInterpreter` -> `EmbedXPLInterpreter`, `RouterXPLException` -> `EmbedXPLException`
- **Log file**: `routerxpl.log` -> `embedxpl.log`
- **GitHub repo**: `mrhenrike/RouterXPL-Forge` -> `mrhenrike/EmbedXPL-Forge`

### Changed (Scope)
- **Target scope expanded**: framework now explicitly covers Routers, Switches L2/L3, IP Cameras, GPON ONTs, ISP CPEs, and IoT/Embedded Edge devices
- Banner updated to reflect expanded scope
- `pyproject.toml`: added `embedded`, `firmware` keywords; description updated

### Coverage Summary

| Metric | Count |
|--------|-------|
| Total modules | 690+ |
| Exploit modules | 540+ |
| Scanner modules | 90+ |
| Credential modules | 88 |
| Payload modules | 32 |
| Encoder modules | 13 |
| Generic modules | 12 |
| CVEs covered | 343+ |
| Vendors | 53+ |

### Protocols Supported

| Protocol | Usage |
|----------|-------|
| HTTP/HTTPS | Web interface exploitation, API abuse, config download |
| SSH | Brute-force, weak algorithm detection, key extraction |
| Telnet | Default credential testing, command injection |
| SNMP v1/v2c/v3 | Community brute-force, MIB walk, config extraction |
| FTP/SFTP | Credential testing, firmware download |
| RTSP | Camera stream access, authentication bypass |
| ONVIF/SOAP | Device discovery, auth bypass, service enumeration |
| Modbus TCP | ICS/SCADA register read/write, coil manipulation |
| S7comm | Siemens PLC communication, CPU control |
| BACnet | BMS device discovery, property read/write |
| DNP3 | Outstation enumeration, unsolicited response injection |
| EtherNet/IP | CIP service enumeration, identity query |
| MQTT | Broker auth bypass, topic enumeration, message inject |
| CoAP | Resource discovery, observe attack |
| CAN bus | Frame injection, UDS diagnostics, ECU fuzzing |
| BLE | GATT enumeration, pairing hijack, advertisement spoof |
| Zigbee/Thread | Network key sniffing, 802.15.4 frame injection |
| UPnP/SSDP | IGD port mapping abuse, service discovery |

### Install by Category

```bash
# Core (network-only modules, no special hardware needed)
pip install embedxpl

# Category-specific extras
pip install embedxpl[routers]          # Routers, CPEs, APs, SOHO edge
pip install embedxpl[firewalls]        # Firewalls and NGFW appliances
pip install embedxpl[printers]         # Network printers
pip install embedxpl[iot]              # Cameras, smart TVs, VoIP, NAS, UPS
pip install embedxpl[ot]               # ICS/SCADA, BMS, smart meters
pip install embedxpl[iiot]             # Industrial IoT, BMC/IPMI
pip install embedxpl[smart-home]       # Smart assistants, appliances, HVAC
pip install embedxpl[wearables]        # Fitness bands, smartwatches
pip install embedxpl[vehicles]         # Automotive CAN bus
pip install embedxpl[medical]          # Medical embedded devices
pip install embedxpl[access-control]   # RFID, gates, elevators
pip install embedxpl[network-perimeter] # Full perimeter stack
pip install embedxpl[all]              # Everything
```

### Infrastructure
- CI/CD guard conditions updated to `mrhenrike/EmbedXPL-Forge`
- PyPI OIDC Trusted Publisher re-bound to `embedxpl` project + `EmbedXPL-Forge` repo
- All 6 architecture PNG diagrams regenerated with EmbedXPL-Forge branding (v1.0.0)
- All 5 Mermaid source files updated
- All 26 wiki pages updated (en-US + pt-BR)
- GitHub Actions release workflow (`release.yml`) with quality gates (pytest, docgen, theoretical audit)
- Category registry (`embedxpl/registry/categories.py`) with 17 install categories
- Hardware install notice CLI (`embedxpl/tools/hw_install_notice.py`)


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
- CVE catalog: 338 ? 343 entries (+5)

### Changed
- Module counts: 670 ? 690 total, 520 ? 540 exploits, 51 ? 53 vendors
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
- `pyproject.toml`: 0.6.1 ? 0.6.2
- README.md: 657 ? **666 modules**, 510 ? **516 exploits**, 9 ? **12 generic**, 49 ? **51 vendors**
- COVERAGE_MATRIX.md: updated to v0.6.2

### Module Counts

| Category | 0.6.1 | 0.6.2 |
|----------|-------|-------|
| Exploits | 510 | **516** |
| Generic | 9 | **12** |
| **Total** | **657** | **666** |
| Vendors | 49 | **51** |


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
- `pyproject.toml` version 0.6.0 ? 0.6.1
- README.md: 647 ? **657 modules**, 500 ? **510 exploits**
- COVERAGE_MATRIX.md updated to v0.6.1

### Module Counts

| Category | 0.6.0 | 0.6.1 |
|----------|-------|-------|
| Exploits | 500 | **510** |
| Creds | 88 | 88 |
| **Total** | **647** | **657** |


## [0.6.0] — 2026-04-08

### Added
- **11 Huawei EG8145X6-10 exploit modules** — info disclosure, brute-force (rate-limit bypass), CSRF static token, pre-auth user enum, config AES decrypt, Epuser firewall bypass (CVE-2025-49599), MitM credential intercept, Telnet enable, CSRF payload generator, DNS poison via CSRF, WiFi credential extractor
- **`eg8145x6_autopwn`** — 9-phase chained exploitation: fingerprint ? info disclosure ? CSRF ? user enum ? brute-force ? config decrypt ? JS capture ? port scan ? report + generic fallback (v1.1.0)
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


## [0.4.0-beta] — 2026-04-03

### Added
- Major exploit incorporation: 575 modules, 330 CVEs, 49 vendors
- Architecture diagrams (Mermaid + PNG)
- Coverage matrix
- Bilingual documentation (en-US + pt-BR)

## [3.7.1] - 2026-06-15

### Added - Printer modules (missed in v3.7.0 wave)
- printers/samba_print_cmd_inject_cve_2026_4480.py: Samba smbd MS-RPRN print command injection (CVE-2026-4480, CVSS 8.8)
- printers/hp/deskjet_wsd_scan_rce_cve_2026_4682.py: HP DeskJet/OfficeJet WSD scan service stack buffer overflow RCE (CVE-2026-4682, CVSS 9.3)

### Updated - NSE scripts (v3.7.0 additions)
- 
se/embedxpl-perimeter-vuln.nse (v1.1.0): Added CVE-2025-53847 (FortiOS fgfmd missing auth), CVE-2026-20127 (Cisco SD-WAN JWT bypass), CVE-2026-20245 (Cisco SD-WAN CLI privesc KEV)
- 
se/embedxpl-iot-cve-check.nse (v2.1.0): Added CVE-2026-29114/29116 (Dahua), CVE-2026-8631 (HPLIP), CVE-2026-25205 (Samsung Tizen Escargot JS engine)
- 
se/embedxpl-suite-ref.nse (v1.1.0): Registered 4 new v3.7.0 NSE scripts (unifi-vuln, switch-vuln, drone-vuln, ups-pdu-vuln); added NSE scripts index section
