# Changelog

All notable changes to EmbedXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`.


## [3.1.0] — 2026-05-12

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
| `easybox` | `easybox_wpa_keygen.py` | WPA2 default key generator (MAC → MD5 algorithm, Arcadyan EasyBox 802/803/804) |
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
