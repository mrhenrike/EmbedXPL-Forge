# Referência de Módulos por CVE

**Idioma:** Português (pt-BR). **English:** — *(página exclusiva pt-BR)*

---

## Visão geral

Esta página serve como índice de referência cruzada entre CVEs e os módulos EmbedXPL-Forge correspondentes. Os CVEs estão organizados por ano (mais recente primeiro) e por severidade (CVSS decrescente).

Para busca rápida por CVE no shell interativo:

```
exf > search CVE-2021-36260
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exploits/cameras/dahua/cctv_rce_cve_2021_36260
```

---

## CVEs 2026

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2026-35616 | 9.8 | Fortinet / FortiClient EMS | RCE pre-auth | `exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616` |
| CVE-2026-34480 | 9.8 | Linux / CUPS | RCE via cadeia Pwn2Own | `exploits/printers/linux/cups_pwn2own_chain_cve_2026_34480` |
| CVE-2026-8153 | 9.8 | Universal Robots / PolyScope 5 | RCE via injeção de comando | `exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153` |
| CVE-2026-0257 | 7.8 | Palo Alto / GlobalProtect | Bypass de auth cookie (CISA KEV) | `exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257` |

---

## CVEs 2025

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2025-20188 | 10.0 | Cisco / IOS XE WLC | RCE via JWT hardcoded + upload | `exploits/routers/cisco/ios_xe_wlc_jwt_file_upload_cve_2025_20188` |
| CVE-2025-9377 | 9.8 | TP-Link / WR841N | RCE via controle parental | `exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377` |
| CVE-2025-1316 | 9.8 | Edimax / IC-7100 | RCE não autenticado | `exploits/cameras/edimax/ic7100_unauth_rce_cve_2025_1316` |
| CVE-2025-60787 | 9.8 | MotionEye | RCE não autenticado | `exploits/cameras/motioneye/motioneye_rce_cve_2025_60787` |

---

## CVEs 2024

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2024-47575 | 9.8 | Fortinet / FortiManager | RCE (FortiJump) | `exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575` |
| CVE-2024-53704 | 9.8 | SonicWall / SonicOS | Bypass SSL-VPN | `exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704` |
| CVE-2024-37630 | 9.8 | Uniview / NVR | RCE não autenticado | `exploits/cameras/uniview/uniview_nvr_unauth_rce_cve_2024_37630` |
| CVE-2024-21762 | 9.6 | Fortinet / FortiOS SSL-VPN | RCE OOB Write | `exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762` |
| CVE-2024-21888 | 9.8 | Ivanti / Connect Secure | SSRF + RCE em cadeia | `exploits/vpn/ivanti/ivanti_connect_secure_ssrf_rce_cve_2024_21888` |
| CVE-2024-3400 | 10.0 | Palo Alto / PAN-OS GlobalProtect | RCE não autenticado (CISA KEV) | `exploits/firewalls/paloalto/panos_globalprotect_rce_cve_2024_3400` |

---

## CVEs 2023

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2023-50224 | 7.5 | TP-Link / WR841N | Divulgação de credenciais | `exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224` |
| CVE-2023-28808 | 9.8 | Hikvision / NAS | Bypass de auth | `exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808` |
| CVE-2023-27997 | 9.8 | Fortinet / FortiOS SSL-VPN | Heap overflow RCE | `exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997` |
| CVE-2023-25594 | 9.8 | Aruba / ClearPass Policy Manager | RCE não autenticado | `exploits/nac/aruba/aruba_clearpass_rce_cve_2023_25594` |
| CVE-2023-20198 | 10.0 | Cisco / IOS XE WebUI | Escalada de privilégio | `exploits/network_os/cisco/ios_xe_webui_privesc_cve_2023_20198` |
| CVE-2023-4966 | 9.4 | Citrix / NetScaler ADC/Gateway | CitrixBleed — vazamento de token de sessão | `exploits/appliances/citrix/citrix_bleed_info_disclosure_cve_2023_4966` |
| CVE-2023-3519 | 9.8 | Citrix / NetScaler | RCE não autenticado | `exploits/appliances/citrix/netscaler_rce_cve_2023_3519` |

---

## CVEs 2022

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2022-40684 | 9.8 | Fortinet / FortiOS | Bypass de auth admin | `exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684` |
| CVE-2022-40685 | 7.5 | Fortinet / FortiOS | Path traversal | `exploits/firewalls/fortinet/fortios_path_traversal_cve_2022_40685` |
| CVE-2022-37897 | 9.8 | Aruba / ClearPass Policy Manager | SQL injection | `exploits/nac/aruba/aruba_clearpass_sqli_cve_2022_37897` |
| CVE-2022-30600 | 9.8 | Reolink / NVR | Extração de UID P2P | `exploits/cameras/reolink/reolink_nvr_p2p_uid_extract_cve_2022_30600` |
| CVE-2022-4934 | 8.8 | Sophos / UTM | Injeção de comando via web proxy | `exploits/firewalls/sophos/sophos_utm_rce_cve_2022_4934` |
| CVE-2022-1388 | 9.8 | F5 / BIG-IP iControl REST | RCE não autenticado | `exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388` |

---

## CVEs 2021

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2021-40655 | 9.8 | Reolink / Baicells | Bypass auth + RCE | `exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655` |
| CVE-2021-36300 | 9.8 | Dell / iDRAC9 | Divulgação de info não autenticada | `exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300` |
| CVE-2021-36260 | 9.8 | Hikvision / Câmeras IP | RCE não autenticado | `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260` |
| CVE-2021-36260 | 9.8 | Dahua / CCTV | RCE configManager.cgi | `exploits/cameras/dahua/cctv_rce_cve_2021_36260` |
| CVE-2021-33044 | 9.8 | Dahua / Câmeras e DVRs | Bypass de autenticação | `exploits/cameras/dahua/auth_bypass_cve_2021_33044` |
| CVE-2021-33044 | 9.8 | Dahua / CCTV (variante) | Bypass de autenticação | `exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044` |
| CVE-2021-32941 | 9.8 | Annke / DVR/NVR | RCE não autenticado | `exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941` |
| CVE-2021-30358 | 9.8 | Check Point / Gaia portal | SQL injection | `exploits/firewalls/checkpoint/checkpoint_gaia_portal_sqli_cve_2021_30358` |
| CVE-2021-26103 | 9.8 | Fortinet / FortiAnalyzer | SQL injection | `exploits/firewalls/fortinet/fortianalyzer_sql_inject_cve_2021_26103` |
| CVE-2021-22986 | 9.8 | F5 / BIG-IQ iControl | RCE | `exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986` |
| CVE-2021-4045 | 9.8 | TP-Link / Tapo C200/C210 | RCE não autenticado | `exploits/cameras/tapo/tapo_c200_c210_unauth_rce_cve_2021_4045` |
| CVE-2021-1442 | 8.8 | Cisco / IOS XE | CSRF para RCE | `exploits/firewalls/cisco/cisco_ios_xe_csrf_rce_cve_2021_1442` |

---

## CVEs 2020

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2020-29583 | 9.8 | Sophos / XG Firewall | RCE via credencial hardcoded | `exploits/firewalls/sophos/sophos_xg_rce_cve_2020_29583` |
| CVE-2020-6017 | 8.1 | Check Point / Mobile Access | SSRF | `exploits/firewalls/checkpoint/checkpoint_mobile_access_ssrf_cve_2020_6017` |
| CVE-2020-3452 | 7.5 | Cisco / ASA e FTD | Path traversal | `exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452` |
| CVE-2020-25078 | 7.5 | Dahua / CCTV | Divulgação de nome de usuário | `exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078` |

---

## CVEs 2019

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2019-19781 | 9.8 | Citrix / NetScaler | Path traversal (Shitrix) | `exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781` |
| CVE-2019-13393 | 9.8 | Sangfor / NGFW | RCE não autenticado | `exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393` |
| CVE-2019-3950 | 9.8 | Amcrest / Câmeras | Divulgação de info não autenticada | `exploits/cameras/amcrest/amcrest_camera_unauth_info_disclosure_cve_2019_3950` |
| CVE-2019-1653 | 9.8 | Cisco / RV320/RV325 | Divulgação de info | `exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653` |
| CVE-2019-1652 | 9.8 | Cisco / RV320/RV325 | Injeção de comando | `exploits/routers/cisco/rv320_command_injection` |
| CVE-2019-0028 | 9.8 | Juniper / EX series | Bypass de autenticação J-Web | `exploits/firewalls/juniper/juniper_ex_auth_bypass_cve_2019_0028` |

---

## CVEs 2018

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2018-14847 | 9.1 | MikroTik / RouterOS | Divulgação de credenciais Winbox | `exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847` |
| CVE-2018-13379 | 9.8 | Fortinet / FortiOS SSL-VPN | Path traversal | `exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379` |
| CVE-2018-10660 | 9.8 | Axis / Câmeras | RCE via parhand | `exploits/cameras/axis/srv_parhand_rce_cve_2018_10660` |
| CVE-2018-0296 | 7.5 | Cisco / ASA | Path traversal HTTP | `exploits/firewalls/cisco/cisco_asa_path_traversal_cve_2018_0296` |
| CVE-2018-0171 | 9.8 | Cisco / IOS Smart Install | RCE não autenticado | `exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171` |

---

## CVEs 2017

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2017-7921 | 9.8 | Hikvision / Câmeras IP | Divulgação de info não autenticada | `exploits/cameras/hikvision/info_disclosure_cve_2017_7921` |
| CVE-2017-17105 | 9.8 | Zivif / Câmeras | RCE via ipcheck | `exploits/cameras/zivif/ipcheck_rce_cve_2017_17105` |
| CVE-2017-6742 | 9.8 | Cisco / IOS (SNMP) | RCE | `generic/snmp/snmp_bruteforce` |

---

## CVEs históricos (2013–2016)

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2016-6366 | 9.8 | Cisco / ASA | RCE via SNMP (EXTRABACON) | `exploits/firewalls/cisco/cisco_asa_snmp_rce_cve_2016_6366` |
| CVE-2015-2049 | 9.8 | D-Link / DCS-931L | RCE via upload de arquivo | `exploits/cameras/dlink/dcs_931l_file_upload_rce_cve_2015_2049` |
| CVE-2014-3390 | 10.0 | Cisco / ASA | RCE via WebVPN | `exploits/firewalls/cisco/cisco_asa_webvpn_rce_cve_2014_3390` |
| CVE-2013-6117 | 9.8 | Dahua / DVR (antigo) | Bypass de autenticação | `exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117` |
| CVE-2013-4786 | 10.0 | Supermicro / IPMI 2.0 | Hash HMAC RAKP (sem auth) | `exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786` |

---

## Advisories próprios (Herospeed/Longsee)

| Advisory | CVSS | Plataforma | Tipo | Módulo EmbedXPL |
|----------|------|-----------|------|----------------|
| HSLS-2026-001 | 9.1 | Herospeed MC6830 | Enumeração de contas não autenticada | `exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum` |
| HSLS-2026-002 | 6.5 | Herospeed MC6830 | Divulgação de credenciais via vb.htm | `exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure` |
| HSLS-2026-003 | 8.8 | Herospeed MC6830 | RCE via injeção de source update.sh | `exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce` |
| HSLS-2026-004 | 9.8 | Herospeed MC6830 | Hash root hardcoded em todas versões | `exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash` |
| HSLS-2026-005 | 8.8 | Herospeed MC6830 | Chave AES hardcoded para config export | `exploits/cameras/herospeed/herospeed_nvr_config_export_cred_recovery` |
| HSLS-2026-006-A | 8.8 | Herospeed MC6830 | RCE via FTP field → popen() | `exploits/cameras/herospeed/herospeed_nvr_ftp_diagnostic_rce` |

---

[Hub da Wiki](../README.md)
