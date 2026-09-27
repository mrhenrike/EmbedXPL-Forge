# Referência de Módulos por CVE

**Idioma:** Português (pt-BR). **English:** [../en-US/22-cve-module-reference.md](../en-US/22-cve-module-reference.md)

---

## Visão geral

Esta página serve como índice de referência cruzada entre CVEs e os módulos EmbedXPL-Forge correspondentes. Os CVEs estão organizados por ano (mais recente primeiro) e por severidade (CVSS decrescente) dentro de cada ano.

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
| CVE-2026-20182 | 10.0 | Cisco / SD-WAN Manager (vManage) | Bypass de auth DTLS + injeção de chave SSH | `exploits/firewalls/cisco/cisco_sdwan_dtls_auth_bypass_cve_2026_20182` |
| CVE-2026-35616 | 9.8 | Fortinet / FortiClient EMS | RCE pré-autenticado | `exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616` |
| CVE-2026-34480 | 9.8 | Linux / CUPS | RCE via cadeia Pwn2Own | `exploits/printers/linux/cups_pwn2own_chain_cve_2026_34480` |
| CVE-2026-8153 | 9.8 | Universal Robots / PolyScope 5 | RCE via injeção de comando | `exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153` |
| CVE-2026-25249 | 9.8 | Fortinet / FortiOS | Heap overflow RCE no daemon HTTPS | `exploits/firewalls/fortinet/fortios_heap_overflow_rce_cve_2026_25249` |
| CVE-2026-20079 | 9.8 | Cisco / FMC (Firepower Mgmt Center) | Bypass de auth + RCE | `exploits/firewalls/cisco/cisco_fmc_auth_bypass_rce_cve_2026_20079` |
| CVE-2026-0264 | 9.8 | Palo Alto / PAN-OS | Heap overflow DNS — RCE | `exploits/firewalls/paloalto/panos_dns_heap_rce_cve_2026_0264` |
| CVE-2026-0300 | 9.8 | Palo Alto / PAN-OS | Buffer overflow User-ID — RCE | `exploits/firewalls/paloalto/panos_userid_bof_rce_cve_2026_0300` |
| CVE-2026-0265 | 9.3 | Palo Alto / PAN-OS | Bypass do Cloud Auth Service | `exploits/firewalls/paloalto/panos_cas_auth_bypass_cve_2026_0265` |
| CVE-2026-24858 | 9.1 | Fortinet / FortiCloud | Bypass de SSO | `exploits/firewalls/fortinet/forticloud_sso_auth_bypass_cve_2026_24858` |
| CVE-2026-0257 | 7.8 | Palo Alto / GlobalProtect | Bypass de cookie de autenticação (CISA KEV) | `exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257` |

---

## CVEs 2025

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2025-20188 | 10.0 | Cisco / IOS XE WLC | RCE via JWT hardcoded + upload de arquivo | `exploits/routers/cisco/ios_xe_wlc_jwt_file_upload_cve_2025_20188` |
| CVE-2025-53844 | 9.8 | Fortinet / FortiOS | Escrita fora dos limites — RCE | `exploits/firewalls/fortinet/fortios_oob_write_rce_cve_2025_53844` |
| CVE-2025-32756 | 9.8 | Fortinet / FortiOS | Stack overflow RCE (CISA KEV) | `exploits/firewalls/fortinet/fortios_stack_overflow_rce_cve_2025_32756` |
| CVE-2025-21590 | 9.8 | Juniper / SRX series | RCE não autenticado | `exploits/firewalls/juniper/juniper_srx_unauth_rce_cve_2025_21590` |
| CVE-2025-9377 | 9.8 | TP-Link / WR841N | RCE via controle parental | `exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377` |
| CVE-2025-1316 | 9.8 | Edimax / IC-7100 | RCE não autenticado | `exploits/cameras/edimax/ic7100_unauth_rce_cve_2025_1316` |
| CVE-2025-60787 | 9.8 | MotionEye | RCE não autenticado | `exploits/cameras/motioneye/motioneye_rce_cve_2025_60787` |
| CVE-2025-5688 | 9.8 | FreeRTOS / FreeRTOS+TCP | Escrita fora dos limites | `exploits/ics/freertos/freertos_plus_tcp_oob_write_cve_2025_5688` |

---

## CVEs 2024

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2024-3400 | 10.0 | Palo Alto / PAN-OS GlobalProtect | RCE não autenticado — injeção de comando OS (CISA KEV) | `exploits/firewalls/globalprotect_cmd_injection_cve_2024_3400` |
| CVE-2024-47575 | 9.8 | Fortinet / FortiManager | RCE (FortiJump) — registro de dispositivo não autenticado | `exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575` |
| CVE-2024-53704 | 9.8 | SonicWall / SonicOS | Bypass de auth SSL-VPN | `exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704` |
| CVE-2024-53700 | 9.8 | SonicWall / SonicOS | Sequestro de sessão SSL-VPN | `exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53700` |
| CVE-2024-37630 | 9.8 | Uniview / NVR | RCE não autenticado | `exploits/cameras/uniview/uniview_nvr_unauth_rce_cve_2024_37630` |
| CVE-2024-21888 | 9.8 | Ivanti / Connect Secure | SSRF + RCE em cadeia | `exploits/vpn/ivanti/ivanti_connect_secure_ssrf_rce_cve_2024_21888` |
| CVE-2024-23113 | 9.8 | Fortinet / FortiOS | RCE via format string FGFM (CISA KEV) | `exploits/firewalls/fortinet/fortios_format_string_rce_cve_2024_23113` |
| CVE-2024-21793 | 9.8 | F5 / BIG-IP | Injeção OData + bypass de auth iControl REST | `exploits/firewalls/lb/f5/bigip_icontrol_rest_auth_bypass_cve_2024_21793` |
| CVE-2024-5829 | 9.8 | Hillstone / StoneOS | RCE na interface de gerenciamento web | `exploits/firewalls/hillstone/hillstone_stoneos_web_rce_cve_2024_5829` |
| CVE-2024-9137 | 9.8 | Moxa / EDR-G9010 | Segredo JWT hardcoded | `exploits/firewalls/moxa/edr_g_jwt_hardcoded_cve_2024_9137` |
| CVE-2024-21591 | 9.8 | Juniper / SRX, EX | Escrita fora dos limites J-Web — RCE | `exploits/firewalls/juniper/jweb_oob_write_rce_cve_2024_21591` |
| CVE-2024-9463 | 9.9 | Palo Alto / PAN-OS Expedition | Injeção de comando OS não autenticada | `exploits/firewalls/paloalto/panos_expedition_cmd_injection_cve_2024_9463` |
| CVE-2024-21762 | 9.6 | Fortinet / FortiOS SSL-VPN | Escrita fora dos limites — RCE | `exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762` |
| CVE-2024-55591 | 9.6 | Fortinet / FortiOS | Bypass de auth via WebSocket CSF proxy | `exploits/firewalls/fortinet/fortios_websocket_auth_bypass_cve_2024_55591` |
| CVE-2024-0012 | 9.3 | Palo Alto / PAN-OS | Bypass de auth na WebUI de gerenciamento | `exploits/firewalls/paloalto/panos_mgmt_auth_bypass_cve_2024_0012` |
| CVE-2024-48887 | 9.3 | Fortinet / FortiSwitch | Alteração de senha não autenticada | `exploits/firewalls/fortinet/fortiswitch_unauth_passwd_cve_2024_48887` |
| CVE-2024-40766 | 9.3 | SonicWall / SonicOS | Controle de acesso impróprio | `exploits/firewalls/sonicwall/sonicos_sslvpn_access_cve_2024_40766` |
| CVE-2024-9138 | 9.1 | Moxa / EDR firewall | Injeção de comando | `exploits/firewalls/moxa/edr_cmd_injection_cve_2024_9138` |
| CVE-2024-24919 | 8.6 | Check Point / Quantum Security Gateway | Leitura arbitrária de arquivo via VPN | `exploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919` |
| CVE-2024-50562 | 8.1 | Fortinet / FortiOS | Reutilização de token de sessão SSL-VPN | `exploits/firewalls/fortinet/fortios_sslvpn_session_reuse_cve_2024_50562` |
| CVE-2024-6077 | 8.6 | Rockwell / CompactLogix | DoS via CIP | `exploits/ics/rockwell/compactlogix_cip_dos_cve_2024_6077` |
| CVE-2024-9474 | 6.9 | Palo Alto / PAN-OS | Escalada de privilégio (cadeia com CVE-2024-0012) | `exploits/firewalls/paloalto/panos_privesc_cve_2024_9474` |

---

## CVEs 2023

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2023-20198 | 10.0 | Cisco / IOS XE WebUI | Escalada de privilégio (CISA KEV) | `exploits/network_os/cisco/ios_xe_webui_privesc_cve_2023_20198` |
| CVE-2023-48788 | 9.8 | Fortinet / FortiClientEMS | SQL injection para RCE | `exploits/firewalls/fortinet/forticlientems_sqli_rce_cve_2023_48788` |
| CVE-2023-36845 | 9.8 | Juniper / SRX, EX | RCE via env PHP do J-Web | `exploits/firewalls/juniper/jweb_php_rce_cve_2023_36845` |
| CVE-2023-28808 | 9.8 | Hikvision / NAS | Bypass de autenticação | `exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808` |
| CVE-2023-27997 | 9.8 | Fortinet / FortiOS SSL-VPN | Heap overflow RCE (XORtigate) | `exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997` |
| CVE-2023-25594 | 9.8 | Aruba / ClearPass Policy Manager | RCE não autenticado | `exploits/nac/aruba/aruba_clearpass_rce_cve_2023_25594` |
| CVE-2023-20032 | 9.8 | Cisco / FMC (Firepower Mgmt Center) | RCE não autenticado via ClamAV | `exploits/firewalls/cisco/cisco_fmc_rce_cve_2023_20032` |
| CVE-2023-44373 | 9.8 | Siemens / SCALANCE W780/W786 | Injeção de comando | `exploits/firewalls/siemens/scalance_cmd_injection_cve_2023_44373` |
| CVE-2023-24845 | 9.8 | Siemens / RUGGEDCOM ROX | RCE na interface web | `exploits/firewalls/siemens/ruggedcom_web_rce_cve_2023_24845` |
| CVE-2023-46853 | 9.8 | OpenVPN / Access Server | Bypass de auth na API REST | `exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2023_46853` |
| CVE-2023-24512 | 9.8 | Arista / EOS | Bypass de auth na API REST do EOS | `exploits/firewalls/arista/arista_eos_rest_api_bypass_cve_2023_24512` |
| CVE-2023-28648 | 9.8 | Osprey / Controlador de bomba | Bypass de autenticação | `exploits/ics/osprey/pump_controller_auth_bypass_cve_2023_28648` |
| CVE-2023-28461 | 9.8 | Array Networks / vxAG | RCE não autenticado via exec proxy | `exploits/firewalls/array_networks/array_networks_vxag_rce_cve_2023_28461` |
| CVE-2023-42326 | 9.8 | pfSense / pfSense | Injeção de comando via interfaces | `exploits/firewalls/pfsense/interfaces_cmd_injection_cve_2023_42326` |
| CVE-2023-27100 | 9.8 | pfSense / pfSense | Bypass de anti-brute-force | `exploits/firewalls/pfsense/antibruteforce_bypass_cve_2023_27100` |
| CVE-2023-31493 | 9.8 | Hillstone / StoneOS | RCE não autenticado | `exploits/firewalls/hillstone/hillstone_ngfw_rce_cve_2023_31493` |
| CVE-2023-31992 | 9.8 | VyOS / Roteador VyOS | RCE via API REST | `exploits/firewalls/vyos/vyos_rce_cve_2023_31992` |
| CVE-2023-4966 | 9.4 | Citrix / NetScaler ADC/Gateway | CitrixBleed — vazamento de token de sessão | `exploits/appliances/citrix/citrix_bleed_info_disclosure_cve_2023_4966` |
| CVE-2023-3519 | 9.8 | Citrix / NetScaler | RCE não autenticado | `exploits/appliances/citrix/netscaler_rce_cve_2023_3519` |
| CVE-2023-27253 | 8.8 | pfSense / pfSense | Injeção de comando via RRD | `exploits/firewalls/pfsense/pfsense_rrd_cmd_injection_cve_2023_27253` |
| CVE-2023-46226 | 8.8 | IPFire | Injeção de comando via rule_path IDS | `exploits/firewalls/ipfire/ipfire_ids_cmd_inject_cve_2023_46226` |
| CVE-2023-23770 | 9.1 | Stormshield / SNS | Bypass de autenticação | `exploits/firewalls/stormshield/stormshield_sns_auth_bypass_cve_2023_23770` |
| CVE-2023-36851 | 5.3 | Juniper / SRX series | Upload de arquivo não autenticado | `exploits/firewalls/juniper/juniper_srx_file_upload_rce_cve_2023_36851` |
| CVE-2023-50224 | 7.5 | TP-Link / WR841N | Divulgação de credenciais | `exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224` |

---

## CVEs 2022

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2022-40684 | 9.8 | Fortinet / FortiOS, FortiProxy | Bypass de auth de administrador | `exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684` |
| CVE-2022-37897 | 9.8 | Aruba / ClearPass Policy Manager | SQL injection | `exploits/nac/aruba/aruba_clearpass_sqli_cve_2022_37897` |
| CVE-2022-31814 | 9.8 | pfSense / pfBlockerNG | RCE não autenticado | `exploits/firewalls/pfsense/pfblockerng_rce_cve_2022_31814` |
| CVE-2022-30600 | 9.8 | Reolink / NVR | Extração de UID P2P | `exploits/cameras/reolink/reolink_nvr_p2p_uid_extract_cve_2022_30600` |
| CVE-2022-30525 | 9.8 | Zyxel / USG FLEX, ATP, VPN | Injeção de comando não autenticada | `exploits/firewalls/zyxel/usg_flex_cmd_injection_cve_2022_30525` |
| CVE-2022-3236 | 9.8 | Sophos / Firewall | Injeção de código (user portal) | `exploits/firewalls/sophos/firewall_code_injection_cve_2022_3236` |
| CVE-2022-1040 | 9.8 | Sophos / XG Firewall | Bypass de autenticação | `exploits/firewalls/sophos/xg_auth_bypass_cve_2022_1040` |
| CVE-2022-1388 | 9.8 | F5 / BIG-IP iControl REST | RCE não autenticado | `exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388` |
| CVE-2022-45315 | 9.8 | MikroTik / RouterOS | Stack overflow RCE | `exploits/firewalls/mikrotik/mikrotik_routeros_rce_cve_2022_45315` |
| CVE-2022-25752 | 9.8 | Symantec (Broadcom) / EDR Appliance | RCE via injeção de configuração | `exploits/firewalls/symantec/symantec_edr_rce_cve_2022_25752` |
| CVE-2022-26776 | 9.8 | WatchGuard / Firebox | Bypass de autenticação | `exploits/firewalls/watchguard/firebox_auth_bypass_cve_2022_26776` |
| CVE-2022-35534 | 9.8 | H3C / NGFW | Injeção de comando OS | `exploits/firewalls/h3c/h3c_ngfw_rce_cve_2022_35534` |
| CVE-2022-0547 | 9.8 | OpenVPN / Access Server | Bypass do módulo de autenticação LDAP | `exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2022_0547` |
| CVE-2022-27510 | 9.8 | Citrix / ADC, Gateway | Bypass de autenticação | `exploits/firewalls/citrix/citrix_adc_auth_bypass_cve_2022_27510` |
| CVE-2022-27518 | 9.8 | Citrix / ADC, Gateway | RCE não autenticado | `exploits/firewalls/citrix/citrix_adc_rce_cve_2022_27518` |
| CVE-2022-24665 | 9.8 | Kerio / Kerio Control | RCE não autenticado via CSRF | `exploits/firewalls/kerio/kerio_control_rce_cve_2022_24665` |
| CVE-2022-20713 | 9.8 | Cisco / FTD, ASA | Bypass de autenticação ASDM Launcher | `exploits/firewalls/cisco/cisco_ftd_asdm_bypass_cve_2022_20713` |
| CVE-2022-1161 | 9.8 | Rockwell / CompactLogix | Injeção de código via ladder logic | `exploits/ics/rockwell/compactlogix_code_injection_cve_2022_1161` |
| CVE-2022-42475 | 9.3 | Fortinet / FortiOS SSL-VPN | Heap overflow (XORtigate) | `exploits/firewalls/fortinet/fortios_sslvpn_heap_rce_cve_2022_42475` |
| CVE-2022-32257 | 9.1 | Siemens / SINEMA Remote Connect | Path traversal | `exploits/firewalls/siemens/sinema_rc_path_traversal_cve_2022_32257` |
| CVE-2022-4934 | 8.8 | Sophos / UTM | Injeção de comando via web proxy | `exploits/firewalls/sophos/sophos_utm_rce_cve_2022_4934` |
| CVE-2022-23176 | 8.8 | WatchGuard / Firebox | Implante Cyclops Blink (estado-nação) | `exploits/firewalls/watchguard/firebox_cyclops_blink_cve_2022_23176` |
| CVE-2022-0993 | 8.8 | OPNsense / OPNsense | Bypass de autenticação | `exploits/firewalls/opnsense/opnsense_auth_bypass_cve_2022_0993` |
| CVE-2022-25359 | 9.1 | ScadaFlex / SC-168 | Escrita arbitrária de arquivo | `exploits/ics/scadaflex/sc168_file_write_cve_2022_25359` |
| CVE-2022-22509 | 7.5 | Phoenix Contact / mGuard | SNMP public expõe chaves VPN | `exploits/firewalls/phoenix/mguard_firmware_extract_cve_2022_22509` |
| CVE-2022-40685 | 7.5 | Fortinet / FortiOS | Path traversal | `exploits/firewalls/fortinet/fortios_path_traversal_cve_2022_40685` |

---

## CVEs 2021

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2021-40655 | 9.8 | Reolink / Baicells | Bypass de auth + RCE | `exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655` |
| CVE-2021-36300 | 9.8 | Dell / iDRAC9 | Divulgação de info não autenticada | `exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300` |
| CVE-2021-36260 | 9.8 | Hikvision / Câmeras IP | RCE não autenticado | `exploits/cameras/hikvision/rtsp_rce_cve_2021_36260` |
| CVE-2021-36260 | 9.8 | Dahua / CCTV | RCE via configManager.cgi | `exploits/cameras/dahua/cctv_rce_cve_2021_36260` |
| CVE-2021-33044 | 9.8 | Dahua / Câmeras e DVRs | Bypass de autenticação | `exploits/cameras/dahua/auth_bypass_cve_2021_33044` |
| CVE-2021-33044 | 9.8 | Dahua / CCTV (variante) | Bypass de autenticação | `exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044` |
| CVE-2021-32941 | 9.8 | Annke / DVR/NVR | RCE não autenticado | `exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941` |
| CVE-2021-30358 | 9.8 | Check Point / Portal Gaia | SQL injection | `exploits/firewalls/checkpoint/checkpoint_gaia_portal_sqli_cve_2021_30358` |
| CVE-2021-26103 | 9.8 | Fortinet / FortiAnalyzer | SQL injection | `exploits/firewalls/fortinet/fortianalyzer_sql_inject_cve_2021_26103` |
| CVE-2021-22986 | 9.8 | F5 / BIG-IQ iControl | RCE | `exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986` |
| CVE-2021-4045 | 9.8 | TP-Link Tapo / C200/C210 | RCE não autenticado | `exploits/cameras/tapo/tapo_c200_c210_unauth_rce_cve_2021_4045` |
| CVE-2021-22893 | 9.8 | Pulse Secure / Pulse Connect Secure | RCE pré-autenticado via SSL-VPN (CISA KEV) | `exploits/firewalls/vpn/pulsesecure/pulse_connect_secure_rce_cve_2021_22893` |
| CVE-2021-20034 | 9.8 | SonicWall / SMA100 | Deleção arbitrária de arquivo — reset de senha | `exploits/firewalls/sonicwall/sma_password_reset_cve_2021_20034` |
| CVE-2021-20016 | 9.8 | SonicWall / SMA100 | SQL injection não autenticado | `exploits/firewalls/sonicwall/sma100_sqli_cve_2021_20016` |
| CVE-2021-22323 | 9.8 | Huawei / USG6000V2 | Integer overflow — RCE | `exploits/firewalls/huawei/huawei_usg_auth_bypass_rce_cve_2021_22323` |
| CVE-2021-30641 | 9.8 | Symantec (Broadcom) / ProxySG | Bypass de auth na interface de gerenciamento | `exploits/firewalls/symantec/proxysg_auth_bypass_cve_2021_30641` |
| CVE-2021-28250 | 9.8 | Trend Micro / TippingPoint SMS | RCE não autenticado via API de gerenciamento | `exploits/firewalls/trendmicro/trendmicro_tippingpoint_rce_cve_2021_28250` |
| CVE-2021-22681 | 9.8 | Rockwell / CompactLogix | Bypass de auth CIP | `exploits/ics/rockwell/compactlogix_auth_bypass_cve_2021_22681` |
| CVE-2021-1497 | 9.8 | Cisco Meraki / MX | RCE via upload de arquivo no dashboard | `exploits/firewalls/cisco/meraki/meraki_mx_dashboard_rce_cve_2021_1497` |
| CVE-2021-43139 | 9.8 | Array Networks / ArrayOS | Injeção de campo POST pré-autenticada | `exploits/firewalls/array_networks/array_networks_arrayos_rce_cve_2021_43139` |
| CVE-2021-41579 | 8.8 | LAQUIS / LAQUIS SCADA | Escrita arbitrária de arquivo | `exploits/ics/scada/laquis_arb_file_write_cve_2021_41579` |
| CVE-2021-4080 | 8.8 | McAfee/Trellix / NGFW | RCE via injeção de configuração autenticada | `exploits/firewalls/trellix/trellix_ngfw_config_rce_cve_2021_4080` |
| CVE-2021-35278 | 8.8 | VyOS / Roteador VyOS | Injeção de configuração OpenVPN — execução de comando OS | `exploits/firewalls/vyos/vyos_openvpn_injection_cve_2021_35278` |
| CVE-2021-1442 | 8.8 | Cisco / IOS XE | CSRF para RCE | `exploits/firewalls/cisco/cisco_ios_xe_csrf_rce_cve_2021_1442` |

---

## CVEs 2020

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2020-2021 | 10.0 | Palo Alto / PAN-OS | Bypass de autenticação SAML | `exploits/firewalls/paloalto/panos_saml_auth_bypass_cve_2020_2021` |
| CVE-2020-29583 | 9.8 | Sophos / XG Firewall | RCE via credencial hardcoded | `exploits/firewalls/sophos/sophos_xg_rce_cve_2020_29583` |
| CVE-2020-12271 | 9.8 | Sophos / XG Firewall | SQL injection (campanha Asnarok) | `exploits/firewalls/sophos/xg_sqli_asnarok_cve_2020_12271` |
| CVE-2020-27232 | 9.8 | Radware / Alteon ADC, AppWall WAF | RCE não autenticado via API REST | `exploits/firewalls/radware/alteon_rce_cve_2020_27232` |
| CVE-2020-15921 | 9.8 | Trend Micro / Deep Security Manager | RCE via desserialização Java | `exploits/firewalls/trendmicro/trendmicro_deep_security_rce_cve_2020_15921` |
| CVE-2020-5902 | 9.8 | F5 / BIG-IP TMUI | RCE não autenticado via TMUI (F5 BIG-IP) | `exploits/firewalls/lb/f5/bigip_tmui_rce_cve_2020_5902` |
| CVE-2020-5135 | 9.8 | SonicWall / SonicOS | Buffer overflow VPN | `exploits/firewalls/sonicwall/sonicos_vpn_buffer_overflow_cve_2020_5135` |
| CVE-2020-18175 | 9.8 | Stormshield / SNS | RCE na interface de gerenciamento | `exploits/firewalls/stormshield/stormshield_sns_rce_cve_2020_18175` |
| CVE-2020-7270 | 9.0 | McAfee/Trellix / NGFW | Injeção de script de administração | `exploits/firewalls/trellix/trellix_ngfw_rce_cve_2020_7270` |
| CVE-2020-6017 | 8.1 | Check Point / Mobile Access | SSRF | `exploits/firewalls/checkpoint/checkpoint_mobile_access_ssrf_cve_2020_6017` |
| CVE-2020-3452 | 7.5 | Cisco / ASA e FTD | Path traversal | `exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452` |
| CVE-2020-25078 | 7.5 | Dahua / CCTV | Divulgação de nome de usuário | `exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078` |
| CVE-2020-24586 | 7.5 | Múltiplos / Wi-Fi 802.11 | FragAttacks — fragmentação e agregação | `exploits/ics/bluetooth_ble/wifi_fragattacks_cve_2020_24586` |

---

## CVEs 2019

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2019-19781 | 9.8 | Citrix / NetScaler ADC/Gateway | Path traversal (Shitrix) | `exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781` |
| CVE-2019-13393 | 9.8 | Sangfor / NGFW | RCE não autenticado | `exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393` |
| CVE-2019-3950 | 9.8 | Amcrest / Câmeras | Divulgação de info não autenticada | `exploits/cameras/amcrest/amcrest_camera_unauth_info_disclosure_cve_2019_3950` |
| CVE-2019-11510 | 9.8 | Pulse Secure / Pulse Connect Secure | Leitura arbitrária de arquivo + vazamento de credenciais | `exploits/firewalls/vpn/pulsesecure/pulse_connect_rce_cve_2019_11510` |
| CVE-2019-1653 | 9.8 | Cisco / RV320/RV325 | Divulgação de informações | `exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653` |
| CVE-2019-1652 | 9.8 | Cisco / RV320/RV325 | Injeção de comando | `exploits/routers/cisco/rv320_command_injection` |
| CVE-2019-1023 | 9.8 | Huawei / USG6xxx | Injeção de comando | `exploits/firewalls/huawei/huawei_usg_cmd_inject_cve_2019_1023` |
| CVE-2019-18981 | 9.8 | IPFire | Injeção de rede via CGI | `exploits/firewalls/ipfire/ipfire_rce_cve_2019_18981` |
| CVE-2019-20224 | 9.8 | H3C / SecPath | Bypass de autenticação | `exploits/firewalls/h3c/h3c_secpath_auth_bypass_cve_2019_20224` |
| CVE-2019-11831 | 9.8 | Hirschmann / CMS | RCE via interface de gerenciamento | `exploits/firewalls/hirschmann/hirschmann_cms_rce_cve_2019_11831` |
| CVE-2019-0028 | 9.8 | Juniper / EX series | Bypass de autenticação J-Web | `exploits/firewalls/juniper/juniper_ex_auth_bypass_cve_2019_0028` |
| CVE-2019-8461 | 7.8 | Check Point / Endpoint Security | Escalada de privilégio | `exploits/firewalls/checkpoint/endpoint_security_privesc_cve_2019_8461` |
| CVE-2019-3977 | 7.5 | MikroTik / RouterOS | Jailbreak / escalada | `exploits/firewalls/mikrotik/mikrotik_jailbreak_cve_2019_3977` |
| CVE-2019-15126 | 6.5 | Broadcom/Cypress / Chip Wi-Fi | Kr00k — descriptografia de tráfego Wi-Fi | `exploits/ics/bluetooth_ble/wifi_kr00k_attack_cve_2019_15126` |

---

## CVEs 2018

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2018-14847 | 9.1 | MikroTik / RouterOS | Divulgação de credenciais Winbox | `exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847` |
| CVE-2018-13379 | 9.8 | Fortinet / FortiOS SSL-VPN | Path traversal | `exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379` |
| CVE-2018-10660 | 9.8 | Axis / Câmeras | RCE via parhand | `exploits/cameras/axis/srv_parhand_rce_cve_2018_10660` |
| CVE-2018-0101 | 10.0 | Cisco / ASA, ISA3000 | Heap overflow RCE via IKEv1/IKEv2 | `exploits/firewalls/cisco/isa3000_asa_rce_cve_2018_0101` |
| CVE-2018-9195 | 9.8 | Radware / DefenseSSL | Bypass de autenticação | `exploits/firewalls/radware/defensessl_auth_bypass_cve_2018_9195` |
| CVE-2018-7841 | 9.8 | Schneider Electric / Modicon M340 | Controle Modbus não autenticado | `exploits/ics/schneider/modicon_modbus_control_cve_2018_7841` |
| CVE-2018-7784 | 9.8 | Schneider Electric / NET55xx Encoder | RCE via interface web | `exploits/ics/schneider/net55xx_encoder_rce_cve_2018_7784` |
| CVE-2018-0296 | 7.5 | Cisco / ASA | Path traversal HTTP | `exploits/firewalls/cisco/cisco_asa_path_traversal_cve_2018_0296` |
| CVE-2018-0171 | 9.8 | Cisco / IOS Smart Install | RCE não autenticado | `exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171` |

---

## CVEs 2017

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2017-7921 | 9.8 | Hikvision / Câmeras IP | Divulgação de info não autenticada | `exploits/cameras/hikvision/info_disclosure_cve_2017_7921` |
| CVE-2017-17105 | 9.8 | Zivif / Câmeras | RCE via ipcheck | `exploits/cameras/zivif/ipcheck_rce_cve_2017_17105` |
| CVE-2017-6742 | 9.8 | Cisco / IOS (SNMP) | RCE via SNMP | `generic/snmp/snmp_bruteforce` |
| CVE-2017-0781 | 8.8 | Múltiplos / Android Bluetooth | BlueBorne — RCE Bluetooth | `exploits/ics/bluetooth_ble/blueborne_attack_cve_2017_0781` |
| CVE-2017-13077 | 8.8 | Múltiplos / WPA2 | KRACK — reinstalação de chave WPA2 | `exploits/ics/bluetooth_ble/wifi_krack_attack_cve_2017_13077` |

---

## CVEs históricos (2013–2016)

| CVE | CVSS | Vendor / Produto | Tipo | Módulo EmbedXPL |
|-----|------|-----------------|------|----------------|
| CVE-2016-6366 | 9.8 | Cisco / ASA | RCE via SNMP (EXTRABACON) | `exploits/firewalls/cisco/cisco_asa_snmp_rce_cve_2016_6366` |
| CVE-2015-6023 | 9.8 | Advantech / Switch industrial | Shellshock no switch industrial | `exploits/ics/advantech/switch_shellshock_cve_2015_6023` |
| CVE-2015-2049 | 9.8 | D-Link / DCS-931L | RCE via upload de arquivo | `exploits/cameras/dlink/dcs_931l_file_upload_rce_cve_2015_2049` |
| CVE-2015-5374 | 7.8 | Siemens / SIPROTEC | DoS no relé de proteção | `exploits/ics/siemens/siprotec_relay_dos_cve_2015_5374` |
| CVE-2014-3390 | 10.0 | Cisco / ASA | RCE via WebVPN | `exploits/firewalls/cisco/cisco_asa_webvpn_rce_cve_2014_3390` |
| CVE-2013-6117 | 9.8 | Dahua / DVR (antigo) | Bypass de autenticação | `exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117` |
| CVE-2013-4786 | 10.0 | Supermicro / IPMI 2.0 | Hash HMAC RAKP (sem autenticação) | `exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786` |

---

## Advisories próprios (Herospeed/Longsee)

| Advisory | CVSS | Plataforma | Tipo | Módulo EmbedXPL |
|----------|------|-----------|------|----------------|
| HSLS-2026-001 | 9.1 | Herospeed MC6830 | Enumeração de contas não autenticada | `exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum` |
| HSLS-2026-002 | 6.5 | Herospeed MC6830 | Divulgação de credenciais via vb.htm | `exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure` |
| HSLS-2026-003 | 8.8 | Herospeed MC6830 | RCE via injeção de source update.sh | `exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce` |
| HSLS-2026-004 | 9.8 | Herospeed MC6830 | Hash root hardcoded em todas versões | `exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash` |
| HSLS-2026-005 | 8.8 | Herospeed MC6830 | Chave AES hardcoded para config export | `exploits/cameras/herospeed/herospeed_nvr_config_export_cred_recovery` |
| HSLS-2026-006-A | 8.8 | Herospeed MC6830 | RCE via FTP field — popen() | `exploits/cameras/herospeed/herospeed_nvr_ftp_diagnostic_rce` |

---

[Hub da Wiki](../README.md)
