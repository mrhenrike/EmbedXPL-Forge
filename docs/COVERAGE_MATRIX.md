# RouterXPL-Forge — Coverage Matrix

> Auto-generated from module metadata.
> **Version:** 0.5.0-beta | **Modules:** 575 | **CVEs:** 330 | **Vendors:** 46+
>
> Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## Summary

| Metric | Count |
|---|---|
| Total modules | 575 |
| Exploit modules | 429 |
| Credential modules | 88 |
| Payload modules | 32 |
| Encoder modules | 13 |
| Generic modules | 8 |
| Scanner modules | 5 |
| Unique CVEs | 330 |
| Hardware vendors (exploits + creds) | 49 |
| Unique device models affected | 672+ |

---

## Attack Capabilities

### Exploit Categories (429 modules)

| Attack Type | Modules |
|---|---|
| RCE / Command Injection | 147 |
| Other | 69 |
| Information / Credential Disclosure | 49 |
| Authentication Bypass | 28 |
| Cross-Site Scripting (XSS) | 27 |
| Path / Directory Traversal | 25 |
| Buffer Overflow | 21 |
| Denial of Service | 19 |
| Cross-Site Request Forgery (CSRF) | 17 |
| Privilege Escalation | 13 |
| DNS Hijacking | 6 |
| Backdoor / Hardcoded Credentials | 5 |
| SQL Injection | 3 |

### Credential Testing Protocols (88 modules)

| Protocol | Modules |
|---|---|
| FTP (default + bruteforce) | 26 |
| SSH (default + bruteforce) | 26 |
| Telnet (default + bruteforce) | 26 |
| HTTP Basic/Digest/Form | 5 |
| SFTP | 2 |
| SNMP / SNMPv3 | 2 |
| MikroTik API | 1 |

### Payload Generation (32 modules)

| Architecture | Modules | Type |
|---|---|---|
| CMD (Shell) | 14 | reverse_tcp, bind_tcp |
| Python | 4 | reverse_tcp, bind_tcp |
| ARM (LE) | 2 | reverse_tcp, bind_tcp |
| MIPS (BE) | 2 | reverse_tcp, bind_tcp |
| MIPS (LE) | 2 | reverse_tcp, bind_tcp |
| Perl | 2 | reverse_tcp, bind_tcp |
| PHP | 2 | reverse_tcp, bind_tcp |
| x64 | 2 | reverse_tcp, bind_tcp |
| x86 | 2 | reverse_tcp, bind_tcp |

### Encoding (13 modules)

| Language | Modules | Formats |
|---|---|---|
| Python | 5 | base64, hex (encoder + decoder) |
| Perl | 4 | base64, hex (encoder + decoder) |
| PHP | 4 | base64, hex (encoder + decoder) |

---

## CVE Coverage (330 unique)

### CVE Distribution by Year

| Year | CVEs |
|---|---|
| 2001 | 1 |
| 2008 | 1 |
| 2010 | 2 |
| 2012 | 2 |
| 2013 | 3 |
| 2014 | 18 |
| 2015 | 15 |
| 2016 | 38 |
| 2017 | 49 |
| 2018 | 55 |
| 2019 | 66 |
| 2020 | 23 |
| 2021 | 22 |
| 2022 | 17 |
| 2023 | 4 |
| 2024 | 5 |
| 2025 | 9 |

### CVE Table (2016–2025)

| CVE | Year | Vendor | Module(s) | Attack Type |
|---|---|---|---|---|
| CVE-2016-10174 | 2016 | Netgear | `wnr2000v5_hidden_lang_avi_remote_stack_overflow_metasploit_cve_2016_10174`, `wnr2000v5_remote_code_execution_cve_2016_10174` | RCE / Command Injection |
| CVE-2016-10175 | 2016 | Netgear | `wnr2000v5_remote_code_execution_cve_2016_10174` | RCE / Command Injection |
| CVE-2016-10176 | 2016 | Netgear | `wnr2000v5_remote_code_execution_cve_2016_10174` | RCE / Command Injection |
| CVE-2016-10401 | 2016 | Zyxel | `pk5001z_modem_backdoor_account_cve_2016_10401` | Backdoor / Hardcoded Credentials |
| CVE-2016-1287 | 2016 | Cisco | `asa_software_8_x_9_x_ikev1_ikev2_buffer_overflow_cve_2016_1287` | Buffer Overflow |
| CVE-2016-1328 | 2016 | Cisco | `epc_3928_multiple_vulnerabilities_cve_2015_6401` | Other |
| CVE-2016-1336 | 2016 | Cisco | `epc_3928_multiple_vulnerabilities_cve_2015_6401` | Other |
| CVE-2016-1337 | 2016 | Cisco | `epc_3928_multiple_vulnerabilities_cve_2015_6401` | Other |
| CVE-2016-1415 | 2016 | Cisco | `webex_player_t29_10_arf_out_of_bounds_memory_corruption_cve_2016_1415` | Other |
| CVE-2016-1464 | 2016 | Cisco | `webex_player_t29_10_wrf_use_after_free_memory_corruption_cve_2016_1464` | Other |
| CVE-2016-1524 | 2016 | Netgear | `nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524` | Other |
| CVE-2016-1525 | 2016 | Netgear | `nms300_prosafe_network_management_system_arbitrary_file_uplo_cve_2016_1525`, `nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524` | Other |
| CVE-2016-1555 | 2016 | Netgear | `devices_unauthenticated_remote_command_execution_metasploit_cve_2016_1555` | RCE / Command Injection |
| CVE-2016-1909 | 2016 | Fortinet | `fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909` | Backdoor / Hardcoded Credentials |
| CVE-2016-4657 | 2016 | Multi | `nintendo_switch_webkit_code_execution_poc_cve_2016_4657` | RCE / Command Injection |
| CVE-2016-5674 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5675 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5676 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5677 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5678 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5679 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-5680 | 2016 | Netgear | `nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674` | Other |
| CVE-2016-6277 | 2016 | Netgear | `r7000_command_injection_cve_2016_6277`, `r7000_r6400_cgi_bin_command_injection_metasploit_cve_2016_6277` | RCE / Command Injection |
| CVE-2016-6366 | 2016 | Cisco | `asa_8_x_extrabacon_authentication_bypass_cve_2016_6366` | Authentication Bypass |
| CVE-2016-6367 | 2016 | Cisco | `asa_pix_epicbanana_local_privilege_escalation_cve_2016_6367` | Privilege Escalation |
| CVE-2016-6415 | 2016 | Cisco | `ios_12_2_12_4_15_0_15_6_security_association_negotiation_req_cve_2016_6415` | Other |
| CVE-2016-6433 | 2016 | Cisco | `firepower_management_console_6_0_post_authentication_useradd_cve_2016_6433`, `firepower_threat_management_console_6_0_1_remote_command_exe_cve_2016_6433` | RCE / Command Injection |
| CVE-2016-6434 | 2016 | Cisco | `firepower_threat_management_console_6_0_1_hard_coded_mysql_c_cve_2016_6434` | Backdoor / Hardcoded Credentials |
| CVE-2016-6435 | 2016 | Cisco | `firepower_threat_management_console_6_0_1_local_file_inclusi_cve_2016_6435` | Path / Directory Traversal |
| CVE-2016-6563 | 2016 | Dlink | `dir_series_routers_hnap_login_stack_buffer_overflow_metasplo_cve_2016_6563` | Buffer Overflow |
| CVE-2016-6914 | 2016 | Ubiquiti | `unifi_video_3_7_3_local_privilege_escalation_cve_2016_6914` | Privilege Escalation |
| CVE-2016-7454 | 2016 | Technicolor | `xfinity_gateway_dpc3941t_cross_site_request_forgery_cve_2016_7454` | Cross-Site Request Forgery (CSRF) |
| CVE-2016-8526 | 2016 | Aruba | `airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526` | Cross-Site Scripting (XSS) |
| CVE-2016-8527 | 2016 | Aruba | `airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526` | Cross-Site Scripting (XSS) |
| CVE-2016-8769 | 2016 | Huawei | `utps_unquoted_service_path_privilege_escalation_cve_2016_8769` | Privilege Escalation |
| CVE-2016-9682 | 2016 | Sonicwall | `secure_remote_access_8_1_0_2_14sv_command_injection_cve_2016_9682` | RCE / Command Injection |
| CVE-2016-9683 | 2016 | Sonicwall | `8_1_0_2_14sv_extensionsettings_cgi_remote_command_injection_cve_2016_9683` | RCE / Command Injection |
| CVE-2016-9684 | 2016 | Sonicwall | `8_1_0_2_14sv_viewcert_cgi_remote_command_injection_metasploi_cve_2016_9684` | RCE / Command Injection |
| CVE-2017-11320 | 2017 | Technicolor | `tc7337_ssid_persistent_cross_site_scripting_cve_2017_11320` | Cross-Site Scripting (XSS) |
| CVE-2017-11345 | 2017 | Asus | `stack_overflow_cve_2017_11345` | Buffer Overflow |
| CVE-2017-11435 | 2017 | Multi | `humax_wi_fi_router_hg100r_2_0_6_authentication_bypass_cve_2017_11435` | Authentication Bypass |
| CVE-2017-11502 | 2017 | Cisco | `dpc3928_router_arbitrary_file_disclosure_cve_2017_11502` | Other |
| CVE-2017-11519 | 2017 | Tplink | `archer_c9_admin_password_reset` | Other |
| CVE-2017-12243 | 2017 | Cisco | `ucs_platform_emulator_3_1_2epe1_remote_code_execution_cve_2017_12243` | RCE / Command Injection |
| CVE-2017-12943 | 2017 | Dlink | `dir_600_authentication_bypass_cve_2017_12943` | Authentication Bypass |
| CVE-2017-13772 | 2017 | Tplink | `wdr4300_remote_code_execution_authenticated_cve_2017_13772`, `wr940n_authenticated_remote_code_cve_2017_13772` | RCE / Command Injection |
| CVE-2017-14147 | 2017 | Fiberhome | `adsl_an1020_25_improper_access_restrictions_cve_2017_14147` | Other |
| CVE-2017-14219 | 2017 | Intelbras | `roteador_wireless_wrn150_cross_site_scripting_cve_2017_14219` | Cross-Site Scripting (XSS) |
| CVE-2017-14243 | 2017 | Multi | `utstar_wa3002g4_adsl_broadband_modem_authentication_bypass_cve_2017_14243` | Authentication Bypass |
| CVE-2017-14244 | 2017 | Multi | `iball_adsl2_home_router_authentication_bypass_cve_2017_14244` | Authentication Bypass |
| CVE-2017-15291 | 2017 | Tplink | `tl_mr3220_cross_site_scripting_cve_2017_15291` | Cross-Site Scripting (XSS) |
| CVE-2017-15647 | 2017 | Fiberhome | `directory_traversal_cve_2017_15647` | Path / Directory Traversal |
| CVE-2017-16885 | 2017 | Fiberhome | `lm53q1_multiple_vulnerabilities_cve_2017_16885` | Other |
| CVE-2017-16886 | 2017 | Fiberhome | `lm53q1_multiple_vulnerabilities_cve_2017_16885` | Other |
| CVE-2017-16887 | 2017 | Fiberhome | `lm53q1_multiple_vulnerabilities_cve_2017_16885` | Other |
| CVE-2017-16953 | 2017 | Zte | `zxdsl_831cii_improper_access_restrictions_cve_2017_16953` | Other |
| CVE-2017-16957 | 2017 | Tplink | `wvr_war_diagnostic_rce_cve_2017_16957` | RCE / Command Injection |
| CVE-2017-17020 | 2017 | Dlink | `dcs_5020l_remote_code_execution_poc_cve_2017_17020` | RCE / Command Injection |
| CVE-2017-17215 | 2017 | Huawei | `hg532_rce`, `router_hg532_arbitrary_command_execution_cve_2017_17215` | RCE / Command Injection |
| CVE-2017-17411 | 2017 | Linksys | `wvbr0_25_user_agent_command_execution_metasploit_cve_2017_17411`, `wvbr0_user_agent_remote_command_injection_cve_2017_17411` | RCE / Command Injection |
| CVE-2017-17538 | 2017 | Mikrotik | `6_40_5_icmp_denial_of_service_cve_2017_17538` | Denial of Service |
| CVE-2017-17867 | 2017 | Multi | `iopsys_router_dhcp_remote_code_execution_cve_2017_17867` | RCE / Command Injection |
| CVE-2017-3131 | 2017 | Fortinet | `fortios_5_6_0_cross_site_scripting_cve_2017_3131` | Cross-Site Scripting (XSS) |
| CVE-2017-3132 | 2017 | Fortinet | `fortios_5_6_0_cross_site_scripting_cve_2017_3131` | Cross-Site Scripting (XSS) |
| CVE-2017-3133 | 2017 | Fortinet | `fortios_5_6_0_cross_site_scripting_cve_2017_3131` | Cross-Site Scripting (XSS) |
| CVE-2017-3807 | 2017 | Cisco | `asa_webvpn_cifs_handling_buffer_overflow_cve_2017_3807` | Buffer Overflow |
| CVE-2017-3813 | 2017 | Cisco | `anyconnect_secure_mobility_client_4_3_04027_local_privilege_cve_2017_3813` | Privilege Escalation |
| CVE-2017-3881 | 2017 | Cisco | `catalyst_2960_ios_12_2_55_se11_rocem_remote_code_execution_cve_2017_3881`, `catalyst_2960_ios_12_2_55_se1_rocem_remote_code_execution_cve_2017_3881`, `catalyst_2960_rocem` | RCE / Command Injection |
| CVE-2017-5135 | 2017 | Technicolor | `dpc3928sl_snmp_authentication_bypass_cve_2017_5135` | Authentication Bypass |
| CVE-2017-5521 | 2017 | Netgear | `multi_password_disclosure-2017-5521`, `routers_password_disclosure_cve_2017_5521` | Information / Credential Disclosure |
| CVE-2017-5633 | 2017 | Dlink | `di_524_cross_site_request_forgery_cve_2017_5633` | Cross-Site Request Forgery (CSRF) |
| CVE-2017-6077 | 2017 | Netgear | `dgn2200_ping_cgi_rce`, `dgn2200v1_v2_v3_v4_ping_cgi_remote_command_execution_cve_2017_6077` | RCE / Command Injection |
| CVE-2017-6190 | 2017 | Dlink | `dwr_116_dwr_116a1_arbitrary_file_download_cve_2017_6190` | Other |
| CVE-2017-6206 | 2017 | Dlink | `dgs_1510_multiple_vulnerabilities_cve_2017_6206` | Other |
| CVE-2017-6315 | 2017 | Multi | `astaro_security_gateway_7_remote_code_execution_cve_2017_6315` | RCE / Command Injection |
| CVE-2017-6334 | 2017 | Netgear | `dgn2200_dnslookup_cgi_command_injection_metasploit_cve_2017_6334`, `dgn2200_dnslookup_cgi_rce`, `dgn2200_rce` +2 | RCE / Command Injection |
| CVE-2017-6366 | 2017 | Netgear | `dgn2200v1_v2_v3_v4_cross_site_request_forgery_cve_2017_6334` | Cross-Site Request Forgery (CSRF) |
| CVE-2017-6411 | 2017 | Dlink | `dsl_2730u_wireless_n_150_cross_site_request_forgery_cve_2017_6411` | Cross-Site Request Forgery (CSRF) |
| CVE-2017-6444 | 2017 | Mikrotik | `router_arp_table_overflow_denial_of_service_cve_2017_6444` | Denial of Service |
| CVE-2017-6622 | 2017 | Cisco | `prime_collaboration_provisioning_12_1_authentication_bypass_cve_2017_6622` | RCE / Command Injection |
| CVE-2017-6736 | 2017 | Cisco | `ios_remote_code_execution_cve_2017_6736` | RCE / Command Injection |
| CVE-2017-6896 | 2017 | Multi | `digisol_dg_hr1400_1_00_02_wireless_router_privilege_escalati_cve_2017_6896` | Privilege Escalation |
| CVE-2017-7285 | 2017 | Mikrotik | `routerboard_6_38_5_denial_of_service_cve_2017_7285` | Denial of Service |
| CVE-2017-7398 | 2017 | Dlink | `dir_615_cross_site_request_forgery_cve_2017_7398` | Cross-Site Request Forgery (CSRF) |
| CVE-2017-7851 | 2017 | Dlink | `dcs_936l_network_camera_cross_site_request_forgery_cve_2017_7851` | Cross-Site Request Forgery (CSRF) |
| CVE-2017-7852 | 2017 | Dlink | `dcs_series_cameras_insecure_crossdomain_cve_2017_7852` | Other |
| CVE-2017-9675 | 2017 | Dlink | `dir_605l_2_08_denial_of_service_cve_2017_9675` | Denial of Service |
| CVE-2018-0101 | 2018 | Cisco | `asa_crash_poc_cve_2018_0101` | Other |
| CVE-2018-0114 | 2018 | Cisco | `node_jos_0_11_0_re_sign_tokens_cve_2018_0114` | Other |
| CVE-2018-0171 | 2018 | Cisco | `smart_install_crash_poc_cve_2018_0171` | Other |
| CVE-2018-0296 | 2018 | Cisco | `adaptive_security_appliance_path_traversal_cve_2018_0296`, `adaptive_security_appliance_path_traversal_metasploit_cve_2018_0296` | Path / Directory Traversal |
| CVE-2018-0437 | 2018 | Cisco | `umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437` | Privilege Escalation |
| CVE-2018-0438 | 2018 | Cisco | `umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437` | Privilege Escalation |
| CVE-2018-10070 | 2018 | Mikrotik | `6_41_4_ftp_daemon_denial_of_service_poc_cve_2018_10070` | Denial of Service |
| CVE-2018-10110 | 2018 | Dlink | `dir_615_wireless_router_persistent_cross_site_scripting_cve_2018_10110` | Other |
| CVE-2018-10561 | 2018 | Gpon | `routers_authentication_bypass_command_injection_cve_2018_10561` | RCE / Command Injection |
| CVE-2018-10562 | 2018 | Gpon | `home_gateway_rce_cve_2018_10562`, `routers_authentication_bypass_command_injection_cve_2018_10561` | RCE / Command Injection |
| CVE-2018-10618 | 2018 | Multi | `davolink_dvw_3200_router_password_disclosure_cve_2018_10618` | Information / Credential Disclosure |
| CVE-2018-10822 | 2018 | Dlink | `routers_directory_traversal_cve_2018_10822` | Path / Directory Traversal |
| CVE-2018-10823 | 2018 | Dlink | `routers_command_injection_cve_2018_10823` | RCE / Command Injection |
| CVE-2018-10824 | 2018 | Dlink | `routers_plaintext_password_cve_2018_10824` | Other |
| CVE-2018-11094 | 2018 | Intelbras | `ncloud_300_1_0_authentication_bypass_cve_2018_11094` | Authentication Bypass |
| CVE-2018-11492 | 2018 | Asus | `hg100_denial_of_service_cve_2018_11492` | Denial of Service |
| CVE-2018-12710 | 2018 | Dlink | `dir_601_credential_disclosure_cve_2018_12710` | Information / Credential Disclosure |
| CVE-2018-13134 | 2018 | Tplink | `wireless_router_archer_c1200_cross_site_scripting_cve_2018_13134` | Cross-Site Scripting (XSS) |
| CVE-2018-13374 | 2018 | Fortinet | `fortigate_fortios_6_0_3_ldap_credential_disclosure_cve_2018_13374` | Information / Credential Disclosure |
| CVE-2018-13379 | 2018 | Fortinet | `fortios_5_6_3_5_6_7_fortios_6_0_0_6_0_4_credentials_disclosu_cve_2018_13379` | Information / Credential Disclosure |
| CVE-2018-13382 | 2018 | Fortinet | `fortios_6_0_4_unauthenticated_ssl_vpn_user_password_modifica_cve_2018_13382` | Other |
| CVE-2018-14336 | 2018 | Tplink | `tl_wr840n_denial_of_service_cve_2018_14336` | Denial of Service |
| CVE-2018-14497 | 2018 | Tenda | `adsl_router_d152_cross_site_scripting_cve_2018_14497` | Cross-Site Scripting (XSS) |
| CVE-2018-14847 | 2018 | Mikrotik | `winbox_cred_disclosure_cve_2018_14847` | Information / Credential Disclosure |
| CVE-2018-15172 | 2018 | Tplink | `wr840n_0_9_1_3_16_denial_of_service_poc_cve_2018_15172` | Denial of Service |
| CVE-2018-15379 | 2018 | Cisco | `prime_infrastructure_unauthenticated_remote_code_execution_cve_2018_15379` | RCE / Command Injection |
| CVE-2018-15437 | 2018 | Cisco | `immunet_6_2_0_amp_for_endpoints_6_2_0_denial_of_service_cve_2018_15437` | Denial of Service |
| CVE-2018-15839 | 2018 | Dlink | `dir_615_denial_of_service_poc_cve_2018_15839` | Denial of Service |
| CVE-2018-17440 | 2018 | Dlink | `central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440` | Other |
| CVE-2018-17441 | 2018 | Dlink | `central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440` | Other |
| CVE-2018-17442 | 2018 | Dlink | `central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440` | Other |
| CVE-2018-17443 | 2018 | Dlink | `central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440` | Other |
| CVE-2018-18428 | 2018 | Tplink | `tl_sc3130_1_6_18_rtsp_stream_disclosure_cve_2018_18428` | Other |
| CVE-2018-18852 | 2018 | Cerio | `multi_rce_cve_2018_18852` | RCE / Command Injection |
| CVE-2018-19524 | 2018 | Gpon | `skyworth_homegateways_and_optical_network_terminals_stack_ov_cve_2018_19524` | Buffer Overflow |
| CVE-2018-19537 | 2018 | Tplink | `archer_c5_rce_cve_2018_19537` | RCE / Command Injection |
| CVE-2018-20326 | 2018 | Multi | `plc_wireless_router_gpn2_4p21_c_cn_cross_site_scripting_cve_2018_20326` | Cross-Site Scripting (XSS) |
| CVE-2018-20523 | 2018 | Xiaomi | `browser_10_2_4_g_browser_search_history_disclosure_cve_2018_20523` | Other |
| CVE-2018-5234 | 2018 | Multi | `norton_core_secure_wifi_router_ble_command_injection_poc_cve_2018_5234` | RCE / Command Injection |
| CVE-2018-5708 | 2018 | Dlink | `dir_601_admin_password_disclosure_cve_2018_5708` | Information / Credential Disclosure |
| CVE-2018-5767 | 2018 | Tenda | `ac15_router_remote_code_execution_cve_2018_5767` | RCE / Command Injection |
| CVE-2018-5999 | 2018 | Multi | `asuswrt_lan_rce`, `wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999` | RCE / Command Injection |
| CVE-2018-6000 | 2018 | Multi | `asuswrt_lan_rce`, `wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999` | RCE / Command Injection |
| CVE-2018-6190 | 2018 | Netcore | `wf2419_router_cross_site_scripting_cve_2018_6190` | Cross-Site Scripting (XSS) |
| CVE-2018-6936 | 2018 | Dlink | `dir_600m_wireless_cross_site_scripting_cve_2018_6936` | Cross-Site Scripting (XSS) |
| CVE-2018-7355 | 2018 | Zte | `mf65_bd_hdv6mf65v1_0_0b05_cross_site_scripting_cve_2018_7355` | Cross-Site Scripting (XSS) |
| CVE-2018-7357 | 2018 | Zte | `zxhn_h168n_improper_access_restrictions_cve_2018_7357` | Other |
| CVE-2018-7358 | 2018 | Zte | `zxhn_h168n_improper_access_restrictions_cve_2018_7357` | Other |
| CVE-2018-7445 | 2018 | Mikrotik | `routeros_6_41_3_6_42rc27_smb_buffer_overflow_cve_2018_7445` | Buffer Overflow |
| CVE-2018-7921 | 2018 | Huawei | `b315s_22_information_leak_cve_2018_7921` | Other |
| CVE-2018-8772 | 2018 | Multi | `coship_rt3052_wireless_router_persistent_cross_site_scriptin_cve_2018_8772` | Cross-Site Scripting (XSS) |
| CVE-2018-8898 | 2018 | Dlink | `dsl_3782_authentication_bypass_cve_2018_8898` | Authentication Bypass |
| CVE-2018-9010 | 2018 | Intelbras | `telefone_ip_tip200_lite_local_file_disclosure_cve_2018_9010` | Other |
| CVE-2018-9032 | 2018 | Dlink | `dir_850l_wireless_ac1200_dual_band_gigabit_cloud_router_auth_cve_2018_9032` | Authentication Bypass |
| CVE-2018-9248 | 2018 | Fiberhome | `vdsl2_modem_hg_150_ub_authentication_bypass_cve_2018_9248` | Authentication Bypass |
| CVE-2019-10677 | 2019 | Zhone | `dasan_znid_2426a_eu_multiple_cross_site_scripting_cve_2019_10677` | Cross-Site Scripting (XSS) |
| CVE-2019-10709 | 2019 | Asus | `precision_touchpad_11_0_0_25_denial_of_service_cve_2019_10709` | Denial of Service |
| CVE-2019-11017 | 2019 | Dlink | `di_524_v2_06ru_multiple_cross_site_scripting_cve_2019_11017` | Cross-Site Scripting (XSS) |
| CVE-2019-11415 | 2019 | Intelbras | `iwr_3000n_denial_of_service_remote_reboot_cve_2019_11415` | Denial of Service |
| CVE-2019-11416 | 2019 | Intelbras | `iwr_3000n_1_5_0_cross_site_request_forgery_cve_2019_11416` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-12195 | 2019 | Tplink | `tl_wr840n_v5_00000005_cross_site_scripting_cve_2019_12195` | Cross-Site Scripting (XSS) |
| CVE-2019-12624 | 2019 | Cisco | `wireless_controller_3_6_10e_cross_site_request_forgery_cve_2019_12624` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-13101 | 2019 | Dlink | `dir_600m_authentication_bypass_metasploit_cve_2019_13101` | Authentication Bypass |
| CVE-2019-13150 | 2019 | Trendnet | `tew827dru_stack_overflow_cve_2019_13150` | Buffer Overflow |
| CVE-2019-13276 | 2019 | Trendnet | `tew827dru_cmd_injection_cve_2019_13276` | RCE / Command Injection |
| CVE-2019-13277 | 2019 | Trendnet | `tew827dru_cmd_injection_cve_2019_13277` | Denial of Service |
| CVE-2019-13278 | 2019 | Trendnet | `tew827dru_cmd_injection_cve_2019_13278` | RCE / Command Injection |
| CVE-2019-13279 | 2019 | Trendnet | `tew827dru_stack_overflow_cve_2019_13279` | Buffer Overflow |
| CVE-2019-13280 | 2019 | Trendnet | `tew827dru_stack_overflow_cve_2019_13280` | Buffer Overflow |
| CVE-2019-13491 | 2019 | Tenda | `d301_v2_modem_router_persistent_cross_site_scripting_cve_2019_13491` | Cross-Site Scripting (XSS) |
| CVE-2019-15253 | 2019 | Cisco | `digital_network_architecture_center_1_3_1_4_persistent_cross_cve_2019_15253` | Cross-Site Scripting (XSS) |
| CVE-2019-15276 | 2019 | Cisco | `wlc_2504_8_9_denial_of_service_poc_cve_2019_15276` | Denial of Service |
| CVE-2019-15975 | 2019 | Cisco | `data_center_network_manager_11_2_remote_code_execution_cve_2019_15975` | RCE / Command Injection |
| CVE-2019-15976 | 2019 | Cisco | `data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976` | SQL Injection |
| CVE-2019-15977 | 2019 | Cisco | `data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977` | RCE / Command Injection |
| CVE-2019-15978 | 2019 | Cisco | `data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977` | RCE / Command Injection |
| CVE-2019-15984 | 2019 | Cisco | `data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976` | SQL Injection |
| CVE-2019-15993 | 2019 | Cisco | `dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993` | Information / Credential Disclosure |
| CVE-2019-15999 | 2019 | Cisco | `dcnm_jboss_10_4_credential_leakage_cve_2019_15999` | Information / Credential Disclosure |
| CVE-2019-1619 | 2019 | Cisco | `data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619` | RCE / Command Injection |
| CVE-2019-1620 | 2019 | Cisco | `data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619` | RCE / Command Injection |
| CVE-2019-1622 | 2019 | Cisco | `data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619` | RCE / Command Injection |
| CVE-2019-1642 | 2019 | Cisco | `firepower_management_center_6_2_2_2_6_2_3_cross_site_scripti_cve_2019_1642` | Cross-Site Scripting (XSS) |
| CVE-2019-1652 | 2019 | Cisco | `rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652`, `rv320_command_injection`, `rv320_dual_gigabit_wan_vpn_router_1_4_2_15_command_injection_cve_2019_1652` | RCE / Command Injection |
| CVE-2019-1653 | 2019 | Cisco | `rv300_rv320_information_disclosure_cve_2019_1653`, `rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652` | RCE / Command Injection |
| CVE-2019-1663 | 2019 | Cisco | `rv110w_rv130_w_rv215w_routers_management_interface_remote_co_cve_2019_1663`, `rv130w_1_0_3_44_remote_stack_overflow_cve_2019_1663`, `rv130w_rce` +1 | RCE / Command Injection |
| CVE-2019-1674 | 2019 | Cisco | `webex_meetings_33_6_6_33_9_1_privilege_escalation_cve_2019_1674` | Privilege Escalation |
| CVE-2019-16893 | 2019 | Tplink | `tp_sg105e_1_0_0_unauthenticated_remote_reboot_cve_2019_16893` | Other |
| CVE-2019-16920 | 2019 | Dlink | `dir_655_866_652_rce` | RCE / Command Injection |
| CVE-2019-17525 | 2019 | Dlink | `dir_615_t1_20_10_captcha_bypass_cve_2019_17525` | Other |
| CVE-2019-1821 | 2019 | Cisco | `prime_infrastructure_health_monitor_ha_tararchive_directory_cve_2019_1821`, `prime_infrastructure_health_monitor_tararchive_directory_tra_cve_2019_1821` | Path / Directory Traversal |
| CVE-2019-18396 | 2019 | Technicolor | `td5130_2_remote_command_execution_cve_2019_18396` | RCE / Command Injection |
| CVE-2019-1912 | 2019 | Cisco | `small_business_220_series_multiple_vulnerabilities_cve_2019_1912` | Other |
| CVE-2019-1913 | 2019 | Cisco | `small_business_220_series_multiple_vulnerabilities_cve_2019_1912` | Other |
| CVE-2019-1914 | 2019 | Cisco | `small_business_220_series_multiple_vulnerabilities_cve_2019_1912` | Other |
| CVE-2019-19142 | 2019 | Intelbras | `wireless_n_150mbps_wrn240_authentication_bypass_config_uploa_cve_2019_19142` | Authentication Bypass |
| CVE-2019-19143 | 2019 | Tplink | `wr849n_config_bypass_cve_2019_19143` | Other |
| CVE-2019-1935 | 2019 | Cisco | `ucs_director_default_scpuser_password_metasploit_cve_2019_1935` | Other |
| CVE-2019-1937 | 2019 | Cisco | `ucs_imc_supervisor_2_2_0_0_authentication_bypass_cve_2019_1937` | Authentication Bypass |
| CVE-2019-1943 | 2019 | Cisco | `small_business_200_300_500_switches_multiple_vulnerabilities_cve_2019_1943` | Other |
| CVE-2019-19516 | 2019 | Intelbras | `router_rf1200_1_1_3_cross_site_request_forgery_cve_2019_19516` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-19742 | 2019 | Dlink | `dir_615_wireless_router_persistent_cross_site_scripting_cve_2019_19742` | Cross-Site Scripting (XSS) |
| CVE-2019-19743 | 2019 | Dlink | `dir_615_privilege_escalation_cve_2019_19743` | Privilege Escalation |
| CVE-2019-20215 | 2019 | Dlink | `devices_unauthenticated_remote_command_execution_in_ssdpcgi_cve_2019_20215` | RCE / Command Injection |
| CVE-2019-20499 | 2019 | Dlink | `dwl_2600_authenticated_remote_command_injection_metasploit_cve_2019_20499`, `dwl_2600ap_multiple_os_command_injection_cve_2019_20499` | RCE / Command Injection |
| CVE-2019-20500 | 2019 | Dlink | `dwl_2600ap_multiple_os_command_injection_cve_2019_20499` | RCE / Command Injection |
| CVE-2019-20501 | 2019 | Dlink | `dwl_2600ap_multiple_os_command_injection_cve_2019_20499` | RCE / Command Injection |
| CVE-2019-3921 | 2019 | Gpon | `alcatel_lucent_nokia_i_240w_q_buffer_overflow_cve_2019_3921` | Buffer Overflow |
| CVE-2019-3924 | 2019 | Mikrotik | `routeros_6_43_12_stable_6_42_12_long_term_firewall_and_nat_b_cve_2019_3924` | Other |
| CVE-2019-3978 | 2019 | Mikrotik | `routeros_6_45_6_dns_cache_poisoning_cve_2019_3978` | DNS Hijacking |
| CVE-2019-6279 | 2019 | Multi | `plc_wireless_router_gpn2_4p21_c_cn_incorrect_access_control_cve_2019_6279` | Other |
| CVE-2019-6282 | 2019 | Multi | `plc_wireless_router_gpn2_4p21_c_cn_cross_site_request_forger_cve_2019_6282` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-6441 | 2019 | Multi | `coship_wireless_router_4_0_0_48_4_0_0_40_5_0_0_54_5_0_0_55_1_cve_2019_6441` | Other |
| CVE-2019-6710 | 2019 | Zyxel | `nbg_418n_v2_modem_1_00_aaxm_6_c0_cross_site_request_forgery_cve_2019_6710` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-6967 | 2019 | Multi | `airties_air5341_modem_1_0_0_12_cross_site_request_forgery_cve_2019_6967` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-6971 | 2019 | Tplink | `tl_wr1043nd_2_authentication_bypass_cve_2019_6971`, `wr1043nd_auth_bypass` | Authentication Bypass |
| CVE-2019-6989 | 2019 | Tplink | `tl_wr940n_tl_wr941nd_buffer_overflow_cve_2019_6989` | Buffer Overflow |
| CVE-2019-7391 | 2019 | Zyxel | `vmg3312_b10b_dsl_491hnu_b1b_v2_modem_cross_site_request_forg_cve_2019_7391` | Cross-Site Request Forgery (CSRF) |
| CVE-2019-8385 | 2019 | Thomson | `reuters_concourse_firm_central_2_13_0097_directory_traversal_cve_2019_8385` | Path / Directory Traversal |
| CVE-2019-9556 | 2019 | Fiberhome | `an5506_04_f_rp2669_persistent_cross_site_scripting_cve_2019_9556` | Cross-Site Scripting (XSS) |
| CVE-2019-9955 | 2019 | Zyxel | `zywall_310_zywall_110_usg1900_atp500_usg40_login_page_cross_cve_2019_9955` | Cross-Site Scripting (XSS) |
| CVE-2020-10173 | 2020 | Comtrend | `vr_3033_command_injection_cve_2020_10173` | RCE / Command Injection |
| CVE-2020-10882 | 2020 | Tplink | `archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882` | RCE / Command Injection |
| CVE-2020-10883 | 2020 | Tplink | `archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882` | RCE / Command Injection |
| CVE-2020-10884 | 2020 | Tplink | `archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882` | RCE / Command Injection |
| CVE-2020-13118 | 2020 | Mikrotik | `router_monitoring_system_1_2_3_community_sql_injection_cve_2020_13118` | SQL Injection |
| CVE-2020-14461 | 2020 | Zyxel | `armor_x1_wap6806_directory_traversal_cve_2020_14461` | Path / Directory Traversal |
| CVE-2020-17456 | 2020 | Multi | `seowon_slr_120_router_remote_code_execution_unauthenticated_cve_2020_17456` | RCE / Command Injection |
| CVE-2020-24363 | 2020 | Tplink | `tl_wa855re_v5_200415_device_reset_auth_bypass_cve_2020_24363` | Authentication Bypass |
| CVE-2020-25988 | 2020 | Multi | `genexis_platinum_4410_router_2_1_upnp_credential_exposure_cve_2020_25988` | Information / Credential Disclosure |
| CVE-2020-26567 | 2020 | Dlink | `dsr_250n_3_12_denial_of_service_poc_cve_2020_26567` | Denial of Service |
| CVE-2020-3161 | 2020 | Cisco | `ip_phone_11_7_denial_of_service_poc_cve_2020_3161` | Denial of Service |
| CVE-2020-3187 | 2020 | Cisco | `adaptive_security_appliance_software_9_7_unauthenticated_arb_cve_2020_3187` | Other |
| CVE-2020-3452 | 2020 | Cisco | `adaptive_security_appliance_software_9_11_local_file_inclusi_cve_2020_3452`, `asa_9_14_1_10_and_ftd_6_6_0_1_path_traversal_2_cve_2020_3452`, `asa_and_ftd_9_6_4_42_path_traversal_cve_2020_3452` | Path / Directory Traversal |
| CVE-2020-35391 | 2020 | Tenda | `n300_f3_12_01_01_48_malformed_http_request_header_processing_cve_2020_35391` | Other |
| CVE-2020-35575 | 2020 | Tplink | `wr841nd_password_disclosure_cve_2020_35575` | Information / Credential Disclosure |
| CVE-2020-35576 | 2020 | Tplink | `tl_wr841n_command_injection_cve_2020_35576` | RCE / Command Injection |
| CVE-2020-5147 | 2020 | Sonicwall | `netextender_10_2_0_300_unquoted_service_path_cve_2020_5147` | Other |
| CVE-2020-5330 | 2020 | Cisco | `dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993` | Information / Credential Disclosure |
| CVE-2020-6862 | 2020 | Zte | `router_f602w_captcha_bypass_cve_2020_6862` | Other |
| CVE-2020-7115 | 2020 | Aruba | `clearpass_policy_manager_6_7_0_unauthenticated_remote_comman_cve_2020_7115` | RCE / Command Injection |
| CVE-2020-8515 | 2020 | Draytek | `multiple_products_pre_authentication_remote_root_code_execut_cve_2020_8515` | RCE / Command Injection |
| CVE-2020-9374 | 2020 | Tplink | `wr849n_rce_cve_2020_9374` | RCE / Command Injection |
| CVE-2020-9375 | 2020 | Tplink | `archer_c50_3_denial_of_service_poc_cve_2020_9375` | Denial of Service |
| CVE-2021-20031 | 2021 | Sonicwall | `sonicos_7_0_host_header_injection_cve_2021_20031` | Other |
| CVE-2021-20034 | 2021 | Sonicwall | `sma_10_2_1_0_17sv_password_reset_cve_2021_20034` | Other |
| CVE-2021-25155 | 2021 | Aruba | `instant_8_7_1_0_arbitrary_file_modification_cve_2021_25155`, `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25156 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25157 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25158 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25159 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25160 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25161 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-25162 | 2021 | Aruba | `instant_iap_remote_code_execution_cve_2021_25155` | RCE / Command Injection |
| CVE-2021-31152 | 2021 | Multi | `laser_router_re018_ac1200_cross_site_request_forgery_enable_cve_2021_31152` | Cross-Site Request Forgery (CSRF) |
| CVE-2021-3186 | 2021 | Tenda | `ac5_ac1200_wireless_wifi_name_password_stored_cross_site_scr_cve_2021_3186` | Other |
| CVE-2021-32403 | 2021 | Intelbras | `router_rf_301k_dns_hijacking_cross_site_request_forgery_csrf_cve_2021_32403` | Cross-Site Request Forgery (CSRF) |
| CVE-2021-33393 | 2021 | Ipfire | `2_25_remote_code_execution_authenticated_cve_2021_33393` | RCE / Command Injection |
| CVE-2021-4039 | 2021 | Zyxel | `nwa_1100_nh_command_injection_cve_2021_4039` | RCE / Command Injection |
| CVE-2021-4045 | 2021 | Tplink | `tapo_c200_1_1_15_remote_code_execution_rce_cve_2021_4045` | RCE / Command Injection |
| CVE-2021-43062 | 2021 | Fortinet | `fortimail_7_0_1_reflected_cross_site_scripting_xss_cve_2021_43062` | Cross-Site Scripting (XSS) |
| CVE-2021-43164 | 2021 | Ruijie | `reyee_mesh_router_remote_code_execution_rce_authenticated_cve_2021_43164` | RCE / Command Injection |
| CVE-2021-46378 | 2021 | Dlink | `dir850_insecure_access_control_cve_2021_46378` | Other |
| CVE-2021-46379 | 2021 | Dlink | `dir850_open_redirect_cve_2021_46379` | Other |
| CVE-2021-46381 | 2021 | Dlink | `dap_1620_a1_v1_01_directory_traversal_cve_2021_46381` | Path / Directory Traversal |
| CVE-2021-46387 | 2021 | Zyxel | `zywall_2_plus_internet_security_appliance_cross_site_scripti_cve_2021_46387` | Cross-Site Scripting (XSS) |
| CVE-2022-23854 | 2022 | Multi | `aveva_intouch_access_anywhere_secure_gateway_2020_r2_path_tr_cve_2022_23854` | Path / Directory Traversal |
| CVE-2022-24354 | 2022 | Tplink | `archer_c7_netusb_rce_cve_2022_24354` | RCE / Command Injection |
| CVE-2022-27226 | 2022 | Multi | `irz_mobile_router_csrf_to_rce_cve_2022_27226` | RCE / Command Injection |
| CVE-2022-30075 | 2022 | Tplink | `ax50_rce`, `router_ax50_firmware_210730_remote_code_execution_rce_authen_cve_2022_30075` | RCE / Command Injection |
| CVE-2022-30525 | 2022 | Zyxel | `usg_flex_5_21_os_command_injection_cve_2022_30525` | RCE / Command Injection |
| CVE-2022-34046 | 2022 | Wavlink | `wn533a8_password_disclosure_cve_2022_34046` | Information / Credential Disclosure |
| CVE-2022-34047 | 2022 | Wavlink | `wn530hg4_password_disclosure_cve_2022_34047` | Information / Credential Disclosure |
| CVE-2022-34048 | 2022 | Wavlink | `wn533a8_cross_site_scripting_xss_cve_2022_34048` | Cross-Site Scripting (XSS) |
| CVE-2022-35899 | 2022 | Asus | `gamesdk_v1_0_0_4_gamesdk_exe_unquoted_service_path_cve_2022_35899` | Other |
| CVE-2022-37661 | 2022 | Multi | `smartrg_router_sr510n_2_6_13_remote_code_execution_cve_2022_37661` | RCE / Command Injection |
| CVE-2022-38841 | 2022 | Linksys | `ax3200_v1_1_00_command_injection_cve_2022_38841` | RCE / Command Injection |
| CVE-2022-40684 | 2022 | Fortinet | `fortios_fortiproxy_and_fortiswitchmanager_7_2_0_authenticati_cve_2022_40684` | Authentication Bypass |
| CVE-2022-40946 | 2022 | Dlink | `dir_819_a1_denial_of_service_cve_2022_40946` | Denial of Service |
| CVE-2022-44149 | 2022 | Multi | `nexxt_router_firmware_42_103_1_5095_remote_code_execution_rc_cve_2022_44149` | RCE / Command Injection |
| CVE-2022-45701 | 2022 | Arris | `router_firmware_9_1_103_remote_code_execution_rce_authentica_cve_2022_45701` | RCE / Command Injection |
| CVE-2022-46552 | 2022 | Dlink | `dir_846_remote_command_execution_rce_vulnerability_cve_2022_46552` | RCE / Command Injection |
| CVE-2022-48194 | 2022 | Tplink | `tl_wr902ac_firmware_210730_v3_remote_code_execution_rce_auth_cve_2022_48194` | RCE / Command Injection |
| CVE-2023-1389 | 2023 | Tplink | `archer_ax21_rce`, `archer_ax21_unauthenticated_command_injection_cve_2023_1389` | RCE / Command Injection |
| CVE-2023-26602 | 2023 | Asus | `asmb8_ikvm_1_14_51_remote_code_execution_rce_cve_2023_26602` | RCE / Command Injection |
| CVE-2023-34723 | 2023 | Multi | `techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34723` | Other |
| CVE-2023-36355 | 2023 | Tplink | `tl_wr940n_v4_buffer_overflow_cve_2023_36355` | Buffer Overflow |
| CVE-2024-11237 | 2024 | Tplink | `vn020_f3v_t_tt_v6_2_1021_dhcp_stack_buffer_overflow_cve_2024_11237` | Buffer Overflow |
| CVE-2024-12342 | 2024 | Tplink | `vn020_f3v_t_tt_v6_2_1021_denial_of_service_dos_cve_2024_12342` | Denial of Service |
| CVE-2024-12344 | 2024 | Tplink | `vn020_f3v_t_tt_v6_2_1021_buffer_overflow_memory_corruption_cve_2024_12344` | Buffer Overflow |
| CVE-2024-20419 | 2024 | Cisco | `smart_software_manager_on_prem_8_202206_account_takeover_cve_2024_20419` | Other |
| CVE-2024-33113 | 2024 | Dlink | `dir845l_cred_disclosure_cve_2024_33113` | Information / Credential Disclosure |
| CVE-2025-10666 | 2025 | Dlink | `dir_825_rev_b_2_10_stack_buffer_overflow_dos_cve_2025_10666` | Buffer Overflow |
| CVE-2025-1731 | 2025 | Zyxel | `usg_flex_h_series_uos_1_31_privilege_escalation_cve_2025_1731` | Privilege Escalation |
| CVE-2025-20124 | 2025 | Cisco | `ise_3_0_remote_code_execution_rce_cve_2025_20124` | RCE / Command Injection |
| CVE-2025-20125 | 2025 | Cisco | `ise_3_0_authorization_bypass_cve_2025_20125` | Other |
| CVE-2025-52089 | 2025 | Totolink | `n300rb_8_54_command_execution_cve_2025_52089` | RCE / Command Injection |
| CVE-2025-6563 | 2025 | Mikrotik | `routeros_7_19_1_reflected_xss_cve_2025_6563` | Cross-Site Scripting (XSS) |
| CVE-2025-7795 | 2025 | Tenda | `fh451_1_0_0_9_router_stack_based_buffer_overflow_cve_2025_7795` | Buffer Overflow |
| CVE-2025-8730 | 2025 | Belkin | `f9k1009_f9k1010_2_00_04_2_00_09_hard_coded_credentials_cve_2025_8730` | Information / Credential Disclosure |
| CVE-2025-9090 | 2025 | Tenda | `ac20_16_03_08_12_command_injection_cve_2025_9090` | RCE / Command Injection |

---

## Vendor Coverage

| Vendor | Exploits | Creds | CVEs | Devices |
|---|---|---|---|---|
| Dlink | 69 | 3 | 48 | 119 |
| Cisco | 66 | 3 | 66 | 71 |
| Multi | 38 | 0 | 32 | 80 |
| Tplink | 38 | 3 | 31 | 45 |
| Netgear | 25 | 3 | 18 | 75 |
| Huawei | 19 | 3 | 10 | 22 |
| Zyxel | 14 | 3 | 9 | 14 |
| Linksys | 12 | 3 | 6 | 32 |
| Mikrotik | 12 | 4 | 10 | 13 |
| Fortinet | 10 | 0 | 11 | 10 |
| Zte | 10 | 3 | 6 | 11 |
| Asus | 9 | 3 | 8 | 24 |
| Intelbras | 8 | 0 | 8 | 8 |
| Technicolor | 8 | 3 | 4 | 9 |
| Tenda | 8 | 0 | 8 | 8 |
| Belkin | 7 | 3 | 4 | 13 |
| Sonicwall | 7 | 0 | 7 | 7 |
| Trendnet | 6 | 0 | 6 | 1 |
| 3Com | 5 | 3 | 0 | 4 |
| Fiberhome | 5 | 0 | 7 | 5 |
| Ipfire | 5 | 0 | 2 | 5 |
| Aruba | 4 | 0 | 11 | 4 |
| Gpon | 4 | 0 | 4 | 4 |
| Thomson | 3 | 3 | 1 | 4 |
| Wavlink | 3 | 0 | 3 | 3 |
| Hootoo | 3 | 0 | 0 | 6 |
| 2Wire | 2 | 3 | 0 | 6 |
| Asmax | 2 | 4 | 0 | 3 |
| Billion | 2 | 3 | 0 | 3 |
| Comtrend | 2 | 3 | 1 | 3 |
| Netcore | 2 | 3 | 1 | 3 |
| Ubiquiti | 2 | 3 | 1 | 3 |
| Xiaomi | 2 | 0 | 1 | 7 |
| Arris | 1 | 0 | 1 | 1 |
| Bhu | 1 | 3 | 0 | 2 |
| Draytek | 1 | 0 | 1 | 1 |
| Mercury | 1 | 0 | 1 | 1 |
| Mitrastar | 1 | 0 | 0 | 1 |
| Movistar | 1 | 3 | 0 | 2 |
| Netsys | 1 | 3 | 0 | 2 |
| Ruijie | 1 | 0 | 1 | 1 |
| Shuttle | 1 | 0 | 0 | 1 |
| Totolink | 1 | 0 | 1 | 1 |
| Zhone | 1 | 0 | 1 | 1 |
| Cerio | 1 | 0 | 1 | 4 |
| Lg | 1 | 0 | 0 | 1 |

---

## Full Capability Summary

| Capability | Description |
|---|---|
| **Exploitation** | 429 modules covering RCE, auth bypass, info disclosure, path traversal, DNS hijacking, credential disclosure, buffer overflow, XSS, CSRF, DoS, privilege escalation, backdoor |
| **Credential Testing** | 88 modules for dictionary attacks via FTP, SSH, Telnet, HTTP, SFTP, SNMP, MikroTik API against 49+ vendors |
| **Payload Generation** | 32 modules generating reverse/bind TCP shells for x86, x64, ARM, MIPS (BE/LE), Python, Perl, PHP, CMD |
| **Encoding** | 13 modules for Base64/Hex encoding in Python, Perl, PHP |
| **Scanning** | 5 modules including AutoPwn, vendor-specific scanners, CVE lookup |
| **Generic Tools** | 8 modules for Heartbleed, ShellShock, HTTP oracle attacks, UPnP/SSDP, SNMP |
| **CVE Coverage** | 330 unique CVEs from 2001 to 2025 |
| **Target Scope** | Routers, Switches L2/L3, SOHO Edge/CPE, TAPs |

---

*Generated from RouterXPL-Forge v0.5.0-beta module metadata.*