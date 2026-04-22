# EmbedXPL-Forge — Module Index

> **Total modules:** 693+ | **Version:** 2.13.0
>
> Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)

---

## v2.13.0 New Modules (routerpwn.com gap analysis)

| Module Path | Name |
|---|---|
| `exploits/routers/alcatel_lucent/omnipcx_masterCGI_rce.py` | Alcatel-Lucent OmniPCX Enterprise — masterCGI Command Injection RCE |
| `exploits/routers/alcatel_lucent/omniswitch_add_admin_csrf.py` | Alcatel-Lucent OmniSwitch — Add Admin User via CSRF |
| `exploits/routers/alpha_networks/web_shell_cmd_rce.py` | Alpha Networks / ZTE — web_shell_cmd.gch Backdoor RCE |
| `exploits/routers/alpha_networks/config_download.py` | Alpha Networks / ZTE — Unauthenticated Config Backup Download |
| `exploits/routers/astoria/astoria_password_reset.py` | Astoria Networks ADSL Router — Unauthenticated Admin Password Reset |
| `exploits/routers/belkin/dns_hijack_csrf.py` | Belkin Router — DNS Hijack + Admin CSRF (N300/N900/F5D8236) |
| `exploits/routers/binatone/dt850w_change_admin.py` | Binatone DT850W — Unauthenticated Admin CSRF Password Change |
| `exploits/routers/ddwrt/ddwrt_info_disclosure.py` | DD-WRT — Unauthenticated Info Disclosure (BID 35742) |
| `exploits/routers/ddwrt/ddwrt_command_exec.py` | DD-WRT — Remote Command Execution via Diagnostics |
| `exploits/routers/easybox/easybox_wpa_keygen.py` | EasyBox (Arcadyan) — WPA2 Default Key Generator |
| `exploits/routers/ee/brightbox_config_disclosure.py` | EE BrightBox — Unauthenticated Configuration Status Disclosure |
| `exploits/routers/freebox/freebox_auth_bypass_reboot.py` | Freebox — Unauthenticated Reboot / Management Bypass |
| `exploits/routers/mifi/mifi_config_backup.py` | MiFi (Novatel) — Unauthenticated Configuration Backup Download |
| `exploits/routers/motorola/sbg6580_info_disclosure.py` | Motorola SBG — DNS CSRF / Password Reset / Config Disclosure |
| `exploits/routers/netgear/dg632_bypass_dos.py` | Netgear DG632 — Auth Bypass + DoS |
| `exploits/routers/netgear/wg602_superman_backdoor.py` | Netgear WG602 — Hardcoded Backdoor Credentials (super/superman) |
| `exploits/routers/observa/observa_telecom_cred_disclosure.py` | Observa Telecom — Credential Disclosure + DNS/Admin CSRF |
| `exploits/routers/ruggedcom/ruggedcom_factory_password.py` | RuggedCom — Factory Backdoor Account Password Generator |
| `exploits/routers/seagate/seagate_nas_php_backdoor.py` | Seagate NAS — Unauthenticated PHP Backdoor RCE (Ghost PHP) |
| `exploits/routers/sitecom/dc227_backdoor_password.py` | Sitecom DC-227 Backdoor + WLR-4000/4004 WPA Key Generator |
| `exploits/routers/starbridge/lynx526_password_reset.py` | Starbridge Lynx 526 — Unauthenticated Admin Password Reset |
| `exploits/routers/trendnet/tew827_backdoor_password.py` | TRENDnet TEW-827DRU — Hardcoded Backdoor Password |
| `exploits/routers/trendnet/camera_mjpeg_unauth.py` | TRENDnet IP Camera — Unauthenticated MJPEG Live Stream |
| `exploits/routers/ubee/ubee_cablemas_bypass.py` | Ubee Cable Modem — Operator Account Bypass (Cablemas ISP) |
| `exploits/routers/unicorn/wb3300nr_factory_reset.py` | Unicorn WB-3300NR — Unauthenticated Factory Reset + DNS Change |
| `exploits/routers/utstarcom/utstar_ppp_password_disclosure.py` | UTStarcom — Unauthenticated PPP Password Disclosure |
| `exploits/routers/zoom/zoom_x4_x5_add_admin.py` | Zoom X4/X5 ADSL — Unauthenticated Admin Account Creation (EDB-26736) |

---

## exploits (543+ modules)

| Module Path | Name |
|---|---|
| `exploits/generic/heartbleed.py` | OpenSSL Heartbleed |
| `exploits/generic/http_form_char_by_char_oracle.py` | HTTP Form Char-by-Char Oracle |
| `exploits/generic/shellshock.py` | Shellshock |
| `exploits/generic/ssh_auth_keys.py` | Multi SSH Authorized Keys |
| `exploits/routers/2wire/4011g_5012nv_path_traversal.py` | 2Wire 4011G & 5012NV Path Traversal |
| `exploits/routers/2wire/gateway_auth_bypass.py` | 2Wire Gateway Auth Bypass |
| `exploits/routers/3com/ap8760_password_disclosure.py` | 3Com AP8760 Password Disclosure |
| `exploits/routers/3com/imc_info_disclosure.py` | 3Com IMC Info Disclosure |
| `exploits/routers/3com/imc_path_traversal.py` | 3Com IMC Path Traversal |
| `exploits/routers/3com/officeconnect_info_disclosure.py` | 3Com OfficeConnect Info Disclosure |
| `exploits/routers/3com/officeconnect_rce.py` | 3Com OfficeConnect RCE |
| `exploits/routers/arris/router_firmware_9_1_103_remote_code_execution_rce_authentica_cve_2022_45701.py` | Arris Router Firmware 9.1.103 - Remote Code Execution (RCE) (Authenticated) |
| `exploits/routers/aruba/airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526.py` | Aruba AirWave 8.2.3 - XML External Entity Injection / Cross-Site Scripting |
| `exploits/routers/aruba/clearpass_policy_manager_6_7_0_unauthenticated_remote_comman_cve_2020_7115.py` | Aruba ClearPass Policy Manager 6.7.0 - Unauthenticated Remote Command Execution |
| `exploits/routers/aruba/instant_8_7_1_0_arbitrary_file_modification_cve_2021_25155.py` | Aruba Instant 8.7.1.0 - Arbitrary File Modification |
| `exploits/routers/aruba/instant_iap_remote_code_execution_cve_2021_25155.py` | Aruba Instant (IAP) - Remote Code Execution |
| `exploits/routers/asmax/ar_1004g_password_disclosure.py` | Asmax AR1004G Password Disclosure |
| `exploits/routers/asmax/ar_804_gu_rce.py` | Asmax AR 804 RCE |
| `exploits/routers/asus/asmb8_ikvm_1_14_51_remote_code_execution_rce_cve_2023_26602.py` | ASUS ASMB8 iKVM 1.14.51 - Remote Code Execution (RCE) |
| `exploits/routers/asus/asuswrt_lan_rce.py` | AsusWRT Lan RCE |
| `exploits/routers/asus/gamesdk_v1_0_0_4_gamesdk_exe_unquoted_service_path_cve_2022_35899.py` | Asus GameSDK v1.0.0.4 - 'GameSDK.exe' Unquoted Service Path |
| `exploits/routers/asus/hg100_denial_of_service_cve_2018_11492.py` | ASUS HG100 - Denial of Service |
| `exploits/routers/asus/infosvr_authentication_bypass_command_execution_metasploit_cve_2014_9583.py` | ASUS infosvr - Authentication Bypass Command Execution (Metasploit) |
| `exploits/routers/asus/infosvr_backdoor_rce.py` | Asus Infosvr Backdoor RCE |
| `exploits/routers/asus/precision_touchpad_11_0_0_25_denial_of_service_cve_2019_10709.py` | Asus Precision TouchPad 11.0.0.25 - Denial of Service |
| `exploits/routers/asus/rt_n16_password_disclosure.py` | Asus RT-N16 Password Disclosure |
| `exploits/routers/asus/stack_overflow_cve_2017_11345.py` | ASUS Router Stack Overflow |
| `exploits/routers/belkin/auth_bypass.py` | Belkin Auth Bypass |
| `exploits/routers/belkin/f9k1009_f9k1010_2_00_04_2_00_09_hard_coded_credentials_cve_2025_8730.py` | Belkin F9K1009 F9K1010 2.00.04/2.00.09 - Hard Coded Credentials |
| `exploits/routers/belkin/g_n150_password_disclosure.py` | Belkin G & N150 Password Disclosure |
| `exploits/routers/belkin/g_plus_info_disclosure.py` | Belkin G Info Disclosure |
| `exploits/routers/belkin/n150_path_traversal.py` | Belkin N150 Path Traversal |
| `exploits/routers/belkin/n750_rce.py` | Belkin N750 RCE |
| `exploits/routers/belkin/play_max_prce.py` | Belkin Play Max Persistent RCE |
| `exploits/routers/bhu/bhu_urouter_rce.py` | BHU uRouter RCE |
| `exploits/routers/billion/billion_5200w_rce.py` | Billion 5200W-T RCE |
| `exploits/routers/billion/billion_7700nr4_password_disclosure.py` | Billion 7700NR4 Password Disclosure |
| `exploits/routers/cisco/adaptive_security_appliance_path_traversal_cve_2018_0296.py` | Cisco Adaptive Security Appliance - Path Traversal |
| `exploits/routers/cisco/adaptive_security_appliance_path_traversal_metasploit_cve_2018_0296.py` | Cisco Adaptive Security Appliance - Path Traversal (Metasploit) |
| `exploits/routers/cisco/adaptive_security_appliance_software_9_11_local_file_inclusi_cve_2020_3452.py` | Cisco Adaptive Security Appliance Software 9.11 - Local File Inclusion |
| `exploits/routers/cisco/adaptive_security_appliance_software_9_7_unauthenticated_arb_cve_2020_3187.py` | Cisco Adaptive Security Appliance Software 9.7 - Unauthenticated Arbitrary File  |
| `exploits/routers/cisco/anyconnect_secure_mobility_client_4_3_04027_local_privilege_cve_2017_3813.py` | Cisco AnyConnect Secure Mobility Client 4.3.04027 - Local Privilege Escalation |
| `exploits/routers/cisco/asa_8_x_extrabacon_authentication_bypass_cve_2016_6366.py` | Cisco ASA 8.x - 'EXTRABACON' Authentication Bypass |
| `exploits/routers/cisco/asa_9_14_1_10_and_ftd_6_6_0_1_path_traversal_2_cve_2020_3452.py` | Cisco ASA 9.14.1.10 and FTD 6.6.0.1 - Path Traversal (2) |
| `exploits/routers/cisco/asa_and_ftd_9_6_4_42_path_traversal_cve_2020_3452.py` | Cisco ASA and FTD 9.6.4.42 - Path Traversal |
| `exploits/routers/cisco/asa_crash_poc_cve_2018_0101.py` | Cisco ASA - Crash (PoC) |
| `exploits/routers/cisco/asa_pix_epicbanana_local_privilege_escalation_cve_2016_6367.py` | Cisco ASA / PIX - 'EPICBANANA' Local Privilege Escalation |
| `exploits/routers/cisco/asa_software_8_x_9_x_ikev1_ikev2_buffer_overflow_cve_2016_1287.py` | Cisco ASA Software 8.x/9.x - IKEv1 / IKEv2 Buffer Overflow |
| `exploits/routers/cisco/asa_webvpn_cifs_handling_buffer_overflow_cve_2017_3807.py` | Cisco ASA - WebVPN CIFS Handling Buffer Overflow |
| `exploits/routers/cisco/catalyst_2960_ios_12_2_55_se11_rocem_remote_code_execution_cve_2017_3881.py` | Cisco Catalyst 2960 IOS 12.2(55)SE11 - 'ROCEM' Remote Code Execution |
| `exploits/routers/cisco/catalyst_2960_ios_12_2_55_se1_rocem_remote_code_execution_cve_2017_3881.py` | Cisco Catalyst 2960 IOS 12.2(55)SE1 - 'ROCEM' Remote Code Execution |
| `exploits/routers/cisco/data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976.py` | Cisco Data Center Network Manager 11.2.1 - 'getVmHostData' SQL Injection |
| `exploits/routers/cisco/data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977.py` | Cisco Data Center Network Manager 11.2.1 - 'LanFabricImpl' Command Injection |
| `exploits/routers/cisco/data_center_network_manager_11_2_remote_code_execution_cve_2019_15975.py` | Cisco Data Center Network Manager 11.2 - Remote Code Execution |
| `exploits/routers/cisco/data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619.py` | Cisco Data Center Network Manager - Unauthenticated Remote Code Execution (Metas |
| `exploits/routers/cisco/dcnm_jboss_10_4_credential_leakage_cve_2019_15999.py` | Cisco DCNM JBoss 10.4 - Credential Leakage |
| `exploits/routers/cisco/dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993.py` | Dell EMC Networking PC5500 firmware versions 4.1.0.22 and  Cisco Sx / SMB - Info |
| `exploits/routers/cisco/digital_network_architecture_center_1_3_1_4_persistent_cross_cve_2019_15253.py` | Cisco Digital Network Architecture Center 1.3.1.4 - Persistent Cross-Site Script |
| `exploits/routers/cisco/dpc2420_info_disclosure.py` | Cisco DPC2420 Info Disclosure |
| `exploits/routers/cisco/dpc3928_router_arbitrary_file_disclosure_cve_2017_11502.py` | Cisco DPC3928 Router - Arbitrary File Disclosure |
| `exploits/routers/cisco/epc_3928_multiple_vulnerabilities_cve_2015_6401.py` | Cisco EPC 3928 - Multiple Vulnerabilities |
| `exploits/routers/cisco/firepower_management_center_6_2_2_2_6_2_3_cross_site_scripti_cve_2019_1642.py` | Cisco Firepower Management Center 6.2.2.2 / 6.2.3 - Cross-Site Scripting |
| `exploits/routers/cisco/firepower_management_console_6_0_post_authentication_useradd_cve_2016_6433.py` | Cisco Firepower Management Console 6.0 - Post Authentication UserAdd (Metasploit |
| `exploits/routers/cisco/firepower_threat_management_console_6_0_1_hard_coded_mysql_c_cve_2016_6434.py` | Cisco Firepower Threat Management Console 6.0.1 - Hard-Coded MySQL Credentials |
| `exploits/routers/cisco/firepower_threat_management_console_6_0_1_local_file_inclusi_cve_2016_6435.py` | Cisco Firepower Threat Management Console 6.0.1 - Local File Inclusion |
| `exploits/routers/cisco/firepower_threat_management_console_6_0_1_remote_command_exe_cve_2016_6433.py` | Cisco Firepower Threat Management Console 6.0.1 - Remote Command Execution |
| `exploits/routers/cisco/immunet_6_2_0_amp_for_endpoints_6_2_0_denial_of_service_cve_2018_15437.py` | Cisco Immunet < 6.2.0 / Cisco AMP For Endpoints 6.2.0 - Denial of Service |
| `exploits/routers/cisco/ios_12_2_12_4_15_0_15_6_security_association_negotiation_req_cve_2016_6415.py` | Cisco IOS 12.2 < 12.4 / 15.0 < 15.6 - Security Association Negotiation Request D |
| `exploits/routers/cisco/ios_http_authorization_bypass.py` | Cisco IOS HTTP Unauthorized Administrative Access |
| `exploits/routers/cisco/ios_remote_code_execution_cve_2017_6736.py` | Cisco IOS - Remote Code Execution |
| `exploits/routers/cisco/ip_phone_11_7_denial_of_service_poc_cve_2020_3161.py` | Cisco IP Phone 11.7 - Denial of service (PoC) |
| `exploits/routers/cisco/ise_3_0_authorization_bypass_cve_2025_20125.py` | Cisco ISE 3.0 - Authorization Bypass |
| `exploits/routers/cisco/ise_3_0_remote_code_execution_rce_cve_2025_20124.py` | Cisco ISE 3.0 - Remote Code Execution (RCE) |
| `exploits/routers/cisco/node_jos_0_11_0_re_sign_tokens_cve_2018_0114.py` | Cisco node-jos < 0.11.0 - Re-sign Tokens |
| `exploits/routers/cisco/prime_collaboration_provisioning_12_1_authentication_bypass_cve_2017_6622.py` | Cisco Prime Collaboration Provisioning < 12.1 - Authentication Bypass / Remote C |
| `exploits/routers/cisco/prime_infrastructure_health_monitor_ha_tararchive_directory_cve_2019_1821.py` | Cisco Prime Infrastructure Health Monitor HA TarArchive - Directory Traversal /  |
| `exploits/routers/cisco/prime_infrastructure_health_monitor_tararchive_directory_tra_cve_2019_1821.py` | Cisco Prime Infrastructure Health Monitor - TarArchive Directory Traversal (Meta |
| `exploits/routers/cisco/prime_infrastructure_unauthenticated_remote_code_execution_cve_2018_15379.py` | Cisco Prime Infrastructure - (Unauthenticated) Remote Code Execution |
| `exploits/routers/cisco/rv110w_password_disclosure_command_execution_cve_2014_0683.py` | Cisco RV110W - Password Disclosure / Command Execution |
| `exploits/routers/cisco/rv110w_rv130_w_rv215w_routers_management_interface_remote_co_cve_2019_1663.py` | Cisco RV110W/RV130(W)/RV215W Routers Management Interface - Remote Command Execu |
| `exploits/routers/cisco/rv130w_1_0_3_44_remote_stack_overflow_cve_2019_1663.py` | Cisco RV130W 1.0.3.44 - Remote Stack Overflow |
| `exploits/routers/cisco/rv130w_rce.py` | Cisco RV130W Stack Overflow RCE |
| `exploits/routers/cisco/rv130w_routers_management_interface_remote_command_execution_cve_2019_1663.py` | Cisco RV130W Routers - Management Interface Remote Command Execution (Metasploit |
| `exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653.py` | Cisco RV300 / RV320 - Information Disclosure |
| `exploits/routers/cisco/rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652.py` | Cisco RV320 and RV325 - Unauthenticated Remote Code Execution (Metasploit) |
| `exploits/routers/cisco/rv320_command_injection.py` | Cisco RV320 Command Injection |
| `exploits/routers/cisco/rv320_dual_gigabit_wan_vpn_router_1_4_2_15_command_injection_cve_2019_1652.py` | Cisco RV320 Dual Gigabit WAN VPN Router 1.4.2.15 - Command Injection |
| `exploits/routers/cisco/small_business_200_300_500_switches_multiple_vulnerabilities_cve_2019_1943.py` | CISCO Small Business 200 / 300 / 500 Switches - Multiple Vulnerabilities |
| `exploits/routers/cisco/small_business_220_series_multiple_vulnerabilities_cve_2019_1912.py` | Cisco Small Business 220 Series - Multiple Vulnerabilities |
| `exploits/routers/cisco/smart_install_crash_poc_cve_2018_0171.py` | Cisco Smart Install - Crash (PoC) |
| `exploits/routers/cisco/smart_software_manager_on_prem_8_202206_account_takeover_cve_2024_20419.py` | Cisco Smart Software Manager On-Prem 8-202206 - Account Takeover |
| `exploits/routers/cisco/ucs_director_default_scpuser_password_metasploit_cve_2019_1935.py` | Cisco UCS Director - default scpuser password (Metasploit) |
| `exploits/routers/cisco/ucs_imc_supervisor_2_2_0_0_authentication_bypass_cve_2019_1937.py` | Cisco UCS-IMC Supervisor 2.2.0.0 - Authentication Bypass |
| `exploits/routers/cisco/ucs_manager_2_1_1b_remote_command_injection_shellshock_cve_2014_6278.py` | Cisco UCS Manager 2.1(1b) - Remote Command Injection (Shellshock) |
| `exploits/routers/cisco/ucs_platform_emulator_3_1_2epe1_remote_code_execution_cve_2017_12243.py` | Cisco UCS Platform Emulator 3.1(2ePE1) - Remote Code Execution |
| `exploits/routers/cisco/umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437.py` | Cisco Umbrella Roaming Client 2.0.168 - Local Privilege Escalation |
| `exploits/routers/cisco/unified_communications_manager_7_8_9_directory_traversal_cve_2013_5528.py` | Cisco Unified Communications Manager 7/8/9 - Directory Traversal |
| `exploits/routers/cisco/webex_meetings_33_6_6_33_9_1_privilege_escalation_cve_2019_1674.py` | Cisco WebEx Meetings < 33.6.6 / < 33.9.1 - Privilege Escalation |
| `exploits/routers/cisco/webex_player_t29_10_arf_out_of_bounds_memory_corruption_cve_2016_1415.py` | Cisco Webex Player T29.10 - '.ARF' Out-of-Bounds Memory Corruption |
| `exploits/routers/cisco/webex_player_t29_10_wrf_use_after_free_memory_corruption_cve_2016_1464.py` | Cisco Webex Player T29.10 - '.WRF' Use-After-Free Memory Corruption |
| `exploits/routers/cisco/wireless_controller_3_6_10e_cross_site_request_forgery_cve_2019_12624.py` | Cisco Wireless Controller 3.6.10E - Cross-Site Request Forgery |
| `exploits/routers/cisco/wlc_2504_8_9_denial_of_service_poc_cve_2019_15276.py` | Cisco WLC 2504 8.9 - Denial of Service (PoC) |
| `exploits/routers/comtrend/ct_5361t_password_disclosure.py` | Comtrend CT 5361T Password Disclosure |
| `exploits/routers/comtrend/vr_3033_command_injection_cve_2020_10173.py` | Comtrend VR-3033 - Command Injection |
| `exploits/routers/dlink/central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440.py` | D-Link Central WiFiManager Software Controller 1.03 - Multiple Vulnerabilities |
| `exploits/routers/dlink/dap_1620_a1_v1_01_directory_traversal_cve_2021_46381.py` | DLINK DAP-1620 A1 v1.01 - Directory Traversal |
| `exploits/routers/dlink/dcs_5020l_remote_code_execution_poc_cve_2017_17020.py` | DLINK DCS-5020L - Remote Code Execution (PoC) |
| `exploits/routers/dlink/dcs_930l_auth_rce.py` | D-Link DCS-930L Auth RCE |
| `exploits/routers/dlink/dcs_931l_arbitrary_file_upload_metasploit_cve_2015_2049.py` | D-Link DCS-931L - Arbitrary File Upload (Metasploit) |
| `exploits/routers/dlink/dcs_936l_network_camera_cross_site_request_forgery_cve_2017_7851.py` | D-Link DCS-936L Network Camera - Cross-Site Request Forgery |
| `exploits/routers/dlink/dcs_series_cameras_insecure_crossdomain_cve_2017_7852.py` | D-Link DCS Series Cameras - Insecure Crossdomain |
| `exploits/routers/dlink/devices_unauthenticated_remote_command_execution_in_ssdpcgi_cve_2019_20215.py` | D-Link Devices - Unauthenticated Remote Command Execution in ssdpcgi (Metasploit |
| `exploits/routers/dlink/dgs_1510_multiple_vulnerabilities_cve_2017_6206.py` | D-Link DGS-1510 - Multiple Vulnerabilities |
| `exploits/routers/dlink/di_524_cross_site_request_forgery_cve_2017_5633.py` | D-Link DI-524 - Cross-Site Request Forgery |
| `exploits/routers/dlink/di_524_v2_06ru_multiple_cross_site_scripting_cve_2019_11017.py` | D-Link DI-524 V2.06RU - Multiple Cross-Site Scripting |
| `exploits/routers/dlink/dir601_cred_disclosure.py` | D-Link DIR-601 Credential Disclosure |
| `exploits/routers/dlink/dir845l_cred_disclosure_cve_2024_33113.py` | D-Link DIR-845L Credentials Disclosure |
| `exploits/routers/dlink/dir850_insecure_access_control_cve_2021_46378.py` | DLINK DIR850 - Insecure Access Control |
| `exploits/routers/dlink/dir850_open_redirect_cve_2021_46379.py` | DLINK DIR850 - Open Redirect |
| `exploits/routers/dlink/dir_300_320_600_615_info_disclosure.py` | D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure |
| `exploits/routers/dlink/dir_300_320_615_auth_bypass.py` | D-Link DIR-300 & DIR-320 & DIR-615 Auth Bypass |
| `exploits/routers/dlink/dir_300_600_rce.py` | D-Link DIR-300 & DIR-600 RCE |
| `exploits/routers/dlink/dir_300_645_815_upnp_rce.py` | D-Link DIR-300 & DIR-645 & DIR-815 UPNP RCE |
| `exploits/routers/dlink/dir_600_authentication_bypass_cve_2017_12943.py` | D-Link DIR-600 - Authentication Bypass |
| `exploits/routers/dlink/dir_600m_authentication_bypass_metasploit_cve_2019_13101.py` | D-Link DIR-600M - Authentication Bypass (Metasploit) |
| `exploits/routers/dlink/dir_600m_wireless_cross_site_scripting_cve_2018_6936.py` | D-Link DIR-600M Wireless - Cross-Site Scripting |
| `exploits/routers/dlink/dir_601_admin_password_disclosure_cve_2018_5708.py` | DLink DIR-601 - Admin Password Disclosure |
| `exploits/routers/dlink/dir_601_credential_disclosure_cve_2018_12710.py` | DLink DIR-601 - Credential Disclosure |
| `exploits/routers/dlink/dir_605l_2_08_denial_of_service_cve_2017_9675.py` | D-Link DIR-605L < 2.08 - Denial of Service |
| `exploits/routers/dlink/dir_615_cross_site_request_forgery_cve_2017_7398.py` | D-Link DIR-615 - Cross-Site Request Forgery |
| `exploits/routers/dlink/dir_615_denial_of_service_poc_cve_2018_15839.py` | D-Link DIR-615 - Denial of Service (PoC) |
| `exploits/routers/dlink/dir_615_privilege_escalation_cve_2019_19743.py` | D-Link DIR-615 - Privilege Escalation |
| `exploits/routers/dlink/dir_615_t1_20_10_captcha_bypass_cve_2019_17525.py` | D-Link DIR-615 T1 20.10 - CAPTCHA Bypass |
| `exploits/routers/dlink/dir_615_wireless_router_persistent_cross_site_scripting_cve_2018_10110.py` | D-Link DIR-615 Wireless Router - Persistent Cross Site Scripting |
| `exploits/routers/dlink/dir_615_wireless_router_persistent_cross_site_scripting_cve_2019_19742.py` | D-Link DIR-615 Wireless Router  -  Persistent Cross-Site Scripting |
| `exploits/routers/dlink/dir_645_815_rce.py` | D-Link DIR-645 & DIR-815 RCE |
| `exploits/routers/dlink/dir_645_password_disclosure.py` | D-Link DIR-645 Password Disclosure |
| `exploits/routers/dlink/dir_655_866_652_rce.py` | D-Link PingTest RCE |
| `exploits/routers/dlink/dir_815_850l_rce.py` | D-Link DIR-815 & DIR-850L RCE |
| `exploits/routers/dlink/dir_819_a1_denial_of_service_cve_2022_40946.py` | DLink DIR 819 A1 - Denial of Service |
| `exploits/routers/dlink/dir_825_path_traversal.py` | D-Link DIR-825 Path Traversal |
| `exploits/routers/dlink/dir_825_rev_b_2_10_stack_buffer_overflow_dos_cve_2025_10666.py` | D-Link DIR-825 Rev.B 2.10 - Stack Buffer Overflow (DoS) |
| `exploits/routers/dlink/dir_846_remote_command_execution_rce_vulnerability_cve_2022_46552.py` | D-Link DIR-846 - Remote Command Execution (RCE) vulnerability |
| `exploits/routers/dlink/dir_850l_creds_disclosure.py` | D-Link DIR-850L Creds Disclosure |
| `exploits/routers/dlink/dir_850l_wireless_ac1200_dual_band_gigabit_cloud_router_auth_cve_2018_9032.py` | D-Link DIR-850L Wireless AC1200 Dual Band Gigabit Cloud Router - Authentication  |
| `exploits/routers/dlink/dir_8xx_password_disclosure.py` | D-Link DIR-8XX Password Disclosure |
| `exploits/routers/dlink/dir_series_routers_hnap_login_stack_buffer_overflow_metasplo_cve_2016_6563.py` | D-Link DIR-Series Routers - HNAP Login Stack Buffer Overflow (Metasploit) |
| `exploits/routers/dlink/dns_320l_327l_rce.py` | D-Link DNS-320L & DIR-327L RCE |
| `exploits/routers/dlink/dsl_2640b_dns_change.py` | D-Link DSL-2640B DNS Change |
| `exploits/routers/dlink/dsl_2730_2750_path_traversal.py` | D-Link DSL-2730U/2750U/2750E Path Traversal |
| `exploits/routers/dlink/dsl_2730b_2780b_526b_dns_change.py` | D-Link DSL-2780B & DSL-2730B & DSL-526B DNS Change |
| `exploits/routers/dlink/dsl_2730u_wireless_n_150_cross_site_request_forgery_cve_2017_6411.py` | D-Link DSL-2730U Wireless N 150 - Cross-Site Request Forgery |
| `exploits/routers/dlink/dsl_2740r_dns_change.py` | D-Link DSL-2740R DNS Change |
| `exploits/routers/dlink/dsl_2750b_info_disclosure.py` | D-Link DSL-2750B Info Disclosure |
| `exploits/routers/dlink/dsl_2750b_rce.py` | D-Link DSL-2750B RCE |
| `exploits/routers/dlink/dsl_3782_authentication_bypass_cve_2018_8898.py` | D-Link DSL-3782 - Authentication Bypass |
| `exploits/routers/dlink/dsr_250n_3_12_denial_of_service_poc_cve_2020_26567.py` | D-Link DSR-250N 3.12 - Denial of Service (PoC) |
| `exploits/routers/dlink/dvg_n5402sp_multiple_vulnerabilities_cve_2015_7245.py` | D-Link DVG­N5402SP - Multiple Vulnerabilities |
| `exploits/routers/dlink/dvg_n5402sp_path_traversal.py` | D-Link DVG-N5402SP Path Traversal |
| `exploits/routers/dlink/dwl_2600_authenticated_remote_command_injection_metasploit_cve_2019_20499.py` | DLINK DWL-2600 - Authenticated Remote Command Injection (Metasploit) |
| `exploits/routers/dlink/dwl_2600ap_multiple_os_command_injection_cve_2019_20499.py` | D-Link DWL-2600AP - Multiple OS Command Injection |
| `exploits/routers/dlink/dwr_116_dwr_116a1_arbitrary_file_download_cve_2017_6190.py` | D-Link DWR-116 / DWR-116A1 - Arbitrary File Download |
| `exploits/routers/dlink/dwr_932_info_disclosure.py` | D-Link DWR-932 Info Disclosure |
| `exploits/routers/dlink/dwr_932b_backdoor.py` | D-Link DWR-932B |
| `exploits/routers/dlink/hedwig_rce_cve_2013_7389.py` | D-Link DIR-645/300/600 hedwig.cgi RCE |
| `exploits/routers/dlink/multi_hedwig_cgi_exec.py` | D-Link Hedwig CGI RCE |
| `exploits/routers/dlink/multi_hnap_rce.py` | D-Link Multi HNAP RCE |
| `exploits/routers/dlink/routers_command_injection_cve_2018_10823.py` | D-Link Routers - Command Injection |
| `exploits/routers/dlink/routers_directory_traversal_cve_2018_10822.py` | D-Link Routers - Directory Traversal |
| `exploits/routers/dlink/routers_plaintext_password_cve_2018_10824.py` | D-Link Routers - Plaintext Password |
| `exploits/routers/draytek/multiple_products_pre_authentication_remote_root_code_execut_cve_2020_8515.py` | Multiple DrayTek Products - Pre-authentication Remote Root Code Execution |
| `exploits/routers/fiberhome/adsl_an1020_25_improper_access_restrictions_cve_2017_14147.py` | FiberHome ADSL AN1020-25 - Improper Access Restrictions |
| `exploits/routers/fiberhome/an5506_04_f_rp2669_persistent_cross_site_scripting_cve_2019_9556.py` | Fiberhome AN5506-04-F RP2669 - Persistent Cross-Site Scripting |
| `exploits/routers/fiberhome/directory_traversal_cve_2017_15647.py` | FiberHome - Directory Traversal |
| `exploits/routers/fiberhome/lm53q1_multiple_vulnerabilities_cve_2017_16885.py` | FiberHome LM53Q1 - Multiple Vulnerabilities |
| `exploits/routers/fiberhome/vdsl2_modem_hg_150_ub_authentication_bypass_cve_2018_9248.py` | FiberHome VDSL2 Modem HG 150-UB - Authentication Bypass |
| `exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_creators_local_privilege_es_cve_2015_4077.py` | Fortinet FortiClient 5.2.3 (Windows 10 x64 Creators) - Local Privilege Escalatio |
| `exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_post_anniversary_local_priv_cve_2015_5736.py` | Fortinet FortiClient 5.2.3 (Windows 10 x64 Post-Anniversary) - Local Privilege E |
| `exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_pre_anniversary_local_privi_cve_2015_5736.py` | Fortinet FortiClient 5.2.3 (Windows 10 x64 Pre-Anniversary) - Local Privilege Es |
| `exploits/routers/fortinet/fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909.py` | Fortinet FortiGate 4.x < 5.0.7 - SSH Backdoor Access |
| `exploits/routers/fortinet/fortigate_fortios_6_0_3_ldap_credential_disclosure_cve_2018_13374.py` | Fortinet FortiGate FortiOS < 6.0.3 - LDAP Credential Disclosure |
| `exploits/routers/fortinet/fortimail_7_0_1_reflected_cross_site_scripting_xss_cve_2021_43062.py` | Fortinet Fortimail 7.0.1 - Reflected Cross-Site Scripting (XSS) |
| `exploits/routers/fortinet/fortios_5_6_0_cross_site_scripting_cve_2017_3131.py` | Fortinet FortiOS < 5.6.0 - Cross-Site Scripting |
| `exploits/routers/fortinet/fortios_5_6_3_5_6_7_fortios_6_0_0_6_0_4_credentials_disclosu_cve_2018_13379.py` | Fortinet FortiOS 5.6.3 - 5.6.7 / FortiOS 6.0.0 - 6.0.4 - Credentials Disclosure |
| `exploits/routers/fortinet/fortios_6_0_4_unauthenticated_ssl_vpn_user_password_modifica_cve_2018_13382.py` | Fortinet FortiOS 6.0.4 - Unauthenticated SSL VPN User Password Modification |
| `exploits/routers/fortinet/fortios_fortiproxy_and_fortiswitchmanager_7_2_0_authenticati_cve_2022_40684.py` | Fortinet FortiOS_ FortiProxy_ and FortiSwitchManager 7.2.0 - Authentication bypa |
| `exploits/routers/gpon/alcatel_lucent_nokia_i_240w_q_buffer_overflow_cve_2019_3921.py` | Alcatel-Lucent (Nokia) GPON I-240W-Q - Buffer Overflow |
| `exploits/routers/gpon/home_gateway_rce_cve_2018_10562.py` | GPON Home Gateway Remote Code Execution |
| `exploits/routers/gpon/routers_authentication_bypass_command_injection_cve_2018_10561.py` | GPON Routers - Authentication Bypass / Command Injection |
| `exploits/routers/gpon/skyworth_homegateways_and_optical_network_terminals_stack_ov_cve_2018_19524.py` | Skyworth GPON HomeGateways and Optical Network Terminals - Stack Overflow |
| `exploits/routers/huawei/b315s_22_information_leak_cve_2018_7921.py` | Huawei B315s-22 - Information Leak |
| `exploits/routers/huawei/e5330_21_210_09_00_158_cross_site_request_forgery_send_sms_cve_2014_5395.py` | Huawei E5330 21.210.09.00.158 - Cross-Site Request Forgery (Send SMS) |
| `exploits/routers/huawei/e5331_mifi_info_disclosure.py` | Huawei E5331 Info Disclosure |
| `exploits/routers/huawei/espace_1_1_11_103_contactsctrl_dll_espacestatusctrl_dll_acti_cve_2014_9418.py` | Huawei eSpace 1.1.11.103 - 'ContactsCtrl.dll' / 'eSpaceStatusCtrl.dll' ActiveX H |
| `exploits/routers/huawei/espace_1_1_11_103_dll_hijacking_cve_2014_9416.py` | Huawei eSpace 1.1.11.103 - DLL Hijacking |
| `exploits/routers/huawei/espace_1_1_11_103_image_file_format_handling_buffer_overflow_cve_2014_9417.py` | Huawei eSpace 1.1.11.103 - Image File Format Handling Buffer Overflow |
| `exploits/routers/huawei/espace_meeting_1_1_11_103_cenwpoll_dll_seh_buffer_overflow_u_cve_2014_9415.py` | Huawei eSpace Meeting 1.1.11.103 - 'cenwpoll.dll' SEH Buffer Overflow (Unicode) |
| `exploits/routers/huawei/hg520_info_disclosure.py` | Huawei HG520 Information Disclosure |
| `exploits/routers/huawei/hg530_hg520b_password_disclosure.py` | Huawei HG530 & HG520b Password Disclosure |
| `exploits/routers/huawei/hg532_rce.py` | Huawei Router HG532 RCE |
| `exploits/routers/huawei/hg532x_path_traversal.py` | Huawei HG532X Path Traversal |
| `exploits/routers/huawei/hg630_info_disclosure.py` | Huawei HG630 Information Disclosure |
| `exploits/routers/huawei/hg8240_auth_rce.py` | Huawei HG824* Authenticated Command Injection |
| `exploits/routers/huawei/hg8240_file_traversal.py` | Huawei HG824* File Traversal |
| `exploits/routers/huawei/hg866_password_change.py` | Huawei HG866 Password Change |
| `exploits/routers/huawei/mate_7_dev_hifi_misc_privilege_escalation_cve_2015_8088.py` | Huawei Mate 7 - '/dev/hifi_misc' Privilege Escalation |
| `exploits/routers/huawei/router_hg532_arbitrary_command_execution_cve_2017_17215.py` | Huawei Router HG532 - Arbitrary Command Execution |
| `exploits/routers/huawei/router_hg532e_command_execution_cve_2015_7254.py` | Huawei Router HG532e - Command Execution |
| `exploits/routers/huawei/utps_unquoted_service_path_privilege_escalation_cve_2016_8769.py` | Huawei UTPS - Unquoted Service Path Privilege Escalation |
| `exploits/routers/intelbras/iwr_3000n_1_5_0_cross_site_request_forgery_cve_2019_11416.py` | Intelbras IWR 3000N 1.5.0 - Cross-Site Request Forgery |
| `exploits/routers/intelbras/iwr_3000n_denial_of_service_remote_reboot_cve_2019_11415.py` | Intelbras IWR 3000N - Denial of Service (Remote Reboot) |
| `exploits/routers/intelbras/ncloud_300_1_0_authentication_bypass_cve_2018_11094.py` | Intelbras NCLOUD 300 1.0 - Authentication bypass |
| `exploits/routers/intelbras/roteador_wireless_wrn150_cross_site_scripting_cve_2017_14219.py` | Roteador Wireless Intelbras WRN150 - Cross-Site Scripting |
| `exploits/routers/intelbras/router_rf1200_1_1_3_cross_site_request_forgery_cve_2019_19516.py` | Intelbras Router RF1200 1.1.3 - Cross-Site Request Forgery |
| `exploits/routers/intelbras/router_rf_301k_dns_hijacking_cross_site_request_forgery_csrf_cve_2021_32403.py` | Intelbras Router RF 301K - 'DNS Hijacking' Cross-Site Request Forgery (CSRF) |
| `exploits/routers/intelbras/telefone_ip_tip200_lite_local_file_disclosure_cve_2018_9010.py` | Intelbras Telefone IP TIP200 LITE - Local File Disclosure |
| `exploits/routers/intelbras/wireless_n_150mbps_wrn240_authentication_bypass_config_uploa_cve_2019_19142.py` | Intelbras Wireless N 150Mbps WRN240 - Authentication Bypass (Config Upload) |
| `exploits/routers/ipfire/ipfire_oinkcode_rce.py` | IPFire Oinkcode RCE |
| `exploits/routers/ipfire/ipfire_proxy_rce.py` | IPFire Proxy RCE |
| `exploits/routers/ipfire/ipfire_shellshock.py` | IPFire Shellshock |
| `exploits/routers/linksys/1500_2500_rce.py` | Linksys E1500/E2500 |
| `exploits/routers/linksys/ax3200_v1_1_00_command_injection_cve_2022_38841.py` | Linksys AX3200 V1.1.00 - Command Injection |
| `exploits/routers/linksys/ea7500_2_0_8_194281_cross_site_scripting_cve_2012_6708.py` | Linksys EA7500 2.0.8.194281 - Cross-Site Scripting |
| `exploits/routers/linksys/eseries_themoon_rce.py` | Linksys E-Series TheMoon RCE |
| `exploits/routers/linksys/eseries_tmunblock_rce.py` | Linksys E-Series tmUnblock Remote Code Execution |
| `exploits/routers/linksys/re6500_rce.py` | Linksys RE6500 Unauthenticated RCE |
| `exploits/routers/linksys/smartwifi_password_disclosure.py` | Linksys SMART WiFi Password Disclosure |
| `exploits/routers/linksys/wap54gv3_debug_rce_cve_2010_1573.py` | Linksys WAP54Gv3 Debug Interface RCE |
| `exploits/routers/linksys/wap54gv3_rce.py` | Linksys WAP54Gv3 |
| `exploits/routers/linksys/wrt100_110_rce.py` | Linksys WRT100/WRT110 RCE |
| `exploits/routers/linksys/wvbr0_25_user_agent_command_execution_metasploit_cve_2017_17411.py` | Linksys WVBR0-25 - User-Agent Command Execution (Metasploit) |
| `exploits/routers/linksys/wvbr0_user_agent_remote_command_injection_cve_2017_17411.py` | Linksys WVBR0 - 'User-Agent' Remote Command Injection |
| `exploits/routers/mercury/hp_loadrunner_agent_magentproc_exe_remote_command_execution_cve_2010_1549.py` | HP Mercury LoadRunner Agent magentproc.exe - Remote Command Execution (Metasploi |
| `exploits/routers/mikrotik/6_40_5_icmp_denial_of_service_cve_2017_17538.py` | MikroTik 6.40.5 ICMP - Denial of Service |
| `exploits/routers/mikrotik/6_41_4_ftp_daemon_denial_of_service_poc_cve_2018_10070.py` | MikroTik 6.41.4 - FTP daemon Denial of Service (PoC) |
| `exploits/routers/mikrotik/router_arp_table_overflow_denial_of_service_cve_2017_6444.py` | MikroTik Router - ARP Table OverFlow Denial Of Service |
| `exploits/routers/mikrotik/router_monitoring_system_1_2_3_community_sql_injection_cve_2020_13118.py` | Mikrotik Router Monitoring System 1.2.3 - 'community' SQL Injection |
| `exploits/routers/mikrotik/routerboard_6_38_5_denial_of_service_cve_2017_7285.py` | MikroTik RouterBoard 6.38.5 - Denial of Service |
| `exploits/routers/mikrotik/routeros_6_41_3_6_42rc27_smb_buffer_overflow_cve_2018_7445.py` | MikroTik RouterOS < 6.41.3/6.42rc27 - SMB Buffer Overflow |
| `exploits/routers/mikrotik/routeros_6_43_12_stable_6_42_12_long_term_firewall_and_nat_b_cve_2019_3924.py` | MikroTik RouterOS < 6.43.12 (stable) / < 6.42.12 (long-term) - Firewall and NAT  |
| `exploits/routers/mikrotik/routeros_6_45_6_dns_cache_poisoning_cve_2019_3978.py` | MikroTik RouterOS 6.45.6 - DNS Cache Poisoning |
| `exploits/routers/mikrotik/routeros_7_19_1_reflected_xss_cve_2025_6563.py` | MikroTik RouterOS 7.19.1 - Reflected XSS |
| `exploits/routers/mikrotik/routeros_jailbreak.py` | Mikrotik RouterOS Jailbreak |
| `exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure.py` | Mikrotik WinBox Auth Bypass - Creds Disclosure |
| `exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847.py` | MikroTik WinBox Credentials Disclosure |
| `exploits/routers/mitrastar/gpt2541gnac_stack_overflow.py` | MitraStar GPT-2541GNAC Stack Overflow RCE |
| `exploits/routers/movistar/adsl_router_bhs_rta_path_traversal.py` | Movistar ADSL Router BHS_RTA Path Traversal |
| `exploits/routers/multi/airties_air5341_modem_1_0_0_12_cross_site_request_forgery_cve_2019_6967.py` | AirTies Air5341 Modem 1.0.0.12 - Cross-Site Request Forgery |
| `exploits/routers/multi/allegrosoft_rompager_auth_bypass.py` | AllegroSoft RomPager Authentication Bypass |
| `exploits/routers/multi/astaro_security_gateway_7_remote_code_execution_cve_2017_6315.py` | Astaro Security Gateway 7 - Remote Code Execution |
| `exploits/routers/multi/aveva_intouch_access_anywhere_secure_gateway_2020_r2_path_tr_cve_2022_23854.py` | AVEVA InTouch Access Anywhere Secure Gateway 2020 R2 - Path Traversal |
| `exploits/routers/multi/cobham_admin_reset_cve_2014_2943.py` | Cobham Aviator/Explorer Serial Reset |
| `exploits/routers/multi/coship_rt3052_wireless_router_persistent_cross_site_scriptin_cve_2018_8772.py` | Coship RT3052 Wireless Router - Persistent Cross-Site Scripting |
| `exploits/routers/multi/coship_wireless_router_4_0_0_48_4_0_0_40_5_0_0_54_5_0_0_55_1_cve_2019_6441.py` | Coship Wireless Router 4.0.0.48 / 4.0.0.40 / 5.0.0.54 / 5.0.0.55 / 10.0.0.49 - U |
| `exploits/routers/multi/davolink_dvw_3200_router_password_disclosure_cve_2018_10618.py` | Davolink DVW 3200 Router - Password Disclosure |
| `exploits/routers/multi/digisol_dg_hr1400_1_00_02_wireless_router_privilege_escalati_cve_2017_6896.py` | DIGISOL DG-HR1400 1.00.02 Wireless Router - Privilege Escalation |
| `exploits/routers/multi/genexis_platinum_4410_router_2_1_upnp_credential_exposure_cve_2020_25988.py` | Genexis Platinum 4410 Router 2.1 - UPnP Credential Exposure |
| `exploits/routers/multi/gpon_home_gateway_rce.py` | GPON Home Gateway RCE |
| `exploits/routers/multi/humax_wi_fi_router_hg100r_2_0_6_authentication_bypass_cve_2017_11435.py` | Humax Wi-Fi Router HG100R 2.0.6 - Authentication Bypass |
| `exploits/routers/multi/iball_adsl2_home_router_authentication_bypass_cve_2017_14244.py` | iBall ADSL2+ Home Router - Authentication Bypass |
| `exploits/routers/multi/iopsys_router_dhcp_remote_code_execution_cve_2017_17867.py` | Iopsys Router - 'dhcp' Remote Code Execution |
| `exploits/routers/multi/irz_mobile_router_csrf_to_rce_cve_2022_27226.py` | iRZ Mobile Router - CSRF to RCE |
| `exploits/routers/multi/laser_router_re018_ac1200_cross_site_request_forgery_enable_cve_2021_31152.py` | Multilaser Router RE018 AC1200 - Cross-Site Request Forgery (Enable Remote Acces |
| `exploits/routers/multi/misfortune_cookie.py` | Misfortune Cookie |
| `exploits/routers/multi/nat_slipstream.py` | NAT Slipstream - ALG Pinhole Opening |
| `exploits/routers/multi/netcommwireless_hspa_3g10wve_wireless_router_ple_vulnerabili_cve_2015_6023.py` | NetCommWireless HSPA 3G10WVE Wireless Router - Multiple Vulnerabilities |
| `exploits/routers/multi/nexxt_router_firmware_42_103_1_5095_remote_code_execution_rc_cve_2022_44149.py` | Nexxt Router Firmware 42.103.1.5095 - Remote Code Execution (RCE) (Authenticated |
| `exploits/routers/multi/nintendo_switch_webkit_code_execution_poc_cve_2016_4657.py` | Nintendo Switch - WebKit Code Execution (PoC) |
| `exploits/routers/multi/norton_core_secure_wifi_router_ble_command_injection_poc_cve_2018_5234.py` | Norton Core Secure WiFi Router - 'BLE' Command Injection (PoC) |
| `exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_cross_site_request_forger_cve_2019_6282.py` | PLC Wireless Router GPN2.4P21-C-CN - Cross-Site Request Forgery |
| `exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_cross_site_scripting_cve_2018_20326.py` | PLC Wireless Router GPN2.4P21-C-CN - Cross-Site Scripting |
| `exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_incorrect_access_control_cve_2019_6279.py` | PLC Wireless Router GPN2.4P21-C-CN - Incorrect Access Control |
| `exploits/routers/multi/rom0.py` | RomPager ROM-0 |
| `exploits/routers/multi/rom0_password_extraction.py` | RomPager rom-0 Password Extraction |
| `exploits/routers/multi/rompager_4_34_ple_router_vendors_misfortune_cookie_authentic_cve_2015_9222.py` | RomPager 4.34 (Multiple Router Vendors) - 'Misfortune Cookie' Authentication Byp |
| `exploits/routers/multi/rompager_password_disclosure_cve_2014_4019.py` | RomPager Multi-Vendor Password Disclosure (rom-0) |
| `exploits/routers/multi/seowon_slr_120_router_remote_code_execution_unauthenticated_cve_2020_17456.py` | Seowon SLR-120 Router - Remote Code Execution (Unauthenticated) |
| `exploits/routers/multi/smartrg_router_sr510n_2_6_13_remote_code_execution_cve_2022_37661.py` | SmartRG Router SR510n 2.6.13 - Remote Code Execution |
| `exploits/routers/multi/tcp_32764_backdoor_rce.py` | TCP 32764 Backdoor Remote Code Execution |
| `exploits/routers/multi/tcp_32764_info_disclosure.py` | TCP-32764 Info Disclosure |
| `exploits/routers/multi/tcp_32764_rce.py` | TCP-32764 RCE |
| `exploits/routers/multi/techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34723.py` | Techview LA-5570 Wireless Gateway Home Automation Controller - Multiple Vulnerab |
| `exploits/routers/multi/utstar_wa3002g4_adsl_broadband_modem_authentication_bypass_cve_2017_14243.py` | UTStar WA3002G4 ADSL Broadband Modem - Authentication Bypass |
| `exploits/routers/multi/viprinet_channel_vpn_router_300_persistent_cross_site_script_cve_2014_2045.py` | Viprinet Multichannel VPN Router 300 - Persistent Cross-Site Scripting |
| `exploits/routers/multi/wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999.py` | AsusWRT Router < 3.0.0.4.380.7743 - LAN Remote Code Execution |
| `exploits/routers/netcore/udp_53413_rce.py` | Netcore/Netis UDP 53413 RCE |
| `exploits/routers/netcore/wf2419_router_cross_site_scripting_cve_2018_6190.py` | Netis WF2419 Router - Cross-Site Scripting |
| `exploits/routers/netgear/devices_unauthenticated_remote_command_execution_metasploit_cve_2016_1555.py` | Netgear Devices - (Unauthenticated) Remote Command Execution (Metasploit) |
| `exploits/routers/netgear/dgn2200_dnslookup_cgi_command_injection_metasploit_cve_2017_6334.py` | Netgear DGN2200 - 'dnslookup.cgi' Command Injection (Metasploit) |
| `exploits/routers/netgear/dgn2200_dnslookup_cgi_rce.py` | Netgear DGN2200 RCE |
| `exploits/routers/netgear/dgn2200_ping_cgi_rce.py` | Netgear DGN2200 RCE |
| `exploits/routers/netgear/dgn2200_rce.py` | Netgear DGN2200v1 Unauthenticated RCE |
| `exploits/routers/netgear/dgn2200v1_v2_v3_v4_cross_site_request_forgery_cve_2017_6334.py` | Netgear DGN2200v1/v2/v3/v4 - Cross-Site Request Forgery |
| `exploits/routers/netgear/dgn2200v1_v2_v3_v4_dnslookup_cgi_remote_command_execution_cve_2017_6334.py` | Netgear DGN2200v1/v2/v3/v4 - 'dnslookup.cgi' Remote Command Execution |
| `exploits/routers/netgear/dgn2200v1_v2_v3_v4_ping_cgi_remote_command_execution_cve_2017_6077.py` | Netgear DGN2200v1/v2/v3/v4 - 'ping.cgi' Remote Command Execution |
| `exploits/routers/netgear/jnr1010_path_traversal.py` | Netgear JNR1010 Path Traversal |
| `exploits/routers/netgear/multi_password_disclosure-2017-5521.py` | Netgear Multi Password Disclosure |
| `exploits/routers/netgear/multi_rce.py` | Netgear Multi RCE |
| `exploits/routers/netgear/n300_auth_bypass.py` | Netgear N300 Auth Bypass |
| `exploits/routers/netgear/nms300_prosafe_network_management_system_arbitrary_file_uplo_cve_2016_1525.py` | Netgear NMS300 ProSafe Network Management System - Arbitrary File Upload (Metasp |
| `exploits/routers/netgear/nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524.py` | Netgear NMS300 ProSafe Network Management System - Multiple Vulnerabilities |
| `exploits/routers/netgear/nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674.py` | NUUO NVRmini2 / NVRsolo / Crystal Devices / NETGEAR ReadyNAS Surveillance Applic |
| `exploits/routers/netgear/r7000_command_injection_cve_2016_6277.py` | Netgear R7000 - Command Injection |
| `exploits/routers/netgear/r7000_r6400_cgi_bin_command_injection_metasploit_cve_2016_6277.py` | Netgear R7000 / R6400 - 'cgi-bin' Command Injection (Metasploit) |
| `exploits/routers/netgear/r7000_r6400_rce.py` | Netgear R7000 & R6400 RCE |
| `exploits/routers/netgear/rax30_rce.py` | Netgear RAX30 RCE |
| `exploits/routers/netgear/routers_password_disclosure_cve_2017_5521.py` | Netgear Routers - Password Disclosure |
| `exploits/routers/netgear/wnap320_rce.py` | Netgear WNAP320 Unauthenticated RCE |
| `exploits/routers/netgear/wnr2000v5_hidden_lang_avi_remote_stack_overflow_metasploit_cve_2016_10174.py` | Netgear WNR2000v5 - 'hidden_lang_avi' Remote Stack Overflow (Metasploit) |
| `exploits/routers/netgear/wnr2000v5_remote_code_execution_cve_2016_10174.py` | Netgear WNR2000v5 - Remote Code Execution |
| `exploits/routers/netgear/wnr500_612v3_jnr1010_2010_path_traversal.py` | Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal |
| `exploits/routers/netsys/multi_rce.py` | Netsys Multi RCE |
| `exploits/routers/ruijie/reyee_mesh_router_remote_code_execution_rce_authenticated_cve_2021_43164.py` | Ruijie Reyee Mesh Router - Remote Code Execution (RCE) (Authenticated) |
| `exploits/routers/shuttle/915wm_dns_change.py` | Shuttle 915 WM DNS Change |
| `exploits/routers/sonicwall/8_1_0_2_14sv_extensionsettings_cgi_remote_command_injection_cve_2016_9683.py` | Sonicwall 8.1.0.2-14sv - 'extensionsettings.cgi' Remote Command Injection (Metas |
| `exploits/routers/sonicwall/8_1_0_2_14sv_viewcert_cgi_remote_command_injection_metasploi_cve_2016_9684.py` | Sonicwall 8.1.0.2-14sv - 'viewcert.cgi' Remote Command Injection (Metasploit) |
| `exploits/routers/sonicwall/dell_scrutinizer_11_01_methoddetail_sql_injection_metasploit_cve_2014_4977.py` | Dell SonicWALL Scrutinizer 11.01 - methodDetail SQL Injection (Metasploit) |
| `exploits/routers/sonicwall/netextender_10_2_0_300_unquoted_service_path_cve_2020_5147.py` | SonicWall NetExtender 10.2.0.300 -  Unquoted Service Path |
| `exploits/routers/sonicwall/secure_remote_access_8_1_0_2_14sv_command_injection_cve_2016_9682.py` | Sonicwall Secure Remote Access 8.1.0.2-14sv - Command Injection |
| `exploits/routers/sonicwall/sma_10_2_1_0_17sv_password_reset_cve_2021_20034.py` | SonicWall SMA 10.2.1.0-17sv - Password Reset |
| `exploits/routers/sonicwall/sonicos_7_0_host_header_injection_cve_2021_20031.py` | Sonicwall SonicOS 7.0 - Host Header Injection |
| `exploits/routers/technicolor/dpc3928sl_snmp_authentication_bypass_cve_2017_5135.py` | Technicolor DPC3928SL - SNMP Authentication Bypass |
| `exploits/routers/technicolor/dwg855_authbypass.py` | Technicolor DWG-855 Auth Bypass |
| `exploits/routers/technicolor/tc7200_password_disclosure.py` | Technicolor TC7200 Password Disclosure |
| `exploits/routers/technicolor/tc7200_password_disclosure_v2.py` | Technicolor TC7200 Password Disclosure V2 |
| `exploits/routers/technicolor/tc7337_ssid_persistent_cross_site_scripting_cve_2017_11320.py` | Technicolor TC7337 - 'SSID' Persistent Cross-Site Scripting |
| `exploits/routers/technicolor/td5130_2_remote_command_execution_cve_2019_18396.py` | Technicolor TD5130.2 - Remote Command Execution |
| `exploits/routers/technicolor/tg784_authbypass.py` | Technicolor TG784n-v3 Auth Bypass |
| `exploits/routers/technicolor/xfinity_gateway_dpc3941t_cross_site_request_forgery_cve_2016_7454.py` | Xfinity Gateway (Technicolor DPC3941T) - Cross-Site Request Forgery |
| `exploits/routers/tenda/ac15_router_remote_code_execution_cve_2018_5767.py` | Tenda AC15 Router - Remote Code Execution |
| `exploits/routers/tenda/ac20_16_03_08_12_command_injection_cve_2025_9090.py` | Tenda AC20 16.03.08.12 - Command Injection |
| `exploits/routers/tenda/ac5_ac1200_wireless_wifi_name_password_stored_cross_site_scr_cve_2021_3186.py` | Tenda AC5 AC1200 Wireless - 'WiFi Name & Password' Stored Cross Site Scripting |
| `exploits/routers/tenda/adsl_router_d152_cross_site_scripting_cve_2018_14497.py` | Tenda ADSL Router D152 - Cross-Site Scripting |
| `exploits/routers/tenda/d301_v2_modem_router_persistent_cross_site_scripting_cve_2019_13491.py` | Tenda D301 v2 Modem Router - Persistent Cross-Site Scripting |
| `exploits/routers/tenda/fh451_1_0_0_9_router_stack_based_buffer_overflow_cve_2025_7795.py` | Tenda FH451 1.0.0.9 Router - Stack-based Buffer Overflow |
| `exploits/routers/tenda/n300_f3_12_01_01_48_malformed_http_request_header_processing_cve_2020_35391.py` | Tenda N300 F3 12.01.01.48 - Malformed HTTP Request Header Processing |
| `exploits/routers/tenda/wireless_n150_router_5_07_50_cross_site_request_forgery_rebo_cve_2015_5996.py` | Tenda Wireless N150 Router 5.07.50 - Cross-Site Request Forgery (Reboot Router) |
| `exploits/routers/thomson/reuters_concourse_firm_central_2_13_0097_directory_traversal_cve_2019_8385.py` | Thomson Reuters Concourse & Firm Central < 2.13.0097 - Directory Traversal / Loc |
| `exploits/routers/thomson/twg849_info_disclosure.py` | Thomson TWG849 Info Disclosure |
| `exploits/routers/thomson/twg850_password_disclosure.py` | Thomson TWG850 Password Disclosure |
| `exploits/routers/totolink/n300rb_8_54_command_execution_cve_2025_52089.py` | TOTOLINK N300RB 8.54 - Command Execution |
| `exploits/routers/tplink/archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882.py` | TP-Link Archer A7/C7 - Unauthenticated LAN Remote Code Execution (Metasploit) |
| `exploits/routers/tplink/archer_ax21_rce.py` | TP-Link Archer AX21 Unauthenticated Command Injection |
| `exploits/routers/tplink/archer_ax21_unauthenticated_command_injection_cve_2023_1389.py` | TP-Link Archer AX21 - Unauthenticated Command Injection |
| `exploits/routers/tplink/archer_c2_c20i_rce.py` | TP-Link Archer C2 & C20i |
| `exploits/routers/tplink/archer_c50_3_denial_of_service_poc_cve_2020_9375.py` | TP-Link Archer C50 3 - Denial of Service (PoC) |
| `exploits/routers/tplink/archer_c5_rce_cve_2018_19537.py` | TP-Link Archer C5 Authenticated RCE |
| `exploits/routers/tplink/archer_c7_netusb_rce_cve_2022_24354.py` | TP-Link Archer C7 NetUSB Kernel RCE |
| `exploits/routers/tplink/archer_c9_admin_password_reset.py` | TP-Link Archer C9 admin password reset (CVE-2017-11519) |
| `exploits/routers/tplink/ax50_rce.py` | TP-Link Archer AX50 Authenticated RCE |
| `exploits/routers/tplink/router_ax50_firmware_210730_remote_code_execution_rce_authen_cve_2022_30075.py` | TP-Link Router AX50 firmware 210730 - Remote Code Execution (RCE) (Authenticated |
| `exploits/routers/tplink/tapo_c200_1_1_15_remote_code_execution_rce_cve_2021_4045.py` | TP-Link Tapo c200 1.1.15 - Remote Code Execution (RCE) |
| `exploits/routers/tplink/tl_mr3220_cross_site_scripting_cve_2017_15291.py` | TP-Link TL-MR3220 - Cross-Site Scripting |
| `exploits/routers/tplink/tl_sc3130_1_6_18_rtsp_stream_disclosure_cve_2018_18428.py` | TP-Link TL-SC3130 1.6.18 - RTSP Stream Disclosure |
| `exploits/routers/tplink/tl_wa855re_v5_200415_device_reset_auth_bypass_cve_2020_24363.py` | TP-Link TL-WA855RE V5_200415 - Device Reset Auth Bypass |
| `exploits/routers/tplink/tl_wr1043nd_2_authentication_bypass_cve_2019_6971.py` | TP-Link TL-WR1043ND 2 - Authentication Bypass |
| `exploits/routers/tplink/tl_wr840n_denial_of_service_cve_2018_14336.py` | TP-Link TL-WR840N - Denial of Service |
| `exploits/routers/tplink/tl_wr840n_v5_00000005_cross_site_scripting_cve_2019_12195.py` | TP-LINK TL-WR840N v5 00000005 - Cross-Site Scripting |
| `exploits/routers/tplink/tl_wr841n_command_injection_cve_2020_35576.py` | TP-Link TL-WR841N - Command Injection |
| `exploits/routers/tplink/tl_wr902ac_firmware_210730_v3_remote_code_execution_rce_auth_cve_2022_48194.py` | TP-Link TL-WR902AC firmware 210730 (V3) - Remote Code Execution (RCE) (Authentic |
| `exploits/routers/tplink/tl_wr940n_tl_wr941nd_buffer_overflow_cve_2019_6989.py` | TP-LINK TL-WR940N / TL-WR941ND - Buffer Overflow |
| `exploits/routers/tplink/tl_wr940n_v4_buffer_overflow_cve_2023_36355.py` | TP-Link TL-WR940N V4 - Buffer OverFlow |
| `exploits/routers/tplink/tp_sg105e_1_0_0_unauthenticated_remote_reboot_cve_2019_16893.py` | TP-Link TP-SG105E 1.0.0 - Unauthenticated Remote Reboot |
| `exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_buffer_overflow_memory_corruption_cve_2024_12344.py` | TP-Link VN020 F3v(T) TT_V6.2.1021 - Buffer Overflow Memory Corruption |
| `exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_denial_of_service_dos_cve_2024_12342.py` | TP-Link VN020 F3v(T) TT_V6.2.1021 - Denial Of Service (DOS) |
| `exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_dhcp_stack_buffer_overflow_cve_2024_11237.py` | TP-Link VN020 F3v(T) TT_V6.2.1021) - DHCP Stack Buffer Overflow |
| `exploits/routers/tplink/wdr4300_remote_code_execution_authenticated_cve_2017_13772.py` | TP-Link WDR4300 - Remote Code Execution (Authenticated) |
| `exploits/routers/tplink/wdr5620_cmd_injection.py` | TP-Link TL-WDR5620 Command Injection |
| `exploits/routers/tplink/wdr740nd_wdr740n_backdoor.py` | TP-Link WDR740ND & WDR740N Backdoor RCE |
| `exploits/routers/tplink/wdr740nd_wdr740n_path_traversal.py` | TP-Link WDR740ND & WDR740N Path Traversal |
| `exploits/routers/tplink/wdr842nd_wdr842n_configure_disclosure.py` | TP-Link WDR842ND configure Disclosure |
| `exploits/routers/tplink/wireless_router_archer_c1200_cross_site_scripting_cve_2018_13134.py` | TP-Link wireless router Archer C1200 - Cross-Site Scripting |
| `exploits/routers/tplink/wr1043nd_auth_bypass.py` | TP-Link TL-WR1043ND V2 Authentication Bypass |
| `exploits/routers/tplink/wr840n_0_9_1_3_16_denial_of_service_poc_cve_2018_15172.py` | TP-Link WR840N 0.9.1 3.16 - Denial of Service (PoC) |
| `exploits/routers/tplink/wr841nd_password_disclosure_cve_2020_35575.py` | TP-Link TL-WR841ND Password Disclosure |
| `exploits/routers/tplink/wr849n_config_bypass_cve_2019_19143.py` | TP-Link TL-WR849N Config Upload Bypass |
| `exploits/routers/tplink/wr849n_rce_cve_2020_9374.py` | TP-Link TL-WR849N Remote Code Execution |
| `exploits/routers/tplink/wr940n_authenticated_remote_code_cve_2017_13772.py` | TP-Link WR940N - (Authenticated) Remote Code |
| `exploits/routers/tplink/wvr_war_diagnostic_rce_cve_2017_16957.py` | TP-Link WVR/WAR Enterprise Router Diagnostic RCE |
| `exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13276.py` | TRENDnet TEW-827DRU Command Injection via apply_cgi usb |
| `exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13277.py` | TRENDnet TEW-827DRU Denial of Service via wizard |
| `exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13278.py` | TRENDnet TEW-827DRU Command Injection via apply_cgi ping |
| `exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13150.py` | TRENDnet TEW-827DRU Stack Overflow via apply.cgi smbServerName |
| `exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13279.py` | TRENDnet TEW-827DRU Stack Overflow via apply.cgi DeviceName |
| `exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13280.py` | TRENDnet TEW-827DRU Stack Overflow via apply.cgi NetBIOSName |
| `exploits/routers/ubiquiti/airos_6_x.py` | AirOS 6.x - Arbitrary File Upload |
| `exploits/routers/ubiquiti/unifi_video_3_7_3_local_privilege_escalation_cve_2016_6914.py` | Ubiquiti UniFi Video 3.7.3 - Local Privilege Escalation |
| `exploits/routers/wavlink/wn530hg4_password_disclosure_cve_2022_34047.py` | Wavlink WN530HG4 - Password Disclosure |
| `exploits/routers/wavlink/wn533a8_cross_site_scripting_xss_cve_2022_34048.py` | Wavlink WN533A8 - Cross-Site Scripting (XSS) |
| `exploits/routers/wavlink/wn533a8_password_disclosure_cve_2022_34046.py` | Wavlink WN533A8 - Password Disclosure |
| `exploits/routers/xiaomi/browser_10_2_4_g_browser_search_history_disclosure_cve_2018_20523.py` | Xiaomi browser 10.2.4.g - Browser Search History Disclosure |
| `exploits/routers/xiaomi/stock_firmware_rce.py` | Xiaomi Router Stock Firmware RCE |
| `exploits/routers/zhone/dasan_znid_2426a_eu_multiple_cross_site_scripting_cve_2019_10677.py` | DASAN Zhone ZNID GPON 2426A EU - Multiple Cross-Site Scripting |
| `exploits/routers/zte/f460_f660_backdoor.py` | ZTE F460 & F660 Backdoor RCE |
| `exploits/routers/zte/f460_f660_rce_cve_2014_2321.py` | ZTE F460/F660 Remote Code Execution |
| `exploits/routers/zte/mf65_bd_hdv6mf65v1_0_0b05_cross_site_scripting_cve_2018_7355.py` | ZTE MF65 BD_HDV6MF65V1.0.0B05 - Cross-Site Scripting |
| `exploits/routers/zte/router_f602w_captcha_bypass_cve_2020_6862.py` | ZTE Router F602W - Captcha Bypass |
| `exploits/routers/zte/zxdsl_831cii_improper_access_restrictions_cve_2017_16953.py` | ZTE ZXDSL 831CII - Improper Access Restrictions |
| `exploits/routers/zte/zxhn_h108n_wifi_password_disclosure.py` | ZTE ZXHN H108N Wifi Password Disclosure |
| `exploits/routers/zte/zxhn_h168n_improper_access_restrictions_cve_2018_7357.py` | ZTE ZXHN H168N - Improper Access Restrictions |
| `exploits/routers/zte/zxv10_h108l_cmd_injection.py` | ZTE ZXV10 H108L Command Injection |
| `exploits/routers/zte/zxv10_rce.py` | ZTE ZXV10 RCE |
| `exploits/routers/zte/zxv10_w812n.py` | ZTE ZXV10 W812N Information Disclosure |
| `exploits/routers/zyxel/armor_x1_wap6806_directory_traversal_cve_2020_14461.py` | Zyxel Armor X1 WAP6806 - Directory Traversal |
| `exploits/routers/zyxel/d1000_rce.py` | Zyxel Eir D1000 RCE |
| `exploits/routers/zyxel/d1000_wifi_password_disclosure.py` | Zyxel Eir D1000 WiFi Password Disclosure |
| `exploits/routers/zyxel/nbg_418n_v2_modem_1_00_aaxm_6_c0_cross_site_request_forgery_cve_2019_6710.py` | Zyxel NBG-418N v2 Modem 1.00(AAXM.6)C0 - Cross-Site Request Forgery |
| `exploits/routers/zyxel/nwa_1100_nh_command_injection_cve_2021_4039.py` | Zyxel NWA-1100-NH - Command Injection |
| `exploits/routers/zyxel/p660hn_t_v1_rce.py` | Zyxel P660HN-T v1 RCE |
| `exploits/routers/zyxel/p660hn_t_v2_rce.py` | Zyxel P660HN-T v2 RCE |
| `exploits/routers/zyxel/pk5001z_modem_backdoor_account_cve_2016_10401.py` | ZyXEL PK5001Z Modem - Backdoor Account |
| `exploits/routers/zyxel/usg_flex_5_21_os_command_injection_cve_2022_30525.py` | Zyxel USG FLEX 5.21 - OS Command Injection |
| `exploits/routers/zyxel/usg_flex_h_series_uos_1_31_privilege_escalation_cve_2025_1731.py` | Zyxel USG FLEX H series uOS 1.31 - Privilege Escalation |
| `exploits/routers/zyxel/vmg3312_b10b_dsl_491hnu_b1b_v2_modem_cross_site_request_forg_cve_2019_7391.py` | Zyxel VMG3312-B10B DSL-491HNU-B1B v2 Modem - Cross-Site Request Forgery |
| `exploits/routers/zyxel/vmg8825_cmd_injection.py` | Zyxel VMG8825-T50 Command Injection |
| `exploits/routers/zyxel/zywall_2_plus_internet_security_appliance_cross_site_scripti_cve_2021_46387.py` | Zyxel ZyWALL 2 Plus Internet Security Appliance - Cross-Site Scripting (XSS) |
| `exploits/routers/zyxel/zywall_310_zywall_110_usg1900_atp500_usg40_login_page_cross_cve_2019_9955.py` | Zyxel ZyWall 310 / ZyWall 110 / USG1900 / ATP500 / USG40 - Login Page Cross-Site |
| `exploits/soho_edge/cerio/multi_rce_cve_2018_18852.py` | CERIO DT300N/DT100G/AMR-3204 Authenticated RCE |
| `exploits/soho_edge/dlink/dsp_w110_rce.py` | D-Link DSP-W110 RCE |
| `exploits/soho_edge/dlink/dwl_3200ap_password_disclosure.py` | D-Link DWL-3200AP Password Disclosure |
| `exploits/soho_edge/hootoo/tripmate_arbitrary_file_upload.py` | HooToo TripMate unauthenticated protocol.csp arbitrary file upload |
| `exploits/soho_edge/hootoo/tripmate_open_forwarding_rce.py` | HooToo TripMate protocol.csp open_forwarding RCE |
| `exploits/soho_edge/hootoo/tripmate_sysfirm_rce.py` | HooToo TripMate sysfirm.csp RCE |
| `exploits/soho_edge/ipfire/2_25_remote_code_execution_authenticated_cve_2021_33393.py` | IPFire 2.25 - Remote Code Execution (Authenticated) |
| `exploits/soho_edge/ipfire/shellshock_bash_environment_variable_command_injection_metas_cve_2014_6271.py` | IPFire - 'Shellshock' Bash Environment Variable Command Injection (Metasploit) |
| `exploits/soho_edge/lg/nas_3718.py` | LG_NAS_3718.510.a0_RCE |
| `exploits/switches/cisco/catalyst_2960_rocem.py` | Cisco Catalyst 2960 ROCEM RCE |
| `exploits/switches/dlink/dgs_1510_add_user.py` | D-Link DGS-1510 Add User |
| `exploits/switches/netgear/prosafe_rce.py` | Netgear ProSafe RCE |

## creds (88 modules)

| Module Path | Name |
|---|---|
| `creds/generic/ftp_bruteforce.py` | FTP Bruteforce |
| `creds/generic/ftp_default.py` | FTP Default Creds |
| `creds/generic/http_basic_digest_bruteforce.py` | HTTP Basic/Digest Bruteforce |
| `creds/generic/http_basic_digest_default.py` | HTTP Basic/Digest Default Creds |
| `creds/generic/http_multi_auth_default.py` | HTTP/HTTPS Multi-Auth Default Creds |
| `creds/generic/http_web_form_bruteforce.py` | HTTP Web Form Bruteforce (Hydra-style) |
| `creds/generic/sftp_bruteforce.py` | SFTP Bruteforce |
| `creds/generic/sftp_default.py` | SFTP Default Creds |
| `creds/generic/snmp_bruteforce.py` | SNMP Bruteforce |
| `creds/generic/snmpv3_default.py` | SNMPv3 Default Creds |
| `creds/generic/ssh_bruteforce.py` | SSH Bruteforce |
| `creds/generic/ssh_default.py` | SSH Default Creds |
| `creds/generic/telnet_bruteforce.py` | Telnet Bruteforce |
| `creds/generic/telnet_default.py` | Telnet Default Creds |
| `creds/routers/2wire/ftp_default_creds.py` | 2Wire Router Default FTP Creds |
| `creds/routers/2wire/ssh_default_creds.py` | 2Wire Router Default SSH Creds |
| `creds/routers/2wire/telnet_default_creds.py` | 2Wire Router Default Telnet Creds |
| `creds/routers/3com/ftp_default_creds.py` | 3Com Router Default FTP Creds |
| `creds/routers/3com/ssh_default_creds.py` | 3Com Router Default SSH Creds |
| `creds/routers/3com/telnet_default_creds.py` | 3Com Router Default Telnet Creds |
| `creds/routers/asmax/ftp_default_creds.py` | Asmax Router Default FTP Creds |
| `creds/routers/asmax/ssh_default_creds.py` | Asmax Router Default SSH Creds |
| `creds/routers/asmax/telnet_default_creds.py` | Asmax Router Default Telnet Creds |
| `creds/routers/asmax/webinterface_http_auth_default_creds.py` | Asmax Router Default Web Interface Creds - HTTP Auth |
| `creds/routers/asus/ftp_default_creds.py` | Asus Router Default FTP Creds |
| `creds/routers/asus/ssh_default_creds.py` | Asus Router Default SSH Creds |
| `creds/routers/asus/telnet_default_creds.py` | Asus Router Default Telnet Creds |
| `creds/routers/belkin/ftp_default_creds.py` | Belkin Router Default FTP Creds |
| `creds/routers/belkin/ssh_default_creds.py` | Belkin Router Default SSH Creds |
| `creds/routers/belkin/telnet_default_creds.py` | Belkin Router Default Telnet Creds |
| `creds/routers/bhu/ftp_default_creds.py` | Belkin Router Default FTP Creds |
| `creds/routers/bhu/ssh_default_creds.py` | Belkin Router Default SSH Creds |
| `creds/routers/bhu/telnet_default_creds.py` | Belkin Router Telnet Creds |
| `creds/routers/billion/ftp_default_creds.py` | Billion Router Default FTP Creds |
| `creds/routers/billion/ssh_default_creds.py` | Billion Router Default SSH Creds |
| `creds/routers/billion/telnet_default_creds.py` | Billion Router Default Telnet Creds |
| `creds/routers/cisco/ftp_default_creds.py` | Cisco Router Default FTP Creds |
| `creds/routers/cisco/ssh_default_creds.py` | Cisco Router Default SSH Creds |
| `creds/routers/cisco/telnet_default_creds.py` | Cisco Router Default Telnet Creds |
| `creds/routers/comtrend/ftp_default_creds.py` | Comtrend Router Default FTP Creds |
| `creds/routers/comtrend/ssh_default_creds.py` | Comtrend Router Default SSH Creds |
| `creds/routers/comtrend/telnet_default_creds.py` | Comtrend Router Default Telnet Creds |
| `creds/routers/dlink/ftp_default_creds.py` | D-Link Router Default FTP Creds |
| `creds/routers/dlink/ssh_default_creds.py` | D-Link Router Default SSH Creds |
| `creds/routers/dlink/telnet_default_creds.py` | D-Link Router Default Telnet Creds |
| `creds/routers/huawei/ftp_default_creds.py` | Huawei Router Default FTP Creds |
| `creds/routers/huawei/ssh_default_creds.py` | Huawei Router Default SSH Creds |
| `creds/routers/huawei/telnet_default_creds.py` | Huawei Router Default Telnet Creds |
| `creds/routers/juniper/ftp_default_creds.py` | Juniper Router Default FTP Creds |
| `creds/routers/juniper/ssh_default_creds.py` | Juniper Router Default SSH Creds |
| `creds/routers/juniper/telnet_default_creds.py` | Juniper Router Default Telnet Creds |
| `creds/routers/linksys/ftp_default_creds.py` | Linksys Router Default FTP Creds |
| `creds/routers/linksys/ssh_default_creds.py` | Linksys Router Default SSH Creds |
| `creds/routers/linksys/telnet_default_creds.py` | Linksys Router Default Telnet Creds |
| `creds/routers/mikrotik/api_ros_default_creds.py` | Mikrotik Default Creds - API ROS |
| `creds/routers/mikrotik/ftp_default_creds.py` | Mikrotik Router Default FTP Creds |
| `creds/routers/mikrotik/ssh_default_creds.py` | Mikrotik Router Default SSH Creds |
| `creds/routers/mikrotik/telnet_default_creds.py` | Mikrotik Router Default Telnet Creds |
| `creds/routers/movistar/ftp_default_creds.py` | Movistar Router Default FTP Creds |
| `creds/routers/movistar/ssh_default_creds.py` | Movistar Router Default SSH Creds |
| `creds/routers/movistar/telnet_default_creds.py` | Movistar Router Default Telnet Creds |
| `creds/routers/netcore/ftp_default_creds.py` | Netcore Router Default FTP Creds |
| `creds/routers/netcore/ssh_default_creds.py` | Netcore Router Default SSH Creds |
| `creds/routers/netcore/telnet_default_creds.py` | Netcore Router Default Telnet Creds |
| `creds/routers/netgear/ftp_default_creds.py` | Netgear Router Default FTP Creds |
| `creds/routers/netgear/ssh_default_creds.py` | Netgear Router Default SSH Creds |
| `creds/routers/netgear/telnet_default_creds.py` | Netgear Router Default Telnet Creds |
| `creds/routers/netsys/ftp_default_creds.py` | Netsys Router Default FTP Creds |
| `creds/routers/netsys/ssh_default_creds.py` | Netsys Router Default SSH Creds |
| `creds/routers/netsys/telnet_default_creds.py` | Netsys Router Default Telnet Creds |
| `creds/routers/technicolor/ftp_default_creds.py` | Technicolor Router Default FTP Creds |
| `creds/routers/technicolor/ssh_default_creds.py` | Technicolor Router Default SSH Creds |
| `creds/routers/technicolor/telnet_default_creds.py` | Technicolor Router Default Telnet Creds |
| `creds/routers/thomson/ftp_default_creds.py` | Thomson Router Default FTP Creds |
| `creds/routers/thomson/ssh_default_creds.py` | Thomson Router Default SSH Creds |
| `creds/routers/thomson/telnet_default_creds.py` | Thomson Router Default Telnet Creds |
| `creds/routers/tplink/ftp_default_creds.py` | TP-Link Router Default FTP Creds |
| `creds/routers/tplink/ssh_default_creds.py` | TP-Link Router Default SSH Creds |
| `creds/routers/tplink/telnet_default_creds.py` | TP-Link Router Default Telnet Creds |
| `creds/routers/ubiquiti/ftp_default_creds.py` | Ubiquiti Router Default FTP Creds |
| `creds/routers/ubiquiti/ssh_default_creds.py` | Ubiquiti Router Default SSH Creds |
| `creds/routers/ubiquiti/telnet_default_creds.py` | Ubiquiti Router Default Telnet Creds |
| `creds/routers/zte/ftp_default_creds.py` | ZTE Router Default FTP Creds |
| `creds/routers/zte/ssh_default_creds.py` | ZTE Router Default SSH Creds |
| `creds/routers/zte/telnet_default_creds.py` | ZTE Router Default Telnet Creds |
| `creds/routers/zyxel/ftp_default_creds.py` | Zyxel Router Default FTP Creds |
| `creds/routers/zyxel/ssh_default_creds.py` | Zyxel Router Default SSH Creds |
| `creds/routers/zyxel/telnet_default_creds.py` | Zyxel Router Default Telnet Creds |

## scanners (5 modules)

| Module Path | Name |
|---|---|
| `scanners/autopwn.py` | AutoPwn |
| `scanners/misc/misc_scan.py` | Misc Scanner |
| `scanners/misc/soho_exploit_catalog_server.py` | SOHO Exploit Catalog (local HTTP) |
| `scanners/routers/router_scan.py` | Router Scanner |
| `scanners/soho_edge/hootoo_scan.py` | HooToo Scanner |

## payloads (32 modules)

| Module Path | Name |
|---|---|
| `payloads/armle/bind_tcp.py` | ARMLE Bind TCP |
| `payloads/armle/reverse_tcp.py` | ARMLE Reverse TCP |
| `payloads/cmd/awk_bind_tcp.py` | Awk Bind TCP |
| `payloads/cmd/awk_bind_udp.py` | Awk Bind UDP |
| `payloads/cmd/awk_reverse_tcp.py` | Awk Reverse TCP |
| `payloads/cmd/bash_reverse_tcp.py` | Bash Reverse TCP |
| `payloads/cmd/netcat_bind_tcp.py` | Netcat Bind TCP |
| `payloads/cmd/netcat_reverse_tcp.py` | Netcat Reverse TCP |
| `payloads/cmd/perl_bind_tcp.py` | Perl Bind TCP One-Liner |
| `payloads/cmd/perl_reverse_tcp.py` | Perl Reverse TCP One-Liner |
| `payloads/cmd/php_bind_tcp.py` | PHP Bind TCP One-Liner |
| `payloads/cmd/php_reverse_tcp.py` | PHP Reverse TCP One-Liner |
| `payloads/cmd/python_bind_tcp.py` | Python Reverse TCP One-Liner |
| `payloads/cmd/python_bind_udp.py` | Python Bind UDP One-Liner |
| `payloads/cmd/python_reverse_tcp.py` | Python Reverse TCP One-Liner |
| `payloads/cmd/python_reverse_udp.py` | Python Reverse UDP One-Liner |
| `payloads/mipsbe/bind_tcp.py` | MIPSBE Bind TCP |
| `payloads/mipsbe/reverse_tcp.py` | MIPSBE Reverse TCP |
| `payloads/mipsle/bind_tcp.py` | MIPSLE Bind TCP |
| `payloads/mipsle/reverse_tcp.py` | MIPSLE Reverse TCP |
| `payloads/perl/bind_tcp.py` | Perl Bind TCP |
| `payloads/perl/reverse_tcp.py` | Perl Reverse TCP |
| `payloads/php/bind_tcp.py` | PHP Bind TCP |
| `payloads/php/reverse_tcp.py` | PHP Reverse TCP |
| `payloads/python/bind_tcp.py` | Python Bind TCP |
| `payloads/python/bind_udp.py` | Python Bind UDP |
| `payloads/python/reverse_tcp.py` | Python Reverse TCP |
| `payloads/python/reverse_udp.py` | Python Reverse UDP |
| `payloads/x64/bind_tcp.py` | X64 Bind TCP |
| `payloads/x64/reverse_tcp.py` | X64 Reverse TCP |
| `payloads/x86/bind_tcp.py` | X86 Bind TCP |
| `payloads/x86/reverse_tcp.py` | X86 Reverse TCP |

## encoders (13 modules)

| Module Path | Name |
|---|---|
| `encoders/perl/base64.py` | Perl Base64 Encoder |
| `encoders/perl/hex.py` | Perl Hex Encoder |
| `encoders/perl/rot13.py` | Perl ROT13 Encoder |
| `encoders/perl/url.py` | Perl URL Encoder |
| `encoders/php/base64.py` | PHP Base64 Encoder |
| `encoders/php/hex.py` | PHP Hex Encoder |
| `encoders/php/rot13.py` | PHP ROT13 Encoder |
| `encoders/php/url.py` | PHP URL Encoder |
| `encoders/python/base32.py` | Python Base32 Encoder |
| `encoders/python/base64.py` | Python Base64 Encoder |
| `encoders/python/hex.py` | Python Hex Encoder |
| `encoders/python/rot13.py` | Python ROT13 Encoder |
| `encoders/python/url.py` | Python URL Encoder |

## generic (8 modules)

| Module Path | Name |
|---|---|
| `generic/cve/cve_lookup.py` | CVE Lookup by Banner / Vendor / Product |
| `generic/external/exploitdb_embedded_lookup.py` | ExploitDB embedded lookup (CSV) |
| `generic/external/metasploit_console_bridge.py` | Metasploit Console Bridge |
| `generic/external/metasploit_rb_inspect.py` | Metasploit Ruby Module Metadata (read-only) |
| `generic/external/mikrotikapi_bf_bridge.py` | MikrotikAPI-BF Bridge |
| `generic/snmp/snmp_trap_listener.py` | SNMP Trap Listener |
| `generic/upnp/ssdp_msearch.py` | SSDP M-SEARCH Info Discovery |
| `generic/wordlist/wordlist_generator.py` | Interactive Wordlist Generator |
