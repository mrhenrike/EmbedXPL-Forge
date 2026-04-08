# RouterXPL-Forge Coverage Matrix

## Product Scope

- In scope: routers, switches, taps, fw and ngfw (residential, ISP, enterprise/corporate, industrial; IT/OT/AT/IoT/IIoT).
- Out of scope: camera/printer/dvr modules (disabled in this product line).

## Platform Compatibility Status

| Platform | Status |
|---|---|
| Windows | Compatible (validated locally) |
| WSL / Debian-based Linux | Compatible (validated locally) |
| RHEL-based Linux | Compatible by design, not tested effectively yet |
| macOS | Compatible by design, not tested effectively yet |
| Termux / Android / NetHunter | Compatible by design, not tested effectively yet |


## Global Capability Summary

- Module tree (routerxpl/modules): d188ea08bf66af26f351e2fead2c9d9345f20e08
- Total modules indexed: 666
- Distinct vendor/product entries: 665
- Distinct CVEs mapped in modules: 394
- Attack classes identified: auth_bypass, backdoor, creds_disclosure, dns_change, dos_or_crash, info_disclosure, password_reset_or_change, path_traversal, rce

### Module Type Counts
- creds: 88
- encoders: 13
- exploits: 516
- generic: 12
- payloads: 32
- scanners: 5

## Protocol Coverage (Inferred)

| Protocol | Covered |
|---|---|
| ftp | yes |
| ftps | no |
| sftp | yes |
| ssh | yes |
| telnet | yes |
| snmp | yes |
| snmp_trap | yes |
| api | yes |
| http | yes |
| https | yes |

## OSI/TCP-IP Coverage Matrix

### Priority Definitions

- P1: Critical first wave: management plane and service base protocols with immediate operational risk.
- P2: Second wave: control and environment-specific protocols with medium operational impact.
- P3: Third wave: legacy or lower-frequency protocols tracked until full closure.

### Environment Focus

| Environment | Priority Order | Focus |
|---|---|---|
| ISP | P1,P2,P3 | CPE and provider edge management plane, service availability, routing control and subscriber provisioning. |
| Corporate | P1,P2,P3 | Enterprise access/distribution/core, segmentation, identity-aware admin access and telemetry. |
| OT_IIoT | P1,P2,P3 | Availability first, deterministic network behavior, IT/OT boundary control and secure remote management. |

### Layer Attack/Test Matrix

| OSI | Layer | Attack Vectors | Test Types |
|---|---|---|---|
| L1 | Physical | link_disruption_or_flap_induction, tap_or_span_blind_spot_abuse, physical_plane_availability_degradation | link_state_validation, duplex_speed_mismatch_detection, capture_integrity_verification |
| L2 | Data Link | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction |
| L3 | Network | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation |
| L4 | Transport | service_enumeration_and_port_abuse, session_exhaustion_or_flood_paths, transport_timeout_and_retry_abuse | tcp_udp_surface_mapping, session_stability_validation, timeout_retry_behavior_checks |
| L5-L7 | Session/Presentation/Application | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation |

### Layer and Protocol Coverage (Inferred)

| OSI | TCP/IP | Layer | Protocol | Module Hits | Covered | Attack Vectors | Test Types | ISP | Corporate | OT_IIoT |
|---|---|---|---|---:|---|---|---|---|---|---|
| L1 | Link | Physical | ethernet | 4 | yes | link_disruption_or_flap_induction, tap_or_span_blind_spot_abuse, physical_plane_availability_degradation | link_state_validation, duplex_speed_mismatch_detection, capture_integrity_verification | P2 | P2 | P2 |
| L2 | Link | Data Link | arp | 2 | yes | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P1 | P1 |
| L2 | Link | Data Link | vlan_8021q_qinq | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P1 | P1 |
| L2 | Link | Data Link | 802.11_wifi | 37 | yes | offline_wpa_crack, handshake_capture_replay, credential_harvest | ap_enumeration, station_mapping, handshake_extraction, cleartext_sniffing | P2 | P1 | P2 |
| L2 | Link | Data Link | stp_rstp_mstp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P1 | P2 |
| L2 | Link | Data Link | lacp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P1 | P2 |
| L2 | Link | Data Link | lldp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P2 | P2 |
| L2 | Link | Data Link | pppoe | 3 | yes | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P3 | P3 |
| L3 | Internet | Network | ipv4_ipv6 | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P1 | P1 | P1 |
| L3 | Internet | Network | icmp_icmpv6 | 1 | yes | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P1 | P1 | P2 |
| L3 | Internet | Network | ospf | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P2 | P2 | P3 |
| L3 | Internet | Network | bgp | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P2 | P3 | P3 |
| L4 | Transport | Transport | tcp | 32 | yes | service_enumeration_and_port_abuse, session_exhaustion_or_flood_paths, transport_timeout_and_retry_abuse | tcp_udp_surface_mapping, session_stability_validation, timeout_retry_behavior_checks | P1 | P1 | P1 |
| L4 | Transport | Transport | udp | 10 | yes | service_enumeration_and_port_abuse, session_exhaustion_or_flood_paths, transport_timeout_and_retry_abuse | tcp_udp_surface_mapping, session_stability_validation, timeout_retry_behavior_checks | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | dns | 16 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P2 |
| L5-L7 | Application | Session/Presentation/Application | dhcp | 2 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P2 |
| L5-L7 | Application | Session/Presentation/Application | ntp_ptp | 2 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P2 | P1 |
| L5-L7 | Application | Session/Presentation/Application | snmp_snmpv3 | 7 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | ssh | 31 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | telnet | 33 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | ftp_ftps_sftp | 30 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P2 | P2 |
| L5-L7 | Application | Session/Presentation/Application | http_https_api | 23 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | radius_tacacs | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P2 | P3 |
| L5-L7 | Application | Session/Presentation/Application | tr069_cwmp | 1 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P3 | P3 |
| L5-L7 | Application | Session/Presentation/Application | syslog | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P1 | P2 |
| L5-L7 | Application | Session/Presentation/Application | modbus_tcp | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | dnp3 | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | opc_ua | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | mqtt | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | bacnet_ip | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | profinet_ethernet | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P3 | P2 |

### Layer Hit Totals

| Layer | Total Protocol Hits |
|---|---:|
| L1 Physical | 4 |
| L2 Data Link | 42 |
| L3 Network | 1 |
| L4 Transport | 42 |
| L5-L7 Session/Presentation/Application | 145 |

## Market Priority Coverage (2010-2026)

### Yearly Minimum Validation

- Brazil domestic minimum/year: 10
- Brazil corporate minimum/year: 10
- Global minimum/year: 5

#### Brazil Domestic Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 11 | 11 | ok | 9 | 6 |
| 2011 | 11 | 11 | ok | 9 | 5 |
| 2012 | 11 | 11 | ok | 9 | 11 |
| 2013 | 11 | 11 | ok | 8 | 6 |
| 2014 | 11 | 11 | ok | 8 | 8 |
| 2015 | 11 | 11 | ok | 9 | 12 |
| 2016 | 12 | 12 | ok | 10 | 3 |
| 2017 | 13 | 13 | ok | 10 | 3 |
| 2018 | 13 | 13 | ok | 10 | 3 |
| 2019 | 13 | 13 | ok | 10 | 3 |
| 2020 | 13 | 13 | ok | 13 | 8 |
| 2021 | 14 | 14 | ok | 11 | 3 |
| 2022 | 14 | 14 | ok | 12 | 0 |
| 2023 | 15 | 15 | ok | 12 | 0 |
| 2024 | 14 | 14 | ok | 12 | 0 |
| 2025 | 16 | 16 | ok | 13 | 0 |
| 2026 | 15 | 15 | ok | 12 | 0 |

#### Brazil Corporate Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 13 | 13 | ok | 11 | 4 |
| 2011 | 13 | 13 | ok | 11 | 4 |
| 2012 | 15 | 15 | ok | 13 | 5 |
| 2013 | 15 | 15 | ok | 13 | 2 |
| 2014 | 15 | 15 | ok | 13 | 2 |
| 2015 | 15 | 15 | ok | 13 | 2 |
| 2016 | 15 | 15 | ok | 13 | 2 |
| 2017 | 15 | 15 | ok | 13 | 2 |
| 2018 | 17 | 17 | ok | 15 | 2 |
| 2019 | 20 | 20 | ok | 15 | 2 |
| 2020 | 20 | 20 | ok | 15 | 2 |
| 2021 | 22 | 22 | ok | 14 | 2 |
| 2022 | 23 | 23 | ok | 15 | 2 |
| 2023 | 22 | 22 | ok | 17 | 2 |
| 2024 | 24 | 24 | ok | 17 | 2 |
| 2025 | 24 | 24 | ok | 17 | 2 |
| 2026 | 24 | 24 | ok | 17 | 2 |

#### Global Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 5 | 6 | ok | 5 | 7 |
| 2011 | 5 | 6 | ok | 5 | 5 |
| 2012 | 5 | 7 | ok | 7 | 7 |
| 2013 | 5 | 8 | ok | 6 | 3 |
| 2014 | 5 | 8 | ok | 5 | 2 |
| 2015 | 5 | 7 | ok | 5 | 1 |
| 2016 | 5 | 9 | ok | 6 | 3 |
| 2017 | 5 | 9 | ok | 6 | 2 |
| 2018 | 5 | 12 | ok | 7 | 2 |
| 2019 | 5 | 12 | ok | 6 | 2 |
| 2020 | 5 | 11 | ok | 7 | 0 |
| 2021 | 5 | 12 | ok | 6 | 0 |
| 2022 | 5 | 12 | ok | 7 | 0 |
| 2023 | 5 | 13 | ok | 7 | 0 |
| 2024 | 5 | 13 | ok | 7 | 0 |
| 2025 | 5 | 13 | ok | 7 | 0 |
| 2026 | 5 | 13 | ok | 5 | 0 |

### Brazil Domestic Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | Netgear | WNDR3700 | router-home | yes | 1 |
| 2010 | Linksys | WRT610N | router-home | yes | 0 |
| 2010 | D-Link | DIR-655 | router-home | yes | 1 |
| 2010 | TP-Link | TL-WR1043ND | router-home | yes | 2 |
| 2010 | ASUS | RT-N13U | router-home | yes | 0 |
| 2010 | Netgear | WNDR3800 | router-home | yes | 1 |
| 2010 | Linksys | E3000 | router-home | yes | 0 |
| 2010 | Trendnet | TEW-691GR | router-home | yes | 0 |
| 2010 | Apple | AirPort Extreme 4th Gen | router-home | no | 0 |
| 2010 | Belkin | N750 DB | router-home | yes | 1 |
| 2010 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2011 | Linksys | E4200 | router-home | yes | 1 |
| 2011 | ASUS | RT-N56U | router-home | yes | 1 |
| 2011 | Netgear | WNDR4000 | router-home | yes | 0 |
| 2011 | Trendnet | TEW-692GR | router-home | yes | 0 |
| 2011 | Belkin | N750 DB | router-home | yes | 1 |
| 2011 | ASUS | RT-N66U | router-home | yes | 0 |
| 2011 | D-Link | DIR-819 | router-home | yes | 1 |
| 2011 | Linksys | E3200 | router-home | yes | 0 |
| 2011 | Netgear | WNDR3700 | router-home | yes | 1 |
| 2011 | Apple | AirPort Extreme 5th Gen | router-home | no | 0 |
| 2011 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | TP-Link | Archer C20 | router-home | yes | 2 |
| 2012 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2012 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2012 | D-Link | DIR-819 | router-home | yes | 1 |
| 2012 | D-Link | DIR-822 | router-home | yes | 0 |
| 2012 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2012 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2012 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2012 | TP-Link | TL-WR940N | router-home | yes | 3 |
| 2012 | TP-Link | TL-WR840N | router-home | yes | 3 |
| 2012 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2013 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2013 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2013 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2013 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2013 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2013 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2013 | TP-Link | TL-WR940N | router-home | yes | 3 |
| 2013 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2013 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2013 | Mercusys | MR60X | router-home | no | 0 |
| 2013 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2014 | TP-Link | Archer C20 | router-home | yes | 2 |
| 2014 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2014 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2014 | TP-Link | TL-WR940N | router-home | yes | 3 |
| 2014 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2014 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2014 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2014 | D-Link | DIR-819 | router-home | yes | 1 |
| 2014 | D-Link | DIR-822 | router-home | yes | 0 |
| 2014 | Mercusys | MR60X | router-home | no | 0 |
| 2014 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2015 | TP-Link | Archer C20 | router-home | yes | 2 |
| 2015 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2015 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2015 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2015 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2015 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2015 | D-Link | DIR-819 | router-home | yes | 1 |
| 2015 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2015 | TP-Link | TL-WR840N | router-home | yes | 3 |
| 2015 | TP-Link | TL-WR940N | router-home | yes | 3 |
| 2015 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2016 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2016 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2016 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2016 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2016 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2016 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2016 | D-Link | DIR-822 | router-home | yes | 0 |
| 2016 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2016 | Mercusys | MR60X | router-home | no | 0 |
| 2016 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2016 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2016 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2017 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2017 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2017 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2017 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2017 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2017 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2017 | Mercusys | MR60X | router-home | no | 0 |
| 2017 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2017 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2017 | Tenda | AC23 | router-home | yes | 0 |
| 2017 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2017 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2017 | Mercusys | MS105G | switch-soho | no | 0 |
| 2018 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2018 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2018 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2018 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2018 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2018 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2018 | Mercusys | MR60X | router-home | no | 0 |
| 2018 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2018 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2018 | Tenda | AC23 | router-home | yes | 0 |
| 2018 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2018 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2018 | Mercusys | MS105G | switch-soho | no | 0 |
| 2019 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2019 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2019 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2019 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2019 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2019 | D-Link | DIR-822 | router-home | yes | 0 |
| 2019 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2019 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2019 | Mercusys | MR60X | router-home | no | 0 |
| 2019 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2019 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2019 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2019 | Mercusys | MS105G | switch-soho | no | 0 |
| 2020 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2020 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2020 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2020 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2020 | D-Link | DIR-819 | router-home | yes | 1 |
| 2020 | TP-Link | Archer C20 | router-home | yes | 2 |
| 2020 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2020 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2020 | D-Link | DIR-822 | router-home | yes | 0 |
| 2020 | TP-Link | TL-WR840N | router-home | yes | 3 |
| 2020 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2020 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2020 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2021 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2021 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2021 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2021 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2021 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2021 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2021 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2021 | TP-Link | TL-WR940N | router-home | yes | 3 |
| 2021 | Mercusys | MR60X | router-home | no | 0 |
| 2021 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2021 | OpenWrt | OpenWrt 21.02 Generic Targets | router-firmware | no | 0 |
| 2021 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2021 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2021 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2022 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2022 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2022 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2022 | Mercusys | MR60X | router-home | no | 0 |
| 2022 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2022 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2022 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2022 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2022 | Huawei | AX2S | router-home | yes | 0 |
| 2022 | Mercusys | MR80X | router-home | no | 0 |
| 2022 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2022 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2022 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2022 | Netgear | GS305 | switch-soho | yes | 0 |
| 2023 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2023 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2023 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2023 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2023 | Mercusys | MR60X | router-home | no | 0 |
| 2023 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2023 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2023 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2023 | Intelbras | AX 1500 | router-home | yes | 0 |
| 2023 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2023 | OpenWrt | OpenWrt 22.03 Generic Targets | router-firmware | no | 0 |
| 2023 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2023 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2023 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2023 | Netgear | GS305 | switch-soho | yes | 0 |
| 2024 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2024 | Huawei | AX2S | router-home | yes | 0 |
| 2024 | ASUS | AX5400 | router-home | yes | 0 |
| 2024 | Mercusys | MR60X | router-home | no | 0 |
| 2024 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2024 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2024 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2024 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2024 | TP-Link | Archer C80 | router-home | yes | 0 |
| 2024 | TP-Link | Deco BE85 | router-mesh | yes | 0 |
| 2024 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2024 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2024 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2024 | Netgear | GS305 | switch-soho | yes | 0 |
| 2025 | Mercusys | MR60X | router-home | no | 0 |
| 2025 | TP-Link | Archer AXE75 | router-home | yes | 0 |
| 2025 | ASUS | ROG Rapture GT-BE98 Pro | router-home | yes | 0 |
| 2025 | TP-Link | Deco BE85 | router-mesh | yes | 0 |
| 2025 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2025 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2025 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2025 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2025 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2025 | TP-Link | Archer BE550 | router-home | yes | 0 |
| 2025 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2025 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2025 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2025 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2025 | Netgear | GS305 | switch-soho | yes | 0 |
| 2025 | TP-Link | TL-SG108E | switch-smart | yes | 0 |
| 2026 | TP-Link | Archer BE900 | router-home | yes | 0 |
| 2026 | TP-Link | Archer BE550 | router-home | yes | 0 |
| 2026 | TP-Link | Archer BE220 | router-home | yes | 0 |
| 2026 | eero | Max 7 | router-mesh | no | 0 |
| 2026 | GL.iNet | Flint 3 (GL-BE9300) | router-home | no | 0 |
| 2026 | Mercusys | MR80X | router-home | no | 0 |
| 2026 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2026 | Huawei | AX2S | router-home | yes | 0 |
| 2026 | Intelbras | Action RG 1200 | router-home | yes | 0 |
| 2026 | TP-Link | Archer C80 | router-home | yes | 0 |
| 2026 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2026 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2026 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2026 | Netgear | GS305 | switch-soho | yes | 0 |
| 2026 | TP-Link | TL-SG108E | switch-smart | yes | 0 |

### Brazil Corporate Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | DrayTek | Vigor2110n | router-corporate | yes | 0 |
| 2010 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2010 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2010 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2010 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2010 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2010 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2010 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2010 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2010 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2010 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2010 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2010 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2011 | DrayTek | Vigor2110n | router-corporate | yes | 0 |
| 2011 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2011 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2011 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2011 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2011 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2011 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2011 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2011 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2011 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2011 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2011 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2011 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2012 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2012 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2012 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2012 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2012 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2012 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2012 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2012 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2012 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2012 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2012 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2012 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2012 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2013 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2013 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2013 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2013 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2013 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2013 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2013 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2013 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2013 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2013 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2013 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2013 | Intelbras | SG 800 Q+ | switch-soho | yes | 0 |
| 2013 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2013 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2013 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2014 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2014 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2014 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2014 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2014 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2014 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2014 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2014 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2014 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2014 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2014 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2014 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2014 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2014 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2014 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2015 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2015 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2015 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2015 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2015 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2015 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2015 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2015 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2015 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2015 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2015 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2015 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2015 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2015 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2015 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2016 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2016 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2016 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2016 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2016 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2016 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2016 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2016 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2016 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2016 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2016 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2016 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2016 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2016 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2016 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2017 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2017 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2017 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2017 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2017 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2017 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2017 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2017 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2017 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2017 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2017 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2017 | Intelbras | SG 1024 MR | switch-corporate | yes | 0 |
| 2017 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2017 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2017 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2018 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2018 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2018 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2018 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2018 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2018 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2018 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2018 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2018 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2018 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2018 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2018 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2018 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2018 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2018 | SonicWall | TZ Series | fw-smb | yes | 0 |
| 2018 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2018 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2019 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2019 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2019 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2019 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2019 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2019 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2019 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2019 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2019 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2019 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2019 | OpenWrt | OpenWrt 19.07 Generic Targets | router-firmware | no | 0 |
| 2019 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2019 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2019 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2019 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2019 | SonicWall | TZ Series | fw-smb | yes | 0 |
| 2019 | Netgate | pfSense | fw-opensource | no | 0 |
| 2019 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2019 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2019 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2020 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2020 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2020 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2020 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2020 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2020 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2020 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2020 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2020 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2020 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2020 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2020 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2020 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2020 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2020 | SonicWall | TZ Series | fw-smb | yes | 0 |
| 2020 | Netgate | pfSense | fw-opensource | no | 0 |
| 2020 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2020 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2020 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2020 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2021 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2021 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2021 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2021 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2021 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2021 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2021 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2021 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2021 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2021 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2021 | OpenWrt | OpenWrt 21.02 Generic Targets | router-firmware | no | 0 |
| 2021 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2021 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2021 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2021 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2021 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2021 | Netgate | pfSense | fw-opensource | no | 0 |
| 2021 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2021 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2021 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2021 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2021 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2022 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2022 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2022 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2022 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2022 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2022 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2022 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2022 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2022 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2022 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2022 | OpenWrt | OpenWrt 22.03 Generic Targets | router-firmware | no | 0 |
| 2022 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2022 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2022 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2022 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2022 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2022 | Netgate | pfSense | fw-opensource | no | 0 |
| 2022 | Cisco | Business CBS250 | switch-corporate | yes | 0 |
| 2022 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2022 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2022 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2022 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2022 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2023 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2023 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2023 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2023 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2023 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2023 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2023 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2023 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2023 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2023 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2023 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2023 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2023 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2023 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2023 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2023 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2023 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2023 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2023 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2023 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2023 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2023 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2024 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2024 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2024 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2024 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2024 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2024 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2024 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2024 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2024 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2024 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2024 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2024 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2024 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2024 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2024 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2024 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2024 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2024 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2024 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2024 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2024 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2024 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2024 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2024 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2025 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2025 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2025 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2025 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2025 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2025 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2025 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2025 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2025 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2025 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2025 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2025 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2025 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2025 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2025 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2025 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2025 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2025 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2025 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2025 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2025 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2025 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2025 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2025 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |
| 2026 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 1 |
| 2026 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2026 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2026 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2026 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2026 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2026 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2026 | Fortinet | FortiGate 60F | ngfw-corporate | yes | 0 |
| 2026 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2026 | Aruba | 2930F | switch-corporate | yes | 0 |
| 2026 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2026 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2026 | Aruba | Instant On 1930 | switch-corporate | yes | 0 |
| 2026 | Intelbras | SG 2404 PoE | switch-poe | yes | 0 |
| 2026 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2026 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2026 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2026 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2026 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2026 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2026 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2026 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2026 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2026 | DrayTek | Vigor2960 Firewall VPN | fw-smb | yes | 1 |

### Global Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | Netgear | WNDR3700 | router-home | yes | 1 |
| 2010 | Linksys | WRT610N | router-home | yes | 0 |
| 2010 | D-Link | DIR-655 | router-home | yes | 1 |
| 2010 | TP-Link | TL-WR1043ND | router-home | yes | 2 |
| 2010 | Apple | AirPort Extreme 4th Gen | router-home | no | 0 |
| 2010 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2011 | Linksys | E4200 | router-home | yes | 1 |
| 2011 | ASUS | RT-N56U | router-home | yes | 1 |
| 2011 | Netgear | WNDR4000 | router-home | yes | 0 |
| 2011 | Trendnet | TEW-692GR | router-home | yes | 0 |
| 2011 | Apple | AirPort Extreme 5th Gen | router-home | no | 0 |
| 2011 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2012 | TP-Link | Archer C20 | router-home | yes | 2 |
| 2012 | Linksys | E3200 | router-home | yes | 0 |
| 2012 | Netgear | WNDR3700 | router-home | yes | 1 |
| 2012 | D-Link | DIR-819 | router-home | yes | 1 |
| 2012 | ASUS | RT-N66U | router-home | yes | 0 |
| 2012 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 3 |
| 2012 | Juniper | EX2300 | switch-enterprise | yes | 0 |
| 2013 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2013 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2013 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2013 | Linksys | E4200 | router-home | yes | 1 |
| 2013 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2013 | AT&T / Arris | NVG589 VDSL Gateway | isp-cpe/modem-router | no | 0 |
| 2013 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2013 | Juniper | EX2300 | switch-enterprise | yes | 0 |
| 2014 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2014 | D-Link | DIR-822 | router-home | yes | 0 |
| 2014 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2014 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2014 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2014 | AT&T / Arris | NVG599 VDSL Gateway | isp-cpe/modem-router | no | 0 |
| 2014 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2014 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2015 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2015 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2015 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2015 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2015 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2015 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2015 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2016 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2016 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2016 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2016 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2016 | D-Link | DIR-822 | router-home | yes | 0 |
| 2016 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2016 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2016 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2016 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2017 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2017 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2017 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2017 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2017 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2017 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2017 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2017 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2017 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2018 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2018 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2018 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2018 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2018 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2018 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2018 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2018 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2018 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2018 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2018 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2018 | Fortinet | FortiGate 100F | ngfw-corporate | yes | 0 |
| 2019 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2019 | TP-Link | Archer C7 | router-home | yes | 2 |
| 2019 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2019 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2019 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2019 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2019 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2019 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2019 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2019 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2019 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2019 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2020 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2020 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2020 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2020 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2020 | D-Link | DIR-822 | router-home | yes | 0 |
| 2020 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2020 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2020 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2020 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2020 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2020 | Check Point | Quantum Security Gateway | ngfw-enterprise | no | 0 |
| 2021 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2021 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2021 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2021 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2021 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2021 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2021 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2021 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2021 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2021 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2021 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2021 | Check Point | Quantum Security Gateway | ngfw-enterprise | no | 0 |
| 2022 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2022 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2022 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2022 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2022 | Mercusys | MR60X | router-home | no | 0 |
| 2022 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2022 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2022 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2022 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2022 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2022 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2022 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2023 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2023 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2023 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2023 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2023 | Mercusys | MR60X | router-home | no | 0 |
| 2023 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2023 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2023 | AT&T / Nokia | BGW320-505 XGS-PON Gateway | isp-cpe/gateway | no | 0 |
| 2023 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2023 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2023 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2023 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2023 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2024 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2024 | ASUS | AX5400 | router-home | yes | 0 |
| 2024 | TP-Link | Deco BE85 | router-mesh | yes | 0 |
| 2024 | Mercusys | MR60X | router-home | no | 0 |
| 2024 | Huawei | AX2S | router-home | yes | 0 |
| 2024 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2024 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2024 | AT&T / Nokia | BGW320-505 XGS-PON Gateway | isp-cpe/gateway | no | 0 |
| 2024 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2024 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2024 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2024 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2024 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2025 | TP-Link | Archer AXE75 | router-home | yes | 0 |
| 2025 | ASUS | ROG Rapture GT-BE98 Pro | router-home | yes | 0 |
| 2025 | TP-Link | Deco BE85 | router-mesh | yes | 0 |
| 2025 | eero | Max 7 | router-mesh | no | 0 |
| 2025 | TP-Link | Archer BE550 | router-home | yes | 0 |
| 2025 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2025 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2025 | AT&T / Nokia | BGW320-505 XGS-PON Gateway | isp-cpe/gateway | no | 0 |
| 2025 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2025 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2025 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2025 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2025 | Palo Alto Networks | PA-3200 | ngfw-enterprise | no | 0 |
| 2026 | TP-Link | Archer BE900 | router-home | yes | 0 |
| 2026 | TP-Link | Archer BE550 | router-home | yes | 0 |
| 2026 | eero | Max 7 | router-mesh | no | 0 |
| 2026 | GL.iNet | Flint 3 (GL-BE9300) | router-home | no | 0 |
| 2026 | Mercusys | MR80X | router-home | no | 0 |
| 2026 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2026 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2026 | AT&T / Nokia | BGW320-505 XGS-PON Gateway | isp-cpe/gateway | no | 0 |
| 2026 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2026 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2026 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2026 | Fortinet | FortiGate 200F | ngfw-corporate | yes | 0 |
| 2026 | Palo Alto Networks | PA-3200 | ngfw-enterprise | no | 0 |

### Yearly Reference (2010-2026)

| Year | Vendor | Product |
|---:|---|---|
| 2010 | Netgear | WNDR3700 |
| 2011 | Linksys | E4200 |
| 2012 | TP-Link | Archer C20 |
| 2013 | TP-Link | Archer C7 |
| 2014 | ASUS | RT-AC86U |
| 2015 | TP-Link | Archer C9 |
| 2016 | Google | Nest Wi-Fi |
| 2017 | TP-Link | Deco M4 |
| 2018 | TP-Link | Deco M4 |
| 2019 | Netgear | XR500 |
| 2020 | TP-Link | Archer AX10 |
| 2021 | TP-Link | Archer AX73 |
| 2022 | Huawei | AX3 Dual Core |
| 2023 | Intelbras | Action RG 1200 |
| 2024 | Ubiquiti | Cloud Gateway Ultra |
| 2025 | ASUS | ROG Rapture GT-BE98 Pro |
| 2026 | TP-Link | Archer BE900 |



## Architecture Inventory Snapshot

- Name: RouterXPL-Forge Arsenal Index
- Scope: routers, switches, taps, fw, ngfw
- Out of scope: cameras, printers, dvr, dvrs
- Generated by: tools/build_arsenal_index.py

| Domain | Count |
|---|---:|
| catalogs | 7 |
| wordlists | 33 |
| ssh_keys | 8 |
| vendors datasets | 2 |
| mibs | 1758 |
| modules.exploits | 516 |
| modules.creds | 88 |
| modules.scanners | 5 |
| modules.generic | 12 |
| modules.encoders | 13 |
| modules.payloads | 32 |

| curated_arsenal domain | Count |
|---|---:|
| binaries | 1 |
| credentials | 1 |
| firmware | 1 |
| intel | 1 |
| mibs | 1 |
| pocs | 1 |
| wordlists | 1 |

## Workspace Reuse Inventory Snapshot

- workspace_reuse_inventory.json not found.

## Deep Intel Backlog Snapshot

- deep_intel_backlog.json not found.

## Honeypot Final Validation Snapshot

- honeypot_validation_campaign.json not found.

## Vendor/Product Capability Matrix

| Vendor | Product | Modules | Exploits | Creds | Scanners | Generic | Payloads | Encoders | CVEs | Attack Classes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| 2wire | 4011g_5012nv_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| 2wire | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| 2wire | gateway_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| 2wire | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| 2wire | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| 3com | ap8760_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| 3com | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| 3com | imc_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| 3com | imc_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| 3com | officeconnect_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| 3com | officeconnect_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| 3com | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| 3com | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| actiontec | mi424wr_rce_cve_2014_9583 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9583 | rce |
| arcadyan | o2_box_6431_password_disclosure_cve_2015_7288 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-7288 | - |
| armle | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| armle | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| arris | router_firmware_9_1_103_remote_code_execution_rce_authentica_cve_2022_45701 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-45701 | rce |
| arris | tm602a_password_of_the_day | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| aruba | airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-8526, CVE-2016-8527 | - |
| aruba | clearpass_policy_manager_6_7_0_unauthenticated_remote_comman_cve_2020_7115 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-7115 | - |
| aruba | instant_8_7_1_0_arbitrary_file_modification_cve_2021_25155 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-25155 | - |
| aruba | instant_iap_remote_code_execution_cve_2021_25155 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-25155, CVE-2021-25156, CVE-2021-25157, CVE-2021-25158, CVE-2021-25159, CVE-2021-25160, CVE-2021-25161, CVE-2021-25162 | - |
| asmax | ar_1004g_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| asmax | ar_804_gu_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| asmax | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | webinterface_http_auth_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | asmb8_ikvm_1_14_51_remote_code_execution_rce_cve_2023_26602 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-26602 | rce |
| asus | asus_rt_n56u_remote_root_shell_exploit_apps_name_cve_2013_6343 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-6343 | - |
| asus | asustor_adm_3_1_2rhg1_remote_code_execution_cve_2018_11510 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-11510 | rce |
| asus | asuswrt_lan_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5999, CVE-2018-6000 | rce |
| asus | exploitdb_49036_rb_cve_2018_9285 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-9285 | - |
| asus | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | gamesdk_v1_0_0_4_gamesdk_exe_unquoted_service_path_cve_2022_35899 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-35899 | - |
| asus | hg100_denial_of_service_cve_2018_11492 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-11492 | dos_or_crash |
| asus | infosvr_authentication_bypass_command_execution_metasploit_cve_2014_9583 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9583 | - |
| asus | infosvr_backdoor_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| asus | precision_touchpad_11_0_0_25_denial_of_service_cve_2019_10709 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-10709 | dos_or_crash |
| asus | rt_n16_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| asus | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | stack_overflow_cve_2017_11345 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11345 | - |
| asus | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| belkin | auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, creds_disclosure |
| belkin | f9k1009_f9k1010_2_00_04_2_00_09_hard_coded_credentials_cve_2025_8730 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-8730 | - |
| belkin | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| belkin | g_n150_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2012-2765 | - |
| belkin | g_plus_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2008-0403 | info_disclosure |
| belkin | n150_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| belkin | n750_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-1635 | rce |
| belkin | play_max_prce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| belkin | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| belkin | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| bhu | bhu_urouter_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| bhu | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| bhu | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| bhu | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| billion | billion_5200w_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| billion | billion_7700nr4_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| billion | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| billion | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| billion | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cerio | multi_rce_cve_2018_18852 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-18852 | rce |
| cisco | adaptive_security_appliance_path_traversal_cve_2018_0296 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0296 | path_traversal |
| cisco | adaptive_security_appliance_path_traversal_metasploit_cve_2018_0296 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0296 | path_traversal |
| cisco | adaptive_security_appliance_software_9_11_local_file_inclusi_cve_2020_3452 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-3452 | - |
| cisco | adaptive_security_appliance_software_9_7_unauthenticated_arb_cve_2020_3187 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-3187 | - |
| cisco | anyconnect_secure_mobility_client_4_3_04027_local_privilege_cve_2017_3813 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3813 | - |
| cisco | asa_8_x_extrabacon_authentication_bypass_cve_2016_6366 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6366 | - |
| cisco | asa_9_14_1_10_and_ftd_6_6_0_1_path_traversal_2_cve_2020_3452 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-3452 | path_traversal |
| cisco | asa_and_ftd_9_6_4_42_path_traversal_cve_2020_3452 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-3452 | path_traversal |
| cisco | asa_crash_poc_cve_2018_0101 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0101 | - |
| cisco | asa_pix_epicbanana_local_privilege_escalation_cve_2016_6367 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6367 | - |
| cisco | asa_software_8_x_9_x_ikev1_ikev2_buffer_overflow_cve_2016_1287 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1287 | - |
| cisco | asa_webvpn_cifs_handling_buffer_overflow_cve_2017_3807 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3807 | - |
| cisco | catalyst_2960_ios_12_2_55_se11_rocem_remote_code_execution_cve_2017_3881 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3881 | - |
| cisco | catalyst_2960_ios_12_2_55_se1_rocem_remote_code_execution_cve_2017_3881 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3881 | - |
| cisco | catalyst_2960_rocem | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3881 | - |
| cisco | cisco_firepower_management_center_cve_2023_20048 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-20048 | - |
| cisco | data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15976, CVE-2019-15984 | - |
| cisco | data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15977, CVE-2019-15978 | - |
| cisco | data_center_network_manager_11_2_remote_code_execution_cve_2019_15975 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15975 | - |
| cisco | data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1619, CVE-2019-1620, CVE-2019-1622 | - |
| cisco | dcnm_jboss_10_4_credential_leakage_cve_2019_15999 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15999 | info_disclosure |
| cisco | dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15993, CVE-2020-5330 | - |
| cisco | digital_network_architecture_center_1_3_1_4_persistent_cross_cve_2019_15253 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15253 | - |
| cisco | dpc2420_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| cisco | dpc3928_router_arbitrary_file_disclosure_cve_2017_11502 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11502 | - |
| cisco | epc_3928_multiple_vulnerabilities_cve_2015_6401 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-6401, CVE-2015-6402, CVE-2016-1328, CVE-2016-1336, CVE-2016-1337 | - |
| cisco | firepower_management_center_6_2_2_2_6_2_3_cross_site_scripti_cve_2019_1642 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1642 | - |
| cisco | firepower_management_console_6_0_post_authentication_useradd_cve_2016_6433 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6433 | - |
| cisco | firepower_threat_management_console_6_0_1_hard_coded_mysql_c_cve_2016_6434 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6434 | - |
| cisco | firepower_threat_management_console_6_0_1_local_file_inclusi_cve_2016_6435 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6435 | - |
| cisco | firepower_threat_management_console_6_0_1_remote_command_exe_cve_2016_6433 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6433 | - |
| cisco | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cisco | immunet_6_2_0_amp_for_endpoints_6_2_0_denial_of_service_cve_2018_15437 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-15437 | dos_or_crash |
| cisco | ios_12_2_12_4_15_0_15_6_security_association_negotiation_req_cve_2016_6415 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6415 | - |
| cisco | ios_http_authorization_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2001-0537 | - |
| cisco | ios_remote_code_execution_cve_2017_6736 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6736 | - |
| cisco | ip_phone_11_7_denial_of_service_poc_cve_2020_3161 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-3161 | dos_or_crash |
| cisco | ise_3_0_authorization_bypass_cve_2025_20125 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-20125 | auth_bypass |
| cisco | ise_3_0_remote_code_execution_rce_cve_2025_20124 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-20124 | rce |
| cisco | node_jos_0_11_0_re_sign_tokens_cve_2018_0114 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0114 | - |
| cisco | prime_collaboration_provisioning_12_1_authentication_bypass_cve_2017_6622 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6622 | - |
| cisco | prime_infrastructure_health_monitor_ha_tararchive_directory_cve_2019_1821 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1821 | path_traversal |
| cisco | prime_infrastructure_health_monitor_tararchive_directory_tra_cve_2019_1821 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1821 | path_traversal |
| cisco | prime_infrastructure_unauthenticated_remote_code_execution_cve_2018_15379 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-15379 | - |
| cisco | rv110w_password_disclosure_command_execution_cve_2014_0683 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-0683, CVE-2015-6396 | - |
| cisco | rv110w_rv130_w_rv215w_routers_management_interface_remote_co_cve_2019_1663 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1663 | - |
| cisco | rv130w_1_0_3_44_remote_stack_overflow_cve_2019_1663 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1663 | - |
| cisco | rv130w_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1663 | rce |
| cisco | rv130w_routers_management_interface_remote_command_execution_cve_2019_1663 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1663 | - |
| cisco | rv300_rv320_information_disclosure_cve_2019_1653 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1653 | - |
| cisco | rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1652, CVE-2019-1653 | - |
| cisco | rv320_command_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1652 | rce |
| cisco | rv320_dual_gigabit_wan_vpn_router_1_4_2_15_command_injection_cve_2019_1652 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1652 | - |
| cisco | small_business_200_300_500_switches_multiple_vulnerabilities_cve_2019_1943 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1943 | - |
| cisco | small_business_220_series_multiple_vulnerabilities_cve_2019_1912 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1912, CVE-2019-1913, CVE-2019-1914 | - |
| cisco | smart_install_crash_poc_cve_2018_0171 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0171 | - |
| cisco | smart_software_manager_on_prem_8_202206_account_takeover_cve_2024_20419 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-20419 | - |
| cisco | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cisco | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cisco | ucs_director_default_scpuser_password_metasploit_cve_2019_1935 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1935 | - |
| cisco | ucs_imc_supervisor_2_2_0_0_authentication_bypass_cve_2019_1937 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1937 | - |
| cisco | ucs_manager_2_1_1b_remote_command_injection_shellshock_cve_2014_6278 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-6278 | rce |
| cisco | ucs_platform_emulator_3_1_2epe1_remote_code_execution_cve_2017_12243 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-12243 | - |
| cisco | umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-0437, CVE-2018-0438 | - |
| cisco | unified_communications_manager_7_8_9_directory_traversal_cve_2013_5528 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-5528 | path_traversal |
| cisco | webex_meetings_33_6_6_33_9_1_privilege_escalation_cve_2019_1674 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1674 | - |
| cisco | webex_player_t29_10_arf_out_of_bounds_memory_corruption_cve_2016_1415 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1415 | - |
| cisco | webex_player_t29_10_wrf_use_after_free_memory_corruption_cve_2016_1464 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1464 | - |
| cisco | wireless_controller_3_6_10e_cross_site_request_forgery_cve_2019_12624 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-12624 | - |
| cisco | wlc_2504_8_9_denial_of_service_poc_cve_2019_15276 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-15276 | dos_or_crash |
| cmd | awk_bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | awk_bind_udp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | awk_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | bash_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | netcat_bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | netcat_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | perl_bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | perl_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | php_bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | php_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | python_bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | python_bind_udp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | python_reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| cmd | python_reverse_udp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| comtrend | ct_5361t_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| comtrend | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| comtrend | persistent_xss_on_comtrend_ar_5387un_router_cve_2018_8062 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-8062 | - |
| comtrend | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| comtrend | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| comtrend | vr_3033_command_injection_cve_2020_10173 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-10173 | - |
| cve | cve_lookup | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| dlink | central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-17440, CVE-2018-17441, CVE-2018-17442, CVE-2018-17443 | - |
| dlink | dap_1620_a1_v1_01_directory_traversal_cve_2021_46381 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-46381 | path_traversal |
| dlink | dcs_5020l_remote_code_execution_poc_cve_2017_17020 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17020 | - |
| dlink | dcs_930l_auth_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dcs_931l_arbitrary_file_upload_metasploit_cve_2015_2049 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-2049 | - |
| dlink | dcs_936l_network_camera_cross_site_request_forgery_cve_2017_7851 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-7851 | - |
| dlink | dcs_cred_disclosure_cve_2020_25078 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-25078 | - |
| dlink | dcs_series_cameras_insecure_crossdomain_cve_2017_7852 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-7852 | - |
| dlink | devices_unauthenticated_remote_command_execution_in_ssdpcgi_cve_2019_20215 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-20215 | - |
| dlink | dgs_1510_add_user | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dgs_1510_multiple_vulnerabilities_cve_2017_6206 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6206 | - |
| dlink | di_524_cross_site_request_forgery_cve_2017_5633 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-5633 | - |
| dlink | di_524_v2_06ru_multiple_cross_site_scripting_cve_2019_11017 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-11017 | - |
| dlink | dir601_cred_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| dlink | dir845l_cred_disclosure_cve_2024_33113 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-33113 | - |
| dlink | dir850_insecure_access_control_cve_2021_46378 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-46378 | - |
| dlink | dir850_open_redirect_cve_2021_46379 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-46379 | - |
| dlink | dir890l_soapaction_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_300_320_600_615_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dir_300_320_615_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| dlink | dir_300_600_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_300_645_815_upnp_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_600_authentication_bypass_cve_2017_12943 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-12943 | - |
| dlink | dir_600m_authentication_bypass_metasploit_cve_2019_13101 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13101 | - |
| dlink | dir_600m_wireless_cross_site_scripting_cve_2018_6936 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-6936 | - |
| dlink | dir_601_admin_password_disclosure_cve_2018_5708 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5708 | - |
| dlink | dir_601_credential_disclosure_cve_2018_12710 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-12710 | creds_disclosure |
| dlink | dir_605l_2_08_denial_of_service_cve_2017_9675 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-9675 | dos_or_crash |
| dlink | dir_615_cross_site_request_forgery_cve_2017_7398 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-7398 | - |
| dlink | dir_615_denial_of_service_poc_cve_2018_15839 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-15839 | dos_or_crash |
| dlink | dir_615_privilege_escalation_cve_2019_19743 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-19743 | - |
| dlink | dir_615_t1_20_10_captcha_bypass_cve_2019_17525 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-17525 | - |
| dlink | dir_615_wireless_router_persistent_cross_site_scripting_cve_2018_10110 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10110 | - |
| dlink | dir_615_wireless_router_persistent_cross_site_scripting_cve_2019_19742 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-19742 | - |
| dlink | dir_645_815_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_645_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dir_655_866_652_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-16920 | rce |
| dlink | dir_815_850l_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_819_a1_denial_of_service_cve_2022_40946 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-40946 | dos_or_crash |
| dlink | dir_825_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dir_825_rev_b_2_10_stack_buffer_overflow_dos_cve_2025_10666 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-10666 | dos_or_crash |
| dlink | dir_846_remote_command_execution_rce_vulnerability_cve_2022_46552 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-46552 | rce |
| dlink | dir_850l_creds_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dir_850l_wireless_ac1200_dual_band_gigabit_cloud_router_auth_cve_2018_9032 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-9032 | - |
| dlink | dir_8xx_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dir_series_routers_hnap_login_stack_buffer_overflow_metasplo_cve_2016_6563 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6563 | - |
| dlink | dns_320l_327l_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dsl_2640b_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2730_2750_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dsl_2730b_2780b_526b_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2730u_wireless_n_150_cross_site_request_forgery_cve_2017_6411 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6411 | - |
| dlink | dsl_2740r_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2750b_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dsl_2750b_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dsl_3782_authentication_bypass_cve_2018_8898 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-8898 | - |
| dlink | dsp_w110_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dsr_250n_3_12_denial_of_service_poc_cve_2020_26567 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-26567 | dos_or_crash |
| dlink | dvg_n5402sp_multiple_vulnerabilities_cve_2015_7245 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-7245, CVE-2015-7246, CVE-2015-7247 | - |
| dlink | dvg_n5402sp_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dwl_2600_authenticated_remote_command_injection_metasploit_cve_2019_20499 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-20499 | - |
| dlink | dwl_2600ap_multiple_os_command_injection_cve_2019_20499 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-20499, CVE-2019-20500, CVE-2019-20501 | - |
| dlink | dwl_3200ap_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| dlink | dwr_116_dwr_116a1_arbitrary_file_download_cve_2017_6190 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6190 | - |
| dlink | dwr_932_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dwr_932b_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| dlink | exploitdb_30062_py_cve_2013_5946 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-5945, CVE-2013-5946 | - |
| dlink | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| dlink | hedwig_rce_cve_2013_7389 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-7389 | rce |
| dlink | multi_hedwig_cgi_exec | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | multi_hnap_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | routers_command_injection_cve_2018_10823 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10823 | - |
| dlink | routers_directory_traversal_cve_2018_10822 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10822 | path_traversal |
| dlink | routers_plaintext_password_cve_2018_10824 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10824 | - |
| dlink | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| dlink | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| dlink_dsl | dsl_2640b_wps_rce_cve_2013_5223 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-5223 | rce |
| dlink_dsl | dsl_2750b_remote_code_execution_cve_2016_20017 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-20017 | - |
| draytek | multiple_products_pre_authentication_remote_root_code_execut_cve_2020_8515 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-8515 | - |
| draytek | vigor_master_key | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| external | exploitdb_embedded_lookup | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | metasploit_console_bridge | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | metasploit_rb_inspect | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | mikrotikapi_bf_bridge | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| fiberhome | adsl_an1020_25_improper_access_restrictions_cve_2017_14147 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-14147 | - |
| fiberhome | an5506_04_f_rp2669_persistent_cross_site_scripting_cve_2019_9556 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-9556 | - |
| fiberhome | directory_traversal_cve_2017_15647 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-15647 | path_traversal |
| fiberhome | lm53q1_multiple_vulnerabilities_cve_2017_16885 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-16885, CVE-2017-16886, CVE-2017-16887 | - |
| fiberhome | vdsl2_modem_hg_150_ub_authentication_bypass_cve_2018_9248 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-9248 | - |
| fortinet | forticlient_5_2_3_windows_10_x64_creators_local_privilege_es_cve_2015_4077 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-4077, CVE-2015-5736 | - |
| fortinet | forticlient_5_2_3_windows_10_x64_post_anniversary_local_priv_cve_2015_5736 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-5736 | - |
| fortinet | forticlient_5_2_3_windows_10_x64_pre_anniversary_local_privi_cve_2015_5736 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-5736 | - |
| fortinet | fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1909 | backdoor |
| fortinet | fortigate_fortios_6_0_3_ldap_credential_disclosure_cve_2018_13374 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-13374 | creds_disclosure |
| fortinet | fortimail_7_0_1_reflected_cross_site_scripting_xss_cve_2021_43062 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-43062 | - |
| fortinet | fortios_5_6_0_cross_site_scripting_cve_2017_3131 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3131, CVE-2017-3132, CVE-2017-3133 | - |
| fortinet | fortios_5_6_3_5_6_7_fortios_6_0_0_6_0_4_credentials_disclosu_cve_2018_13379 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-13379 | - |
| fortinet | fortios_6_0_4_unauthenticated_ssl_vpn_user_password_modifica_cve_2018_13382 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-13382 | - |
| fortinet | fortios_fortiproxy_and_fortiswitchmanager_7_2_0_authenticati_cve_2022_40684 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-40684 | auth_bypass |
| ftp_bruteforce.py | ftp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ftp_default.py | ftp_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| gpon | alcatel_lucent_nokia_i_240w_q_buffer_overflow_cve_2019_3921 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-3921 | - |
| gpon | home_gateway_rce_cve_2018_10562 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10561, CVE-2018-10562 | auth_bypass, rce |
| gpon | routers_authentication_bypass_command_injection_cve_2018_10561 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10561, CVE-2018-10562 | - |
| gpon | skyworth_homegateways_and_optical_network_terminals_stack_ov_cve_2018_19524 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-19524 | - |
| heartbleed.py | heartbleed | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| hootoo | tripmate_arbitrary_file_upload | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| hootoo | tripmate_open_forwarding_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| hootoo | tripmate_sysfirm_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| http_basic_digest_bruteforce.py | http_basic_digest_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_basic_digest_default.py | http_basic_digest_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_form_char_by_char_oracle.py | http_form_char_by_char_oracle | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| http_multi_auth_default.py | http_multi_auth_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_web_form_bruteforce.py | http_web_form_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | b315s_22_information_leak_cve_2018_7921 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-7921 | info_disclosure |
| huawei | e5330_21_210_09_00_158_cross_site_request_forgery_send_sms_cve_2014_5395 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-5395 | - |
| huawei | e5331_mifi_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | eg8145x6_autopwn | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-6271, CVE-2017-17215, CVE-2018-10561, CVE-2018-10562, CVE-2025-49599 | - |
| huawei | eg8145x6_bruteforce_login | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_config_decrypt | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_csrf_payload_generator | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-49599 | - |
| huawei | eg8145x6_csrf_static_token | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_dns_poison_csrf | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_epuser_firewall_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-49599 | - |
| huawei | eg8145x6_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | eg8145x6_mitm_credential_intercept | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_preauth_password_enum | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | eg8145x6_telnet_enable | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-49599 | - |
| huawei | eg8145x6_wifi_credential_extractor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| huawei | espace_1_1_11_103_contactsctrl_dll_espacestatusctrl_dll_acti_cve_2014_9418 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9418 | - |
| huawei | espace_1_1_11_103_dll_hijacking_cve_2014_9416 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9416 | - |
| huawei | espace_1_1_11_103_image_file_format_handling_buffer_overflow_cve_2014_9417 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9417 | - |
| huawei | espace_meeting_1_1_11_103_cenwpoll_dll_seh_buffer_overflow_u_cve_2014_9415 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9415 | - |
| huawei | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | hg520_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | hg530_hg520b_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| huawei | hg532_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17215 | rce |
| huawei | hg532x_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| huawei | hg630_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | hg8240_auth_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| huawei | hg8240_file_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| huawei | hg866_password_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | password_reset_or_change |
| huawei | mate_7_dev_hifi_misc_privilege_escalation_cve_2015_8088 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-8088 | - |
| huawei | router_hg532_arbitrary_command_execution_cve_2017_17215 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17215 | - |
| huawei | router_hg532e_command_execution_cve_2015_7254 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-7254 | - |
| huawei | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | utps_unquoted_service_path_privilege_escalation_cve_2016_8769 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-8769 | - |
| intelbras | iwr_3000n_1_5_0_cross_site_request_forgery_cve_2019_11416 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-11416 | - |
| intelbras | iwr_3000n_denial_of_service_remote_reboot_cve_2019_11415 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-11415 | dos_or_crash |
| intelbras | ncloud_300_1_0_authentication_bypass_cve_2018_11094 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-11094 | auth_bypass |
| intelbras | roteador_wireless_wrn150_cross_site_scripting_cve_2017_14219 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-14219 | - |
| intelbras | router_rf1200_1_1_3_cross_site_request_forgery_cve_2019_19516 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-19516 | - |
| intelbras | router_rf_301k_dns_hijacking_cross_site_request_forgery_csrf_cve_2021_32403 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-32403 | - |
| intelbras | telefone_ip_tip200_lite_local_file_disclosure_cve_2018_9010 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-9010 | - |
| intelbras | wireless_n_150mbps_wrn240_authentication_bypass_config_uploa_cve_2019_19142 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-19142 | - |
| ipfire | 2_25_remote_code_execution_authenticated_cve_2021_33393 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-33393 | - |
| ipfire | ipfire_oinkcode_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| ipfire | ipfire_proxy_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| ipfire | ipfire_shellshock | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| ipfire | shellshock_bash_environment_variable_command_injection_metas_cve_2014_6271 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-6271 | rce |
| juniper | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| juniper | junos_backdoor_cve_2015_7755 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-7755 | backdoor |
| juniper | junos_web_auth_bypass_cve_2023_36845 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-36845 | auth_bypass |
| juniper | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| juniper | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| lg | nas_3718 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| linksys | 1500_2500_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | ax3200_v1_1_00_command_injection_cve_2022_38841 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-38841 | - |
| linksys | ea6100_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, info_disclosure |
| linksys | ea7500_2_0_8_194281_cross_site_scripting_cve_2012_6708 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2012-6708 | - |
| linksys | eseries_themoon_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | eseries_tmunblock_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | re6500_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | smartwifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-8243 | creds_disclosure |
| linksys | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | wap54gv3_debug_rce_cve_2010_1573 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2010-1573 | rce |
| linksys | wap54gv3_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | wrt100_110_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-3568 | rce |
| linksys | wvbr0_25_user_agent_command_execution_metasploit_cve_2017_17411 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17411 | - |
| linksys | wvbr0_user_agent_remote_command_injection_cve_2017_17411 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17411 | - |
| mercury | hp_loadrunner_agent_magentproc_exe_remote_command_execution_cve_2010_1549 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2010-1549 | - |
| mikrotik | 6_40_5_icmp_denial_of_service_cve_2017_17538 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17538 | dos_or_crash |
| mikrotik | 6_41_4_ftp_daemon_denial_of_service_poc_cve_2018_10070 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10070 | dos_or_crash |
| mikrotik | api_ros_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | cve_2024_27686_routeros_smb_dos | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-27686 | dos_or_crash |
| mikrotik | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | router_arp_table_overflow_denial_of_service_cve_2017_6444 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6444 | dos_or_crash |
| mikrotik | router_monitoring_system_1_2_3_community_sql_injection_cve_2020_13118 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-13118 | - |
| mikrotik | routerboard_6_38_5_denial_of_service_cve_2017_7285 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-7285 | dos_or_crash |
| mikrotik | routeros_6_41_3_6_42rc27_smb_buffer_overflow_cve_2018_7445 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-7445 | - |
| mikrotik | routeros_6_43_12_stable_6_42_12_long_term_firewall_and_nat_b_cve_2019_3924 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-3924 | - |
| mikrotik | routeros_6_45_6_dns_cache_poisoning_cve_2019_3978 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-3978 | - |
| mikrotik | routeros_7_19_1_reflected_xss_cve_2025_6563 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-6563 | - |
| mikrotik | routeros_jailbreak | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | winbox_auth_bypass_creds_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, creds_disclosure |
| mikrotik | winbox_cred_disclosure_cve_2018_14847 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-14847 | - |
| mipsbe | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsbe | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsle | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsle | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| misc | misc_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| misc | soho_exploit_catalog_server | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| mitrastar | gpt2541gnac_stack_overflow | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| movistar | adsl_router_bhs_rta_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| movistar | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| movistar | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| movistar | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| multi | 3com_ap8670_cred_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| multi | accton_switch_backdoor_password | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| multi | airlive_wt2000arm_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| multi | airties_air5341_modem_1_0_0_12_cross_site_request_forgery_cve_2019_6967 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6967 | - |
| multi | allegrosoft_rompager_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9222 | auth_bypass |
| multi | astaro_security_gateway_7_remote_code_execution_cve_2017_6315 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6315 | - |
| multi | aveva_intouch_access_anywhere_secure_gateway_2020_r2_path_tr_cve_2022_23854 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-23854 | - |
| multi | barracuda_load_balancer_firmware_v6_0_1_006_2016_08_19_posta_cve_2017_6320 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6320 | - |
| multi | check_point_security_gateway_information_disclosure_unauthen_cve_2024_24919 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-24919 | info_disclosure |
| multi | cobham_admin_reset_cve_2014_2943 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-2943 | - |
| multi | coship_rt3052_wireless_router_persistent_cross_site_scriptin_cve_2018_8772 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-8772 | - |
| multi | coship_wireless_router_4_0_0_48_4_0_0_40_5_0_0_54_5_0_0_55_1_cve_2019_6441 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6441 | - |
| multi | credential_leakage_through_unprotected_system_logs_and_weak_cve_2023_43261 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-43261 | info_disclosure |
| multi | cve_2017_6552_local_dos_buffer_overflow_livebox_3 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6552 | dos_or_crash |
| multi | davolink_dvw_3200_router_password_disclosure_cve_2018_10618 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-10618 | - |
| multi | digisol_dg_hr1400_1_00_02_wireless_router_privilege_escalati_cve_2017_6896 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6896 | - |
| multi | exploitdb_45942_py_cve_2018_11741 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-11741, CVE-2018-11742 | - |
| multi | exploitdb_49038_rb_cve_2020_8196 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-8193, CVE-2020-8195, CVE-2020-8196 | - |
| multi | exploitdb_51865_py_cve_2023_46453 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-46453 | - |
| multi | f5_big_ip_13_1_3_build_0_0_6_local_file_inclusion_cve_2020_5902 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-5902 | - |
| multi | f5_big_ip_16_0_x_icontrol_rest_remote_code_execution_unauthe_cve_2021_22986 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-22986 | rce |
| multi | fortirecorder_6_4_3_denial_of_service_cve_2022_41333 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-41333 | dos_or_crash |
| multi | genexis_platinum_4410_router_2_1_upnp_credential_exposure_cve_2020_25988 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-25988 | - |
| multi | gl_inet_3_216_remote_code_execution_via_openvpn_client_cve_2023_46456 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-46456 | rce |
| multi | gl_inet_4_3_7_arbitrary_file_write_cve_2023_46455 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-46455 | - |
| multi | gl_inet_4_3_7_remote_code_execution_via_openvpn_client_cve_2023_46454 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-46454 | rce |
| multi | gl_inet_mt6000_4_5_5_arbitrary_file_download_cve_2024_27356 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-27356 | - |
| multi | gpon_home_gateway_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| multi | grandstream_gxv3611_hd_telnet_sql_injection_and_backdoor_com_cve_2015_2866 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-2866 | backdoor |
| multi | grandstream_ucm6200_series_cti_interface_user_password_sql_i_cve_2020_5726 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-5726 | - |
| multi | grandstream_ucm6200_series_websocket_1_0_20_20_user_password_cve_2020_5725 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-5725 | - |
| multi | hughesnet_ht2000w_satellite_modem_arcadyan_httpd_1_0_passwor_cve_2021_20090 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-20090 | - |
| multi | humax_wi_fi_router_hg100r_2_0_6_authentication_bypass_cve_2017_11435 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11435 | - |
| multi | iball_adsl2_home_router_authentication_bypass_cve_2017_14244 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-14244 | - |
| multi | iopsys_router_dhcp_remote_code_execution_cve_2017_17867 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17867 | - |
| multi | iqrouter_3_3_1_firmware_remote_code_execution_cve_2020_11963 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-11963, CVE-2020-11964, CVE-2020-11966, CVE-2020-11967, CVE-2020-11968 | rce |
| multi | irz_mobile_router_csrf_to_rce_cve_2022_27226 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-27226 | rce |
| multi | laser_router_re018_ac1200_cross_site_request_forgery_enable_cve_2021_31152 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-31152 | - |
| multi | misfortune_cookie | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9222 | auth_bypass |
| multi | msnswitch_firmware_mnt_2408_remote_code_exectuion_rce_cve_2022_32429 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-32429 | rce |
| multi | nat_slipstream | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| multi | netcommwireless_hspa_3g10wve_wireless_router_ple_vulnerabili_cve_2015_6023 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-6023, CVE-2015-6024 | - |
| multi | netis_wf2419_2_2_36123_remote_code_execution_cve_2019_1337 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1337, CVE-2019-19356 | rce |
| multi | netusb_kernel_stack_overflow_cve_2021_45388 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-45388, CVE-2021-45608 | - |
| multi | nexxt_router_firmware_42_103_1_5095_remote_code_execution_rc_cve_2022_44149 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-44149 | - |
| multi | nintendo_switch_webkit_code_execution_poc_cve_2016_4657 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-4657 | - |
| multi | norton_core_secure_wifi_router_ble_command_injection_poc_cve_2018_5234 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5234 | - |
| multi | openwrt_luci_rce_cve_2021_22161 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-8597, CVE-2021-22161 | rce |
| multi | pfsensece_v2_6_0_anti_brute_force_protection_bypass_cve_2023_27100 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-27100 | - |
| multi | plc_wireless_router_gpn2_4p21_c_cn_cross_site_request_forger_cve_2019_6282 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6282 | - |
| multi | plc_wireless_router_gpn2_4p21_c_cn_cross_site_scripting_cve_2018_20326 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-20326 | - |
| multi | plc_wireless_router_gpn2_4p21_c_cn_incorrect_access_control_cve_2019_6279 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6279 | - |
| multi | qubes_mirage_firewall_v0_8_3_denial_of_service_dos_cve_2022_46770 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-46770 | dos_or_crash |
| multi | rom0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| multi | rom0_password_extraction | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| multi | rompager_4_34_ple_router_vendors_misfortune_cookie_authentic_cve_2015_9222 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-9222 | - |
| multi | rompager_password_disclosure_cve_2014_4019 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-4019 | - |
| multi | ruckus_iot_controller_ruckus_vriot_1_5_1_0_21_remote_code_ex_cve_2020_26878 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-26878 | rce |
| multi | sagem_fast_telnet_password | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| multi | seowon_slr_120_router_remote_code_execution_unauthenticated_cve_2020_17456 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-17456 | - |
| multi | smartrg_router_sr510n_2_6_13_remote_code_execution_cve_2022_37661 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-37661 | - |
| multi | tcp_32764_backdoor_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| multi | tcp_32764_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, info_disclosure |
| multi | tcp_32764_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| multi | techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34723 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-34723 | - |
| multi | techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34724 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-34724, CVE-2023-34725 | - |
| multi | telesquare_sdt_cw3b1_1_1_0_os_command_injection_cve_2021_46422 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-46422 | rce |
| multi | ticketbleed_cve_2016_9244 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-9244 | - |
| multi | ucm6202_1_0_18_13_remote_command_injection_cve_2020_5722 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-5722 | rce |
| multi | unauthenticated_command_injection_vulnerability_in_vmware_ns_cve_2018_6961 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-6961 | rce |
| multi | utstar_wa3002g4_adsl_broadband_modem_authentication_bypass_cve_2017_14243 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-14243 | - |
| multi | viprinet_channel_vpn_router_300_persistent_cross_site_script_cve_2014_2045 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-2045 | - |
| multi | wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5999, CVE-2018-6000 | - |
| netcore | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | udp_53413_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| netcore | wf2419_router_cross_site_scripting_cve_2018_6190 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-6190 | - |
| netgear | devices_unauthenticated_remote_command_execution_metasploit_cve_2016_1555 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1555 | - |
| netgear | dgn1000_setup_cgi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | dgn1000_unauthenticated_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | dgn2200_dnslookup_cgi_command_injection_metasploit_cve_2017_6334 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334 | - |
| netgear | dgn2200_dnslookup_cgi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334 | rce |
| netgear | dgn2200_ping_cgi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6077 | rce |
| netgear | dgn2200_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334 | rce |
| netgear | dgn2200v1_v2_v3_v4_cross_site_request_forgery_cve_2017_6334 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334, CVE-2017-6366 | - |
| netgear | dgn2200v1_v2_v3_v4_dnslookup_cgi_remote_command_execution_cve_2017_6334 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334 | - |
| netgear | dgn2200v1_v2_v3_v4_ping_cgi_remote_command_execution_cve_2017_6077 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6077 | - |
| netgear | exploitdb_27774_py_cve_2013_4775 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-4775 | - |
| netgear | exploitdb_27775_py_cve_2013_4776 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-4776 | - |
| netgear | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | jnr1010_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| netgear | jwnr2010v5_password_leak | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| netgear | multi_password_disclosure-2017-5521 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-5521 | creds_disclosure |
| netgear | multi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | n300_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| netgear | netusb_kernel_stack_buffer_overflow_cve_2015_3036 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-3036 | - |
| netgear | nms300_prosafe_network_management_system_arbitrary_file_uplo_cve_2016_1525 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1525 | - |
| netgear | nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-1524, CVE-2016-1525 | - |
| netgear | nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-5674, CVE-2016-5675, CVE-2016-5676, CVE-2016-5677, CVE-2016-5678, CVE-2016-5679, CVE-2016-5680 | - |
| netgear | prosafe_rce | 2 | 2 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | r7000_command_injection_cve_2016_6277 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6277 | - |
| netgear | r7000_r6400_cgi_bin_command_injection_metasploit_cve_2016_6277 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6277 | - |
| netgear | r7000_r6400_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | rax30_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | routers_password_disclosure_cve_2017_5521 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-5521 | - |
| netgear | rp614_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| netgear | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | wg102_wn604_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | wnap320_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | wndr_soap_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, info_disclosure |
| netgear | wnr2000v5_hidden_lang_avi_remote_stack_overflow_metasploit_cve_2016_10174 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-10174 | - |
| netgear | wnr2000v5_remote_code_execution_cve_2016_10174 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-10174, CVE-2016-10175, CVE-2016-10176 | - |
| netgear | wnr500_612v3_jnr1010_2010_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| netis | mw5360_mw5370_rce_cve_2014_8572 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-8572 | backdoor, rce |
| netsys | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netsys | multi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netsys | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netsys | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| perl | base64 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| perl | hex | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| perl | rot13 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | url | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| pfsense | pfsense_2_2_6_command_injection_cve_2016_10709 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-10709 | rce |
| php | base64 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| php | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| php | hex | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| php | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| php | rot13 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| php | url | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| python | base32 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| python | base64 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| python | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| python | bind_udp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| python | hex | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| python | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| python | reverse_udp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| python | rot13 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| python | url | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| routers | router_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| ruijie | reyee_mesh_router_remote_code_execution_rce_authenticated_cve_2021_43164 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-43164 | rce |
| scanners | autopwn | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| sftp_bruteforce.py | sftp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| sftp_default.py | sftp_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| shellshock.py | shellshock | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-6271, CVE-2014-6278, CVE-2014-7169 | rce |
| shuttle | 915wm_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| siemens | ccms2025_cred_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| siemens | ccms2025_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| snmp | snmp_bruteforce | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| snmp | snmp_trap_listener | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| snmp_bruteforce.py | snmp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| snmpv3_default.py | snmpv3_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| soho_edge | hootoo_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| sonicwall | 8_1_0_2_14sv_extensionsettings_cgi_remote_command_injection_cve_2016_9683 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-9683 | - |
| sonicwall | 8_1_0_2_14sv_viewcert_cgi_remote_command_injection_metasploi_cve_2016_9684 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-9684 | - |
| sonicwall | dell_scrutinizer_11_01_methoddetail_sql_injection_metasploit_cve_2014_4977 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-4977 | - |
| sonicwall | netextender_10_2_0_300_unquoted_service_path_cve_2020_5147 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-5147 | - |
| sonicwall | secure_remote_access_8_1_0_2_14sv_command_injection_cve_2016_9682 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-9682 | - |
| sonicwall | sma_10_2_1_0_17sv_password_reset_cve_2021_20034 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-20034 | password_reset_or_change |
| sonicwall | sonicos_7_0_host_header_injection_cve_2021_20031 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-20031 | - |
| ssh_auth_keys.py | ssh_auth_keys | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| ssh_bruteforce.py | ssh_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ssh_default.py | ssh_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tcp_xmas.py | tcp_xmas | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| technicolor | dpc3928sl_snmp_authentication_bypass_cve_2017_5135 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-5135 | - |
| technicolor | dwg855_authbypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| technicolor | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | tc7200_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| technicolor | tc7200_password_disclosure_v2 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| technicolor | tc7337_ssid_persistent_cross_site_scripting_cve_2017_11320 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11320 | - |
| technicolor | td5130_2_remote_command_execution_cve_2019_18396 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-18396 | - |
| technicolor | technicolor_tc7300_b0_hostname_persistent_cross_site_scripti_cve_2019_17524 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-17524 | - |
| technicolor | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | tg784_authbypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| technicolor | xfinity_gateway_dpc3941t_cross_site_request_forgery_cve_2016_7454 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-7454 | - |
| telnet_bruteforce.py | telnet_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| telnet_default.py | telnet_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tenda | ac15_router_remote_code_execution_cve_2018_5767 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5767 | - |
| tenda | ac20_16_03_08_12_command_injection_cve_2025_9090 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-9090 | - |
| tenda | ac5_ac1200_wireless_wifi_name_password_stored_cross_site_scr_cve_2021_3186 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-3186 | - |
| tenda | adsl_router_d152_cross_site_scripting_cve_2018_14497 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-14497 | - |
| tenda | d301_v2_modem_router_persistent_cross_site_scripting_cve_2019_13491 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13491 | - |
| tenda | fh451_1_0_0_9_router_stack_based_buffer_overflow_cve_2025_7795 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-7795 | - |
| tenda | n300_f3_12_01_01_48_malformed_http_request_header_processing_cve_2020_35391 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-35391 | - |
| tenda | wireless_n150_router_5_07_50_cross_site_request_forgery_rebo_cve_2015_5996 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2015-5996 | - |
| thomson | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | reuters_concourse_firm_central_2_13_0097_directory_traversal_cve_2019_8385 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-8385 | path_traversal |
| thomson | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | twg849_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| thomson | twg850_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| totolink | n300rb_8_54_command_execution_cve_2025_52089 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-52089 | - |
| tplink | archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-10882, CVE-2020-10883, CVE-2020-10884 | - |
| tplink | archer_ax21_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-1389 | rce |
| tplink | archer_ax21_unauthenticated_command_injection_cve_2023_1389 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-1389 | - |
| tplink | archer_c2_c20i_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| tplink | archer_c50_3_denial_of_service_poc_cve_2020_9375 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-9375 | dos_or_crash |
| tplink | archer_c5_rce_cve_2018_19537 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-19537 | rce |
| tplink | archer_c7_netusb_rce_cve_2022_24354 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-24354 | rce |
| tplink | archer_c9_admin_password_reset | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11519 | password_reset_or_change |
| tplink | ax50_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-30075 | rce |
| tplink | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | router_ax50_firmware_210730_remote_code_execution_rce_authen_cve_2022_30075 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-30075 | rce |
| tplink | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | tapo_c200_1_1_15_remote_code_execution_rce_cve_2021_4045 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-4045 | rce |
| tplink | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | tl_mr3220_cross_site_scripting_cve_2017_15291 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-15291 | - |
| tplink | tl_sc3130_1_6_18_rtsp_stream_disclosure_cve_2018_18428 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-18428 | - |
| tplink | tl_wa855re_v5_200415_device_reset_auth_bypass_cve_2020_24363 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-24363 | auth_bypass |
| tplink | tl_wr1043nd_2_authentication_bypass_cve_2019_6971 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6971 | - |
| tplink | tl_wr840n_denial_of_service_cve_2018_14336 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-14336 | dos_or_crash |
| tplink | tl_wr840n_v5_00000005_cross_site_scripting_cve_2019_12195 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-12195 | - |
| tplink | tl_wr841n_command_injection_cve_2020_35576 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-35576 | - |
| tplink | tl_wr841nd_password_disclosure_cve_2020_35575 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-35575 | - |
| tplink | tl_wr902ac_firmware_210730_v3_remote_code_execution_rce_auth_cve_2022_48194 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-48194 | rce |
| tplink | tl_wr940n_tl_wr941nd_buffer_overflow_cve_2019_6989 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6989 | - |
| tplink | tl_wr940n_v4_buffer_overflow_cve_2023_36355 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2023-36355 | - |
| tplink | tp_sg105e_1_0_0_unauthenticated_remote_reboot_cve_2019_16893 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-16893 | - |
| tplink | vn020_f3v_t_tt_v6_2_1021_buffer_overflow_memory_corruption_cve_2024_12344 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-12344 | - |
| tplink | vn020_f3v_t_tt_v6_2_1021_denial_of_service_dos_cve_2024_12342 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-12342 | dos_or_crash |
| tplink | vn020_f3v_t_tt_v6_2_1021_dhcp_stack_buffer_overflow_cve_2024_11237 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2024-11237 | - |
| tplink | wdr4300_remote_code_execution_authenticated_cve_2017_13772 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-13772 | - |
| tplink | wdr5620_cmd_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| tplink | wdr740nd_wdr740n_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| tplink | wdr740nd_wdr740n_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| tplink | wdr842nd_wdr842n_configure_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| tplink | wireless_router_archer_c1200_cross_site_scripting_cve_2018_13134 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-13134 | - |
| tplink | wr1043nd_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6971 | auth_bypass |
| tplink | wr840n_0_9_1_3_16_denial_of_service_poc_cve_2018_15172 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-15172 | dos_or_crash |
| tplink | wr841nd_password_disclosure_cve_2020_35575 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-35575 | creds_disclosure |
| tplink | wr849n_config_bypass_cve_2019_19143 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-19143 | - |
| tplink | wr849n_rce_cve_2020_9374 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-9374 | rce |
| tplink | wr849n_traceroute_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| tplink | wr940n_authenticated_remote_code_cve_2017_13772 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-13772 | - |
| tplink | wvr_war_diagnostic_rce_cve_2017_16957 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-16957 | rce |
| trendnet | tew827dru_cmd_injection_cve_2019_13276 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13276 | rce |
| trendnet | tew827dru_cmd_injection_cve_2019_13277 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13277 | dos_or_crash |
| trendnet | tew827dru_cmd_injection_cve_2019_13278 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13278 | rce |
| trendnet | tew827dru_stack_overflow_cve_2019_13150 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13150 | - |
| trendnet | tew827dru_stack_overflow_cve_2019_13279 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13279 | - |
| trendnet | tew827dru_stack_overflow_cve_2019_13280 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13280 | - |
| trendnet | tew_651br_tew_652brp_rce_cve_2019_13276 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13276, CVE-2019-13278 | rce |
| trendnet | tew_827dru_ping_command_injection_cve_2019_13150 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-13150 | rce |
| ubiquiti | airos_6_x | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | unifi_video_3_7_3_local_privilege_escalation_cve_2016_6914 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-6914 | - |
| udp_amplification.py | udp_amplification | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | dos_or_crash |
| upnp | igd_exploit | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | dos_or_crash |
| upnp | ssdp_msearch | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| wavlink | wn530hg4_password_disclosure_cve_2022_34047 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-34047 | - |
| wavlink | wn533a8_cross_site_scripting_xss_cve_2022_34048 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-34048 | - |
| wavlink | wn533a8_password_disclosure_cve_2022_34046 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-34046 | - |
| wordlist | wordlist_generator | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| x64 | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x64 | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x86 | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x86 | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| xiaomi | browser_10_2_4_g_browser_search_history_disclosure_cve_2018_20523 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-20523 | - |
| xiaomi | stock_firmware_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zhone | dasan_znid_2426a_eu_multiple_cross_site_scripting_cve_2019_10677 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-10677 | - |
| zte | f460_f660_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| zte | f460_f660_rce_cve_2014_2321 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-2321 | rce |
| zte | f660_config_download_decrypt | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-0329 | - |
| zte | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | mf65_bd_hdv6mf65v1_0_0b05_cross_site_scripting_cve_2018_7355 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-7355 | - |
| zte | router_f602w_captcha_bypass_cve_2020_6862 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-6862 | - |
| zte | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | zxdsl_831cii_improper_access_restrictions_cve_2017_16953 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-16953 | - |
| zte | zxhn_h108n_wifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| zte | zxhn_h168n_improper_access_restrictions_cve_2018_7357 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-7357, CVE-2018-7358 | - |
| zte | zxv10_h108l_cmd_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zte | zxv10_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zte | zxv10_w812n | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| zyxel | armor_x1_wap6806_directory_traversal_cve_2020_14461 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2020-14461 | path_traversal |
| zyxel | d1000_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | d1000_wifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| zyxel | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zyxel | nbg_418n_v2_modem_1_00_aaxm_6_c0_cross_site_request_forgery_cve_2019_6710 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-6710 | - |
| zyxel | nwa_1100_nh_command_injection_cve_2021_4039 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-4039 | - |
| zyxel | p660hn_t_v1_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | p660hn_t_v2_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | pk5001z_modem_backdoor_account_cve_2016_10401 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2016-10401 | backdoor |
| zyxel | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zyxel | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zyxel | usg_flex_5_21_os_command_injection_cve_2022_30525 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2022-30525 | - |
| zyxel | usg_flex_h_series_uos_1_31_privilege_escalation_cve_2025_1731 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2025-1731 | - |
| zyxel | vmg3312_b10b_dsl_491hnu_b1b_v2_modem_cross_site_request_forg_cve_2019_7391 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-7391 | - |
| zyxel | vmg8825_cmd_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | vmg8825_ping_cmd_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | vmg8825_ping_command_injection_cve_2019_9955 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-9955 | rce |
| zyxel | zywall_2_plus_internet_security_appliance_cross_site_scripti_cve_2021_46387 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2021-46387 | - |
| zyxel | zywall_310_zywall_110_usg1900_atp500_usg40_login_page_cross_cve_2019_9955 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-9955 | - |

## Modules By Vendor/Product

### 2wire / 4011g_5012nv_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/2wire/4011g_5012nv_path_traversal.py`

### 2wire / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/2wire/ftp_default_creds.py`

### 2wire / gateway_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/2wire/gateway_auth_bypass.py`

### 2wire / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/2wire/ssh_default_creds.py`

### 2wire / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/2wire/telnet_default_creds.py`

### 3com / ap8760_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/3com/ap8760_password_disclosure.py`

### 3com / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/3com/ftp_default_creds.py`

### 3com / imc_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/3com/imc_info_disclosure.py`

### 3com / imc_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/3com/imc_path_traversal.py`

### 3com / officeconnect_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/3com/officeconnect_info_disclosure.py`

### 3com / officeconnect_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/3com/officeconnect_rce.py`

### 3com / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/3com/ssh_default_creds.py`

### 3com / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/3com/telnet_default_creds.py`

### actiontec / mi424wr_rce_cve_2014_9583

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9583
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/actiontec/mi424wr_rce_cve_2014_9583.py`

### arcadyan / o2_box_6431_password_disclosure_cve_2015_7288

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-7288
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/arcadyan/o2_box_6431_password_disclosure_cve_2015_7288.py`

### armle / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/armle/bind_tcp.py`

### armle / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/armle/reverse_tcp.py`

### arris / router_firmware_9_1_103_remote_code_execution_rce_authentica_cve_2022_45701

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-45701
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/arris/router_firmware_9_1_103_remote_code_execution_rce_authentica_cve_2022_45701.py`

### arris / tm602a_password_of_the_day

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/arris/tm602a_password_of_the_day.py`

### aruba / airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-8526, CVE-2016-8527
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/aruba/airwave_8_2_3_xml_external_entity_injection_cross_site_scrip_cve_2016_8526.py`

### aruba / clearpass_policy_manager_6_7_0_unauthenticated_remote_comman_cve_2020_7115

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-7115
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/aruba/clearpass_policy_manager_6_7_0_unauthenticated_remote_comman_cve_2020_7115.py`

### aruba / instant_8_7_1_0_arbitrary_file_modification_cve_2021_25155

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-25155
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/aruba/instant_8_7_1_0_arbitrary_file_modification_cve_2021_25155.py`

### aruba / instant_iap_remote_code_execution_cve_2021_25155

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-25155, CVE-2021-25156, CVE-2021-25157, CVE-2021-25158, CVE-2021-25159, CVE-2021-25160, CVE-2021-25161, CVE-2021-25162
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/aruba/instant_iap_remote_code_execution_cve_2021_25155.py`

### asmax / ar_1004g_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/asmax/ar_1004g_password_disclosure.py`

### asmax / ar_804_gu_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/asmax/ar_804_gu_rce.py`

### asmax / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asmax/ftp_default_creds.py`

### asmax / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asmax/ssh_default_creds.py`

### asmax / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asmax/telnet_default_creds.py`

### asmax / webinterface_http_auth_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asmax/webinterface_http_auth_default_creds.py`

### asus / asmb8_ikvm_1_14_51_remote_code_execution_rce_cve_2023_26602

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-26602
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/asus/asmb8_ikvm_1_14_51_remote_code_execution_rce_cve_2023_26602.py`

### asus / asus_rt_n56u_remote_root_shell_exploit_apps_name_cve_2013_6343

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-6343
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/asus/asus_rt_n56u_remote_root_shell_exploit_apps_name_cve_2013_6343.py`

### asus / asustor_adm_3_1_2rhg1_remote_code_execution_cve_2018_11510

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-11510
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/asus/asustor_adm_3_1_2rhg1_remote_code_execution_cve_2018_11510.py`

### asus / asuswrt_lan_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5999, CVE-2018-6000
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/asus/asuswrt_lan_rce.py`

### asus / exploitdb_49036_rb_cve_2018_9285

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-9285
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/asus/exploitdb_49036_rb_cve_2018_9285.py`

### asus / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asus/ftp_default_creds.py`

### asus / gamesdk_v1_0_0_4_gamesdk_exe_unquoted_service_path_cve_2022_35899

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-35899
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/asus/gamesdk_v1_0_0_4_gamesdk_exe_unquoted_service_path_cve_2022_35899.py`

### asus / hg100_denial_of_service_cve_2018_11492

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-11492
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/asus/hg100_denial_of_service_cve_2018_11492.py`

### asus / infosvr_authentication_bypass_command_execution_metasploit_cve_2014_9583

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9583
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/asus/infosvr_authentication_bypass_command_execution_metasploit_cve_2014_9583.py`

### asus / infosvr_backdoor_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/asus/infosvr_backdoor_rce.py`

### asus / precision_touchpad_11_0_0_25_denial_of_service_cve_2019_10709

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-10709
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/asus/precision_touchpad_11_0_0_25_denial_of_service_cve_2019_10709.py`

### asus / rt_n16_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/asus/rt_n16_password_disclosure.py`

### asus / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asus/ssh_default_creds.py`

### asus / stack_overflow_cve_2017_11345

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11345
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/asus/stack_overflow_cve_2017_11345.py`

### asus / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asus/telnet_default_creds.py`

### belkin / auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass, creds_disclosure
- Module paths:
  - `modules/exploits/routers/belkin/auth_bypass.py`

### belkin / f9k1009_f9k1010_2_00_04_2_00_09_hard_coded_credentials_cve_2025_8730

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-8730
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/belkin/f9k1009_f9k1010_2_00_04_2_00_09_hard_coded_credentials_cve_2025_8730.py`

### belkin / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/belkin/ftp_default_creds.py`

### belkin / g_n150_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2012-2765
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/belkin/g_n150_password_disclosure.py`

### belkin / g_plus_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2008-0403
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/belkin/g_plus_info_disclosure.py`

### belkin / n150_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/belkin/n150_path_traversal.py`

### belkin / n750_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-1635
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/belkin/n750_rce.py`

### belkin / play_max_prce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/belkin/play_max_prce.py`

### belkin / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/belkin/ssh_default_creds.py`

### belkin / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/belkin/telnet_default_creds.py`

### bhu / bhu_urouter_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/bhu/bhu_urouter_rce.py`

### bhu / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/bhu/ftp_default_creds.py`

### bhu / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/bhu/ssh_default_creds.py`

### bhu / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/bhu/telnet_default_creds.py`

### billion / billion_5200w_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/billion/billion_5200w_rce.py`

### billion / billion_7700nr4_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/billion/billion_7700nr4_password_disclosure.py`

### billion / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/billion/ftp_default_creds.py`

### billion / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/billion/ssh_default_creds.py`

### billion / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/billion/telnet_default_creds.py`

### cerio / multi_rce_cve_2018_18852

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-18852
- Attack classes: rce
- Module paths:
  - `modules/exploits/soho_edge/cerio/multi_rce_cve_2018_18852.py`

### cisco / adaptive_security_appliance_path_traversal_cve_2018_0296

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0296
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/adaptive_security_appliance_path_traversal_cve_2018_0296.py`

### cisco / adaptive_security_appliance_path_traversal_metasploit_cve_2018_0296

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0296
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/adaptive_security_appliance_path_traversal_metasploit_cve_2018_0296.py`

### cisco / adaptive_security_appliance_software_9_11_local_file_inclusi_cve_2020_3452

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-3452
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/adaptive_security_appliance_software_9_11_local_file_inclusi_cve_2020_3452.py`

### cisco / adaptive_security_appliance_software_9_7_unauthenticated_arb_cve_2020_3187

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-3187
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/adaptive_security_appliance_software_9_7_unauthenticated_arb_cve_2020_3187.py`

### cisco / anyconnect_secure_mobility_client_4_3_04027_local_privilege_cve_2017_3813

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3813
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/anyconnect_secure_mobility_client_4_3_04027_local_privilege_cve_2017_3813.py`

### cisco / asa_8_x_extrabacon_authentication_bypass_cve_2016_6366

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6366
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/asa_8_x_extrabacon_authentication_bypass_cve_2016_6366.py`

### cisco / asa_9_14_1_10_and_ftd_6_6_0_1_path_traversal_2_cve_2020_3452

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-3452
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/asa_9_14_1_10_and_ftd_6_6_0_1_path_traversal_2_cve_2020_3452.py`

### cisco / asa_and_ftd_9_6_4_42_path_traversal_cve_2020_3452

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-3452
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/asa_and_ftd_9_6_4_42_path_traversal_cve_2020_3452.py`

### cisco / asa_crash_poc_cve_2018_0101

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0101
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/asa_crash_poc_cve_2018_0101.py`

### cisco / asa_pix_epicbanana_local_privilege_escalation_cve_2016_6367

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6367
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/asa_pix_epicbanana_local_privilege_escalation_cve_2016_6367.py`

### cisco / asa_software_8_x_9_x_ikev1_ikev2_buffer_overflow_cve_2016_1287

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1287
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/asa_software_8_x_9_x_ikev1_ikev2_buffer_overflow_cve_2016_1287.py`

### cisco / asa_webvpn_cifs_handling_buffer_overflow_cve_2017_3807

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3807
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/asa_webvpn_cifs_handling_buffer_overflow_cve_2017_3807.py`

### cisco / catalyst_2960_ios_12_2_55_se11_rocem_remote_code_execution_cve_2017_3881

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3881
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/catalyst_2960_ios_12_2_55_se11_rocem_remote_code_execution_cve_2017_3881.py`

### cisco / catalyst_2960_ios_12_2_55_se1_rocem_remote_code_execution_cve_2017_3881

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3881
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/catalyst_2960_ios_12_2_55_se1_rocem_remote_code_execution_cve_2017_3881.py`

### cisco / catalyst_2960_rocem

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3881
- Attack classes: none
- Module paths:
  - `modules/exploits/switches/cisco/catalyst_2960_rocem.py`

### cisco / cisco_firepower_management_center_cve_2023_20048

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-20048
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/cisco_firepower_management_center_cve_2023_20048.py`

### cisco / data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15976, CVE-2019-15984
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/data_center_network_manager_11_2_1_getvmhostdata_sql_injecti_cve_2019_15976.py`

### cisco / data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15977, CVE-2019-15978
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/data_center_network_manager_11_2_1_lanfabricimpl_command_inj_cve_2019_15977.py`

### cisco / data_center_network_manager_11_2_remote_code_execution_cve_2019_15975

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15975
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/data_center_network_manager_11_2_remote_code_execution_cve_2019_15975.py`

### cisco / data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1619, CVE-2019-1620, CVE-2019-1622
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/data_center_network_manager_unauthenticated_remote_code_exec_cve_2019_1619.py`

### cisco / dcnm_jboss_10_4_credential_leakage_cve_2019_15999

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15999
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/cisco/dcnm_jboss_10_4_credential_leakage_cve_2019_15999.py`

### cisco / dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15993, CVE-2020-5330
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/dell_emc_networking_pc5500_firmware_versions_4_1_0_22_and_sx_cve_2019_15993.py`

### cisco / digital_network_architecture_center_1_3_1_4_persistent_cross_cve_2019_15253

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15253
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/digital_network_architecture_center_1_3_1_4_persistent_cross_cve_2019_15253.py`

### cisco / dpc2420_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/cisco/dpc2420_info_disclosure.py`

### cisco / dpc3928_router_arbitrary_file_disclosure_cve_2017_11502

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11502
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/dpc3928_router_arbitrary_file_disclosure_cve_2017_11502.py`

### cisco / epc_3928_multiple_vulnerabilities_cve_2015_6401

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-6401, CVE-2015-6402, CVE-2016-1328, CVE-2016-1336, CVE-2016-1337
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/epc_3928_multiple_vulnerabilities_cve_2015_6401.py`

### cisco / firepower_management_center_6_2_2_2_6_2_3_cross_site_scripti_cve_2019_1642

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1642
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/firepower_management_center_6_2_2_2_6_2_3_cross_site_scripti_cve_2019_1642.py`

### cisco / firepower_management_console_6_0_post_authentication_useradd_cve_2016_6433

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6433
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/firepower_management_console_6_0_post_authentication_useradd_cve_2016_6433.py`

### cisco / firepower_threat_management_console_6_0_1_hard_coded_mysql_c_cve_2016_6434

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6434
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/firepower_threat_management_console_6_0_1_hard_coded_mysql_c_cve_2016_6434.py`

### cisco / firepower_threat_management_console_6_0_1_local_file_inclusi_cve_2016_6435

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6435
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/firepower_threat_management_console_6_0_1_local_file_inclusi_cve_2016_6435.py`

### cisco / firepower_threat_management_console_6_0_1_remote_command_exe_cve_2016_6433

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6433
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/firepower_threat_management_console_6_0_1_remote_command_exe_cve_2016_6433.py`

### cisco / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/cisco/ftp_default_creds.py`

### cisco / immunet_6_2_0_amp_for_endpoints_6_2_0_denial_of_service_cve_2018_15437

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-15437
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/cisco/immunet_6_2_0_amp_for_endpoints_6_2_0_denial_of_service_cve_2018_15437.py`

### cisco / ios_12_2_12_4_15_0_15_6_security_association_negotiation_req_cve_2016_6415

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6415
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ios_12_2_12_4_15_0_15_6_security_association_negotiation_req_cve_2016_6415.py`

### cisco / ios_http_authorization_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2001-0537
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ios_http_authorization_bypass.py`

### cisco / ios_remote_code_execution_cve_2017_6736

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6736
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ios_remote_code_execution_cve_2017_6736.py`

### cisco / ip_phone_11_7_denial_of_service_poc_cve_2020_3161

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-3161
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/cisco/ip_phone_11_7_denial_of_service_poc_cve_2020_3161.py`

### cisco / ise_3_0_authorization_bypass_cve_2025_20125

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-20125
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/cisco/ise_3_0_authorization_bypass_cve_2025_20125.py`

### cisco / ise_3_0_remote_code_execution_rce_cve_2025_20124

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-20124
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/cisco/ise_3_0_remote_code_execution_rce_cve_2025_20124.py`

### cisco / node_jos_0_11_0_re_sign_tokens_cve_2018_0114

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0114
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/node_jos_0_11_0_re_sign_tokens_cve_2018_0114.py`

### cisco / prime_collaboration_provisioning_12_1_authentication_bypass_cve_2017_6622

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6622
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/prime_collaboration_provisioning_12_1_authentication_bypass_cve_2017_6622.py`

### cisco / prime_infrastructure_health_monitor_ha_tararchive_directory_cve_2019_1821

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1821
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/prime_infrastructure_health_monitor_ha_tararchive_directory_cve_2019_1821.py`

### cisco / prime_infrastructure_health_monitor_tararchive_directory_tra_cve_2019_1821

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1821
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/prime_infrastructure_health_monitor_tararchive_directory_tra_cve_2019_1821.py`

### cisco / prime_infrastructure_unauthenticated_remote_code_execution_cve_2018_15379

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-15379
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/prime_infrastructure_unauthenticated_remote_code_execution_cve_2018_15379.py`

### cisco / rv110w_password_disclosure_command_execution_cve_2014_0683

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-0683, CVE-2015-6396
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv110w_password_disclosure_command_execution_cve_2014_0683.py`

### cisco / rv110w_rv130_w_rv215w_routers_management_interface_remote_co_cve_2019_1663

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1663
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv110w_rv130_w_rv215w_routers_management_interface_remote_co_cve_2019_1663.py`

### cisco / rv130w_1_0_3_44_remote_stack_overflow_cve_2019_1663

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1663
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv130w_1_0_3_44_remote_stack_overflow_cve_2019_1663.py`

### cisco / rv130w_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1663
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/cisco/rv130w_rce.py`

### cisco / rv130w_routers_management_interface_remote_command_execution_cve_2019_1663

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1663
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv130w_routers_management_interface_remote_command_execution_cve_2019_1663.py`

### cisco / rv300_rv320_information_disclosure_cve_2019_1653

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1653
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653.py`

### cisco / rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1652, CVE-2019-1653
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv320_and_rv325_unauthenticated_remote_code_execution_metasp_cve_2019_1652.py`

### cisco / rv320_command_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1652
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/cisco/rv320_command_injection.py`

### cisco / rv320_dual_gigabit_wan_vpn_router_1_4_2_15_command_injection_cve_2019_1652

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1652
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/rv320_dual_gigabit_wan_vpn_router_1_4_2_15_command_injection_cve_2019_1652.py`

### cisco / small_business_200_300_500_switches_multiple_vulnerabilities_cve_2019_1943

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1943
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/small_business_200_300_500_switches_multiple_vulnerabilities_cve_2019_1943.py`

### cisco / small_business_220_series_multiple_vulnerabilities_cve_2019_1912

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1912, CVE-2019-1913, CVE-2019-1914
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/small_business_220_series_multiple_vulnerabilities_cve_2019_1912.py`

### cisco / smart_install_crash_poc_cve_2018_0171

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0171
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/smart_install_crash_poc_cve_2018_0171.py`

### cisco / smart_software_manager_on_prem_8_202206_account_takeover_cve_2024_20419

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-20419
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/smart_software_manager_on_prem_8_202206_account_takeover_cve_2024_20419.py`

### cisco / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/cisco/ssh_default_creds.py`

### cisco / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/cisco/telnet_default_creds.py`

### cisco / ucs_director_default_scpuser_password_metasploit_cve_2019_1935

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1935
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ucs_director_default_scpuser_password_metasploit_cve_2019_1935.py`

### cisco / ucs_imc_supervisor_2_2_0_0_authentication_bypass_cve_2019_1937

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1937
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ucs_imc_supervisor_2_2_0_0_authentication_bypass_cve_2019_1937.py`

### cisco / ucs_manager_2_1_1b_remote_command_injection_shellshock_cve_2014_6278

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-6278
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/cisco/ucs_manager_2_1_1b_remote_command_injection_shellshock_cve_2014_6278.py`

### cisco / ucs_platform_emulator_3_1_2epe1_remote_code_execution_cve_2017_12243

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-12243
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ucs_platform_emulator_3_1_2epe1_remote_code_execution_cve_2017_12243.py`

### cisco / umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-0437, CVE-2018-0438
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/umbrella_roaming_client_2_0_168_local_privilege_escalation_cve_2018_0437.py`

### cisco / unified_communications_manager_7_8_9_directory_traversal_cve_2013_5528

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-5528
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/cisco/unified_communications_manager_7_8_9_directory_traversal_cve_2013_5528.py`

### cisco / webex_meetings_33_6_6_33_9_1_privilege_escalation_cve_2019_1674

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1674
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/webex_meetings_33_6_6_33_9_1_privilege_escalation_cve_2019_1674.py`

### cisco / webex_player_t29_10_arf_out_of_bounds_memory_corruption_cve_2016_1415

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1415
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/webex_player_t29_10_arf_out_of_bounds_memory_corruption_cve_2016_1415.py`

### cisco / webex_player_t29_10_wrf_use_after_free_memory_corruption_cve_2016_1464

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1464
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/webex_player_t29_10_wrf_use_after_free_memory_corruption_cve_2016_1464.py`

### cisco / wireless_controller_3_6_10e_cross_site_request_forgery_cve_2019_12624

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-12624
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/wireless_controller_3_6_10e_cross_site_request_forgery_cve_2019_12624.py`

### cisco / wlc_2504_8_9_denial_of_service_poc_cve_2019_15276

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-15276
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/cisco/wlc_2504_8_9_denial_of_service_poc_cve_2019_15276.py`

### cmd / awk_bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/awk_bind_tcp.py`

### cmd / awk_bind_udp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/awk_bind_udp.py`

### cmd / awk_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/awk_reverse_tcp.py`

### cmd / bash_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/bash_reverse_tcp.py`

### cmd / netcat_bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/netcat_bind_tcp.py`

### cmd / netcat_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/netcat_reverse_tcp.py`

### cmd / perl_bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/perl_bind_tcp.py`

### cmd / perl_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/perl_reverse_tcp.py`

### cmd / php_bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/php_bind_tcp.py`

### cmd / php_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/php_reverse_tcp.py`

### cmd / python_bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/python_bind_tcp.py`

### cmd / python_bind_udp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/python_bind_udp.py`

### cmd / python_reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/python_reverse_tcp.py`

### cmd / python_reverse_udp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/cmd/python_reverse_udp.py`

### comtrend / ct_5361t_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/comtrend/ct_5361t_password_disclosure.py`

### comtrend / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/comtrend/ftp_default_creds.py`

### comtrend / persistent_xss_on_comtrend_ar_5387un_router_cve_2018_8062

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-8062
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/comtrend/persistent_xss_on_comtrend_ar_5387un_router_cve_2018_8062.py`

### comtrend / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/comtrend/ssh_default_creds.py`

### comtrend / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/comtrend/telnet_default_creds.py`

### comtrend / vr_3033_command_injection_cve_2020_10173

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-10173
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/comtrend/vr_3033_command_injection_cve_2020_10173.py`

### cve / cve_lookup

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/cve/cve_lookup.py`

### dlink / central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-17440, CVE-2018-17441, CVE-2018-17442, CVE-2018-17443
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/central_wifimanager_software_controller_1_03_multiple_vulner_cve_2018_17440.py`

### dlink / dap_1620_a1_v1_01_directory_traversal_cve_2021_46381

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-46381
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dap_1620_a1_v1_01_directory_traversal_cve_2021_46381.py`

### dlink / dcs_5020l_remote_code_execution_poc_cve_2017_17020

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17020
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dcs_5020l_remote_code_execution_poc_cve_2017_17020.py`

### dlink / dcs_930l_auth_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dcs_930l_auth_rce.py`

### dlink / dcs_931l_arbitrary_file_upload_metasploit_cve_2015_2049

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-2049
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dcs_931l_arbitrary_file_upload_metasploit_cve_2015_2049.py`

### dlink / dcs_936l_network_camera_cross_site_request_forgery_cve_2017_7851

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-7851
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dcs_936l_network_camera_cross_site_request_forgery_cve_2017_7851.py`

### dlink / dcs_cred_disclosure_cve_2020_25078

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-25078
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dcs_cred_disclosure_cve_2020_25078.py`

### dlink / dcs_series_cameras_insecure_crossdomain_cve_2017_7852

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-7852
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dcs_series_cameras_insecure_crossdomain_cve_2017_7852.py`

### dlink / devices_unauthenticated_remote_command_execution_in_ssdpcgi_cve_2019_20215

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-20215
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/devices_unauthenticated_remote_command_execution_in_ssdpcgi_cve_2019_20215.py`

### dlink / dgs_1510_add_user

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/switches/dlink/dgs_1510_add_user.py`

### dlink / dgs_1510_multiple_vulnerabilities_cve_2017_6206

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6206
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dgs_1510_multiple_vulnerabilities_cve_2017_6206.py`

### dlink / di_524_cross_site_request_forgery_cve_2017_5633

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-5633
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/di_524_cross_site_request_forgery_cve_2017_5633.py`

### dlink / di_524_v2_06ru_multiple_cross_site_scripting_cve_2019_11017

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-11017
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/di_524_v2_06ru_multiple_cross_site_scripting_cve_2019_11017.py`

### dlink / dir601_cred_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/dlink/dir601_cred_disclosure.py`

### dlink / dir845l_cred_disclosure_cve_2024_33113

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-33113
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir845l_cred_disclosure_cve_2024_33113.py`

### dlink / dir850_insecure_access_control_cve_2021_46378

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-46378
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir850_insecure_access_control_cve_2021_46378.py`

### dlink / dir850_open_redirect_cve_2021_46379

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-46379
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir850_open_redirect_cve_2021_46379.py`

### dlink / dir890l_soapaction_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir890l_soapaction_rce.py`

### dlink / dir_300_320_600_615_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_300_320_600_615_info_disclosure.py`

### dlink / dir_300_320_615_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/dlink/dir_300_320_615_auth_bypass.py`

### dlink / dir_300_600_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_300_600_rce.py`

### dlink / dir_300_645_815_upnp_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_300_645_815_upnp_rce.py`

### dlink / dir_600_authentication_bypass_cve_2017_12943

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-12943
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_600_authentication_bypass_cve_2017_12943.py`

### dlink / dir_600m_authentication_bypass_metasploit_cve_2019_13101

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13101
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_600m_authentication_bypass_metasploit_cve_2019_13101.py`

### dlink / dir_600m_wireless_cross_site_scripting_cve_2018_6936

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-6936
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_600m_wireless_cross_site_scripting_cve_2018_6936.py`

### dlink / dir_601_admin_password_disclosure_cve_2018_5708

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5708
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_601_admin_password_disclosure_cve_2018_5708.py`

### dlink / dir_601_credential_disclosure_cve_2018_12710

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-12710
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_601_credential_disclosure_cve_2018_12710.py`

### dlink / dir_605l_2_08_denial_of_service_cve_2017_9675

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-9675
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/dlink/dir_605l_2_08_denial_of_service_cve_2017_9675.py`

### dlink / dir_615_cross_site_request_forgery_cve_2017_7398

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-7398
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_cross_site_request_forgery_cve_2017_7398.py`

### dlink / dir_615_denial_of_service_poc_cve_2018_15839

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-15839
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_denial_of_service_poc_cve_2018_15839.py`

### dlink / dir_615_privilege_escalation_cve_2019_19743

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-19743
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_privilege_escalation_cve_2019_19743.py`

### dlink / dir_615_t1_20_10_captcha_bypass_cve_2019_17525

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-17525
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_t1_20_10_captcha_bypass_cve_2019_17525.py`

### dlink / dir_615_wireless_router_persistent_cross_site_scripting_cve_2018_10110

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10110
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_wireless_router_persistent_cross_site_scripting_cve_2018_10110.py`

### dlink / dir_615_wireless_router_persistent_cross_site_scripting_cve_2019_19742

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-19742
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_615_wireless_router_persistent_cross_site_scripting_cve_2019_19742.py`

### dlink / dir_645_815_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_645_815_rce.py`

### dlink / dir_645_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_645_password_disclosure.py`

### dlink / dir_655_866_652_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-16920
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_655_866_652_rce.py`

### dlink / dir_815_850l_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_815_850l_rce.py`

### dlink / dir_819_a1_denial_of_service_cve_2022_40946

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-40946
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/dlink/dir_819_a1_denial_of_service_cve_2022_40946.py`

### dlink / dir_825_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dir_825_path_traversal.py`

### dlink / dir_825_rev_b_2_10_stack_buffer_overflow_dos_cve_2025_10666

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-10666
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/dlink/dir_825_rev_b_2_10_stack_buffer_overflow_dos_cve_2025_10666.py`

### dlink / dir_846_remote_command_execution_rce_vulnerability_cve_2022_46552

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-46552
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dir_846_remote_command_execution_rce_vulnerability_cve_2022_46552.py`

### dlink / dir_850l_creds_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_850l_creds_disclosure.py`

### dlink / dir_850l_wireless_ac1200_dual_band_gigabit_cloud_router_auth_cve_2018_9032

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-9032
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_850l_wireless_ac1200_dual_band_gigabit_cloud_router_auth_cve_2018_9032.py`

### dlink / dir_8xx_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_8xx_password_disclosure.py`

### dlink / dir_series_routers_hnap_login_stack_buffer_overflow_metasplo_cve_2016_6563

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6563
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dir_series_routers_hnap_login_stack_buffer_overflow_metasplo_cve_2016_6563.py`

### dlink / dns_320l_327l_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dns_320l_327l_rce.py`

### dlink / dsl_2640b_dns_change

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: dns_change
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2640b_dns_change.py`

### dlink / dsl_2730_2750_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2730_2750_path_traversal.py`

### dlink / dsl_2730b_2780b_526b_dns_change

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: dns_change
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2730b_2780b_526b_dns_change.py`

### dlink / dsl_2730u_wireless_n_150_cross_site_request_forgery_cve_2017_6411

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6411
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2730u_wireless_n_150_cross_site_request_forgery_cve_2017_6411.py`

### dlink / dsl_2740r_dns_change

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: dns_change
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2740r_dns_change.py`

### dlink / dsl_2750b_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2750b_info_disclosure.py`

### dlink / dsl_2750b_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dsl_2750b_rce.py`

### dlink / dsl_3782_authentication_bypass_cve_2018_8898

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-8898
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dsl_3782_authentication_bypass_cve_2018_8898.py`

### dlink / dsp_w110_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/soho_edge/dlink/dsp_w110_rce.py`

### dlink / dsr_250n_3_12_denial_of_service_poc_cve_2020_26567

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-26567
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/dlink/dsr_250n_3_12_denial_of_service_poc_cve_2020_26567.py`

### dlink / dvg_n5402sp_multiple_vulnerabilities_cve_2015_7245

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-7245, CVE-2015-7246, CVE-2015-7247
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dvg_n5402sp_multiple_vulnerabilities_cve_2015_7245.py`

### dlink / dvg_n5402sp_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dvg_n5402sp_path_traversal.py`

### dlink / dwl_2600_authenticated_remote_command_injection_metasploit_cve_2019_20499

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-20499
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dwl_2600_authenticated_remote_command_injection_metasploit_cve_2019_20499.py`

### dlink / dwl_2600ap_multiple_os_command_injection_cve_2019_20499

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-20499, CVE-2019-20500, CVE-2019-20501
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dwl_2600ap_multiple_os_command_injection_cve_2019_20499.py`

### dlink / dwl_3200ap_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/soho_edge/dlink/dwl_3200ap_password_disclosure.py`

### dlink / dwr_116_dwr_116a1_arbitrary_file_download_cve_2017_6190

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6190
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dwr_116_dwr_116a1_arbitrary_file_download_cve_2017_6190.py`

### dlink / dwr_932_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dwr_932_info_disclosure.py`

### dlink / dwr_932b_backdoor

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/dlink/dwr_932b_backdoor.py`

### dlink / exploitdb_30062_py_cve_2013_5946

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-5945, CVE-2013-5946
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/exploitdb_30062_py_cve_2013_5946.py`

### dlink / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/dlink/ftp_default_creds.py`

### dlink / hedwig_rce_cve_2013_7389

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-7389
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/hedwig_rce_cve_2013_7389.py`

### dlink / multi_hedwig_cgi_exec

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/multi_hedwig_cgi_exec.py`

### dlink / multi_hnap_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/multi_hnap_rce.py`

### dlink / routers_command_injection_cve_2018_10823

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10823
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/routers_command_injection_cve_2018_10823.py`

### dlink / routers_directory_traversal_cve_2018_10822

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10822
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/routers_directory_traversal_cve_2018_10822.py`

### dlink / routers_plaintext_password_cve_2018_10824

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10824
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/routers_plaintext_password_cve_2018_10824.py`

### dlink / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/dlink/ssh_default_creds.py`

### dlink / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/dlink/telnet_default_creds.py`

### dlink_dsl / dsl_2640b_wps_rce_cve_2013_5223

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-5223
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink_dsl/dsl_2640b_wps_rce_cve_2013_5223.py`

### dlink_dsl / dsl_2750b_remote_code_execution_cve_2016_20017

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-20017
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink_dsl/dsl_2750b_remote_code_execution_cve_2016_20017.py`

### draytek / multiple_products_pre_authentication_remote_root_code_execut_cve_2020_8515

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-8515
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/draytek/multiple_products_pre_authentication_remote_root_code_execut_cve_2020_8515.py`

### draytek / vigor_master_key

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/draytek/vigor_master_key.py`

### external / exploitdb_embedded_lookup

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/external/exploitdb_embedded_lookup.py`

### external / metasploit_console_bridge

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/external/metasploit_console_bridge.py`

### external / metasploit_rb_inspect

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/external/metasploit_rb_inspect.py`

### external / mikrotikapi_bf_bridge

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/external/mikrotikapi_bf_bridge.py`

### fiberhome / adsl_an1020_25_improper_access_restrictions_cve_2017_14147

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-14147
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fiberhome/adsl_an1020_25_improper_access_restrictions_cve_2017_14147.py`

### fiberhome / an5506_04_f_rp2669_persistent_cross_site_scripting_cve_2019_9556

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-9556
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fiberhome/an5506_04_f_rp2669_persistent_cross_site_scripting_cve_2019_9556.py`

### fiberhome / directory_traversal_cve_2017_15647

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-15647
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/fiberhome/directory_traversal_cve_2017_15647.py`

### fiberhome / lm53q1_multiple_vulnerabilities_cve_2017_16885

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-16885, CVE-2017-16886, CVE-2017-16887
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fiberhome/lm53q1_multiple_vulnerabilities_cve_2017_16885.py`

### fiberhome / vdsl2_modem_hg_150_ub_authentication_bypass_cve_2018_9248

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-9248
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fiberhome/vdsl2_modem_hg_150_ub_authentication_bypass_cve_2018_9248.py`

### fortinet / forticlient_5_2_3_windows_10_x64_creators_local_privilege_es_cve_2015_4077

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-4077, CVE-2015-5736
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_creators_local_privilege_es_cve_2015_4077.py`

### fortinet / forticlient_5_2_3_windows_10_x64_post_anniversary_local_priv_cve_2015_5736

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-5736
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_post_anniversary_local_priv_cve_2015_5736.py`

### fortinet / forticlient_5_2_3_windows_10_x64_pre_anniversary_local_privi_cve_2015_5736

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-5736
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/forticlient_5_2_3_windows_10_x64_pre_anniversary_local_privi_cve_2015_5736.py`

### fortinet / fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1909
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/fortinet/fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909.py`

### fortinet / fortigate_fortios_6_0_3_ldap_credential_disclosure_cve_2018_13374

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-13374
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/fortinet/fortigate_fortios_6_0_3_ldap_credential_disclosure_cve_2018_13374.py`

### fortinet / fortimail_7_0_1_reflected_cross_site_scripting_xss_cve_2021_43062

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-43062
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/fortimail_7_0_1_reflected_cross_site_scripting_xss_cve_2021_43062.py`

### fortinet / fortios_5_6_0_cross_site_scripting_cve_2017_3131

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3131, CVE-2017-3132, CVE-2017-3133
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/fortios_5_6_0_cross_site_scripting_cve_2017_3131.py`

### fortinet / fortios_5_6_3_5_6_7_fortios_6_0_0_6_0_4_credentials_disclosu_cve_2018_13379

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-13379
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/fortios_5_6_3_5_6_7_fortios_6_0_0_6_0_4_credentials_disclosu_cve_2018_13379.py`

### fortinet / fortios_6_0_4_unauthenticated_ssl_vpn_user_password_modifica_cve_2018_13382

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-13382
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/fortinet/fortios_6_0_4_unauthenticated_ssl_vpn_user_password_modifica_cve_2018_13382.py`

### fortinet / fortios_fortiproxy_and_fortiswitchmanager_7_2_0_authenticati_cve_2022_40684

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-40684
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/fortinet/fortios_fortiproxy_and_fortiswitchmanager_7_2_0_authenticati_cve_2022_40684.py`

### ftp_bruteforce.py / ftp_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/ftp_bruteforce.py`

### ftp_default.py / ftp_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/ftp_default.py`

### gpon / alcatel_lucent_nokia_i_240w_q_buffer_overflow_cve_2019_3921

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-3921
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/gpon/alcatel_lucent_nokia_i_240w_q_buffer_overflow_cve_2019_3921.py`

### gpon / home_gateway_rce_cve_2018_10562

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10561, CVE-2018-10562
- Attack classes: auth_bypass, rce
- Module paths:
  - `modules/exploits/routers/gpon/home_gateway_rce_cve_2018_10562.py`

### gpon / routers_authentication_bypass_command_injection_cve_2018_10561

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10561, CVE-2018-10562
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/gpon/routers_authentication_bypass_command_injection_cve_2018_10561.py`

### gpon / skyworth_homegateways_and_optical_network_terminals_stack_ov_cve_2018_19524

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-19524
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/gpon/skyworth_homegateways_and_optical_network_terminals_stack_ov_cve_2018_19524.py`

### heartbleed.py / heartbleed

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/generic/heartbleed.py`

### hootoo / tripmate_arbitrary_file_upload

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/soho_edge/hootoo/tripmate_arbitrary_file_upload.py`

### hootoo / tripmate_open_forwarding_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/soho_edge/hootoo/tripmate_open_forwarding_rce.py`

### hootoo / tripmate_sysfirm_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/soho_edge/hootoo/tripmate_sysfirm_rce.py`

### http_basic_digest_bruteforce.py / http_basic_digest_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/http_basic_digest_bruteforce.py`

### http_basic_digest_default.py / http_basic_digest_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/http_basic_digest_default.py`

### http_form_char_by_char_oracle.py / http_form_char_by_char_oracle

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/generic/http_form_char_by_char_oracle.py`

### http_multi_auth_default.py / http_multi_auth_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/http_multi_auth_default.py`

### http_web_form_bruteforce.py / http_web_form_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/http_web_form_bruteforce.py`

### huawei / b315s_22_information_leak_cve_2018_7921

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-7921
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/b315s_22_information_leak_cve_2018_7921.py`

### huawei / e5330_21_210_09_00_158_cross_site_request_forgery_send_sms_cve_2014_5395

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-5395
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/e5330_21_210_09_00_158_cross_site_request_forgery_send_sms_cve_2014_5395.py`

### huawei / e5331_mifi_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/e5331_mifi_info_disclosure.py`

### huawei / eg8145x6_autopwn

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-6271, CVE-2017-17215, CVE-2018-10561, CVE-2018-10562, CVE-2025-49599
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_autopwn.py`

### huawei / eg8145x6_bruteforce_login

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_bruteforce_login.py`

### huawei / eg8145x6_config_decrypt

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_config_decrypt.py`

### huawei / eg8145x6_csrf_payload_generator

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-49599
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_csrf_payload_generator.py`

### huawei / eg8145x6_csrf_static_token

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_csrf_static_token.py`

### huawei / eg8145x6_dns_poison_csrf

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_dns_poison_csrf.py`

### huawei / eg8145x6_epuser_firewall_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-49599
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_epuser_firewall_bypass.py`

### huawei / eg8145x6_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_info_disclosure.py`

### huawei / eg8145x6_mitm_credential_intercept

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_mitm_credential_intercept.py`

### huawei / eg8145x6_preauth_password_enum

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_preauth_password_enum.py`

### huawei / eg8145x6_telnet_enable

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-49599
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_telnet_enable.py`

### huawei / eg8145x6_wifi_credential_extractor

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/eg8145x6_wifi_credential_extractor.py`

### huawei / espace_1_1_11_103_contactsctrl_dll_espacestatusctrl_dll_acti_cve_2014_9418

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9418
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/espace_1_1_11_103_contactsctrl_dll_espacestatusctrl_dll_acti_cve_2014_9418.py`

### huawei / espace_1_1_11_103_dll_hijacking_cve_2014_9416

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9416
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/espace_1_1_11_103_dll_hijacking_cve_2014_9416.py`

### huawei / espace_1_1_11_103_image_file_format_handling_buffer_overflow_cve_2014_9417

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9417
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/espace_1_1_11_103_image_file_format_handling_buffer_overflow_cve_2014_9417.py`

### huawei / espace_meeting_1_1_11_103_cenwpoll_dll_seh_buffer_overflow_u_cve_2014_9415

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9415
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/espace_meeting_1_1_11_103_cenwpoll_dll_seh_buffer_overflow_u_cve_2014_9415.py`

### huawei / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/huawei/ftp_default_creds.py`

### huawei / hg520_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/hg520_info_disclosure.py`

### huawei / hg530_hg520b_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/hg530_hg520b_password_disclosure.py`

### huawei / hg532_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17215
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/huawei/hg532_rce.py`

### huawei / hg532x_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/huawei/hg532x_path_traversal.py`

### huawei / hg630_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/hg630_info_disclosure.py`

### huawei / hg8240_auth_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/huawei/hg8240_auth_rce.py`

### huawei / hg8240_file_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/huawei/hg8240_file_traversal.py`

### huawei / hg866_password_change

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: password_reset_or_change
- Module paths:
  - `modules/exploits/routers/huawei/hg866_password_change.py`

### huawei / mate_7_dev_hifi_misc_privilege_escalation_cve_2015_8088

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-8088
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/mate_7_dev_hifi_misc_privilege_escalation_cve_2015_8088.py`

### huawei / router_hg532_arbitrary_command_execution_cve_2017_17215

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17215
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/router_hg532_arbitrary_command_execution_cve_2017_17215.py`

### huawei / router_hg532e_command_execution_cve_2015_7254

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-7254
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/router_hg532e_command_execution_cve_2015_7254.py`

### huawei / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/huawei/ssh_default_creds.py`

### huawei / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/huawei/telnet_default_creds.py`

### huawei / utps_unquoted_service_path_privilege_escalation_cve_2016_8769

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-8769
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/huawei/utps_unquoted_service_path_privilege_escalation_cve_2016_8769.py`

### intelbras / iwr_3000n_1_5_0_cross_site_request_forgery_cve_2019_11416

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-11416
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/iwr_3000n_1_5_0_cross_site_request_forgery_cve_2019_11416.py`

### intelbras / iwr_3000n_denial_of_service_remote_reboot_cve_2019_11415

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-11415
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/intelbras/iwr_3000n_denial_of_service_remote_reboot_cve_2019_11415.py`

### intelbras / ncloud_300_1_0_authentication_bypass_cve_2018_11094

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-11094
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/intelbras/ncloud_300_1_0_authentication_bypass_cve_2018_11094.py`

### intelbras / roteador_wireless_wrn150_cross_site_scripting_cve_2017_14219

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-14219
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/roteador_wireless_wrn150_cross_site_scripting_cve_2017_14219.py`

### intelbras / router_rf1200_1_1_3_cross_site_request_forgery_cve_2019_19516

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-19516
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/router_rf1200_1_1_3_cross_site_request_forgery_cve_2019_19516.py`

### intelbras / router_rf_301k_dns_hijacking_cross_site_request_forgery_csrf_cve_2021_32403

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-32403
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/router_rf_301k_dns_hijacking_cross_site_request_forgery_csrf_cve_2021_32403.py`

### intelbras / telefone_ip_tip200_lite_local_file_disclosure_cve_2018_9010

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-9010
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/telefone_ip_tip200_lite_local_file_disclosure_cve_2018_9010.py`

### intelbras / wireless_n_150mbps_wrn240_authentication_bypass_config_uploa_cve_2019_19142

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-19142
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/intelbras/wireless_n_150mbps_wrn240_authentication_bypass_config_uploa_cve_2019_19142.py`

### ipfire / 2_25_remote_code_execution_authenticated_cve_2021_33393

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-33393
- Attack classes: none
- Module paths:
  - `modules/exploits/soho_edge/ipfire/2_25_remote_code_execution_authenticated_cve_2021_33393.py`

### ipfire / ipfire_oinkcode_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/ipfire/ipfire_oinkcode_rce.py`

### ipfire / ipfire_proxy_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/ipfire/ipfire_proxy_rce.py`

### ipfire / ipfire_shellshock

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/ipfire/ipfire_shellshock.py`

### ipfire / shellshock_bash_environment_variable_command_injection_metas_cve_2014_6271

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-6271
- Attack classes: rce
- Module paths:
  - `modules/exploits/soho_edge/ipfire/shellshock_bash_environment_variable_command_injection_metas_cve_2014_6271.py`

### juniper / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/juniper/ftp_default_creds.py`

### juniper / junos_backdoor_cve_2015_7755

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-7755
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/juniper/junos_backdoor_cve_2015_7755.py`

### juniper / junos_web_auth_bypass_cve_2023_36845

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-36845
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/juniper/junos_web_auth_bypass_cve_2023_36845.py`

### juniper / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/juniper/ssh_default_creds.py`

### juniper / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/juniper/telnet_default_creds.py`

### lg / nas_3718

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/soho_edge/lg/nas_3718.py`

### linksys / 1500_2500_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/1500_2500_rce.py`

### linksys / ax3200_v1_1_00_command_injection_cve_2022_38841

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-38841
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/linksys/ax3200_v1_1_00_command_injection_cve_2022_38841.py`

### linksys / ea6100_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass, info_disclosure
- Module paths:
  - `modules/exploits/routers/linksys/ea6100_auth_bypass.py`

### linksys / ea7500_2_0_8_194281_cross_site_scripting_cve_2012_6708

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2012-6708
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/linksys/ea7500_2_0_8_194281_cross_site_scripting_cve_2012_6708.py`

### linksys / eseries_themoon_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/eseries_themoon_rce.py`

### linksys / eseries_tmunblock_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/eseries_tmunblock_rce.py`

### linksys / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/linksys/ftp_default_creds.py`

### linksys / re6500_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/re6500_rce.py`

### linksys / smartwifi_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-8243
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/linksys/smartwifi_password_disclosure.py`

### linksys / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/linksys/ssh_default_creds.py`

### linksys / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/linksys/telnet_default_creds.py`

### linksys / wap54gv3_debug_rce_cve_2010_1573

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2010-1573
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/wap54gv3_debug_rce_cve_2010_1573.py`

### linksys / wap54gv3_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/wap54gv3_rce.py`

### linksys / wrt100_110_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-3568
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/wrt100_110_rce.py`

### linksys / wvbr0_25_user_agent_command_execution_metasploit_cve_2017_17411

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17411
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/linksys/wvbr0_25_user_agent_command_execution_metasploit_cve_2017_17411.py`

### linksys / wvbr0_user_agent_remote_command_injection_cve_2017_17411

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17411
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/linksys/wvbr0_user_agent_remote_command_injection_cve_2017_17411.py`

### mercury / hp_loadrunner_agent_magentproc_exe_remote_command_execution_cve_2010_1549

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2010-1549
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mercury/hp_loadrunner_agent_magentproc_exe_remote_command_execution_cve_2010_1549.py`

### mikrotik / 6_40_5_icmp_denial_of_service_cve_2017_17538

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17538
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/mikrotik/6_40_5_icmp_denial_of_service_cve_2017_17538.py`

### mikrotik / 6_41_4_ftp_daemon_denial_of_service_poc_cve_2018_10070

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10070
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/mikrotik/6_41_4_ftp_daemon_denial_of_service_poc_cve_2018_10070.py`

### mikrotik / api_ros_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/api_ros_default_creds.py`

### mikrotik / cve_2024_27686_routeros_smb_dos

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-27686
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/mikrotik/cve_2024_27686_routeros_smb_dos.py`

### mikrotik / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/ftp_default_creds.py`

### mikrotik / router_arp_table_overflow_denial_of_service_cve_2017_6444

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6444
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/mikrotik/router_arp_table_overflow_denial_of_service_cve_2017_6444.py`

### mikrotik / router_monitoring_system_1_2_3_community_sql_injection_cve_2020_13118

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-13118
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/router_monitoring_system_1_2_3_community_sql_injection_cve_2020_13118.py`

### mikrotik / routerboard_6_38_5_denial_of_service_cve_2017_7285

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-7285
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/mikrotik/routerboard_6_38_5_denial_of_service_cve_2017_7285.py`

### mikrotik / routeros_6_41_3_6_42rc27_smb_buffer_overflow_cve_2018_7445

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-7445
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/routeros_6_41_3_6_42rc27_smb_buffer_overflow_cve_2018_7445.py`

### mikrotik / routeros_6_43_12_stable_6_42_12_long_term_firewall_and_nat_b_cve_2019_3924

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-3924
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/routeros_6_43_12_stable_6_42_12_long_term_firewall_and_nat_b_cve_2019_3924.py`

### mikrotik / routeros_6_45_6_dns_cache_poisoning_cve_2019_3978

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-3978
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/routeros_6_45_6_dns_cache_poisoning_cve_2019_3978.py`

### mikrotik / routeros_7_19_1_reflected_xss_cve_2025_6563

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-6563
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/routeros_7_19_1_reflected_xss_cve_2025_6563.py`

### mikrotik / routeros_jailbreak

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/routeros_jailbreak.py`

### mikrotik / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/ssh_default_creds.py`

### mikrotik / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/telnet_default_creds.py`

### mikrotik / winbox_auth_bypass_creds_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass, creds_disclosure
- Module paths:
  - `modules/exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure.py`

### mikrotik / winbox_cred_disclosure_cve_2018_14847

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-14847
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847.py`

### mipsbe / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/mipsbe/bind_tcp.py`

### mipsbe / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/mipsbe/reverse_tcp.py`

### mipsle / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/mipsle/bind_tcp.py`

### mipsle / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/mipsle/reverse_tcp.py`

### misc / misc_scan

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/misc/misc_scan.py`

### misc / soho_exploit_catalog_server

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/misc/soho_exploit_catalog_server.py`

### mitrastar / gpt2541gnac_stack_overflow

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/mitrastar/gpt2541gnac_stack_overflow.py`

### movistar / adsl_router_bhs_rta_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/movistar/adsl_router_bhs_rta_path_traversal.py`

### movistar / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/movistar/ftp_default_creds.py`

### movistar / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/movistar/ssh_default_creds.py`

### movistar / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/movistar/telnet_default_creds.py`

### multi / 3com_ap8670_cred_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/3com_ap8670_cred_disclosure.py`

### multi / accton_switch_backdoor_password

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/multi/accton_switch_backdoor_password.py`

### multi / airlive_wt2000arm_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/multi/airlive_wt2000arm_info_disclosure.py`

### multi / airties_air5341_modem_1_0_0_12_cross_site_request_forgery_cve_2019_6967

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6967
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/airties_air5341_modem_1_0_0_12_cross_site_request_forgery_cve_2019_6967.py`

### multi / allegrosoft_rompager_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9222
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/multi/allegrosoft_rompager_auth_bypass.py`

### multi / astaro_security_gateway_7_remote_code_execution_cve_2017_6315

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6315
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/astaro_security_gateway_7_remote_code_execution_cve_2017_6315.py`

### multi / aveva_intouch_access_anywhere_secure_gateway_2020_r2_path_tr_cve_2022_23854

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-23854
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/aveva_intouch_access_anywhere_secure_gateway_2020_r2_path_tr_cve_2022_23854.py`

### multi / barracuda_load_balancer_firmware_v6_0_1_006_2016_08_19_posta_cve_2017_6320

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6320
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/barracuda_load_balancer_firmware_v6_0_1_006_2016_08_19_posta_cve_2017_6320.py`

### multi / check_point_security_gateway_information_disclosure_unauthen_cve_2024_24919

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-24919
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/multi/check_point_security_gateway_information_disclosure_unauthen_cve_2024_24919.py`

### multi / cobham_admin_reset_cve_2014_2943

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-2943
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/cobham_admin_reset_cve_2014_2943.py`

### multi / coship_rt3052_wireless_router_persistent_cross_site_scriptin_cve_2018_8772

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-8772
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/coship_rt3052_wireless_router_persistent_cross_site_scriptin_cve_2018_8772.py`

### multi / coship_wireless_router_4_0_0_48_4_0_0_40_5_0_0_54_5_0_0_55_1_cve_2019_6441

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6441
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/coship_wireless_router_4_0_0_48_4_0_0_40_5_0_0_54_5_0_0_55_1_cve_2019_6441.py`

### multi / credential_leakage_through_unprotected_system_logs_and_weak_cve_2023_43261

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-43261
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/multi/credential_leakage_through_unprotected_system_logs_and_weak_cve_2023_43261.py`

### multi / cve_2017_6552_local_dos_buffer_overflow_livebox_3

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6552
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/multi/cve_2017_6552_local_dos_buffer_overflow_livebox_3.py`

### multi / davolink_dvw_3200_router_password_disclosure_cve_2018_10618

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-10618
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/davolink_dvw_3200_router_password_disclosure_cve_2018_10618.py`

### multi / digisol_dg_hr1400_1_00_02_wireless_router_privilege_escalati_cve_2017_6896

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6896
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/digisol_dg_hr1400_1_00_02_wireless_router_privilege_escalati_cve_2017_6896.py`

### multi / exploitdb_45942_py_cve_2018_11741

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-11741, CVE-2018-11742
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/exploitdb_45942_py_cve_2018_11741.py`

### multi / exploitdb_49038_rb_cve_2020_8196

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-8193, CVE-2020-8195, CVE-2020-8196
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/exploitdb_49038_rb_cve_2020_8196.py`

### multi / exploitdb_51865_py_cve_2023_46453

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-46453
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/exploitdb_51865_py_cve_2023_46453.py`

### multi / f5_big_ip_13_1_3_build_0_0_6_local_file_inclusion_cve_2020_5902

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-5902
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/f5_big_ip_13_1_3_build_0_0_6_local_file_inclusion_cve_2020_5902.py`

### multi / f5_big_ip_16_0_x_icontrol_rest_remote_code_execution_unauthe_cve_2021_22986

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-22986
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/f5_big_ip_16_0_x_icontrol_rest_remote_code_execution_unauthe_cve_2021_22986.py`

### multi / fortirecorder_6_4_3_denial_of_service_cve_2022_41333

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-41333
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/multi/fortirecorder_6_4_3_denial_of_service_cve_2022_41333.py`

### multi / genexis_platinum_4410_router_2_1_upnp_credential_exposure_cve_2020_25988

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-25988
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/genexis_platinum_4410_router_2_1_upnp_credential_exposure_cve_2020_25988.py`

### multi / gl_inet_3_216_remote_code_execution_via_openvpn_client_cve_2023_46456

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-46456
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/gl_inet_3_216_remote_code_execution_via_openvpn_client_cve_2023_46456.py`

### multi / gl_inet_4_3_7_arbitrary_file_write_cve_2023_46455

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-46455
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/gl_inet_4_3_7_arbitrary_file_write_cve_2023_46455.py`

### multi / gl_inet_4_3_7_remote_code_execution_via_openvpn_client_cve_2023_46454

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-46454
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/gl_inet_4_3_7_remote_code_execution_via_openvpn_client_cve_2023_46454.py`

### multi / gl_inet_mt6000_4_5_5_arbitrary_file_download_cve_2024_27356

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-27356
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/gl_inet_mt6000_4_5_5_arbitrary_file_download_cve_2024_27356.py`

### multi / gpon_home_gateway_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/gpon_home_gateway_rce.py`

### multi / grandstream_gxv3611_hd_telnet_sql_injection_and_backdoor_com_cve_2015_2866

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-2866
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/multi/grandstream_gxv3611_hd_telnet_sql_injection_and_backdoor_com_cve_2015_2866.py`

### multi / grandstream_ucm6200_series_cti_interface_user_password_sql_i_cve_2020_5726

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-5726
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/grandstream_ucm6200_series_cti_interface_user_password_sql_i_cve_2020_5726.py`

### multi / grandstream_ucm6200_series_websocket_1_0_20_20_user_password_cve_2020_5725

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-5725
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/grandstream_ucm6200_series_websocket_1_0_20_20_user_password_cve_2020_5725.py`

### multi / hughesnet_ht2000w_satellite_modem_arcadyan_httpd_1_0_passwor_cve_2021_20090

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-20090
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/hughesnet_ht2000w_satellite_modem_arcadyan_httpd_1_0_passwor_cve_2021_20090.py`

### multi / humax_wi_fi_router_hg100r_2_0_6_authentication_bypass_cve_2017_11435

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11435
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/humax_wi_fi_router_hg100r_2_0_6_authentication_bypass_cve_2017_11435.py`

### multi / iball_adsl2_home_router_authentication_bypass_cve_2017_14244

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-14244
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/iball_adsl2_home_router_authentication_bypass_cve_2017_14244.py`

### multi / iopsys_router_dhcp_remote_code_execution_cve_2017_17867

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-17867
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/iopsys_router_dhcp_remote_code_execution_cve_2017_17867.py`

### multi / iqrouter_3_3_1_firmware_remote_code_execution_cve_2020_11963

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-11963, CVE-2020-11964, CVE-2020-11966, CVE-2020-11967, CVE-2020-11968
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/iqrouter_3_3_1_firmware_remote_code_execution_cve_2020_11963.py`

### multi / irz_mobile_router_csrf_to_rce_cve_2022_27226

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-27226
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/irz_mobile_router_csrf_to_rce_cve_2022_27226.py`

### multi / laser_router_re018_ac1200_cross_site_request_forgery_enable_cve_2021_31152

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-31152
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/laser_router_re018_ac1200_cross_site_request_forgery_enable_cve_2021_31152.py`

### multi / misfortune_cookie

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9222
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/multi/misfortune_cookie.py`

### multi / msnswitch_firmware_mnt_2408_remote_code_exectuion_rce_cve_2022_32429

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-32429
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/msnswitch_firmware_mnt_2408_remote_code_exectuion_rce_cve_2022_32429.py`

### multi / nat_slipstream

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/nat_slipstream.py`

### multi / netcommwireless_hspa_3g10wve_wireless_router_ple_vulnerabili_cve_2015_6023

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-6023, CVE-2015-6024
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/netcommwireless_hspa_3g10wve_wireless_router_ple_vulnerabili_cve_2015_6023.py`

### multi / netis_wf2419_2_2_36123_remote_code_execution_cve_2019_1337

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1337, CVE-2019-19356
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/netis_wf2419_2_2_36123_remote_code_execution_cve_2019_1337.py`

### multi / netusb_kernel_stack_overflow_cve_2021_45388

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-45388, CVE-2021-45608
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/netusb_kernel_stack_overflow_cve_2021_45388.py`

### multi / nexxt_router_firmware_42_103_1_5095_remote_code_execution_rc_cve_2022_44149

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-44149
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/nexxt_router_firmware_42_103_1_5095_remote_code_execution_rc_cve_2022_44149.py`

### multi / nintendo_switch_webkit_code_execution_poc_cve_2016_4657

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-4657
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/nintendo_switch_webkit_code_execution_poc_cve_2016_4657.py`

### multi / norton_core_secure_wifi_router_ble_command_injection_poc_cve_2018_5234

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5234
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/norton_core_secure_wifi_router_ble_command_injection_poc_cve_2018_5234.py`

### multi / openwrt_luci_rce_cve_2021_22161

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-8597, CVE-2021-22161
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/openwrt_luci_rce_cve_2021_22161.py`

### multi / pfsensece_v2_6_0_anti_brute_force_protection_bypass_cve_2023_27100

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-27100
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/pfsensece_v2_6_0_anti_brute_force_protection_bypass_cve_2023_27100.py`

### multi / plc_wireless_router_gpn2_4p21_c_cn_cross_site_request_forger_cve_2019_6282

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6282
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_cross_site_request_forger_cve_2019_6282.py`

### multi / plc_wireless_router_gpn2_4p21_c_cn_cross_site_scripting_cve_2018_20326

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-20326
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_cross_site_scripting_cve_2018_20326.py`

### multi / plc_wireless_router_gpn2_4p21_c_cn_incorrect_access_control_cve_2019_6279

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6279
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/plc_wireless_router_gpn2_4p21_c_cn_incorrect_access_control_cve_2019_6279.py`

### multi / qubes_mirage_firewall_v0_8_3_denial_of_service_dos_cve_2022_46770

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-46770
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/multi/qubes_mirage_firewall_v0_8_3_denial_of_service_dos_cve_2022_46770.py`

### multi / rom0

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/multi/rom0.py`

### multi / rom0_password_extraction

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/rom0_password_extraction.py`

### multi / rompager_4_34_ple_router_vendors_misfortune_cookie_authentic_cve_2015_9222

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-9222
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/rompager_4_34_ple_router_vendors_misfortune_cookie_authentic_cve_2015_9222.py`

### multi / rompager_password_disclosure_cve_2014_4019

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-4019
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/rompager_password_disclosure_cve_2014_4019.py`

### multi / ruckus_iot_controller_ruckus_vriot_1_5_1_0_21_remote_code_ex_cve_2020_26878

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-26878
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/ruckus_iot_controller_ruckus_vriot_1_5_1_0_21_remote_code_ex_cve_2020_26878.py`

### multi / sagem_fast_telnet_password

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/sagem_fast_telnet_password.py`

### multi / seowon_slr_120_router_remote_code_execution_unauthenticated_cve_2020_17456

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-17456
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/seowon_slr_120_router_remote_code_execution_unauthenticated_cve_2020_17456.py`

### multi / smartrg_router_sr510n_2_6_13_remote_code_execution_cve_2022_37661

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-37661
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/smartrg_router_sr510n_2_6_13_remote_code_execution_cve_2022_37661.py`

### multi / tcp_32764_backdoor_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/multi/tcp_32764_backdoor_rce.py`

### multi / tcp_32764_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, info_disclosure
- Module paths:
  - `modules/exploits/routers/multi/tcp_32764_info_disclosure.py`

### multi / tcp_32764_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/multi/tcp_32764_rce.py`

### multi / techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34723

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-34723
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34723.py`

### multi / techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34724

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-34724, CVE-2023-34725
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/techview_la_5570_wireless_gateway_home_automation_controller_cve_2023_34724.py`

### multi / telesquare_sdt_cw3b1_1_1_0_os_command_injection_cve_2021_46422

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-46422
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/telesquare_sdt_cw3b1_1_1_0_os_command_injection_cve_2021_46422.py`

### multi / ticketbleed_cve_2016_9244

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-9244
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/ticketbleed_cve_2016_9244.py`

### multi / ucm6202_1_0_18_13_remote_command_injection_cve_2020_5722

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-5722
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/ucm6202_1_0_18_13_remote_command_injection_cve_2020_5722.py`

### multi / unauthenticated_command_injection_vulnerability_in_vmware_ns_cve_2018_6961

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-6961
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/unauthenticated_command_injection_vulnerability_in_vmware_ns_cve_2018_6961.py`

### multi / utstar_wa3002g4_adsl_broadband_modem_authentication_bypass_cve_2017_14243

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-14243
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/utstar_wa3002g4_adsl_broadband_modem_authentication_bypass_cve_2017_14243.py`

### multi / viprinet_channel_vpn_router_300_persistent_cross_site_script_cve_2014_2045

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-2045
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/viprinet_channel_vpn_router_300_persistent_cross_site_script_cve_2014_2045.py`

### multi / wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5999, CVE-2018-6000
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/multi/wrt_router_3_0_0_4_380_7743_lan_remote_code_execution_cve_2018_5999.py`

### netcore / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netcore/ftp_default_creds.py`

### netcore / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netcore/ssh_default_creds.py`

### netcore / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netcore/telnet_default_creds.py`

### netcore / udp_53413_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/netcore/udp_53413_rce.py`

### netcore / wf2419_router_cross_site_scripting_cve_2018_6190

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-6190
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netcore/wf2419_router_cross_site_scripting_cve_2018_6190.py`

### netgear / devices_unauthenticated_remote_command_execution_metasploit_cve_2016_1555

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1555
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/devices_unauthenticated_remote_command_execution_metasploit_cve_2016_1555.py`

### netgear / dgn1000_setup_cgi_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/dgn1000_setup_cgi_rce.py`

### netgear / dgn1000_unauthenticated_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/dgn1000_unauthenticated_rce.py`

### netgear / dgn2200_dnslookup_cgi_command_injection_metasploit_cve_2017_6334

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6334
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200_dnslookup_cgi_command_injection_metasploit_cve_2017_6334.py`

### netgear / dgn2200_dnslookup_cgi_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6334
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200_dnslookup_cgi_rce.py`

### netgear / dgn2200_ping_cgi_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6077
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200_ping_cgi_rce.py`

### netgear / dgn2200_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6334
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200_rce.py`

### netgear / dgn2200v1_v2_v3_v4_cross_site_request_forgery_cve_2017_6334

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6334, CVE-2017-6366
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200v1_v2_v3_v4_cross_site_request_forgery_cve_2017_6334.py`

### netgear / dgn2200v1_v2_v3_v4_dnslookup_cgi_remote_command_execution_cve_2017_6334

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6334
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200v1_v2_v3_v4_dnslookup_cgi_remote_command_execution_cve_2017_6334.py`

### netgear / dgn2200v1_v2_v3_v4_ping_cgi_remote_command_execution_cve_2017_6077

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-6077
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/dgn2200v1_v2_v3_v4_ping_cgi_remote_command_execution_cve_2017_6077.py`

### netgear / exploitdb_27774_py_cve_2013_4775

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-4775
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/exploitdb_27774_py_cve_2013_4775.py`

### netgear / exploitdb_27775_py_cve_2013_4776

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2013-4776
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/exploitdb_27775_py_cve_2013_4776.py`

### netgear / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netgear/ftp_default_creds.py`

### netgear / jnr1010_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/netgear/jnr1010_path_traversal.py`

### netgear / jwnr2010v5_password_leak

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/netgear/jwnr2010v5_password_leak.py`

### netgear / multi_password_disclosure-2017-5521

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-5521
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/netgear/multi_password_disclosure-2017-5521.py`

### netgear / multi_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/multi_rce.py`

### netgear / n300_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/netgear/n300_auth_bypass.py`

### netgear / netusb_kernel_stack_buffer_overflow_cve_2015_3036

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-3036
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/netusb_kernel_stack_buffer_overflow_cve_2015_3036.py`

### netgear / nms300_prosafe_network_management_system_arbitrary_file_uplo_cve_2016_1525

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1525
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/nms300_prosafe_network_management_system_arbitrary_file_uplo_cve_2016_1525.py`

### netgear / nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-1524, CVE-2016-1525
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/nms300_prosafe_network_management_system_multiple_vulnerabil_cve_2016_1524.py`

### netgear / nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-5674, CVE-2016-5675, CVE-2016-5676, CVE-2016-5677, CVE-2016-5678, CVE-2016-5679, CVE-2016-5680
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/nuuo_nvrmini2_nvrsolo_crystal_devices_readynas_surveillance_cve_2016_5674.py`

### netgear / prosafe_rce

- Totals: modules=2, exploits=2, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/prosafe_rce.py`
  - `modules/exploits/switches/netgear/prosafe_rce.py`

### netgear / r7000_command_injection_cve_2016_6277

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6277
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/r7000_command_injection_cve_2016_6277.py`

### netgear / r7000_r6400_cgi_bin_command_injection_metasploit_cve_2016_6277

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6277
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/r7000_r6400_cgi_bin_command_injection_metasploit_cve_2016_6277.py`

### netgear / r7000_r6400_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/r7000_r6400_rce.py`

### netgear / rax30_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/rax30_rce.py`

### netgear / routers_password_disclosure_cve_2017_5521

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-5521
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/routers_password_disclosure_cve_2017_5521.py`

### netgear / rp614_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/netgear/rp614_auth_bypass.py`

### netgear / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netgear/ssh_default_creds.py`

### netgear / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netgear/telnet_default_creds.py`

### netgear / wg102_wn604_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/wg102_wn604_rce.py`

### netgear / wnap320_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/wnap320_rce.py`

### netgear / wndr_soap_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass, info_disclosure
- Module paths:
  - `modules/exploits/routers/netgear/wndr_soap_auth_bypass.py`

### netgear / wnr2000v5_hidden_lang_avi_remote_stack_overflow_metasploit_cve_2016_10174

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-10174
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/wnr2000v5_hidden_lang_avi_remote_stack_overflow_metasploit_cve_2016_10174.py`

### netgear / wnr2000v5_remote_code_execution_cve_2016_10174

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-10174, CVE-2016-10175, CVE-2016-10176
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/netgear/wnr2000v5_remote_code_execution_cve_2016_10174.py`

### netgear / wnr500_612v3_jnr1010_2010_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/netgear/wnr500_612v3_jnr1010_2010_path_traversal.py`

### netis / mw5360_mw5370_rce_cve_2014_8572

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-8572
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/netis/mw5360_mw5370_rce_cve_2014_8572.py`

### netsys / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netsys/ftp_default_creds.py`

### netsys / multi_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netsys/multi_rce.py`

### netsys / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netsys/ssh_default_creds.py`

### netsys / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/netsys/telnet_default_creds.py`

### perl / base64

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/perl/base64.py`

### perl / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/perl/bind_tcp.py`

### perl / hex

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/perl/hex.py`

### perl / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/perl/reverse_tcp.py`

### perl / rot13

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/perl/rot13.py`

### perl / url

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/perl/url.py`

### pfsense / pfsense_2_2_6_command_injection_cve_2016_10709

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-10709
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/pfsense/pfsense_2_2_6_command_injection_cve_2016_10709.py`

### php / base64

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/php/base64.py`

### php / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/php/bind_tcp.py`

### php / hex

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/php/hex.py`

### php / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/php/reverse_tcp.py`

### php / rot13

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/php/rot13.py`

### php / url

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/php/url.py`

### python / base32

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/python/base32.py`

### python / base64

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/python/base64.py`

### python / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/python/bind_tcp.py`

### python / bind_udp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/python/bind_udp.py`

### python / hex

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/python/hex.py`

### python / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/python/reverse_tcp.py`

### python / reverse_udp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/python/reverse_udp.py`

### python / rot13

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/python/rot13.py`

### python / url

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=0, encoders=1
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/encoders/python/url.py`

### routers / router_scan

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/routers/router_scan.py`

### ruijie / reyee_mesh_router_remote_code_execution_rce_authenticated_cve_2021_43164

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-43164
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/ruijie/reyee_mesh_router_remote_code_execution_rce_authenticated_cve_2021_43164.py`

### scanners / autopwn

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/autopwn.py`

### sftp_bruteforce.py / sftp_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/sftp_bruteforce.py`

### sftp_default.py / sftp_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/sftp_default.py`

### shellshock.py / shellshock

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-6271, CVE-2014-6278, CVE-2014-7169
- Attack classes: rce
- Module paths:
  - `modules/exploits/generic/shellshock.py`

### shuttle / 915wm_dns_change

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: dns_change
- Module paths:
  - `modules/exploits/routers/shuttle/915wm_dns_change.py`

### siemens / ccms2025_cred_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/siemens/ccms2025_cred_disclosure.py`

### siemens / ccms2025_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/siemens/ccms2025_path_traversal.py`

### snmp / snmp_bruteforce

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/snmp/snmp_bruteforce.py`

### snmp / snmp_trap_listener

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/snmp/snmp_trap_listener.py`

### snmp_bruteforce.py / snmp_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/snmp_bruteforce.py`

### snmpv3_default.py / snmpv3_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/snmpv3_default.py`

### soho_edge / hootoo_scan

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/soho_edge/hootoo_scan.py`

### sonicwall / 8_1_0_2_14sv_extensionsettings_cgi_remote_command_injection_cve_2016_9683

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-9683
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/8_1_0_2_14sv_extensionsettings_cgi_remote_command_injection_cve_2016_9683.py`

### sonicwall / 8_1_0_2_14sv_viewcert_cgi_remote_command_injection_metasploi_cve_2016_9684

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-9684
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/8_1_0_2_14sv_viewcert_cgi_remote_command_injection_metasploi_cve_2016_9684.py`

### sonicwall / dell_scrutinizer_11_01_methoddetail_sql_injection_metasploit_cve_2014_4977

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-4977
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/dell_scrutinizer_11_01_methoddetail_sql_injection_metasploit_cve_2014_4977.py`

### sonicwall / netextender_10_2_0_300_unquoted_service_path_cve_2020_5147

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-5147
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/netextender_10_2_0_300_unquoted_service_path_cve_2020_5147.py`

### sonicwall / secure_remote_access_8_1_0_2_14sv_command_injection_cve_2016_9682

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-9682
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/secure_remote_access_8_1_0_2_14sv_command_injection_cve_2016_9682.py`

### sonicwall / sma_10_2_1_0_17sv_password_reset_cve_2021_20034

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-20034
- Attack classes: password_reset_or_change
- Module paths:
  - `modules/exploits/routers/sonicwall/sma_10_2_1_0_17sv_password_reset_cve_2021_20034.py`

### sonicwall / sonicos_7_0_host_header_injection_cve_2021_20031

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-20031
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/sonicwall/sonicos_7_0_host_header_injection_cve_2021_20031.py`

### ssh_auth_keys.py / ssh_auth_keys

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/generic/ssh_auth_keys.py`

### ssh_bruteforce.py / ssh_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/ssh_bruteforce.py`

### ssh_default.py / ssh_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/ssh_default.py`

### tcp_xmas.py / tcp_xmas

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/tcp_xmas.py`

### technicolor / dpc3928sl_snmp_authentication_bypass_cve_2017_5135

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-5135
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/technicolor/dpc3928sl_snmp_authentication_bypass_cve_2017_5135.py`

### technicolor / dwg855_authbypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/technicolor/dwg855_authbypass.py`

### technicolor / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/technicolor/ftp_default_creds.py`

### technicolor / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/technicolor/ssh_default_creds.py`

### technicolor / tc7200_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/technicolor/tc7200_password_disclosure.py`

### technicolor / tc7200_password_disclosure_v2

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/technicolor/tc7200_password_disclosure_v2.py`

### technicolor / tc7337_ssid_persistent_cross_site_scripting_cve_2017_11320

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11320
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/technicolor/tc7337_ssid_persistent_cross_site_scripting_cve_2017_11320.py`

### technicolor / td5130_2_remote_command_execution_cve_2019_18396

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-18396
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/technicolor/td5130_2_remote_command_execution_cve_2019_18396.py`

### technicolor / technicolor_tc7300_b0_hostname_persistent_cross_site_scripti_cve_2019_17524

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-17524
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/technicolor/technicolor_tc7300_b0_hostname_persistent_cross_site_scripti_cve_2019_17524.py`

### technicolor / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/technicolor/telnet_default_creds.py`

### technicolor / tg784_authbypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/technicolor/tg784_authbypass.py`

### technicolor / xfinity_gateway_dpc3941t_cross_site_request_forgery_cve_2016_7454

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-7454
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/technicolor/xfinity_gateway_dpc3941t_cross_site_request_forgery_cve_2016_7454.py`

### telnet_bruteforce.py / telnet_bruteforce

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/telnet_bruteforce.py`

### telnet_default.py / telnet_default

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/generic/telnet_default.py`

### tenda / ac15_router_remote_code_execution_cve_2018_5767

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5767
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/ac15_router_remote_code_execution_cve_2018_5767.py`

### tenda / ac20_16_03_08_12_command_injection_cve_2025_9090

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-9090
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/ac20_16_03_08_12_command_injection_cve_2025_9090.py`

### tenda / ac5_ac1200_wireless_wifi_name_password_stored_cross_site_scr_cve_2021_3186

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-3186
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/ac5_ac1200_wireless_wifi_name_password_stored_cross_site_scr_cve_2021_3186.py`

### tenda / adsl_router_d152_cross_site_scripting_cve_2018_14497

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-14497
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/adsl_router_d152_cross_site_scripting_cve_2018_14497.py`

### tenda / d301_v2_modem_router_persistent_cross_site_scripting_cve_2019_13491

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13491
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/d301_v2_modem_router_persistent_cross_site_scripting_cve_2019_13491.py`

### tenda / fh451_1_0_0_9_router_stack_based_buffer_overflow_cve_2025_7795

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-7795
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/fh451_1_0_0_9_router_stack_based_buffer_overflow_cve_2025_7795.py`

### tenda / n300_f3_12_01_01_48_malformed_http_request_header_processing_cve_2020_35391

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-35391
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/n300_f3_12_01_01_48_malformed_http_request_header_processing_cve_2020_35391.py`

### tenda / wireless_n150_router_5_07_50_cross_site_request_forgery_rebo_cve_2015_5996

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2015-5996
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tenda/wireless_n150_router_5_07_50_cross_site_request_forgery_rebo_cve_2015_5996.py`

### thomson / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/thomson/ftp_default_creds.py`

### thomson / reuters_concourse_firm_central_2_13_0097_directory_traversal_cve_2019_8385

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-8385
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/thomson/reuters_concourse_firm_central_2_13_0097_directory_traversal_cve_2019_8385.py`

### thomson / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/thomson/ssh_default_creds.py`

### thomson / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/thomson/telnet_default_creds.py`

### thomson / twg849_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/thomson/twg849_info_disclosure.py`

### thomson / twg850_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/thomson/twg850_password_disclosure.py`

### totolink / n300rb_8_54_command_execution_cve_2025_52089

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-52089
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/totolink/n300rb_8_54_command_execution_cve_2025_52089.py`

### tplink / archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-10882, CVE-2020-10883, CVE-2020-10884
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/archer_a7_c7_unauthenticated_lan_remote_code_execution_metas_cve_2020_10882.py`

### tplink / archer_ax21_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-1389
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/archer_ax21_rce.py`

### tplink / archer_ax21_unauthenticated_command_injection_cve_2023_1389

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-1389
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/archer_ax21_unauthenticated_command_injection_cve_2023_1389.py`

### tplink / archer_c2_c20i_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/archer_c2_c20i_rce.py`

### tplink / archer_c50_3_denial_of_service_poc_cve_2020_9375

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-9375
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/tplink/archer_c50_3_denial_of_service_poc_cve_2020_9375.py`

### tplink / archer_c5_rce_cve_2018_19537

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-19537
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/archer_c5_rce_cve_2018_19537.py`

### tplink / archer_c7_netusb_rce_cve_2022_24354

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-24354
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/archer_c7_netusb_rce_cve_2022_24354.py`

### tplink / archer_c9_admin_password_reset

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11519
- Attack classes: password_reset_or_change
- Module paths:
  - `modules/exploits/routers/tplink/archer_c9_admin_password_reset.py`

### tplink / ax50_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-30075
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/ax50_rce.py`

### tplink / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/ftp_default_creds.py`

### tplink / router_ax50_firmware_210730_remote_code_execution_rce_authen_cve_2022_30075

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-30075
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/router_ax50_firmware_210730_remote_code_execution_rce_authen_cve_2022_30075.py`

### tplink / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/ssh_default_creds.py`

### tplink / tapo_c200_1_1_15_remote_code_execution_rce_cve_2021_4045

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-4045
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/tapo_c200_1_1_15_remote_code_execution_rce_cve_2021_4045.py`

### tplink / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/telnet_default_creds.py`

### tplink / tl_mr3220_cross_site_scripting_cve_2017_15291

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-15291
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_mr3220_cross_site_scripting_cve_2017_15291.py`

### tplink / tl_sc3130_1_6_18_rtsp_stream_disclosure_cve_2018_18428

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-18428
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_sc3130_1_6_18_rtsp_stream_disclosure_cve_2018_18428.py`

### tplink / tl_wa855re_v5_200415_device_reset_auth_bypass_cve_2020_24363

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-24363
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/tplink/tl_wa855re_v5_200415_device_reset_auth_bypass_cve_2020_24363.py`

### tplink / tl_wr1043nd_2_authentication_bypass_cve_2019_6971

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6971
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr1043nd_2_authentication_bypass_cve_2019_6971.py`

### tplink / tl_wr840n_denial_of_service_cve_2018_14336

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-14336
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr840n_denial_of_service_cve_2018_14336.py`

### tplink / tl_wr840n_v5_00000005_cross_site_scripting_cve_2019_12195

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-12195
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr840n_v5_00000005_cross_site_scripting_cve_2019_12195.py`

### tplink / tl_wr841n_command_injection_cve_2020_35576

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-35576
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr841n_command_injection_cve_2020_35576.py`

### tplink / tl_wr841nd_password_disclosure_cve_2020_35575

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-35575
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr841nd_password_disclosure_cve_2020_35575.py`

### tplink / tl_wr902ac_firmware_210730_v3_remote_code_execution_rce_auth_cve_2022_48194

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-48194
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr902ac_firmware_210730_v3_remote_code_execution_rce_auth_cve_2022_48194.py`

### tplink / tl_wr940n_tl_wr941nd_buffer_overflow_cve_2019_6989

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6989
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr940n_tl_wr941nd_buffer_overflow_cve_2019_6989.py`

### tplink / tl_wr940n_v4_buffer_overflow_cve_2023_36355

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2023-36355
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tl_wr940n_v4_buffer_overflow_cve_2023_36355.py`

### tplink / tp_sg105e_1_0_0_unauthenticated_remote_reboot_cve_2019_16893

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-16893
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/tp_sg105e_1_0_0_unauthenticated_remote_reboot_cve_2019_16893.py`

### tplink / vn020_f3v_t_tt_v6_2_1021_buffer_overflow_memory_corruption_cve_2024_12344

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-12344
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_buffer_overflow_memory_corruption_cve_2024_12344.py`

### tplink / vn020_f3v_t_tt_v6_2_1021_denial_of_service_dos_cve_2024_12342

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-12342
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_denial_of_service_dos_cve_2024_12342.py`

### tplink / vn020_f3v_t_tt_v6_2_1021_dhcp_stack_buffer_overflow_cve_2024_11237

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2024-11237
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/vn020_f3v_t_tt_v6_2_1021_dhcp_stack_buffer_overflow_cve_2024_11237.py`

### tplink / wdr4300_remote_code_execution_authenticated_cve_2017_13772

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-13772
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/wdr4300_remote_code_execution_authenticated_cve_2017_13772.py`

### tplink / wdr5620_cmd_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/wdr5620_cmd_injection.py`

### tplink / wdr740nd_wdr740n_backdoor

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/tplink/wdr740nd_wdr740n_backdoor.py`

### tplink / wdr740nd_wdr740n_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/tplink/wdr740nd_wdr740n_path_traversal.py`

### tplink / wdr842nd_wdr842n_configure_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/wdr842nd_wdr842n_configure_disclosure.py`

### tplink / wireless_router_archer_c1200_cross_site_scripting_cve_2018_13134

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-13134
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/wireless_router_archer_c1200_cross_site_scripting_cve_2018_13134.py`

### tplink / wr1043nd_auth_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6971
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/tplink/wr1043nd_auth_bypass.py`

### tplink / wr840n_0_9_1_3_16_denial_of_service_poc_cve_2018_15172

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-15172
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/tplink/wr840n_0_9_1_3_16_denial_of_service_poc_cve_2018_15172.py`

### tplink / wr841nd_password_disclosure_cve_2020_35575

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-35575
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/tplink/wr841nd_password_disclosure_cve_2020_35575.py`

### tplink / wr849n_config_bypass_cve_2019_19143

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-19143
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/wr849n_config_bypass_cve_2019_19143.py`

### tplink / wr849n_rce_cve_2020_9374

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-9374
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/wr849n_rce_cve_2020_9374.py`

### tplink / wr849n_traceroute_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/wr849n_traceroute_rce.py`

### tplink / wr940n_authenticated_remote_code_cve_2017_13772

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-13772
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/tplink/wr940n_authenticated_remote_code_cve_2017_13772.py`

### tplink / wvr_war_diagnostic_rce_cve_2017_16957

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-16957
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/wvr_war_diagnostic_rce_cve_2017_16957.py`

### trendnet / tew827dru_cmd_injection_cve_2019_13276

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13276
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13276.py`

### trendnet / tew827dru_cmd_injection_cve_2019_13277

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13277
- Attack classes: dos_or_crash
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13277.py`

### trendnet / tew827dru_cmd_injection_cve_2019_13278

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13278
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_cmd_injection_cve_2019_13278.py`

### trendnet / tew827dru_stack_overflow_cve_2019_13150

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13150
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13150.py`

### trendnet / tew827dru_stack_overflow_cve_2019_13279

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13279
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13279.py`

### trendnet / tew827dru_stack_overflow_cve_2019_13280

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13280
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/trendnet/tew827dru_stack_overflow_cve_2019_13280.py`

### trendnet / tew_651br_tew_652brp_rce_cve_2019_13276

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13276, CVE-2019-13278
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/trendnet/tew_651br_tew_652brp_rce_cve_2019_13276.py`

### trendnet / tew_827dru_ping_command_injection_cve_2019_13150

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-13150
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/trendnet/tew_827dru_ping_command_injection_cve_2019_13150.py`

### ubiquiti / airos_6_x

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/ubiquiti/airos_6_x.py`

### ubiquiti / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/ubiquiti/ftp_default_creds.py`

### ubiquiti / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/ubiquiti/ssh_default_creds.py`

### ubiquiti / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/ubiquiti/telnet_default_creds.py`

### ubiquiti / unifi_video_3_7_3_local_privilege_escalation_cve_2016_6914

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-6914
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/ubiquiti/unifi_video_3_7_3_local_privilege_escalation_cve_2016_6914.py`

### udp_amplification.py / udp_amplification

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: dos_or_crash
- Module paths:
  - `modules/generic/udp_amplification.py`

### upnp / igd_exploit

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: dos_or_crash
- Module paths:
  - `modules/generic/upnp/igd_exploit.py`

### upnp / ssdp_msearch

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/upnp/ssdp_msearch.py`

### wavlink / wn530hg4_password_disclosure_cve_2022_34047

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-34047
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/wavlink/wn530hg4_password_disclosure_cve_2022_34047.py`

### wavlink / wn533a8_cross_site_scripting_xss_cve_2022_34048

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-34048
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/wavlink/wn533a8_cross_site_scripting_xss_cve_2022_34048.py`

### wavlink / wn533a8_password_disclosure_cve_2022_34046

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-34046
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/wavlink/wn533a8_password_disclosure_cve_2022_34046.py`

### wordlist / wordlist_generator

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/wordlist/wordlist_generator.py`

### x64 / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/x64/bind_tcp.py`

### x64 / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/x64/reverse_tcp.py`

### x86 / bind_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/x86/bind_tcp.py`

### x86 / reverse_tcp

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=0, payloads=1, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/payloads/x86/reverse_tcp.py`

### xiaomi / browser_10_2_4_g_browser_search_history_disclosure_cve_2018_20523

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-20523
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/xiaomi/browser_10_2_4_g_browser_search_history_disclosure_cve_2018_20523.py`

### xiaomi / stock_firmware_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/xiaomi/stock_firmware_rce.py`

### zhone / dasan_znid_2426a_eu_multiple_cross_site_scripting_cve_2019_10677

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-10677
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zhone/dasan_znid_2426a_eu_multiple_cross_site_scripting_cve_2019_10677.py`

### zte / f460_f660_backdoor

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/zte/f460_f660_backdoor.py`

### zte / f460_f660_rce_cve_2014_2321

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-2321
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zte/f460_f660_rce_cve_2014_2321.py`

### zte / f660_config_download_decrypt

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-0329
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zte/f660_config_download_decrypt.py`

### zte / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zte/ftp_default_creds.py`

### zte / mf65_bd_hdv6mf65v1_0_0b05_cross_site_scripting_cve_2018_7355

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-7355
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zte/mf65_bd_hdv6mf65v1_0_0b05_cross_site_scripting_cve_2018_7355.py`

### zte / router_f602w_captcha_bypass_cve_2020_6862

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-6862
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zte/router_f602w_captcha_bypass_cve_2020_6862.py`

### zte / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zte/ssh_default_creds.py`

### zte / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zte/telnet_default_creds.py`

### zte / zxdsl_831cii_improper_access_restrictions_cve_2017_16953

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-16953
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zte/zxdsl_831cii_improper_access_restrictions_cve_2017_16953.py`

### zte / zxhn_h108n_wifi_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/zte/zxhn_h108n_wifi_password_disclosure.py`

### zte / zxhn_h168n_improper_access_restrictions_cve_2018_7357

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-7357, CVE-2018-7358
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zte/zxhn_h168n_improper_access_restrictions_cve_2018_7357.py`

### zte / zxv10_h108l_cmd_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zte/zxv10_h108l_cmd_injection.py`

### zte / zxv10_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zte/zxv10_rce.py`

### zte / zxv10_w812n

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/zte/zxv10_w812n.py`

### zyxel / armor_x1_wap6806_directory_traversal_cve_2020_14461

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2020-14461
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/zyxel/armor_x1_wap6806_directory_traversal_cve_2020_14461.py`

### zyxel / d1000_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/d1000_rce.py`

### zyxel / d1000_wifi_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/zyxel/d1000_wifi_password_disclosure.py`

### zyxel / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zyxel/ftp_default_creds.py`

### zyxel / nbg_418n_v2_modem_1_00_aaxm_6_c0_cross_site_request_forgery_cve_2019_6710

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-6710
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/nbg_418n_v2_modem_1_00_aaxm_6_c0_cross_site_request_forgery_cve_2019_6710.py`

### zyxel / nwa_1100_nh_command_injection_cve_2021_4039

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-4039
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/nwa_1100_nh_command_injection_cve_2021_4039.py`

### zyxel / p660hn_t_v1_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/p660hn_t_v1_rce.py`

### zyxel / p660hn_t_v2_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/p660hn_t_v2_rce.py`

### zyxel / pk5001z_modem_backdoor_account_cve_2016_10401

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2016-10401
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/zyxel/pk5001z_modem_backdoor_account_cve_2016_10401.py`

### zyxel / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zyxel/ssh_default_creds.py`

### zyxel / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zyxel/telnet_default_creds.py`

### zyxel / usg_flex_5_21_os_command_injection_cve_2022_30525

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2022-30525
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/usg_flex_5_21_os_command_injection_cve_2022_30525.py`

### zyxel / usg_flex_h_series_uos_1_31_privilege_escalation_cve_2025_1731

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2025-1731
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/usg_flex_h_series_uos_1_31_privilege_escalation_cve_2025_1731.py`

### zyxel / vmg3312_b10b_dsl_491hnu_b1b_v2_modem_cross_site_request_forg_cve_2019_7391

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-7391
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/vmg3312_b10b_dsl_491hnu_b1b_v2_modem_cross_site_request_forg_cve_2019_7391.py`

### zyxel / vmg8825_cmd_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/vmg8825_cmd_injection.py`

### zyxel / vmg8825_ping_cmd_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/vmg8825_ping_cmd_injection.py`

### zyxel / vmg8825_ping_command_injection_cve_2019_9955

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-9955
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/zyxel/vmg8825_ping_command_injection_cve_2019_9955.py`

### zyxel / zywall_2_plus_internet_security_appliance_cross_site_scripti_cve_2021_46387

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2021-46387
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/zywall_2_plus_internet_security_appliance_cross_site_scripti_cve_2021_46387.py`

### zyxel / zywall_310_zywall_110_usg1900_atp500_usg40_login_page_cross_cve_2019_9955

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-9955
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/zyxel/zywall_310_zywall_110_usg1900_atp500_usg40_login_page_cross_cve_2019_9955.py`
