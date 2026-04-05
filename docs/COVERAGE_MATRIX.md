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

- Module tree (routerxpl/modules): 08f0a5bc65aded0db96ad1e9d5d6422f58e35744
- Total modules indexed: 278
- Distinct vendor/product entries: 278
- Distinct CVEs mapped in modules: 23
- Attack classes identified: auth_bypass, backdoor, creds_disclosure, dns_change, info_disclosure, password_reset_or_change, path_traversal, rce

### Module Type Counts
- creds: 88
- encoders: 13
- exploits: 120
- generic: 20
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
| L1 | Link | Physical | ethernet | 1 | yes | link_disruption_or_flap_induction, tap_or_span_blind_spot_abuse, physical_plane_availability_degradation | link_state_validation, duplex_speed_mismatch_detection, capture_integrity_verification | P2 | P2 | P2 |
| L2 | Link | Data Link | arp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P1 | P1 |
| L2 | Link | Data Link | vlan_8021q_qinq | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P1 | P1 |
| L2 | Link | Data Link | 802.11_wifi | 16 | yes | offline_wpa_crack, handshake_capture_replay, credential_harvest | ap_enumeration, station_mapping, handshake_extraction, cleartext_sniffing | P2 | P1 | P2 |
| L2 | Link | Data Link | stp_rstp_mstp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P1 | P2 |
| L2 | Link | Data Link | lacp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P1 | P2 |
| L2 | Link | Data Link | lldp | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P2 | P2 | P2 |
| L2 | Link | Data Link | pppoe | 0 | no | vlan_hopping_and_tagging_abuse, arp_spoofing_or_poisoning, stp_manipulation_or_loop_induction, mac_table_exhaustion_scenarios, wpa_wpa2_offline_handshake_crack, wireless_credential_harvest_from_pcap, rogue_ap_detection_via_pcap | vlan_segmentation_validation, arp_integrity_checks, stp_lacp_hardening_review, l2_discovery_surface_assessment, pcap_ap_station_enumeration, pcap_handshake_completeness_check, pcap_cleartext_credential_extraction | P1 | P3 | P3 |
| L3 | Internet | Network | ipv4_ipv6 | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P1 | P1 | P1 |
| L3 | Internet | Network | icmp_icmpv6 | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P1 | P1 | P2 |
| L3 | Internet | Network | ospf | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P2 | P2 | P3 |
| L3 | Internet | Network | bgp | 0 | no | route_injection_or_hijack_paths, icmp_or_control_plane_abuse, ipv6_transition_misconfig_exposure | routing_surface_enumeration, dual_stack_consistency_checks, control_plane_exposure_validation | P2 | P3 | P3 |
| L4 | Transport | Transport | tcp | 29 | yes | service_enumeration_and_port_abuse, session_exhaustion_or_flood_paths, transport_timeout_and_retry_abuse | tcp_udp_surface_mapping, session_stability_validation, timeout_retry_behavior_checks | P1 | P1 | P1 |
| L4 | Transport | Transport | udp | 8 | yes | service_enumeration_and_port_abuse, session_exhaustion_or_flood_paths, transport_timeout_and_retry_abuse | tcp_udp_surface_mapping, session_stability_validation, timeout_retry_behavior_checks | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | dns | 6 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P2 |
| L5-L7 | Application | Session/Presentation/Application | dhcp | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P2 |
| L5-L7 | Application | Session/Presentation/Application | ntp_ptp | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P2 | P1 |
| L5-L7 | Application | Session/Presentation/Application | snmp_snmpv3 | 4 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | ssh | 27 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | telnet | 28 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P3 | P2 |
| L5-L7 | Application | Session/Presentation/Application | ftp_ftps_sftp | 29 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P2 | P2 |
| L5-L7 | Application | Session/Presentation/Application | http_https_api | 14 | yes | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P1 | P1 | P1 |
| L5-L7 | Application | Session/Presentation/Application | radius_tacacs | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P3 | P2 | P3 |
| L5-L7 | Application | Session/Presentation/Application | tr069_cwmp | 0 | no | default_credential_and_bruteforce_paths, auth_bypass_and_session_abuse, protocol_parser_and_input_injection_paths, management_api_and_header_abuse, snmp_read_write_and_trap_plane_misuse | credential_validation_matrix, auth_method_coverage_checks, protocol_specific_exploitability_checks, snmpv2_snmpv3_trap_operational_validation, api_and_web_management_flow_validation | P2 | P3 | P3 |
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
| L1 Physical | 1 |
| L2 Data Link | 16 |
| L3 Network | 0 |
| L4 Transport | 37 |
| L5-L7 Session/Presentation/Application | 108 |

## Market Priority Coverage (2010-2026)

### Yearly Minimum Validation

- Brazil domestic minimum/year: 10
- Brazil corporate minimum/year: 10
- Global minimum/year: 5

#### Brazil Domestic Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 11 | 11 | ok | 8 | 2 |
| 2011 | 11 | 11 | ok | 8 | 1 |
| 2012 | 11 | 11 | ok | 8 | 1 |
| 2013 | 11 | 11 | ok | 7 | 1 |
| 2014 | 11 | 11 | ok | 7 | 1 |
| 2015 | 11 | 11 | ok | 8 | 2 |
| 2016 | 12 | 12 | ok | 8 | 1 |
| 2017 | 13 | 13 | ok | 7 | 1 |
| 2018 | 13 | 13 | ok | 7 | 1 |
| 2019 | 13 | 13 | ok | 8 | 1 |
| 2020 | 13 | 13 | ok | 11 | 1 |
| 2021 | 14 | 14 | ok | 9 | 0 |
| 2022 | 14 | 14 | ok | 10 | 0 |
| 2023 | 15 | 15 | ok | 9 | 0 |
| 2024 | 14 | 14 | ok | 10 | 0 |
| 2025 | 16 | 16 | ok | 12 | 0 |
| 2026 | 15 | 15 | ok | 10 | 0 |

#### Brazil Corporate Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 13 | 13 | ok | 7 | 1 |
| 2011 | 13 | 13 | ok | 7 | 1 |
| 2012 | 15 | 15 | ok | 8 | 1 |
| 2013 | 15 | 15 | ok | 8 | 0 |
| 2014 | 15 | 15 | ok | 8 | 0 |
| 2015 | 15 | 15 | ok | 8 | 0 |
| 2016 | 15 | 15 | ok | 8 | 0 |
| 2017 | 15 | 15 | ok | 8 | 0 |
| 2018 | 17 | 17 | ok | 8 | 0 |
| 2019 | 20 | 20 | ok | 8 | 0 |
| 2020 | 20 | 20 | ok | 8 | 0 |
| 2021 | 22 | 22 | ok | 8 | 0 |
| 2022 | 23 | 23 | ok | 9 | 0 |
| 2023 | 22 | 22 | ok | 11 | 0 |
| 2024 | 24 | 24 | ok | 11 | 0 |
| 2025 | 24 | 24 | ok | 11 | 0 |
| 2026 | 24 | 24 | ok | 11 | 0 |

#### Global Coverage By Year

| Year | Required | Cataloged | Status | Vendor Covered Count | Keyword Hits |
|---:|---:|---:|---|---:|---:|
| 2010 | 5 | 6 | ok | 5 | 2 |
| 2011 | 5 | 6 | ok | 4 | 1 |
| 2012 | 5 | 7 | ok | 7 | 2 |
| 2013 | 5 | 8 | ok | 6 | 0 |
| 2014 | 5 | 8 | ok | 5 | 0 |
| 2015 | 5 | 7 | ok | 5 | 1 |
| 2016 | 5 | 9 | ok | 5 | 1 |
| 2017 | 5 | 9 | ok | 5 | 0 |
| 2018 | 5 | 12 | ok | 6 | 0 |
| 2019 | 5 | 12 | ok | 6 | 0 |
| 2020 | 5 | 11 | ok | 7 | 0 |
| 2021 | 5 | 12 | ok | 6 | 0 |
| 2022 | 5 | 12 | ok | 6 | 0 |
| 2023 | 5 | 13 | ok | 6 | 0 |
| 2024 | 5 | 13 | ok | 6 | 0 |
| 2025 | 5 | 13 | ok | 6 | 0 |
| 2026 | 5 | 13 | ok | 4 | 0 |

### Brazil Domestic Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | Netgear | WNDR3700 | router-home | yes | 0 |
| 2010 | Linksys | WRT610N | router-home | yes | 0 |
| 2010 | D-Link | DIR-655 | router-home | yes | 1 |
| 2010 | TP-Link | TL-WR1043ND | router-home | yes | 0 |
| 2010 | ASUS | RT-N13U | router-home | yes | 0 |
| 2010 | Netgear | WNDR3800 | router-home | yes | 0 |
| 2010 | Linksys | E3000 | router-home | yes | 0 |
| 2010 | Trendnet | TEW-691GR | router-home | no | 0 |
| 2010 | Apple | AirPort Extreme 4th Gen | router-home | no | 0 |
| 2010 | Belkin | N750 DB | router-home | yes | 1 |
| 2010 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2011 | Linksys | E4200 | router-home | yes | 0 |
| 2011 | ASUS | RT-N56U | router-home | yes | 0 |
| 2011 | Netgear | WNDR4000 | router-home | yes | 0 |
| 2011 | Trendnet | TEW-692GR | router-home | no | 0 |
| 2011 | Belkin | N750 DB | router-home | yes | 1 |
| 2011 | ASUS | RT-N66U | router-home | yes | 0 |
| 2011 | D-Link | DIR-819 | router-home | yes | 0 |
| 2011 | Linksys | E3200 | router-home | yes | 0 |
| 2011 | Netgear | WNDR3700 | router-home | yes | 0 |
| 2011 | Apple | AirPort Extreme 5th Gen | router-home | no | 0 |
| 2011 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | TP-Link | Archer C20 | router-home | yes | 1 |
| 2012 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2012 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2012 | D-Link | DIR-819 | router-home | yes | 0 |
| 2012 | D-Link | DIR-822 | router-home | yes | 0 |
| 2012 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2012 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2012 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2012 | TP-Link | TL-WR940N | router-home | yes | 0 |
| 2012 | TP-Link | TL-WR840N | router-home | yes | 0 |
| 2012 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2013 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2013 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2013 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2013 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2013 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2013 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2013 | TP-Link | TL-WR940N | router-home | yes | 0 |
| 2013 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2013 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2013 | Mercusys | MR60X | router-home | no | 0 |
| 2013 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2014 | TP-Link | Archer C20 | router-home | yes | 1 |
| 2014 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2014 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2014 | TP-Link | TL-WR940N | router-home | yes | 0 |
| 2014 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2014 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2014 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2014 | D-Link | DIR-819 | router-home | yes | 0 |
| 2014 | D-Link | DIR-822 | router-home | yes | 0 |
| 2014 | Mercusys | MR60X | router-home | no | 0 |
| 2014 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2015 | TP-Link | Archer C20 | router-home | yes | 1 |
| 2015 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2015 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2015 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2015 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2015 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2015 | D-Link | DIR-819 | router-home | yes | 0 |
| 2015 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2015 | TP-Link | TL-WR840N | router-home | yes | 0 |
| 2015 | TP-Link | TL-WR940N | router-home | yes | 0 |
| 2015 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2016 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2016 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2016 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2016 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2016 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2016 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2016 | D-Link | DIR-822 | router-home | yes | 0 |
| 2016 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2016 | Mercusys | MR60X | router-home | no | 0 |
| 2016 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2016 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2016 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2017 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2017 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2017 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2017 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2017 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2017 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2017 | Mercusys | MR60X | router-home | no | 0 |
| 2017 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2017 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2017 | Tenda | AC23 | router-home | no | 0 |
| 2017 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2017 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2017 | Mercusys | MS105G | switch-soho | no | 0 |
| 2018 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2018 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2018 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2018 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2018 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2018 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2018 | Mercusys | MR60X | router-home | no | 0 |
| 2018 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2018 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2018 | Tenda | AC23 | router-home | no | 0 |
| 2018 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2018 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2018 | Mercusys | MS105G | switch-soho | no | 0 |
| 2019 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2019 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2019 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2019 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2019 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2019 | D-Link | DIR-822 | router-home | yes | 0 |
| 2019 | TP-Link | Archer C9 | router-home | yes | 1 |
| 2019 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2019 | Mercusys | MR60X | router-home | no | 0 |
| 2019 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2019 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2019 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2019 | Mercusys | MS105G | switch-soho | no | 0 |
| 2020 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2020 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2020 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2020 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2020 | D-Link | DIR-819 | router-home | yes | 0 |
| 2020 | TP-Link | Archer C20 | router-home | yes | 1 |
| 2020 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2020 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2020 | D-Link | DIR-822 | router-home | yes | 0 |
| 2020 | TP-Link | TL-WR840N | router-home | yes | 0 |
| 2020 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2020 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2020 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2021 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2021 | TP-Link | Archer AX10 | router-home | yes | 0 |
| 2021 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2021 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2021 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2021 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2021 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2021 | TP-Link | TL-WR940N | router-home | yes | 0 |
| 2021 | Mercusys | MR60X | router-home | no | 0 |
| 2021 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2021 | OpenWrt | OpenWrt 21.02 Generic Targets | router-firmware | no | 0 |
| 2021 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2021 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2021 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2022 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2022 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2022 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2022 | Mercusys | MR60X | router-home | no | 0 |
| 2022 | ASUS | RT-AX88U | router-corporate | yes | 0 |
| 2022 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2022 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2022 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2022 | Huawei | AX2S | router-home | yes | 0 |
| 2022 | Mercusys | MR80X | router-home | no | 0 |
| 2022 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2022 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2022 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2022 | Netgear | GS305 | switch-soho | yes | 0 |
| 2023 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2023 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2023 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2023 | Huawei | AX3 Dual Core | router-home | yes | 0 |
| 2023 | Mercusys | MR60X | router-home | no | 0 |
| 2023 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2023 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2023 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2023 | Intelbras | AX 1500 | router-home | no | 0 |
| 2023 | TP-Link | Archer C6 | router-home | yes | 0 |
| 2023 | OpenWrt | OpenWrt 22.03 Generic Targets | router-firmware | no | 0 |
| 2023 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2023 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2023 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2023 | Netgear | GS305 | switch-soho | yes | 0 |
| 2024 | TP-Link | Archer AX73 | router-home | yes | 0 |
| 2024 | Huawei | AX2S | router-home | yes | 0 |
| 2024 | ASUS | AX5400 | router-home | yes | 0 |
| 2024 | Mercusys | MR60X | router-home | no | 0 |
| 2024 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2024 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2024 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2024 | TP-Link | Archer AX12 | router-home | yes | 0 |
| 2024 | TP-Link | Archer C80 | router-home | yes | 0 |
| 2024 | TP-Link | Deco BE85 | router-mesh | yes | 0 |
| 2024 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2024 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
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
| 2025 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
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
| 2026 | Intelbras | Action RG 1200 | router-home | no | 0 |
| 2026 | TP-Link | Archer C80 | router-home | yes | 0 |
| 2026 | TP-Link | TL-SG108 | switch-soho | yes | 0 |
| 2026 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2026 | TP-Link | LS1005G | switch-soho | yes | 0 |
| 2026 | Netgear | GS305 | switch-soho | yes | 0 |
| 2026 | TP-Link | TL-SG108E | switch-smart | yes | 0 |

### Brazil Corporate Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | DrayTek | Vigor2110n | router-corporate | no | 0 |
| 2010 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2010 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2010 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2010 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2010 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2010 | Aruba | 2930F | switch-corporate | no | 0 |
| 2010 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2010 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2010 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2010 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2010 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2010 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2011 | DrayTek | Vigor2110n | router-corporate | no | 0 |
| 2011 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2011 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2011 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2011 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2011 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2011 | Aruba | 2930F | switch-corporate | no | 0 |
| 2011 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2011 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2011 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2011 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2011 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2011 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2012 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2012 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2012 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2012 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2012 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2012 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2012 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2012 | Aruba | 2930F | switch-corporate | no | 0 |
| 2012 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2012 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2012 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2012 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2012 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2012 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2013 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2013 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2013 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2013 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2013 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2013 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2013 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2013 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2013 | Aruba | 2930F | switch-corporate | no | 0 |
| 2013 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2013 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2013 | Intelbras | SG 800 Q+ | switch-soho | no | 0 |
| 2013 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2013 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2013 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2014 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2014 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2014 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2014 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2014 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2014 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2014 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2014 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2014 | Aruba | 2930F | switch-corporate | no | 0 |
| 2014 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2014 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2014 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2014 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2014 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2014 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2015 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2015 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2015 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2015 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2015 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2015 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2015 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2015 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2015 | Aruba | 2930F | switch-corporate | no | 0 |
| 2015 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2015 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2015 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2015 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2015 | BrazilFW | BrazilFW Firewall Router | fw-opensource | no | 0 |
| 2015 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2016 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2016 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2016 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2016 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2016 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2016 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2016 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2016 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2016 | Aruba | 2930F | switch-corporate | no | 0 |
| 2016 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2016 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2016 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2016 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2016 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2016 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2017 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2017 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2017 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2017 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2017 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2017 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2017 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2017 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2017 | Aruba | 2930F | switch-corporate | no | 0 |
| 2017 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2017 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2017 | Intelbras | SG 1024 MR | switch-corporate | no | 0 |
| 2017 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2017 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2017 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2018 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2018 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2018 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2018 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2018 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2018 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2018 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2018 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2018 | Aruba | 2930F | switch-corporate | no | 0 |
| 2018 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2018 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2018 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2018 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2018 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2018 | SonicWall | TZ Series | fw-smb | no | 0 |
| 2018 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2018 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2019 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2019 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2019 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2019 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2019 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2019 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2019 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2019 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2019 | Aruba | 2930F | switch-corporate | no | 0 |
| 2019 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2019 | OpenWrt | OpenWrt 19.07 Generic Targets | router-firmware | no | 0 |
| 2019 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2019 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2019 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2019 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2019 | SonicWall | TZ Series | fw-smb | no | 0 |
| 2019 | Netgate | pfSense | fw-opensource | no | 0 |
| 2019 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2019 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2019 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2020 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2020 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2020 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2020 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2020 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2020 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2020 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2020 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2020 | Aruba | 2930F | switch-corporate | no | 0 |
| 2020 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2020 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2020 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2020 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2020 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2020 | SonicWall | TZ Series | fw-smb | no | 0 |
| 2020 | Netgate | pfSense | fw-opensource | no | 0 |
| 2020 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2020 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2020 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2020 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2021 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2021 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2021 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2021 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2021 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2021 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2021 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2021 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2021 | Aruba | 2930F | switch-corporate | no | 0 |
| 2021 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2021 | OpenWrt | OpenWrt 21.02 Generic Targets | router-firmware | no | 0 |
| 2021 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2021 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2021 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2021 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2021 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2021 | Netgate | pfSense | fw-opensource | no | 0 |
| 2021 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2021 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2021 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2021 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2021 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2022 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2022 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2022 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2022 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2022 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2022 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2022 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2022 | Palo Alto Networks | PA-220 | ngfw-corporate | no | 0 |
| 2022 | Aruba | 2930F | switch-corporate | no | 0 |
| 2022 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2022 | OpenWrt | OpenWrt 22.03 Generic Targets | router-firmware | no | 0 |
| 2022 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2022 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2022 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2022 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
| 2022 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2022 | Netgate | pfSense | fw-opensource | no | 0 |
| 2022 | Cisco | Business CBS250 | switch-corporate | yes | 0 |
| 2022 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2022 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2022 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2022 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2022 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2023 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2023 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2023 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2023 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2023 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2023 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2023 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2023 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2023 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2023 | Aruba | 2930F | switch-corporate | no | 0 |
| 2023 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2023 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2023 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2023 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
| 2023 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2023 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2023 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2023 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2023 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2023 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2023 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2023 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2024 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2024 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2024 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2024 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2024 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2024 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2024 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2024 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2024 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2024 | Aruba | 2930F | switch-corporate | no | 0 |
| 2024 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2024 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2024 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2024 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2024 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
| 2024 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2024 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2024 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2024 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2024 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2024 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2024 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2024 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2024 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2025 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2025 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2025 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2025 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2025 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2025 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2025 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2025 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2025 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2025 | Aruba | 2930F | switch-corporate | no | 0 |
| 2025 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2025 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2025 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2025 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2025 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
| 2025 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2025 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2025 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2025 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2025 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2025 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2025 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2025 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2025 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |
| 2026 | Ubiquiti | UniFi Dream Router | router-corporate | yes | 0 |
| 2026 | Ubiquiti | Cloud Gateway Ultra | router-corporate | yes | 0 |
| 2026 | MikroTik | RB3011UiAS-RM | router-corporate | yes | 0 |
| 2026 | MikroTik | RB4011iGS+RM | router-corporate | yes | 0 |
| 2026 | MikroTik | CRS326 | switch-corporate | yes | 0 |
| 2026 | Cisco | ISR 4331 | router-corporate | yes | 0 |
| 2026 | Cisco | C1111-8P | router-corporate | yes | 0 |
| 2026 | Fortinet | FortiGate 60F | ngfw-corporate | no | 0 |
| 2026 | Juniper | SRX300 | ngfw-corporate | yes | 0 |
| 2026 | Aruba | 2930F | switch-corporate | no | 0 |
| 2026 | OpenWrt | OpenWrt 23.05 Generic Targets | router-firmware | no | 0 |
| 2026 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2026 | Aruba | Instant On 1930 | switch-corporate | no | 0 |
| 2026 | Intelbras | SG 2404 PoE | switch-poe | no | 0 |
| 2026 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
| 2026 | Sophos | XGS Firewall | ngfw-smb | no | 0 |
| 2026 | Cisco | Business CBS350 | switch-corporate | yes | 0 |
| 2026 | Ubiquiti | UniFi Switch 8/16/24/48 PoE | switch-corporate | yes | 0 |
| 2026 | Palo Alto Networks | PA-450 | ngfw-corporate | no | 0 |
| 2026 | Starti | Edge Protect NGFW | ngfw-smb | no | 0 |
| 2026 | Blockbit | Blockbit NGFW/UTM | ngfw-corporate | no | 0 |
| 2026 | Algar Telecom | Algar NGFW | ngfw-isp | no | 0 |
| 2026 | Azion | Azion Edge Firewall/WAF | fw-cloud-edge | no | 0 |
| 2026 | DrayTek | Vigor2960 Firewall VPN | fw-smb | no | 0 |

### Global Device List (2010-2026)

| Year | Vendor | Product | Segment | Vendor Covered | Keyword Hits |
|---:|---|---|---|---|---:|
| 2010 | Netgear | WNDR3700 | router-home | yes | 0 |
| 2010 | Linksys | WRT610N | router-home | yes | 0 |
| 2010 | D-Link | DIR-655 | router-home | yes | 1 |
| 2010 | TP-Link | TL-WR1043ND | router-home | yes | 0 |
| 2010 | Apple | AirPort Extreme 4th Gen | router-home | no | 0 |
| 2010 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2011 | Linksys | E4200 | router-home | yes | 0 |
| 2011 | ASUS | RT-N56U | router-home | yes | 0 |
| 2011 | Netgear | WNDR4000 | router-home | yes | 0 |
| 2011 | Trendnet | TEW-692GR | router-home | no | 0 |
| 2011 | Apple | AirPort Extreme 5th Gen | router-home | no | 0 |
| 2011 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2012 | TP-Link | Archer C20 | router-home | yes | 1 |
| 2012 | Linksys | E3200 | router-home | yes | 0 |
| 2012 | Netgear | WNDR3700 | router-home | yes | 0 |
| 2012 | D-Link | DIR-819 | router-home | yes | 0 |
| 2012 | ASUS | RT-N66U | router-home | yes | 0 |
| 2012 | Cisco | Catalyst 2960-X | switch-enterprise | yes | 1 |
| 2012 | Juniper | EX2300 | switch-enterprise | yes | 0 |
| 2013 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2013 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2013 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2013 | Linksys | E4200 | router-home | yes | 0 |
| 2013 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2013 | AT&T / Arris | NVG589 VDSL Gateway | isp-cpe/modem-router | no | 0 |
| 2013 | Cisco | Catalyst 3850 | switch-enterprise | yes | 0 |
| 2013 | Juniper | EX2300 | switch-enterprise | yes | 0 |
| 2014 | TP-Link | Archer C7 | router-home | yes | 0 |
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
| 2016 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2016 | D-Link | DIR-822 | router-home | yes | 0 |
| 2016 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2016 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2016 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2016 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2017 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2017 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2017 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2017 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2017 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2017 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2017 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2017 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2017 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2018 | TP-Link | Deco M4 | router-mesh | yes | 0 |
| 2018 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2018 | Google | Nest Wi-Fi | router-mesh | no | 0 |
| 2018 | TP-Link | Archer C7 | router-home | yes | 0 |
| 2018 | Netgear | Nighthawk Pro Gaming XR500 | router-home | yes | 0 |
| 2018 | OpenWrt | OpenWrt x86_64 Virtual Router | router-virtual | no | 0 |
| 2018 | AT&T / Pace | 5268AC U-Verse Gateway | isp-cpe/gateway | no | 0 |
| 2018 | AT&T / Arris | BGW210-700 Fiber Gateway | isp-cpe/gateway | no | 0 |
| 2018 | Cisco | Catalyst 9300 | switch-enterprise | yes | 0 |
| 2018 | Arista | 7000 Series | switch-datacenter | no | 0 |
| 2018 | Cisco | Nexus 9000 | switch-datacenter | yes | 0 |
| 2018 | Fortinet | FortiGate 100F | ngfw-corporate | no | 0 |
| 2019 | ASUS | RT-AC86U | router-home | yes | 0 |
| 2019 | TP-Link | Archer C7 | router-home | yes | 0 |
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
| 2022 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
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
| 2023 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
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
| 2024 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
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
| 2025 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
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
| 2026 | Fortinet | FortiGate 200F | ngfw-corporate | no | 0 |
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

## External Tooling and Code Intelligence

| ID | Name | Type | Domain | Scope Alignment | Integration Status | Test Matrix | Source |
|---|---|---|---|---|---|---|---|
| forge-incorporated-third-party-pocs | Local mirror of third-party-router-poc clones (all slugs) | embedded-offline-tree | router-soho | high | embedded-in-forge | tracked | urn:routerxpl:incorporated-third-party-pocs |
| belkin4xx-keygen | Belkin4xx key correlation script | algorithm-research | wifi-default-key | conditional | queued_for_analysis | tracked | https://bitbucket.org/dudux/belkin4xx/src/eb7545023f250589bfc2f944472964754a83f66d/belkin4xx.py?at=master |
| pirelli-prg-eav4202n | PRG EAV4202N default WPA algorithm research | algorithm-research | wifi-default-key | conditional | queued_for_analysis | tracked | https://sviehb.wordpress.com/2011/12/04/prg-eav4202n-default-wpa-key-algorithm/ |
| threat9-upnpfuzz | UPnPFuzz | fuzzing-tool | upnp-discovery-fuzzing | high | planned-adapter | tracked | https://github.com/threat9/upnpfuzz/?tab=readme-ov-file |
| devttys0-repos | devttys0 repositories index | firmware-research-index | firmware-toolchain | high | planned-curation | tracked | https://github.com/devttys0?tab=repositories |
| devttys0-delink | DeLink firmware decryption library | firmware-tool | dlink-firmware-decryption | high | planned-adapter | tracked | https://github.com/devttys0/delink |
| threat9-main | THREAT9 official site | vendor-context | project-context | reference | reference | tracked | https://threat9.com/ |
| routerpwn-site | RouterPWN (SOHO router exploits, generators, advisories) | exploit-index | router-soho | high | queued_for_curation | tracked | https://routerpwn.com/ |
| routerpwn-wayback | RouterPWN — Internet Archive (Wayback) catch-all | exploit-index-archive | router-soho | high | queued_for_curation | tracked | https://web.archive.org/web/*/http://routerpwn.com/ |
| routerpwn-github-mirror | hkm/routerpwn.com (static mirror / offline bundle) | source-mirror | router-soho | high | embedded-in-forge | tracked | https://github.com/hkm/routerpwn.com |
| exploit-db-hardware-search | Exploit-DB — hardware / router vendor search | exploit-index | router-switch-fw | conditional | reference | tracked | https://www.exploit-db.com/ |
| intelbras-vuln-checker-gist | Community Intelbras router vuln checklist (gist) | research-index | router-br | conditional | queued_for_curation | tracked | https://gist.github.com/MrCl0wnLab/2c325380cff786e0e1556c1fc8306098 |
| metasploit-framework-github | Metasploit Framework (Rapid7) — upstream source | exploit-framework | orchestration-bridge | high | adapter-module | tracked | https://github.com/rapid7/metasploit-framework |
| exploitdb-gitlab | Exploit-DB (OffSec) — upstream reference | exploit-database | research-cli | high | embedded-in-forge | tracked | https://gitlab.com/exploit-database/exploitdb |
| mikrotikapi-bf-github | MikrotikAPI-BF — RouterOS toolkit (author) | vendor-toolkit | mikrotik-routeros | high | adapter-module | tracked | https://github.com/mrhenrike/MikrotikAPI-BF |
| bitbucket-router-research | Bitbucket search — router / firmware / exploit keywords | discovery-hint | router-soho | low | reference | tracked | https://bitbucket.org/search?q=router |
| local-poc-0vercl0k-zenith | 0vercl0k__zenith (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/0vercl0k/zenith.git |
| local-poc-0xedh-mistrastar-mips-exploit | 0xedh__mistrastar-mips-exploit (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/0xedh/mistrastar-mips-exploit.git |
| local-poc-0xyassine-poc-seeker | 0xyassine__poc-seeker (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/0xyassine/poc-seeker.git |
| local-poc-649-pingpon-exploit | 649__Pingpon-Exploit (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/649/Pingpon-Exploit.git |
| local-poc-acecilia-openwrtinvasion | acecilia__OpenWRTInvasion (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/acecilia/OpenWRTInvasion.git |
| local-poc-afang5472-tp-link-wdr-router-command-injection_poc | afang5472__TP-Link-WDR-Router-Command-injection_POC (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/afang5472/TP-Link-WDR-Router-Command-injection_POC.git |
| local-poc-arthastang-iot-home-guard | arthastang__IoT-Home-Guard (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/arthastang/IoT-Home-Guard.git |
| local-poc-arthastang-iot-implant-toolkit | arthastang__IoT-Implant-Toolkit (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/arthastang/IoT-Implant-Toolkit.git |
| local-poc-arthastang-router-exploit-shovel | arthastang__Router-Exploit-Shovel (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/arthastang/Router-Exploit-Shovel.git |
| local-poc-coincoin7-wireless-router-vulnerability | coincoin7__Wireless-Router-Vulnerability (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/coincoin7/Wireless-Router-Vulnerability.git |
| local-poc-cybervinner-tp-link-tl-wr820n-cve-2025-14175 | CyberVinner__TP-Link-TL-WR820N-CVE-2025-14175 (clone local PoC) | local-git-submodule | iot_embedded_poc | high | embedded-local-mirror | tracked | https://github.com/CyberVinner/TP-Link-TL-WR820N-CVE-2025-14175.git |
| local-poc-dylvie-cve-2020-35575-tp-link-tl-wr841nd-password-disclosure | dylvie__CVE-2020-35575-TP-LINK-TL-WR841ND-password-disclosure (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/dylvie/CVE-2020-35575-TP-LINK-TL-WR841ND-password-disclosure.git |
| local-poc-elbertavares-routers-exploit | ElberTavares__routers-exploit (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/ElberTavares/routers-exploit.git |
| local-poc-entysec-hatasm | EntySec__HatAsm (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/EntySec/HatAsm.git |
| local-poc-entysec-hatsploit | EntySec__HatSploit (clone local PoC) | local-git-submodule | iot_embedded_poc | high | embedded-local-mirror | tracked | https://github.com/EntySec/HatSploit.git |
| local-poc-entysec-libload | EntySec__libload (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/EntySec/libload.git |
| local-poc-entysec-pwny | EntySec__Pwny (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/EntySec/Pwny.git |
| local-poc-entysec-rombuster | EntySec__RomBuster (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/EntySec/RomBuster.git |
| local-poc-exploit-database-exploitdb | exploit-database__exploitdb (clone local PoC) | local-git-submodule | exploitdb_mirror | conditional | embedded-local-mirror | tracked | https://gitlab.com/exploit-database/exploitdb.git |
| local-poc-exploit-database-exploitdb-bin-sploits | exploit-database__exploitdb-bin-sploits (clone local PoC) | local-git-submodule | exploitdb_mirror | conditional | embedded-local-mirror | tracked | https://gitlab.com/exploit-database/exploitdb-bin-sploits.git |
| local-poc-foreni-packages-cisco-global-exploiter | foreni-packages__cisco-global-exploiter (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/foreni-packages/cisco-global-exploiter.git |
| local-poc-g-bdennour-huawei | G-bdennour__Huawei (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/G-bdennour/Huawei.git |
| local-poc-hkm-routerpwn.com | hkm__routerpwn.com (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/hkm/routerpwn.com.git |
| local-poc-hook-s3c-cve-2018-18852 | hook-s3c__CVE-2018-18852 (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/hook-s3c/CVE-2018-18852.git |
| local-poc-iridium-tapohax | iridium__tapohax (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/iridium/tapohax.git |
| local-poc-j91321-rext | j91321__rext (clone local PoC) | local-git-submodule | iot_embedded_poc | high | embedded-local-mirror | tracked | https://github.com/j91321/rext.git |
| local-poc-jackdoan-tp-link-archerc5-rce | JackDoan__TP-Link-ArcherC5-RCE (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/JackDoan/TP-Link-ArcherC5-RCE.git |
| local-poc-johnoseni1-router-hacker-exploit-and-extract-user-and-password- | johnoseni1__Router-hacker-Exploit-and-extract-user-and-password- (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/johnoseni1/Router-hacker-Exploit-and-extract-user-and-password-.git |
| local-poc-knqyf263-cve-2020-10749 | knqyf263__CVE-2020-10749 (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/knqyf263/CVE-2020-10749.git |
| local-poc-kthemis-routerexploitscan | kthemis__RouterExploitScan (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/kthemis/RouterExploitScan.git |
| local-poc-maherazzouzi-zte-f660-exploit | MaherAzzouzi__ZTE-F660-Exploit (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/MaherAzzouzi/ZTE-F660-Exploit.git |
| local-poc-openwrt-xiaomi-xmir-patcher | openwrt-xiaomi__xmir-patcher (clone local PoC) | local-git-submodule | iot_embedded_poc | high | embedded-local-mirror | tracked | https://github.com/openwrt-xiaomi/xmir-patcher.git |
| local-poc-oscommonjs-exp_iot | oscommonjs__EXP_IOT (clone local PoC) | local-git-submodule | iot_embedded_poc | high | embedded-local-mirror | tracked | https://github.com/oscommonjs/EXP_IOT.git |
| local-poc-samyk-evercookie | samyk__evercookie (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/samyk/evercookie.git |
| local-poc-samyk-magspoof | samyk__magspoof (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/samyk/magspoof.git |
| local-poc-samyk-poisontap | samyk__poisontap (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/samyk/poisontap.git |
| local-poc-samyk-pwnat | samyk__pwnat (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/samyk/pwnat.git |
| local-poc-samyk-skyjack | samyk__skyjack (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/samyk/skyjack.git |
| local-poc-samyk-slipstream | samyk__slipstream (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/samyk/slipstream.git |
| local-poc-seclab-ucr-ccs24mesh | seclab-ucr__CCS24Mesh (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/seclab-ucr/CCS24Mesh.git |
| local-poc-seclab-ucr-koobe | seclab-ucr__KOOBE (clone local PoC) | local-git-submodule | generic_or_offtopic | conditional | embedded-local-mirror | tracked | https://github.com/seclab-ucr/KOOBE.git |
| local-poc-seclab-ucr-symtcp | seclab-ucr__SymTCP (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/seclab-ucr/SymTCP.git |
| local-poc-seclab-ucr-tcp_exploit | seclab-ucr__tcp_exploit (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/seclab-ucr/tcp_exploit.git |
| local-poc-stasinopoulos-ztexploit | stasinopoulos__ZTExploit (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/stasinopoulos/ZTExploit.git |
| local-poc-tacnetsol-trendnetexploits | tacnetsol__TRENDNetExploits (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/tacnetsol/TRENDNetExploits.git |
| local-poc-teteco-cve-2025-67070-intelbras-cftv-mfa-bypass | teteco__CVE-2025-67070-Intelbras-CFTV-MFA-Bypass (clone local PoC) | local-git-submodule | edge_network_poc | high | embedded-local-mirror | tracked | https://github.com/teteco/CVE-2025-67070-Intelbras-CFTV-MFA-Bypass.git |
| local-poc-tg12-poc_cves | tg12__PoC_CVEs (clone local PoC) | local-git-submodule | iot_embedded_poc | conditional | embedded-local-mirror | tracked | https://github.com/tg12/PoC_CVEs.git |
| local-poc-thomasrinsma-vmg8825scripts | ThomasRinsma__vmg8825scripts (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/ThomasRinsma/vmg8825scripts.git |
| local-poc-zeyad-azima-huawei_thief | Zeyad-Azima__Huawei_Thief (clone local PoC) | local-git-submodule | edge_network_poc | conditional | embedded-local-mirror | tracked | https://github.com/Zeyad-Azima/Huawei_Thief.git |

## Discord Requested Devices Coverage

| Vendor | Model | Segment | Vendor Covered | Model Keyword Hits | Exploits | Creds | Scanners | Attack Classes | Context |
|---|---|---|---|---:|---:|---:|---:|---|---|
| TP-Link | AC1700 | router | yes | 8 | 5 | 3 | 0 | backdoor, password_reset_or_change, path_traversal, rce | user asked applicability to TP-Link AC1700 |
| TP-Link | AC1750 | router | yes | 8 | 5 | 3 | 0 | backdoor, password_reset_or_change, path_traversal, rce | home setup mention, landlord-provided router |
| Rogers/Shaw | XB7 (Gen2) | isp-cpe/modem-router | no | 0 | 0 | 0 | 0 | - | customer modem in bridged / passthrough chain |
| Hitron | CGNM-2250 | isp-cpe/modem-router | no | 0 | 0 | 0 | 0 | - | IP passthrough discussion and attack surface concerns |
| AT&T / Pace | 5268AC | isp-cpe/gateway | no | 0 | 0 | 0 | 0 | - | explicit pentest request in conversation |
| ADB / Pirelli | PRG EAV4202N / PRGAV4202N | dsl-gateway | no | 0 | 0 | 0 | 0 | - | default WPA algorithm weakness discussion |
| Technicolor | TG585v6 | dsl-gateway | yes | 7 | 4 | 3 | 0 | auth_bypass, creds_disclosure | legacy vulnerable fleet mentioned in thread |
| EasyBox | EasyBox (German variants) | dsl-gateway | no | 0 | 0 | 0 | 0 | - | algorithm request in discussion comments |
| Generic | Low-cost Chinese ONU/CPE | onu/isp-cpe | yes | 1 | 5 | 0 | 2 | auth_bypass, backdoor, info_disclosure, rce | claim that modern cheap ONUs are not covered |

## Architecture Inventory Snapshot

- Name: RouterXPL-Forge Arsenal Index
- Scope: routers, switches, taps, fw, ngfw
- Out of scope: cameras, printers, dvr, dvrs
- Generated by: tools/build_arsenal_index.py

| Domain | Count |
|---|---:|
| catalogs | 17 |
| wordlists | 10 |
| ssh_keys | 8 |
| vendors datasets | 2 |
| mibs | 1758 |
| modules.exploits | 129 |
| modules.creds | 96 |
| modules.scanners | 6 |
| modules.generic | 20 |
| modules.encoders | 13 |
| modules.payloads | 32 |

| curated_arsenal domain | Count |
|---|---:|
| binaries | 2 |
| credentials | 1 |
| firmware | 2 |
| intel | 6 |
| mibs | 1 |
| pocs | 55060 |
| wordlists | 1 |

## Workspace Reuse Inventory Snapshot

- Total assets discovered: 65650

| Classification | Count |
|---|---:|
| catalog_only | 3677 |
| integrate_core | 41627 |
| reject | 20346 |

## Deep Intel Backlog Snapshot

- Total backlog items: 19
- Total keyword hits across backlog: 125

| Priority | Count |
|---|---:|
| p1 | 15 |
| p2 | 3 |
| p3 | 1 |

## Honeypot Final Validation Snapshot

- Campaign: phase6b_final_honeypot_validation
- Checked at: 2026-04-03T21:56:54.046319+00:00

| Platform | Ready Queries | Blocked Queries |
|---|---:|---:|
| censys | 0 | 3 |
| fofa | 0 | 3 |
| netlas | 0 | 3 |
| shodan | 0 | 4 |
| zoomeye | 0 | 3 |

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
| armle | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| armle | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| asmax | ar_1004g_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| asmax | ar_804_gu_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| asmax | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asmax | webinterface_http_auth_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | asuswrt_lan_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2018-5999, CVE-2018-6000 | rce |
| asus | b1m_projector_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| asus | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | infosvr_backdoor_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| asus | rt_n16_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| asus | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| asus | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| belkin | auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, creds_disclosure |
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
| bluetooth | btle_enumerate | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| bluetooth | btle_scan | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| bluetooth | btle_write | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| cisco | catalyst_2960_rocem | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-3881 | - |
| cisco | dpc2420_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| cisco | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cisco | ios_http_authorization_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2001-0537 | - |
| cisco | rv320_command_injection | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-1652 | rce |
| cisco | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cisco | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
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
| comtrend | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| comtrend | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| cve | cve_lookup | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| dlink | dcs_930l_auth_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dgs_1510_add_user | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dir_300_320_600_615_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dir_300_320_615_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| dlink | dir_300_600_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_300_645_815_upnp_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_645_815_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_645_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dir_655_866_652_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2019-16920 | rce |
| dlink | dir_815_850l_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dir_825_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dir_850l_creds_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dir_8xx_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| dlink | dns_320l_327l_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dsl_2640b_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2730_2750_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dsl_2730b_2780b_526b_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2740r_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| dlink | dsl_2750b_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dsl_2750b_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dsp_w110_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | dvg_n5402sp_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| dlink | dwl_3200ap_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| dlink | dwr_932_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| dlink | dwr_932b_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| dlink | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| dlink | multi_hedwig_cgi_exec | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | multi_hnap_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| dlink | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| dlink | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| external | exploitdb_embedded_lookup | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | metasploit_console_bridge | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | metasploit_rb_inspect | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| external | mikrotikapi_bf_bridge | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| ftp_bruteforce.py | ftp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ftp_default.py | ftp_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| heartbleed.py | heartbleed | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| hootoo | tripmate_arbitrary_file_upload | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| hootoo | tripmate_open_forwarding_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| hootoo | tripmate_sysfirm_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| http_basic_digest_bruteforce.py | http_basic_digest_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_basic_digest_default.py | http_basic_digest_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_form_char_by_char_oracle.py | http_form_char_by_char_oracle | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| http_multi_auth_default.py | http_multi_auth_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| http_web_form_bruteforce.py | http_web_form_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | e5331_mifi_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | hg520_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| huawei | hg530_hg520b_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| huawei | hg532_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-17215 | rce |
| huawei | hg8240_auth_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| huawei | hg8240_file_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| huawei | hg866_password_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | password_reset_or_change |
| huawei | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| huawei | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ipfire | ipfire_oinkcode_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| ipfire | ipfire_proxy_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| ipfire | ipfire_shellshock | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| juniper | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| juniper | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| juniper | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| lg | nas_3718 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| linksys | 1500_2500_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | eseries_themoon_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | smartwifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-8243 | creds_disclosure |
| linksys | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| linksys | wap54gv3_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| linksys | wrt100_110_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2013-3568 | rce |
| miele | pg8528_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-7240 | path_traversal |
| mikrotik | api_ros_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | routeros_jailbreak | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| mikrotik | winbox_auth_bypass_creds_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass, creds_disclosure |
| mipsbe | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsbe | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsle | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| mipsle | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| misc | misc_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| misc | soho_exploit_catalog_server | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| movistar | adsl_router_bhs_rta_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| movistar | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| movistar | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| movistar | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| multi | gpon_home_gateway_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| multi | misfortune_cookie | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-9222 | auth_bypass |
| multi | rom0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| multi | tcp_32764_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, info_disclosure |
| multi | tcp_32764_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| netcore | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netcore | udp_53413_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor, rce |
| netgear | dgn2200_dnslookup_cgi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6334 | rce |
| netgear | dgn2200_ping_cgi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-6077 | rce |
| netgear | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | jnr1010_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| netgear | multi_password_disclosure-2017-5521 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-5521 | creds_disclosure |
| netgear | multi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | n300_auth_bypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| netgear | prosafe_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | r7000_r6400_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | rax30_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netgear | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netgear | wnr500_612v3_jnr1010_2010_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| netsys | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netsys | multi_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| netsys | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| netsys | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| pcap | pcap_ap_station_mapper | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_credential_sniffer | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_dragonblood | 1 | 0 | 0 | 0 | 1 | 0 | 0 | CVE-2019-9494, CVE-2019-9496 | - |
| pcap | pcap_handshake_extractor | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_offline_wpa_crack | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_pmkid_attack | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_tkip_downgrade | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_wep_crack | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| pcap | pcap_wpe_harvest | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| perl | base64 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| perl | hex | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| perl | rot13 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
| perl | url | 1 | 0 | 0 | 0 | 0 | 0 | 1 | - | - |
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
| routers | hootoo_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| routers | router_scan | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| scanners | autopwn | 1 | 0 | 0 | 1 | 0 | 0 | 0 | - | - |
| sftp_bruteforce.py | sftp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| sftp_default.py | sftp_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| shellshock.py | shellshock | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2014-6271, CVE-2014-6278, CVE-2014-7169 | rce |
| shuttle | 915wm_dns_change | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | dns_change |
| snmp | snmp_trap_listener | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| snmp_bruteforce.py | snmp_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| snmpv3_default.py | snmpv3_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ssh_auth_keys.py | ssh_auth_keys | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| ssh_bruteforce.py | ssh_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ssh_default.py | ssh_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | dwg855_authbypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| technicolor | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | tc7200_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| technicolor | tc7200_password_disclosure_v2 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| technicolor | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| technicolor | tg784_authbypass | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | auth_bypass |
| telnet_bruteforce.py | telnet_bruteforce | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| telnet_default.py | telnet_default | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| thomson | twg849_info_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| thomson | twg850_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| tplink | archer_c2_c20i_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| tplink | archer_c9_admin_password_reset | 1 | 1 | 0 | 0 | 0 | 0 | 0 | CVE-2017-11519 | password_reset_or_change |
| tplink | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| tplink | wdr740nd_wdr740n_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| tplink | wdr740nd_wdr740n_path_traversal | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | path_traversal |
| tplink | wdr842nd_wdr842n_configure_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | airos_6_x | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| ubiquiti | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| upnp | ssdp_msearch | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| wepresent | wipg1000_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| wordlist | wordlist_generator | 1 | 0 | 0 | 0 | 1 | 0 | 0 | - | - |
| x64 | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x64 | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x86 | bind_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| x86 | reverse_tcp | 1 | 0 | 0 | 0 | 0 | 1 | 0 | - | - |
| zte | f460_f660_backdoor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | backdoor |
| zte | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zte | zxhn_h108n_wifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| zte | zxv10_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zte | zxv10_w812n | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | info_disclosure |
| zyxel | d1000_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | d1000_wifi_password_disclosure | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | creds_disclosure |
| zyxel | ftp_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zyxel | p660hn_t_v1_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | p660hn_t_v2_rce | 1 | 1 | 0 | 0 | 0 | 0 | 0 | - | rce |
| zyxel | ssh_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |
| zyxel | telnet_default_creds | 1 | 0 | 1 | 0 | 0 | 0 | 0 | - | - |

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

### asus / asuswrt_lan_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2018-5999, CVE-2018-6000
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/asus/asuswrt_lan_rce.py`

### asus / b1m_projector_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/misc/asus/b1m_projector_rce.py`

### asus / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/asus/ftp_default_creds.py`

### asus / infosvr_backdoor_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor, rce
- Module paths:
  - `modules/exploits/routers/asus/infosvr_backdoor_rce.py`

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

### bluetooth / btle_enumerate

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/bluetooth/btle_enumerate.py`

### bluetooth / btle_scan

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/bluetooth/btle_scan.py`

### bluetooth / btle_write

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/bluetooth/btle_write.py`

### cisco / catalyst_2960_rocem

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-3881
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/catalyst_2960_rocem.py`

### cisco / dpc2420_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/cisco/dpc2420_info_disclosure.py`

### cisco / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/cisco/ftp_default_creds.py`

### cisco / ios_http_authorization_bypass

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2001-0537
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/cisco/ios_http_authorization_bypass.py`

### cisco / rv320_command_injection

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2019-1652
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/cisco/rv320_command_injection.py`

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

### cve / cve_lookup

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/cve/cve_lookup.py`

### dlink / dcs_930l_auth_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dcs_930l_auth_rce.py`

### dlink / dgs_1510_add_user

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dgs_1510_add_user.py`

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

### dlink / dir_825_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dir_825_path_traversal.py`

### dlink / dir_850l_creds_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_850l_creds_disclosure.py`

### dlink / dir_8xx_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/dlink/dir_8xx_password_disclosure.py`

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

### dlink / dsp_w110_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/dlink/dsp_w110_rce.py`

### dlink / dvg_n5402sp_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/dlink/dvg_n5402sp_path_traversal.py`

### dlink / dwl_3200ap_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/exploits/routers/dlink/dwl_3200ap_password_disclosure.py`

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

### dlink / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/dlink/ftp_default_creds.py`

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
  - `modules/exploits/routers/hootoo/tripmate_arbitrary_file_upload.py`

### hootoo / tripmate_open_forwarding_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/hootoo/tripmate_open_forwarding_rce.py`

### hootoo / tripmate_sysfirm_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/hootoo/tripmate_sysfirm_rce.py`

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

### huawei / e5331_mifi_info_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: info_disclosure
- Module paths:
  - `modules/exploits/routers/huawei/e5331_mifi_info_disclosure.py`

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

### juniper / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/juniper/ftp_default_creds.py`

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
  - `modules/exploits/routers/lg/nas_3718.py`

### linksys / 1500_2500_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/1500_2500_rce.py`

### linksys / eseries_themoon_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/linksys/eseries_themoon_rce.py`

### linksys / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/linksys/ftp_default_creds.py`

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

### miele / pg8528_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-7240
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/misc/miele/pg8528_path_traversal.py`

### mikrotik / api_ros_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/api_ros_default_creds.py`

### mikrotik / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/mikrotik/ftp_default_creds.py`

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

### multi / gpon_home_gateway_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/multi/gpon_home_gateway_rce.py`

### multi / misfortune_cookie

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2014-9222
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/multi/misfortune_cookie.py`

### multi / rom0

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: auth_bypass
- Module paths:
  - `modules/exploits/routers/multi/rom0.py`

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

### netgear / prosafe_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/netgear/prosafe_rce.py`

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

### netgear / wnr500_612v3_jnr1010_2010_path_traversal

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: path_traversal
- Module paths:
  - `modules/exploits/routers/netgear/wnr500_612v3_jnr1010_2010_path_traversal.py`

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

### pcap / pcap_ap_station_mapper

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_ap_station_mapper.py`

### pcap / pcap_credential_sniffer

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_credential_sniffer.py`

### pcap / pcap_dragonblood

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: CVE-2019-9494, CVE-2019-9496
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_dragonblood.py`

### pcap / pcap_handshake_extractor

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_handshake_extractor.py`

### pcap / pcap_offline_wpa_crack

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_offline_wpa_crack.py`

### pcap / pcap_pmkid_attack

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_pmkid_attack.py`

### pcap / pcap_tkip_downgrade

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_tkip_downgrade.py`

### pcap / pcap_wep_crack

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_wep_crack.py`

### pcap / pcap_wpe_harvest

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/pcap/pcap_wpe_harvest.py`

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

### routers / hootoo_scan

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/routers/hootoo_scan.py`

### routers / router_scan

- Totals: modules=1, exploits=0, creds=0, scanners=1, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/scanners/routers/router_scan.py`

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

### thomson / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/thomson/ftp_default_creds.py`

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

### tplink / archer_c2_c20i_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/routers/tplink/archer_c2_c20i_rce.py`

### tplink / archer_c9_admin_password_reset

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: CVE-2017-11519
- Attack classes: password_reset_or_change
- Module paths:
  - `modules/exploits/routers/tplink/archer_c9_admin_password_reset.py`

### tplink / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/ftp_default_creds.py`

### tplink / ssh_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/ssh_default_creds.py`

### tplink / telnet_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/tplink/telnet_default_creds.py`

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

### upnp / ssdp_msearch

- Totals: modules=1, exploits=0, creds=0, scanners=0, generic=1, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/generic/upnp/ssdp_msearch.py`

### wepresent / wipg1000_rce

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: rce
- Module paths:
  - `modules/exploits/misc/wepresent/wipg1000_rce.py`

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

### zte / f460_f660_backdoor

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: backdoor
- Module paths:
  - `modules/exploits/routers/zte/f460_f660_backdoor.py`

### zte / ftp_default_creds

- Totals: modules=1, exploits=0, creds=1, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: none
- Module paths:
  - `modules/creds/routers/zte/ftp_default_creds.py`

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

### zte / zxhn_h108n_wifi_password_disclosure

- Totals: modules=1, exploits=1, creds=0, scanners=0, generic=0, payloads=0, encoders=0
- CVEs: none
- Attack classes: creds_disclosure
- Module paths:
  - `modules/exploits/routers/zte/zxhn_h108n_wifi_password_disclosure.py`

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
