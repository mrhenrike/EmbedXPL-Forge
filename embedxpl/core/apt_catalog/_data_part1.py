# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""APT catalog data: state-sponsored groups (Part 1)."""

from embedxpl.core.apt_catalog._models import APT_CATALOG, APTGroup, APTAttack


def _build_catalog_part1() -> None:
    """Populate APT catalog with state-sponsored groups (part 1)."""

    APT_CATALOG["apt28"] = APTGroup(
        id="apt28",
        name="APT28 / Forest Blizzard",
        aliases=["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "Storm-2754", "STRONTIUM", "GRU Unit 26165"],
        country="Russia",
        description=(
            "Russian GRU Military Unit 26165. Since Aug 2025, exploits SOHO routers "
            "to hijack DNS and conduct AiTM attacks stealing Outlook/OAuth credentials. "
            "200+ orgs and 5,000+ devices compromised per Microsoft/NCSC (Apr 2026)."
        ),
        campaigns=["DNS Hijack Campaign (2025-2026)", "Quad 7 Botnet Infrastructure"],
        mitre_id="G0007",
        references=[
            "https://attack.mitre.org/groups/G0007/",
            "https://www.microsoft.com/en-us/security/blog/2026/04/07/soho-router-compromise-leads-to-dns-hijacking-and-adversary-in-the-middle-attacks/",
        ],
        attacks=[
            APTAttack(
                name="TP-Link WR841N Credential Disclosure",
                description="Unauthenticated extraction of admin credentials via /loginFs/ path bypass",
                cves=["CVE-2023-50224"],
                modules=["exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224"],
                mitre_techniques=["T1190", "T1552.001"],
                target_devices=["TP-Link TL-WR841N"],
                phase="Initial Access",
            ),
            APTAttack(
                name="TP-Link Parental Control RCE",
                description="Post-auth command injection via url_0 in Parental Control page",
                cves=["CVE-2025-9377"],
                modules=["exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377"],
                mitre_techniques=["T1059.004", "T1190"],
                target_devices=["TP-Link TL-WR841N"],
                phase="Execution",
                requires_auth=True,
            ),
            APTAttack(
                name="TP-Link DNS Hijack (20+ models)",
                description="Rewrite DHCP DNS settings to attacker-controlled resolver",
                cves=[],
                modules=["exploits/routers/tplink/multi_dns_hijack_apt28"],
                mitre_techniques=["T1584.008", "T1557"],
                target_devices=[
                    "TP-Link Archer C5/C7", "TP-Link WDR3500/3600/4300",
                    "TP-Link WR740N-WR941ND", "TP-Link MR3420/MR6400",
                ],
                phase="Impact",
                requires_auth=True,
            ),
            APTAttack(
                name="MikroTik DNS Hijack",
                description="Rewrite DNS on MikroTik via REST API or RouterOS API (port 8728)",
                cves=[],
                modules=["exploits/routers/mikrotik/routeros_dns_hijack_apt28"],
                mitre_techniques=["T1584.008", "T1557"],
                target_devices=["MikroTik RouterOS"],
                phase="Impact",
                requires_auth=True,
            ),
            APTAttack(
                name="DNS Hijack Detection",
                description="Defensive: detect if router DNS has been hijacked by comparing Outlook domain resolution",
                cves=[],
                modules=["generic/dns_hijack_detector"],
                mitre_techniques=["T1557"],
                target_devices=["Any router/gateway"],
                phase="Detection",
            ),
            APTAttack(
                name="AITM Credential Interceptor",
                description="Lab tool: malicious DNS + HTTP capture for Outlook/O365 credential harvesting",
                cves=[],
                modules=["generic/aitm_credential_interceptor"],
                mitre_techniques=["T1557.002", "T1556"],
                target_devices=["Lab infrastructure"],
                phase="Collection",
            ),
            APTAttack(
                name="Full Chain AutoPwn",
                description="Automated: CVE-2023-50224 -> auth -> DNS hijack -> verify -> optional RCE persistence",
                cves=["CVE-2023-50224", "CVE-2025-9377"],
                modules=["exploits/routers/tplink/apt28_full_chain_autopwn"],
                mitre_techniques=["T1190", "T1584.008", "T1557"],
                target_devices=["TP-Link TL-WR841N", "TP-Link multi-model"],
                phase="Full Kill Chain",
            ),
        ],
    )

    APT_CATALOG["volt_typhoon"] = APTGroup(
        id="volt_typhoon",
        name="Volt Typhoon",
        aliases=["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "Insidious Taurus", "UNC3236"],
        country="China",
        description=(
            "Chinese state-sponsored group targeting US critical infrastructure. "
            "Hijacks EOL SOHO routers (Cisco RV320/325, Netgear ProSafe) as proxy "
            "infrastructure for stealthy lateral movement into power grids and "
            "water systems. KV Botnet (MITRE C0035)."
        ),
        campaigns=["KV Botnet (C0035)", "Critical Infrastructure Pivot Campaign"],
        mitre_id="G1017",
        references=[
            "https://attack.mitre.org/groups/G1017/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a",
        ],
        attacks=[
            APTAttack(
                name="Cisco RV320 Command Injection",
                description="Exploits command injection in Cisco RV320/RV325 routers",
                cves=["CVE-2019-1652", "CVE-2019-1653"],
                modules=[
                    "exploits/routers/cisco/rv320_command_injection",
                    "exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653",
                ],
                mitre_techniques=["T1190", "T1059.004"],
                target_devices=["Cisco RV320", "Cisco RV325"],
                phase="Initial Access",
            ),
            APTAttack(
                name="Netgear ProSafe Default Credentials",
                description="Exploit default/weak credentials on Netgear ProSafe series",
                cves=[],
                modules=[
                    "creds/routers/netgear/ssh_default_creds",
                    "creds/routers/netgear/telnet_default_creds",
                ],
                mitre_techniques=["T1078.001"],
                target_devices=["Netgear ProSafe series"],
                phase="Initial Access",
            ),
            APTAttack(
                name="MikroTik Winbox Credential Disclosure",
                description="Extract credentials via Winbox protocol vulnerability",
                cves=["CVE-2018-14847"],
                modules=["exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847"],
                mitre_techniques=["T1552.001"],
                target_devices=["MikroTik RouterOS < 6.42"],
                phase="Credential Access",
            ),
        ],
    )

    APT_CATALOG["sandworm"] = APTGroup(
        id="sandworm",
        name="Sandworm / APT44",
        aliases=["Voodoo Bear", "IRIDIUM", "Electrum", "Telebots", "GRU Unit 74455"],
        country="Russia",
        description=(
            "Russian GRU Unit 74455. Known for destructive attacks (Ukraine power grid, "
            "NotPetya). Since 2022, pivoted to exploiting misconfigured edge devices "
            "(routers, VPNs) instead of zero-days. Cyclops Blink targeted ASUS/WatchGuard."
        ),
        campaigns=["Cyclops Blink (2022)", "Edge Device Misconfiguration Campaign (2021-2025)"],
        mitre_id="G0034",
        references=[
            "https://attack.mitre.org/groups/G0034/",
        ],
        attacks=[
            APTAttack(
                name="ASUS Router Exploitation (Cyclops Blink)",
                description="Cyclops Blink malware targeting ASUS routers with default/weak configs",
                cves=[],
                modules=[
                    "creds/routers/asus/ssh_default_creds",
                    "exploits/routers/asus/rt_n66u_remote_command_execution",
                    "exploits/routers/asus/rt_n16_admin_password_disclosure",
                ],
                mitre_techniques=["T1078.001", "T1059.004"],
                target_devices=["ASUS RT-N16", "ASUS RT-N66U", "ASUS RT-AC66U"],
                phase="Initial Access",
            ),
            APTAttack(
                name="Cisco SNMP RCE",
                description="Remote code execution via SNMP on Cisco IOS routers",
                cves=["CVE-2017-6742"],
                modules=["generic/snmp/snmp_bruteforce"],
                mitre_techniques=["T1190"],
                target_devices=["Cisco IOS routers"],
                phase="Initial Access",
            ),
            APTAttack(
                name="MikroTik Router Jailbreak",
                description="RouterOS jailbreak for persistent access",
                cves=[],
                modules=["exploits/routers/mikrotik/routeros_jailbreak"],
                mitre_techniques=["T1542"],
                target_devices=["MikroTik RouterOS"],
                phase="Persistence",
            ),
        ],
    )

    APT_CATALOG["quad7"] = APTGroup(
        id="quad7",
        name="Quad7 / CovertNetwork-1658",
        aliases=["7777 Botnet", "Storm-0940"],
        country="China",
        description=(
            "Chinese-affiliated botnet of compromised SOHO routers used for "
            "password spraying against enterprise targets. Initially TP-Link, "
            "expanded to Zyxel, Ruckus, ASUS. Storm-0940 leverages credentials "
            "obtained through Quad7 to target government and defense."
        ),
        campaigns=["Quad7 Botnet (C0055)", "Storm-0940 Credential Spray"],
        mitre_id="C0055",
        references=[
            "https://attack.mitre.org/campaigns/C0055/",
        ],
        attacks=[
            APTAttack(
                name="TP-Link WR841N Exploit Chain",
                description="CVE-2023-50224 credential disclosure + CVE-2025-9377 RCE",
                cves=["CVE-2023-50224", "CVE-2025-9377"],
                modules=[
                    "exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224",
                    "exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377",
                ],
                mitre_techniques=["T1190", "T1059.004"],
                target_devices=["TP-Link TL-WR841N"],
                phase="Initial Access + Execution",
            ),
            APTAttack(
                name="Zyxel Router Exploitation",
                description="Exploitation of Zyxel SOHO routers for botnet enrollment",
                cves=["CVE-2019-9955"],
                modules=["exploits/routers/zyxel/zywall_usg_config_hash_extraction"],
                mitre_techniques=["T1190"],
                target_devices=["Zyxel ZyWALL USG series"],
                phase="Initial Access",
            ),
        ],
    )

    APT_CATALOG["turla"] = APTGroup(
        id="turla",
        name="Turla",
        aliases=["Snake", "Venomous Bear", "Uroburos", "Waterbug", "KRYPTON"],
        country="Russia",
        description=(
            "Russian FSB-linked group. Has hijacked other groups' C2 infrastructure "
            "through compromised routers. Known to co-opt Ubiquiti EdgeRouters and "
            "deploy reverse SSH tunnels through compromised network devices."
        ),
        campaigns=["Snake/Uroburos", "EdgeRouter Hijack"],
        mitre_id="G0010",
        references=["https://attack.mitre.org/groups/G0010/"],
        attacks=[
            APTAttack(
                name="Ubiquiti AirOS Command Execution",
                description="Pre-auth command injection on Ubiquiti AirOS devices",
                cves=[],
                modules=["exploits/routers/ubiquiti/airos_pre_auth_command_execution"],
                mitre_techniques=["T1059.004"],
                target_devices=["Ubiquiti AirOS"],
                phase="Initial Access",
            ),
            APTAttack(
                name="Default Credential Access",
                description="Access network devices via factory default credentials",
                cves=[],
                modules=[
                    "creds/routers/ubiquiti/ssh_default_creds",
                ],
                mitre_techniques=["T1078.001"],
                target_devices=["Ubiquiti EdgeRouter"],
                phase="Initial Access",
            ),
        ],
    )

    APT_CATALOG["apt40"] = APTGroup(
        id="apt40",
        name="APT40",
        aliases=["Leviathan", "BRONZE MOHAWK", "TEMP.Periscope", "TEMP.Jumper", "Gadolinium"],
        country="China",
        description=(
            "Chinese MSS-linked group targeting maritime, defense, and government. "
            "Exploits SOHO routers and network devices as ORBs (Operational Relay "
            "Boxes) for proxying C2 traffic."
        ),
        campaigns=["SOHO Router ORB Network"],
        mitre_id="G0065",
        references=["https://attack.mitre.org/groups/G0065/"],
        attacks=[
            APTAttack(
                name="TP-Link Password Disclosure",
                description="Exploit known TP-Link password disclosure vulnerabilities",
                cves=["CVE-2020-35575"],
                modules=[
                    "exploits/routers/tplink/tl_wr841nd_password_disclosure_cve_2020_35575",
                    "exploits/routers/tplink/wr841nd_password_disclosure_cve_2020_35575",
                ],
                mitre_techniques=["T1552.001"],
                target_devices=["TP-Link TL-WR841ND"],
                phase="Credential Access",
            ),
            APTAttack(
                name="Fortinet FortiGate Backdoor",
                description="SSH backdoor on FortiGate OS 4.x-5.0.7",
                cves=["CVE-2016-1909"],
                modules=["exploits/routers/fortinet/fortigate_4_x_5_0_7_ssh_backdoor_access_cve_2016_1909"],
                mitre_techniques=["T1133"],
                target_devices=["Fortinet FortiGate OS 4.x-5.0.7"],
                phase="Initial Access",
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # SALT TYPHOON / RedMike (China — MSS-linked)                         #
    # ------------------------------------------------------------------ #
    APT_CATALOG["salt_typhoon"] = APTGroup(
        id="salt_typhoon",
        name="Salt Typhoon / RedMike",
        aliases=["RedMike", "UNC2286", "UNC5807", "Earth Estries", "FamousSparrow", "GhostEmperor", "OPERATOR PANDA"],
        country="China",
        mitre_id="G1040",
        description=(
            "China MSS-linked APT responsible for the most significant telecom infrastructure breach in US history "
            "(2021–2025). Compromised AT&T, Verizon, Lumen Technologies, and 600+ orgs worldwide, including "
            "CALEA lawful-intercept infrastructure. Mass-exploited Cisco IOS XE in Dec 2024–Jan 2025 "
            "against 1,000+ telecom and university devices."
        ),
        campaigns=["Operation RedMike (2021–2025)", "Cisco IOS XE Mass Exploitation (Dec 2024)", "FamousSparrow Hotels (2020)"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-20273",
            "https://www.recordedfuture.com/research/redmike-salt-typhoon-exploits-vulnerable-devices",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
        attacks=[
            APTAttack(
                name="Cisco IOS XE Web UI RCE (CVE-2023-20198 + CVE-2023-20273)",
                description=(
                    "Unauthenticated privilege escalation to level-15 via CVE-2023-20198, then "
                    "root shell via Guest Shell privilege escalation (CVE-2023-20273). "
                    "Used to deploy persistent GRE tunnels and abuse LAWFUL INTERCEPT (CALEA) features."
                ),
                cves=["CVE-2023-20198", "CVE-2023-20273"],
                modules=[
                    "exploits/cisco/ios_xe_web_ui_priv_esc_cve_2023_20198",
                    "exploits/cisco/ios_xe_guest_shell_rce_cve_2023_20273",
                ],
                mitre_techniques=["T1190", "T1136", "T1601", "T1059.008", "T1572"],
                target_devices=["Cisco IOS XE (ISR, ASR, CSR, catalyst)", "Cisco Cat9k"],
                phase="Initial Access → RCE",
                requires_auth=False,
            ),
            APTAttack(
                name="Cisco IOS Smart Install RCE (CVE-2018-0171)",
                description="Exploits Cisco Smart Install protocol exposed on TCP/4786 for unauthenticated RCE.",
                cves=["CVE-2018-0171"],
                modules=["exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171"],
                mitre_techniques=["T1190"],
                target_devices=["Cisco IOS", "Cisco IOS XE (Smart Install enabled)"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Ivanti Connect Secure Auth Bypass + RCE Chain",
                description=(
                    "Two-stage chain: CVE-2023-46805 (auth bypass) + CVE-2024-21887 (command injection). "
                    "Allows unauthenticated RCE on Ivanti Connect Secure and Policy Secure. "
                    "Salt Typhoon used this to access telecom core networks."
                ),
                cves=["CVE-2023-46805", "CVE-2024-21887"],
                modules=[
                    "exploits/vpn/ivanti/connect_secure_auth_bypass_cve_2023_46805",
                    "exploits/vpn/ivanti/connect_secure_cmd_injection_cve_2024_21887",
                ],
                mitre_techniques=["T1190", "T1059.004"],
                target_devices=["Ivanti Connect Secure", "Ivanti Policy Secure", "Ivanti ZTA Gateway"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Palo Alto PAN-OS GlobalProtect OS Command Injection (CVE-2024-3400)",
                description=(
                    "CVSS 10.0 unauthenticated OS command injection in GlobalProtect gateway. "
                    "Used by Salt Typhoon and Silk Typhoon for initial access into enterprise networks."
                ),
                cves=["CVE-2024-3400"],
                modules=["exploits/ngfw/paloalto/pan_os_globalprotect_rce_cve_2024_3400"],
                mitre_techniques=["T1190"],
                target_devices=["Palo Alto PAN-OS GlobalProtect Gateway"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # SILK TYPHOON / Hafnium (China)                                      #
    # ------------------------------------------------------------------ #
    APT_CATALOG["silk_typhoon"] = APTGroup(
        id="silk_typhoon",
        name="Silk Typhoon / Hafnium",
        aliases=["Hafnium", "UNC5221", "APT27 (partial overlap)"],
        country="China",
        mitre_id="G0125",
        description=(
            "China PRC APT targeting IT supply chain, MSPs, and edge devices. "
            "2025 campaign focused on RMM providers to gain downstream customer access. "
            "Known for rapid weaponization of CVEs and mass exploitation of Ivanti, Palo Alto, and Exchange."
        ),
        campaigns=["IT Supply Chain (2024–2025)", "Exchange ProxyLogon (2021)", "Edge Device Reconnaissance (2025)"],
        references=[
            "https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
        ],
        attacks=[
            APTAttack(
                name="Ivanti Connect Secure Stack Buffer Overflow RCE (CVE-2025-0282)",
                description=(
                    "CVSS 9.0 unauthenticated stack buffer overflow in Ivanti Connect Secure, "
                    "Policy Secure, and ZTA Gateways. Enables pre-auth RCE. Attributed to Silk Typhoon."
                ),
                cves=["CVE-2025-0282"],
                modules=["exploits/vpn/ivanti/connect_secure_stack_overflow_cve_2025_0282"],
                mitre_techniques=["T1190"],
                target_devices=["Ivanti Connect Secure", "Ivanti Policy Secure", "Ivanti ZTA Gateway"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Palo Alto PAN-OS GlobalProtect RCE (CVE-2024-3400)",
                description="Same CVE-2024-3400 as Salt Typhoon. Both groups exploited this in parallel.",
                cves=["CVE-2024-3400"],
                modules=["exploits/ngfw/paloalto/pan_os_globalprotect_rce_cve_2024_3400"],
                mitre_techniques=["T1190"],
                target_devices=["Palo Alto PAN-OS"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # FLAX TYPHOON / Raptor Train (China)                                 #
    # ------------------------------------------------------------------ #
    APT_CATALOG["flax_typhoon"] = APTGroup(
        id="flax_typhoon",
        name="Flax Typhoon / Raptor Train",
        aliases=["UNC5007", "Red Juliet", "Ethereal Panda", "Storm-0919", "Integrity Technology Group"],
        country="China",
        mitre_id="G1044",
        description=(
            "China PRC APT operating the Raptor Train botnet of 260,000+ compromised devices "
            "(NAS, IP cameras, DVRs, routers, firewalls). FBI court-authorized disruption September 2024. "
            "Used 66 CVEs to compromise devices and deploy Nosedive (Mirai variant) C2 via 'Sparrow' app."
        ),
        campaigns=["Raptor Train Botnet (2021–2024)", "SOCKS5 Proxy Infrastructure for PRC APT groups"],
        references=[
            "https://www.ic3.gov/CSA/2024/240918.pdf",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-1388",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-28771",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-3519",
        ],
        attacks=[
            APTAttack(
                name="F5 BIG-IP iControl REST Unauthenticated RCE (CVE-2022-1388)",
                description=(
                    "CVSS 9.8 unauthenticated RCE via F5 BIG-IP iControl REST API. "
                    "Flax Typhoon and Velvet Ant both exploited this for persistent footholds on ADCs."
                ),
                cves=["CVE-2022-1388"],
                modules=["exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388"],
                mitre_techniques=["T1190"],
                target_devices=["F5 BIG-IP 13.x-16.x"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Zyxel ZyWALL/USG OS Command Injection (CVE-2023-28771)",
                description=(
                    "CVSS 9.8 unauthenticated OS command injection in Zyxel ZyWALL/USG/VPN/ATP "
                    "firewall series. Flax Typhoon used this for botnet recruitment of Zyxel devices."
                ),
                cves=["CVE-2023-28771"],
                modules=["exploits/routers/zyxel/zywall_usg_cmd_injection_cve_2023_28771"],
                mitre_techniques=["T1190"],
                target_devices=["Zyxel ZyWALL", "Zyxel USG FLEX", "Zyxel VPN", "Zyxel ATP"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Citrix NetScaler ADC/Gateway RCE (CVE-2023-3519)",
                description=(
                    "CVSS 9.8 unauthenticated RCE in Citrix NetScaler ADC/Gateway. "
                    "Flax Typhoon botnet included Citrix appliances."
                ),
                cves=["CVE-2023-3519"],
                modules=["exploits/appliances/citrix/netscaler_rce_cve_2023_3519"],
                mitre_techniques=["T1190"],
                target_devices=["Citrix NetScaler ADC", "Citrix NetScaler Gateway"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Ivanti Connect Secure Auth Bypass + Command Injection",
                description="Same CVE-2023-46805 + CVE-2024-21887 chain used by multiple China APTs.",
                cves=["CVE-2023-46805", "CVE-2024-21887"],
                modules=[
                    "exploits/vpn/ivanti/connect_secure_auth_bypass_cve_2023_46805",
                    "exploits/vpn/ivanti/connect_secure_cmd_injection_cve_2024_21887",
                ],
                mitre_techniques=["T1190"],
                target_devices=["Ivanti Connect Secure"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # VELVET ANT (China)                                                  #
    # ------------------------------------------------------------------ #
    APT_CATALOG["velvet_ant"] = APTGroup(
        id="velvet_ant",
        name="Velvet Ant",
        aliases=["UTA0137"],
        country="China",
        mitre_id="",
        description=(
            "China-nexus APT known for persistent implants in network infrastructure appliances. "
            "Deployed VELVETSHELL backdoor inside Cisco Nexus switch OS (CVE-2024-20399) and "
            "maintained multi-year F5 BIG-IP footholds that survived factory resets."
        ),
        campaigns=["F5 BIG-IP Persistent Espionage (2021–2024)", "Cisco Nexus Zero-Day (2024)"],
        references=[
            "https://www.sygnia.co/blog/china-threat-group-velvet-ant-cisco-zero-day/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-20399",
        ],
        attacks=[
            APTAttack(
                name="Cisco NX-OS CLI Command Injection (CVE-2024-20399)",
                description=(
                    "CVSS 6.0 authenticated local command injection in Cisco NX-OS CLI. "
                    "Post-auth but allows jailbreak of Cisco Nexus switches to deploy persistent kernel-level "
                    "backdoors (VELVETSHELL) surviving firmware updates."
                ),
                cves=["CVE-2024-20399"],
                modules=["exploits/switches/cisco/nxos_cli_cmd_injection_cve_2024_20399"],
                mitre_techniques=["T1059.008", "T1601.001", "T1014"],
                target_devices=["Cisco Nexus 3000", "Cisco Nexus 5000", "Cisco Nexus 7000", "Cisco Nexus 9000"],
                phase="Execution (post-auth)",
                requires_auth=True,
            ),
            APTAttack(
                name="F5 BIG-IP iControl REST RCE (CVE-2022-1388)",
                description="F5 BIG-IP exploitation for persistent espionage implants surviving factory resets.",
                cves=["CVE-2022-1388"],
                modules=["exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388"],
                mitre_techniques=["T1190", "T1542.005"],
                target_devices=["F5 BIG-IP"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # APT41 / Brass Typhoon (China)                                       #
    # ------------------------------------------------------------------ #
    APT_CATALOG["apt41"] = APTGroup(
        id="apt41",
        name="APT41 / Brass Typhoon",
        aliases=["Winnti Group", "Wicked Panda", "BARIUM", "Double Dragon", "Bronze Atlas"],
        country="China",
        mitre_id="G0096",
        description=(
            "China MSS-linked APT combining state espionage with financially motivated cybercrime. "
            "Known for Operation ShadowHammer (ASUS Live Update supply chain compromise) and "
            "rapid weaponization of critical CVEs within hours of public disclosure."
        ),
        campaigns=["Operation ShadowHammer (2019)", "Cloud Hopper (partial)", "RevivalStone (2025)"],
        references=[
            "https://attack.mitre.org/groups/G0096/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19781",
        ],
        attacks=[
            APTAttack(
                name="Citrix NetScaler ADC/Gateway Path Traversal RCE (CVE-2019-19781)",
                description=(
                    "CVSS 9.8 path traversal in Citrix ADC/Gateway allowing unauthenticated RCE. "
                    "APT41 was one of the first APTs to weaponize this CVE."
                ),
                cves=["CVE-2019-19781"],
                modules=["exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781"],
                mitre_techniques=["T1190"],
                target_devices=["Citrix ADC (NetScaler)", "Citrix Gateway", "Citrix SD-WAN"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="ASUS Live Update Supply Chain Firmware Poisoning (ShadowHammer)",
                description=(
                    "Compromised ASUS Live Update servers to distribute trojanized firmware updates "
                    "signed with legitimate ASUS certificates. ~1 million devices downloaded malicious firmware. "
                    "Targeted specific MAC addresses for second-stage payload delivery."
                ),
                cves=[],
                modules=["exploits/misc/asus/shadowhammer_supply_chain_detect"],
                mitre_techniques=["T1195.002", "T1553.002"],
                target_devices=["ASUS ZenBook", "ASUS VivoBook", "ASUS ROG series"],
                phase="Supply Chain",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # APT10 / Stone Panda (China)                                         #
    # ------------------------------------------------------------------ #
    APT_CATALOG["apt10"] = APTGroup(
        id="apt10",
        name="APT10 / Stone Panda",
        aliases=["MenuPass", "Red Apollo", "CVNX", "Cloud Hopper"],
        country="China",
        mitre_id="G0045",
        description=(
            "China MSS-linked APT responsible for Operation Cloud Hopper — systematic compromise of MSPs "
            "to gain transitive access to downstream clients in 45+ countries. "
            "Network device exploitation used for lateral movement between MSP client environments."
        ),
        campaigns=["Operation Cloud Hopper (2014–2018+)"],
        references=["https://attack.mitre.org/groups/G0045/"],
        attacks=[
            APTAttack(
                name="VPN Appliance Initial Access (MSP network device exploitation)",
                description=(
                    "APT10 systematically exploited VPN appliance management interfaces using harvested "
                    "MSP credentials to pivot between managed client networks. "
                    "Targets included Citrix, Pulse Secure, and legacy SSL-VPN appliances."
                ),
                cves=["CVE-2019-11510"],
                modules=["exploits/vpn/pulse/pulse_connect_secure_path_traversal_cve_2019_11510"],
                mitre_techniques=["T1199", "T1190", "T1078"],
                target_devices=["Pulse Connect Secure VPN", "Citrix NetScaler", "SOHO routers (MSP-managed)"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # CYCLOPS BLINK (Russia/Sandworm subgroup)                            #
    # ------------------------------------------------------------------ #
