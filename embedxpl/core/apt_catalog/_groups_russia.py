# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""APT catalog: Russia-affiliated groups."""

from embedxpl.core.apt_catalog._models import APT_CATALOG, APTGroup, APTAttack


def _register_russia() -> None:
    """APT catalog: Russia-affiliated groups."""

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

    APT_CATALOG["cyclops_blink"] = APTGroup(
        id="cyclops_blink",
        name="Cyclops Blink (Sandworm subgroup)",
        aliases=["FROZENBARENTS sub-op", "VPNFilter successor"],
        country="Russia",
        mitre_id="G0034",
        description=(
            "Cyclops Blink is a Sandworm (GRU) campaign targeting WatchGuard Firebox appliances "
            "and ASUS routers with persistent firmware-level malware. Successor to VPNFilter. "
            "Malware survives factory resets via /etc/init.d/ RC script modification."
        ),
        campaigns=["Cyclops Blink (2019-2022)", "VPNFilter (2016-2018)"],
        references=[
            "https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-26776",
        ],
        attacks=[
            APTAttack(
                name="WatchGuard Firebox Authentication Bypass (CVE-2022-26776)",
                description=(
                    "Authentication bypass in WatchGuard Firebox management interface used by "
                    "Cyclops Blink for initial access to recruit devices into botnet."
                ),
                cves=["CVE-2022-26776"],
                modules=["exploits/firewalls/watchguard/firebox_auth_bypass_cve_2022_26776"],
                mitre_techniques=["T1190", "T1601.001"],
                target_devices=["WatchGuard Firebox", "WatchGuard XTM"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="VPNFilter Stage-1 -- Multi-vendor SOHO Router Compromise",
                description=(
                    "VPNFilter Stage-1 persistence module targeting Linksys, MikroTik, Netgear, "
                    "TP-Link, QNAP, ASUS, D-Link, Huawei, Ubiquiti, ZTE devices. "
                    "CVE-2016-6277 Netgear RCE and CVE-2018-14847 MikroTik Winbox."
                ),
                cves=["CVE-2016-6277", "CVE-2018-14847"],
                modules=[
                    "exploits/routers/netgear/cig_bin_rce_cve_2016_6277",
                    "exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure",
                ],
                mitre_techniques=["T1190", "T1601", "T1584.005"],
                target_devices=["Linksys E-series", "MikroTik RouterOS", "Netgear R7000/R6400", "TP-Link", "QNAP NAS"],
                phase="Initial Access → Persistence",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # APT29 / Midnight Blizzard (Russia -- SVR)                           #
    # ------------------------------------------------------------------ #
    APT_CATALOG["apt29"] = APTGroup(
        id="apt29",
        name="APT29 / Midnight Blizzard",
        aliases=["Cozy Bear", "NOBELIUM", "The Dukes", "UNC2452", "Dark Halo"],
        country="Russia",
        mitre_id="G0016",
        description=(
            "Russia SVR APT responsible for SolarWinds Orion supply chain compromise (2020), "
            "giving access to network management planes of thousands of organizations. "
            "Also exploits VPN appliance vulnerabilities for initial access."
        ),
        campaigns=["SolarWinds Orion SUNBURST (2020)", "Teamviewer Compromise (2024)", "Pulse Secure Mass Exploitation (2021)"],
        references=[
            "https://attack.mitre.org/groups/G0016/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11510",
        ],
        attacks=[
            APTAttack(
                name="Pulse Connect Secure Path Traversal / Auth Bypass (CVE-2019-11510)",
                description=(
                    "CVSS 10.0 unauthenticated path traversal in Pulse Connect Secure allowing "
                    "credential and session file theft. Extensively used by APT29 for initial access."
                ),
                cves=["CVE-2019-11510"],
                modules=["exploits/vpn/pulse/pulse_connect_secure_path_traversal_cve_2019_11510"],
                mitre_techniques=["T1190"],
                target_devices=["Pulse Connect Secure", "Pulse Policy Secure"],
                phase="Initial Access",
                requires_auth=False,
            ),
            APTAttack(
                name="Ivanti Connect Secure Chain (CVE-2023-46805 + CVE-2024-21887)",
                description="APT29 adopted Ivanti exploitation from 2024 onwards for initial access.",
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
    # EMBER BEAR / GRU Unit 29155 (Russia)                                #
    # ------------------------------------------------------------------ #
    APT_CATALOG["ember_bear"] = APTGroup(
        id="ember_bear",
        name="Ember Bear / GRU Unit 29155",
        aliases=["UAC-0028", "UNC4166", "Cadet Blizzard", "Frozenvista"],
        country="Russia",
        mitre_id="G1003",
        description=(
            "Russia GRU Unit 29155 conducting espionage and sabotage operations against NATO states, "
            "Ukraine, and Georgia. Deploys WhisperGate wiper. Exploits perimeter network devices "
            "for initial access coordinated with kinetic operations."
        ),
        campaigns=["WhisperGate Ukraine (2022)", "NATO Infrastructure Espionage (2020-2025)"],
        references=["https://www.cisa.gov/sites/default/files/2024-09/aa24-249a-russian-military-cyber-actors-target-us-and-global-critical-infrastructure.pdf"],
        attacks=[
            APTAttack(
                name="Perimeter Network Device Initial Access (FortiGate, Cisco)",
                description=(
                    "Ember Bear exploits N-day vulnerabilities in FortiGate and Cisco perimeter devices "
                    "to establish initial access beachheads coordinated with GRU kinetic operations."
                ),
                cves=["CVE-2023-27997"],
                modules=["exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997"],
                mitre_techniques=["T1190", "T1485"],
                target_devices=["FortiGate SSL-VPN", "Cisco IOS edge routers"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # XENOTIME / Chernovite (Russia -- TsNIIKhM / ICS-targeting)          #
    # ------------------------------------------------------------------ #
    APT_CATALOG["xenotime"] = APTGroup(
        id="xenotime",
        name="XENOTIME / Chernovite",
        aliases=["TEMP.Veles", "RASPITE", "Chernovite (Dragos)", "TRITON/TRISIS operators"],
        country="Russia",
        mitre_id="G0088",
        description=(
            "Russia TsNIIKhM-linked APT responsible for TRITON/TRISIS -- the first-ever attack "
            "on Safety Instrumented Systems (SIS). Targeted Schneider Electric Triconex SIS at "
            "a Saudi petrochemical facility (2017). Chernovite (Dragos 2022) developed INCONTROLLER/"
            "PIPEDREAM toolkit targeting Schneider Modicon, Omron Sysmac, OPC-UA servers."
        ),
        campaigns=["TRITON/TRISIS -- Saudi Petro Rabigh (2017)", "INCONTROLLER/PIPEDREAM Toolkit (2022)", "XENOTIME ICS Scanning (2019)"],
        references=[
            "https://www.dragos.com/threat/xenotime",
            "https://cloud.google.com/blog/topics/threat-intelligence/incontroller-state-sponsored-ics-tool",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-5374",
        ],
        attacks=[
            APTAttack(
                name="Siemens SIPROTEC Relay DoS (CVE-2015-5374) -- Industroyer/Sandworm",
                description=(
                    "Denial-of-service against Siemens SIPROTEC 4 and 5 protective relays via "
                    "specially crafted EN50022 packet on UDP/2404. Used in Industroyer Ukraine power grid attack. "
                    "Disables protective relays enabling physical damage to electrical equipment."
                ),
                cves=["CVE-2015-5374"],
                modules=["exploits/ics/siemens/siprotec_relay_dos_cve_2015_5374"],
                mitre_techniques=["T0835", "T0813"],
                target_devices=["Siemens SIPROTEC 4", "Siemens SIPROTEC 5"],
                phase="Impact -- Denial of Safety",
                requires_auth=False,
            ),
            APTAttack(
                name="INCONTROLLER/PIPEDREAM -- Modbus Protocol Abuse (Schneider Modicon)",
                description=(
                    "EVILSCHOLAR component of INCONTROLLER abuses Modbus/TCP and UMAS protocol "
                    "to read/write control logic in Schneider Electric Modicon M340/M580 PLCs. "
                    "No CVE -- exploits design weaknesses in unauthenticated ICS protocols."
                ),
                cves=[],
                modules=["exploits/ics/schneider/modicon_modbus_control_cve_2018_7841"],
                mitre_techniques=["T0866", "T0839", "T0820"],
                target_devices=["Schneider Electric Modicon M340", "Modicon M580", "Modicon TM251/TM241"],
                phase="Impact -- Control Logic Manipulation",
                requires_auth=False,
            ),
        ],
    )
