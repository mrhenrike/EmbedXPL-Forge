# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""APT Group Attack Catalog — maps real-world threat actors to EmbedXPL modules.

Provides a structured catalog of Advanced Persistent Threat (APT) groups
that target network devices (routers, switches, IoT) covered by EmbedXPL.
Users can browse groups, review attack chains, and selectively reproduce
specific TTPs for security testing.

Version: 1.0.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("embedxpl.apt_catalog")


@dataclass
class APTAttack:
    """Single attack/technique within an APT campaign."""
    name: str
    description: str
    cves: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    target_devices: List[str] = field(default_factory=list)
    phase: str = ""
    requires_auth: bool = False


@dataclass
class APTGroup:
    """APT group profile with associated attacks reproducible by EmbedXPL."""
    id: str
    name: str
    aliases: List[str]
    country: str
    description: str
    campaigns: List[str] = field(default_factory=list)
    attacks: List[APTAttack] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_id: str = ""


APT_CATALOG: Dict[str, APTGroup] = {}


def _build_catalog() -> None:
    """Populate the APT catalog with known groups targeting EmbedXPL-covered devices."""

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


def get_catalog() -> Dict[str, APTGroup]:
    """Return the full APT catalog, building it on first access."""
    if not APT_CATALOG:
        _build_catalog()
    return APT_CATALOG


def get_group(group_id: str) -> Optional[APTGroup]:
    """Retrieve a specific APT group by ID."""
    catalog = get_catalog()
    return catalog.get(group_id.lower().replace("-", "_").replace(" ", "_"))


def list_groups() -> List[APTGroup]:
    """Return all APT groups sorted by name."""
    return sorted(get_catalog().values(), key=lambda g: g.name)


def find_groups_by_device(device_keyword: str) -> List[APTGroup]:
    """Find APT groups that target devices matching a keyword."""
    keyword = device_keyword.lower()
    results = []
    for group in get_catalog().values():
        for attack in group.attacks:
            if any(keyword in d.lower() for d in attack.target_devices):
                if group not in results:
                    results.append(group)
    return results


def find_groups_by_cve(cve_id: str) -> List[APTGroup]:
    """Find APT groups associated with a specific CVE."""
    cve_upper = cve_id.upper()
    results = []
    for group in get_catalog().values():
        for attack in group.attacks:
            if cve_upper in attack.cves:
                if group not in results:
                    results.append(group)
    return results
