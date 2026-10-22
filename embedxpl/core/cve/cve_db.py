"""Embedded CVE database and lookup engine for network devices.

Provides a curated, offline-first CVE database indexed by vendor, product
and version range, with access-vector classification (remote/local/physical)
and mapping to EmbedXPL-Forge exploit modules when available.

Also supports live enrichment from local JSON catalogs and the existing
module tree's __info__ metadata.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("embedxpl.cve")


# =====================================================================
# Data model
# =====================================================================

@dataclass
class CVEEntry:
    """A single CVE record with access-vector classification."""

    cve_id: str
    vendor: str
    product: str
    affected_versions: str = ""
    description: str = ""
    cvss_score: float = 0.0
    access_vector: str = "REMOTE"  # REMOTE | LOCAL | PHYSICAL | ADJACENT
    exploit_available: bool = False
    exf_module: str = ""  # EmbedXPL-Forge module path if available
    references: List[str] = field(default_factory=list)

    @property
    def is_remote(self) -> bool:
        return self.access_vector.upper() in ("REMOTE", "NETWORK")

    @property
    def is_exploitable_by_exf(self) -> bool:
        return self.is_remote and bool(self.exf_module)

    @property
    def status_label(self) -> str:
        if self.is_exploitable_by_exf:
            return "EXPLOITABLE (exf module available)"
        if self.is_remote:
            return "REMOTE (no exf module yet)"
        return "{} access required".format(self.access_vector.upper())


# =====================================================================
# Embedded CVE catalog  -  curated for in-scope devices
# =====================================================================

_EMBEDDED_CVES: List[Dict[str, Any]] = [
    # --- Netgear ---
    {"cve_id": "CVE-2017-5521", "vendor": "netgear", "product": "multiple", "affected_versions": "R6250, R6400, R6700, R7000, R7100LG, R7300, R7900, R8000, R8300, R8500", "description": "Authentication bypass on Netgear routers via crafted request to passwordrecovered.cgi", "cvss_score": 8.1, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2017-6077", "vendor": "netgear", "product": "dgn2200", "affected_versions": "DGN2200v1-v4", "description": "Remote command execution via ping CGI", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2017-6334", "vendor": "netgear", "product": "dgn2200", "affected_versions": "DGN2200v1-v4", "description": "Remote command execution via dnslookup CGI", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2016-6277", "vendor": "netgear", "product": "r7000", "affected_versions": "R6400, R7000, R8000", "description": "Command injection via cgi-bin", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- TP-Link ---
    {"cve_id": "CVE-2017-11519", "vendor": "tplink", "product": "archer_c9", "affected_versions": "Archer C9 v1", "description": "Admin password reset without authentication", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2017-13772", "vendor": "tplink", "product": "wr940n", "affected_versions": "TL-WR940N v4", "description": "Buffer overflow in HTTP Referer header leading to RCE", "cvss_score": 8.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2019-7405", "vendor": "tplink", "product": "archer_c5", "affected_versions": "Archer C5 v4", "description": "Buffer overflow via HTTPD leading to RCE", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2020-10882", "vendor": "tplink", "product": "archer_a7", "affected_versions": "Archer A7 v5", "description": "tdpServer buffer overflow RCE on LAN", "cvss_score": 8.8, "access_vector": "ADJACENT"},
    {"cve_id": "CVE-2022-30075", "vendor": "tplink", "product": "archer_ax50", "affected_versions": "Archer AX50 v1", "description": "Authenticated RCE via backup restore injection", "cvss_score": 8.8, "access_vector": "REMOTE"},
    # --- D-Link ---
    {"cve_id": "CVE-2019-16920", "vendor": "dlink", "product": "dir-655", "affected_versions": "DIR-655, DIR-866, DIR-652", "description": "Unauthenticated remote command execution", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2017-6190", "vendor": "dlink", "product": "dwr-116", "affected_versions": "DWR-116", "description": "Remote file inclusion via unrestricted upload", "cvss_score": 8.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2019-17621", "vendor": "dlink", "product": "dir-859", "affected_versions": "DIR-859 A1", "description": "UPnP command injection RCE", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Cisco ---
    {"cve_id": "CVE-2017-3881", "vendor": "cisco", "product": "catalyst_2960", "affected_versions": "Catalyst 2960, IOS XE", "description": "Cluster Management Protocol RCE (CIA Vault 7)", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2019-1652", "vendor": "cisco", "product": "rv320", "affected_versions": "RV320, RV325", "description": "Command injection via web management interface", "cvss_score": 7.2, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2016-6433", "vendor": "cisco", "product": "firepower_management", "affected_versions": "Firepower Management Center 6.0", "description": "Deserialization RCE", "cvss_score": 8.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2016-6435", "vendor": "cisco", "product": "firepower_management", "affected_versions": "Firepower Management Center 6.0", "description": "Path traversal and arbitrary file download", "cvss_score": 7.5, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2013-7030", "vendor": "cisco", "product": "ucm", "affected_versions": "UCM multiple", "description": "Information disclosure via web interface", "cvss_score": 5.3, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2018-0171", "vendor": "cisco", "product": "ios_smart_install", "affected_versions": "IOS/IOS XE with Smart Install", "description": "Smart Install Client RCE - buffer overflow", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2023-20198", "vendor": "cisco", "product": "ios_xe", "affected_versions": "IOS XE web UI", "description": "Privilege escalation via web UI to create local accounts", "cvss_score": 10.0, "access_vector": "REMOTE"},
    # --- Linksys ---
    {"cve_id": "CVE-2013-3568", "vendor": "linksys", "product": "wrt100_110", "affected_versions": "WRT100, WRT110", "description": "Remote command execution via CSRF", "cvss_score": 8.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2014-8243", "vendor": "linksys", "product": "smartwifi", "affected_versions": "EA2700, EA3500, E4200v2, EA4500", "description": "Password disclosure via JNAP", "cvss_score": 7.5, "access_vector": "REMOTE"},
    # --- ASUS ---
    {"cve_id": "CVE-2018-5999", "vendor": "asus", "product": "asuswrt", "affected_versions": "RT-AC68U, RT-AC88U (before 3.0.0.4.384.10007)", "description": "LAN RCE via networkmap", "cvss_score": 8.8, "access_vector": "ADJACENT"},
    {"cve_id": "CVE-2018-6000", "vendor": "asus", "product": "asuswrt", "affected_versions": "RT-AC68U, RT-AC88U (before 3.0.0.4.384.10007)", "description": "LAN RCE via ipt module", "cvss_score": 8.8, "access_vector": "ADJACENT"},
    {"cve_id": "CVE-2024-3080", "vendor": "asus", "product": "asuswrt", "affected_versions": "RT-AX88U, RT-AX86U, RT-AX58U", "description": "Authentication bypass allowing unauthenticated remote access", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Huawei ---
    {"cve_id": "CVE-2017-17215", "vendor": "huawei", "product": "hg532", "affected_versions": "HG532", "description": "Remote code execution via UPnP SOAP injection", "cvss_score": 8.8, "access_vector": "REMOTE"},
    # --- Belkin ---
    {"cve_id": "CVE-2014-1635", "vendor": "belkin", "product": "n750", "affected_versions": "N750 DB", "description": "Remote command execution", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2012-2765", "vendor": "belkin", "product": "g_n150", "affected_versions": "G, N150", "description": "Password disclosure via info disclosure", "cvss_score": 7.5, "access_vector": "REMOTE"},
    # --- MikroTik ---
    {"cve_id": "CVE-2018-14847", "vendor": "mikrotik", "product": "routeros", "affected_versions": "RouterOS < 6.42.7, < 6.43rc4", "description": "Winbox authentication bypass and arbitrary file read", "cvss_score": 9.1, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2019-3943", "vendor": "mikrotik", "product": "routeros", "affected_versions": "RouterOS < 6.44.2", "description": "Path traversal leading to arbitrary file write", "cvss_score": 7.5, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2023-30799", "vendor": "mikrotik", "product": "routeros", "affected_versions": "RouterOS < 6.49.7, < 7.10 stable", "description": "Privilege escalation from admin to super-admin", "cvss_score": 7.2, "access_vector": "REMOTE"},
    # --- Fortinet FortiGate ---
    {"cve_id": "CVE-2022-40684", "vendor": "fortinet", "product": "fortigate", "affected_versions": "FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1", "description": "Authentication bypass via crafted HTTP/HTTPS requests", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2023-27997", "vendor": "fortinet", "product": "fortigate", "affected_versions": "FortiOS SSL-VPN", "description": "Heap buffer overflow in SSL-VPN pre-authentication RCE", "cvss_score": 9.8, "access_vector": "REMOTE"},
    {"cve_id": "CVE-2024-21762", "vendor": "fortinet", "product": "fortigate", "affected_versions": "FortiOS 7.4.0-7.4.2, 7.2.0-7.2.6, 7.0.0-7.0.13", "description": "Out-of-bound write in SSL-VPN allowing RCE", "cvss_score": 9.6, "access_vector": "REMOTE"},
    # --- Palo Alto ---
    {"cve_id": "CVE-2024-3400", "vendor": "paloalto", "product": "pan-os", "affected_versions": "PAN-OS 10.2, 11.0, 11.1 with GlobalProtect", "description": "Command injection in GlobalProtect leading to RCE", "cvss_score": 10.0, "access_vector": "REMOTE"},
    # --- SonicWall ---
    {"cve_id": "CVE-2021-20016", "vendor": "sonicwall", "product": "sma", "affected_versions": "SMA 100 Series", "description": "SQL injection leading to credential theft", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Juniper ---
    {"cve_id": "CVE-2023-36845", "vendor": "juniper", "product": "junos", "affected_versions": "SRX/EX Series with J-Web", "description": "PHP environment variable manipulation leading to RCE", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Ubiquiti ---
    {"cve_id": "CVE-2019-5456", "vendor": "ubiquiti", "product": "unifi", "affected_versions": "UniFi Controller < 5.10.19", "description": "CSRF allowing configuration changes", "cvss_score": 8.8, "access_vector": "REMOTE"},
    # --- Dragonblood / WPA3 ---
    {"cve_id": "CVE-2019-9494", "vendor": "generic", "product": "wpa3", "affected_versions": "WPA3-SAE implementations", "description": "SAE side-channel timing attack (Dragonblood)", "cvss_score": 5.9, "access_vector": "ADJACENT"},
    {"cve_id": "CVE-2019-9496", "vendor": "generic", "product": "wpa3", "affected_versions": "WPA3-Transition mode", "description": "SAE transition mode downgrade to WPA2", "cvss_score": 7.5, "access_vector": "ADJACENT"},
    # --- Multi-vendor ---
    {"cve_id": "CVE-2014-9222", "vendor": "multi", "product": "rom0", "affected_versions": "Allegro RomPager < 4.34", "description": "Misfortune Cookie  -  RCE via HTTP cookie overflow in embedded devices", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Physical-only examples (not remotely exploitable) ---
    {"cve_id": "CVE-2020-27301", "vendor": "cisco", "product": "jabber", "affected_versions": "Jabber for Windows", "description": "DLL hijacking (requires local access)", "cvss_score": 7.8, "access_vector": "LOCAL"},
    {"cve_id": "CVE-2018-0150", "vendor": "cisco", "product": "ios_xe", "affected_versions": "IOS XE with hardcoded credentials", "description": "Hardcoded root credentials (console/physical access)", "cvss_score": 9.8, "access_vector": "PHYSICAL"},
    # =====================================================================
    # Router vulnerabilities 2020-2026 (from router_vulns CSV research)
    # 86 new CVEs across 17 vendors
    # =====================================================================
    # --- Asus (router_vulns CSV) ---
    {"cve_id": "CVE-2020-15498", "vendor": "asus", "product": "home_router", "affected_versions": "RT-AC1900P", "description": "Improper certificate validation in firmware update. Device may accept spoofed firmware update server due to certificate validation issue.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-15498"]},
    {"cve_id": "CVE-2021-32030", "vendor": "asus", "product": "gaming_/_mesh_router", "affected_versions": "GT-AC2900 / Lyra Mini", "description": "Authentication bypass. Unauthenticated attacker can bypass authentication on affected ASUS router models.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-32030"]},
    {"cve_id": "CVE-2021-40556", "vendor": "asus", "product": "home_router", "affected_versions": "RT-AX56U", "description": "Stack overflow in httpd. Authenticated request can trigger stack overflow in httpd and execute commands.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-40556"]},
    {"cve_id": "CVE-2021-43702", "vendor": "asus", "product": "home_router", "affected_versions": "RT-A88U", "description": "Stored XSS in Wi-Fi logs. Stored XSS can execute in admin browser viewing logs.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-43702"]},
    {"cve_id": "CVE-2022-32988", "vendor": "asus", "product": "dsl_router", "affected_versions": "DSL-N14U-B1", "description": "Cross-site scripting. Multiple list parameters in web UI vulnerable to XSS.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-32988"]},
    {"cve_id": "CVE-2022-38105", "vendor": "asus", "product": "home_router", "affected_versions": "RT-AX82U", "description": "Configuration service information disclosure. Information disclosure in configuration service may leak sensitive data.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-38105"]},
    {"cve_id": "CVE-2022-38393", "vendor": "asus", "product": "home_router", "affected_versions": "RT-AX82U", "description": "Configuration service denial of service. Attacker can impact availability of configuration service.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-38393"]},
    {"cve_id": "CVE-2025-15101", "vendor": "asus", "product": "home_router", "affected_versions": "Multiple ASUS router models", "description": "CSRF in web management with command execution possibility. Cross-site request forgery on management interface may enable command execution or router setting abuse.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-15101"]},
    {"cve_id": "CVE-2025-59367", "vendor": "asus", "product": "dsl_router", "affected_versions": "DSL-N16 / DSL-AX82U and related DSL models", "description": "Authentication bypass. Authentication bypass in ASUS DSL routers enables unauthorized access to management functions.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-59367"]},
    {"cve_id": "CVE-2025-59368", "vendor": "asus", "product": "home_router", "affected_versions": "AiCloud-enabled router models", "description": "Integer underflow in AiCloud. AiCloud component underflow can impact service availability and stability.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-59368"]},
    # --- Cisco (router_vulns CSV) ---
    {"cve_id": "CVE-2022-20699", "vendor": "cisco", "product": "small_business_router", "affected_versions": "RV160 / RV260 / RV340 / RV345 series", "description": "Multiple vulnerabilities in web-based management interface. Cisco advisory covers multiple web-management vulnerabilities in Small Business routers.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-20699"]},
    {"cve_id": "CVE-2023-20118", "vendor": "cisco", "product": "small_business_router", "affected_versions": "RV016 / RV042 / RV042G / RV082 / RV320 / RV325", "description": "Authenticated remote command execution. Authenticated attacker can execute arbitrary commands as root on Cisco RV series routers; Cisco says no fix for affected line.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-20118"]},
    {"cve_id": "CVE-2024-20362", "vendor": "cisco", "product": "small_business_router", "affected_versions": "RV016 / RV042 / RV042G / RV082 / RV320 / RV325", "description": "Cross-site scripting in web UI. Small Business RV series suffers XSS in web interface.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-20362"]},
    # --- Dlink (router_vulns CSV) ---
    {"cve_id": "CVE-2022-30521", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-890L", "description": "Stack-based buffer overflow. Attack over exposed port 49152 can trigger overflow and potential code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-30521"]},
    {"cve_id": "CVE-2022-35191", "vendor": "dlink", "product": "dsl_router", "affected_versions": "DSL-3782", "description": "Unauthenticated denial of service. Crafted HTTP connection request can render service unavailable.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-35191"]},
    {"cve_id": "CVE-2022-36786", "vendor": "dlink", "product": "dsl_router", "affected_versions": "DSL-224", "description": "Post-auth remote code execution. Authenticated attacker can achieve RCE via JSON-RPC NTP-related endpoint.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-36786"]},
    {"cve_id": "CVE-2022-37055", "vendor": "dlink", "product": "home_router", "affected_versions": "GO-RT-AC750", "description": "Buffer overflow. Buffer overflow vulnerability in D-Link router; CISA KEV lists active exploitation.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37055"]},
    {"cve_id": "CVE-2022-46552", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-846", "description": "Remote code execution via static DHCP list. Parameter lan(0)_dhcps_staticlist enables remote code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-46552"]},
    {"cve_id": "CVE-2023-25280", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-820L/LW", "description": "Command injection. Unauthenticated command injection can yield root-level code execution; CISA KEV listed in 2024.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-25280"]},
    {"cve_id": "CVE-2025-4344", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-600L", "description": "Buffer overflow in formLogin host parameter. Unauthenticated attacker can overflow host parameter in formLogin.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-4344"]},
    {"cve_id": "CVE-2025-60672", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-878", "description": "Unauthenticated command injection. Unauthenticated attacker can inject commands through router web interface.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-60672"]},
    {"cve_id": "CVE-2025-60698", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-882", "description": "Command injection in SysLogRemote_IPAddress. Public exploit references show command injection through syslog remote IP parameter.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-60698"]},
    {"cve_id": "CVE-2025-60700", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-882", "description": "Command injection in DMZIPAddress. Public exploit references show command injection through DMZ configuration.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-60700"]},
    {"cve_id": "CVE-2025-60701", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-882", "description": "Command injection in email configuration. Public exploit references show command injection through email configuration fields.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-60701"]},
    {"cve_id": "CVE-2025-8949", "vendor": "dlink", "product": "home_router", "affected_versions": "DIR-825", "description": "Stack overflow. Public exploit available against unsupported router model.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-8949"]},
    {"cve_id": "CVE-2026-0625", "vendor": "dlink", "product": "home/dsl_routers", "affected_versions": "Multiple DSL / DIR / DNS devices", "description": "Authentication bypass with DNS hijack and possible command injection context. Unauthenticated attacker can change DNS settings on many D-Link routers; NVD notes impact consistent with hijacking and...", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-0625"]},
    # --- Eachitaly (router_vulns CSV) ---
    {"cve_id": "CVE-2025-63422", "vendor": "eachitaly", "product": "wireless_mini_router", "affected_versions": "Wireless Mini Router", "description": "Incorrect access control. Access-control weakness enables unauthorized interaction with router functions.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-63422"]},
    # --- Edimax (router_vulns CSV) ---
    {"cve_id": "CVE-2024-48418", "vendor": "edimax", "product": "home_router", "affected_versions": "BR-6476AC", "description": "Command injection. Affected Edimax router vulnerable to command injection.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-48418"]},
    # --- Genexis (router_vulns CSV) ---
    {"cve_id": "CVE-2020-25015", "vendor": "genexis", "product": "home_router", "affected_versions": "Platinum 4410", "description": "Broken access control / CSRF. Improper access control allows Wi-Fi password or related changes via crafted requests.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-25015", "https://www.exploit-db.com/exploits/49000"]},
    {"cve_id": "CVE-2020-25988", "vendor": "genexis", "product": "home_router", "affected_versions": "Platinum 4410", "description": "UPnP admin credential exposure. UPnP service can expose administrative credentials in clear text or retrievable form.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-25988", "https://www.exploit-db.com/exploits/49075"]},
    # --- Guangzhouvsolution (router_vulns CSV) ---
    {"cve_id": "CVE-2020-8958", "vendor": "guangzhouvsolution", "product": "onu/router", "affected_versions": "1GE ONU V2801RW / V2804RGW", "description": "Command injection via ping diagnostic. Authenticated attacker can inject commands through ping diagnostic endpoint/parameter.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8958"]},
    # --- Huawei (router_vulns CSV) ---
    {"cve_id": "CVE-2023-7266", "vendor": "huawei", "product": "home_router", "affected_versions": "Multiple home router products", "description": "Connection hijacking / information leak / DoS. Attacker can hijack or interfere with router connections and leak information.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-7266"]},
    # --- Intelbras (router_vulns CSV) ---
    {"cve_id": "CVE-2020-36963", "vendor": "intelbras", "product": "home_router", "affected_versions": "RF 301K 1.1.2", "description": "Authentication bypass with configuration disclosure. Unauthenticated attacker can download configuration backup and expose credentials/settings.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-36963", "https://www.exploit-db.com/exploits/49126"]},
    # --- Kuwfi (router_vulns CSV) ---
    {"cve_id": "CVE-2025-68706", "vendor": "kuwfi", "product": "4g_lte_router", "affected_versions": "4G LTE AC900", "description": "Stack-based buffer overflow in GoAhead formMultiApnSetting. Router web interface contains overflow sink in APN configuration handler.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-68706"]},
    # --- Mikrotik (router_vulns CSV) ---
    {"cve_id": "CVE-2020-5721", "vendor": "mikrotik", "product": "routeros_/_winbox", "affected_versions": "WinBox", "description": "Cleartext password in memory/traffic context. Tenable catalogs sensitive cleartext password exposure associated with MikroTik WinBox behavior.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-5721"]},
    {"cve_id": "CVE-2022-45315", "vendor": "mikrotik", "product": "routeros", "affected_versions": "RouterOS SNMP", "description": "Out-of-bounds read / possible code execution. NVD search result mentions authenticated code execution potential via SNMP parsing issue.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-45315"]},
    {"cve_id": "CVE-2024-27686", "vendor": "mikrotik", "product": "routeros", "affected_versions": "SMB service on RouterOS", "description": "SMB denial of service. Public Exploit-DB PoC crashes SMB service on affected RouterOS ranges.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27686", "https://www.exploit-db.com/exploits/51931"]},
    # --- Netgear (router_vulns CSV) ---
    {"cve_id": "CVE-2021-41449", "vendor": "netgear", "product": "home_router", "affected_versions": "RAX35 / RAX38 / RAX40", "description": "Path traversal. Unauthenticated path traversal exposes sensitive files.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41449"]},
    {"cve_id": "CVE-2022-31876", "vendor": "netgear", "product": "wireless_access/router", "affected_versions": "WNAP320", "description": "Incorrect access control exposing cookies. Cookies can be leaked due to weak access control in web interface.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-31876"]},
    {"cve_id": "CVE-2022-37232", "vendor": "netgear", "product": "home_router", "affected_versions": "WNR2000v4", "description": "Buffer overflow in uhttpd. Overflow in uhttpd may lead to denial of service or code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37232"]},
    {"cve_id": "CVE-2022-37234", "vendor": "netgear", "product": "home_router", "affected_versions": "R7000", "description": "Buffer overflow. Affected Netgear router vulnerable to overflow conditions.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37234"]},
    {"cve_id": "CVE-2022-37337", "vendor": "netgear", "product": "mesh_router", "affected_versions": "Orbi RBR750", "description": "Command execution. Authenticated attacker can execute commands on router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-37337"]},
    {"cve_id": "CVE-2022-47052", "vendor": "netgear", "product": "home_router", "affected_versions": "R6220", "description": "CRLF injection leading to reflected XSS/HTML injection. Improper sanitization allows reflected XSS/HTML injection via CRLF injection.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-47052"]},
    {"cve_id": "CVE-2022-48196", "vendor": "netgear", "product": "multiple_routers", "affected_versions": "Multiple unsupported devices", "description": "Unauthenticated buffer overflow. Unauthenticated remote attacker can trigger buffer overflow on several routers.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-48196"]},
    {"cve_id": "CVE-2024-12988", "vendor": "netgear", "product": "home_router", "affected_versions": "R6900P / R7000P", "description": "Host header buffer overflow. Public exploit exists for host-header-triggered overflow in unsupported Netgear routers.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12988"]},
    {"cve_id": "CVE-2025-12943", "vendor": "netgear", "product": "home_router", "affected_versions": "RAX30 / RAXE300 and others", "description": "Improper certificate validation leading to command execution. MITM or spoofed service can leverage certificate validation flaw for code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-12943"]},
    {"cve_id": "CVE-2025-12945", "vendor": "netgear", "product": "home_router", "affected_versions": "R7000P", "description": "Authenticated OS command injection. Authenticated attacker can execute OS commands on supported/unsupported router firmware lines.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-12945"]},
    {"cve_id": "CVE-2025-12946", "vendor": "netgear", "product": "nighthawk_routers", "affected_versions": "Multiple Nighthawk models", "description": "Speedtest feature command execution. Nighthawk routers vulnerable to command execution when speedtest-related communication is manipulated.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-12946"]},
    {"cve_id": "CVE-2025-29044", "vendor": "netgear", "product": "home_router", "affected_versions": "R6100", "description": "Buffer overflow with RCE potential. Public exploit references available for vulnerable unsupported router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-29044"]},
    # --- Seowon (router_vulns CSV) ---
    {"cve_id": "CVE-2020-17456", "vendor": "seowon", "product": "home/isp_router", "affected_versions": "SLC-130 / SLR-120S", "description": "Remote code execution. Routers expose paths/behavior enabling remote code execution; public PoCs exist.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-17456", "https://www.exploit-db.com/exploits/50821"]},
    # --- Synology (router_vulns CSV) ---
    {"cve_id": "CVE-2020-27655", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM before 1.2.4-8081", "description": "Improper access control. Improper access control in Synology Router Manager prior to fixed build.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-27655"]},
    {"cve_id": "CVE-2022-43932", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM", "description": "CGI injection / arbitrary file read. Synology router manager vulnerable to CGI-based file exposure or injection path.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-43932"]},
    {"cve_id": "CVE-2024-11398", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM OTP reset flow", "description": "Path traversal enabling arbitrary file deletion. Traversal in SRM OTP reset can delete arbitrary files.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-11398"]},
    {"cve_id": "CVE-2024-39348", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM", "description": "AirPrint man-in-the-middle arbitrary code execution. MITM on AirPrint communication can lead to arbitrary code execution on Synology routers.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-39348"]},
    {"cve_id": "CVE-2024-53283", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM / Router Port Forward", "description": "Stored XSS with limited file R/W and DoS. Synology states attacker may cause limited file read/write and DoS through stored XSS chain.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-53283"]},
    {"cve_id": "CVE-2024-53286", "vendor": "synology", "product": "router_manager", "affected_versions": "SRM / DDNS Record", "description": "Command injection in DDNS record feature. Command injection in Synology DDNS record handling can lead to code execution.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-53286"]},
    # --- Tenda (router_vulns CSV) ---
    {"cve_id": "CVE-2020-35391", "vendor": "tenda", "product": "home_router", "affected_versions": "N300 F3", "description": "Forced browsing downloads config. Configuration file can be retrieved directly through predictable path/endpoints.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-35391"]},
    {"cve_id": "CVE-2021-31755", "vendor": "tenda", "product": "home_router", "affected_versions": "AC11", "description": "Stack-based buffer overflow. Buffer overflow in Tenda AC11 allows remote code execution or crash.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-31755"]},
    {"cve_id": "CVE-2021-47802", "vendor": "tenda", "product": "dsl_router", "affected_versions": "D151 / D301", "description": "Unauthenticated configuration download. Configuration file download without authentication exposes credentials/settings.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-47802", "https://www.exploit-db.com/exploits/49782"]},
    {"cve_id": "CVE-2025-7795", "vendor": "tenda", "product": "home_router", "affected_versions": "FH451", "description": "Stack-based buffer overflow. Exploit-DB PoC available for Tenda FH451 stack overflow.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-7795", "https://www.exploit-db.com/exploits/52374"]},
    {"cve_id": "CVE-2026-22079", "vendor": "tenda", "product": "home_router", "affected_versions": "F3 / N300 Easy Setup", "description": "Cleartext credential transmission. Credentials may be transmitted or handled in cleartext.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-22079"]},
    {"cve_id": "CVE-2026-22082", "vendor": "tenda", "product": "home_router", "affected_versions": "F3 / N300 Easy Setup", "description": "Session fixation using credentials as session ID. Router uses a session identifier derived from or equal to password/credentials, enabling session abuse.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-22082"]},
    {"cve_id": "CVE-2026-30140", "vendor": "tenda", "product": "business_router", "affected_versions": "W15E", "description": "Unauthenticated configuration download exposing admin credentials. Configuration file is downloadable without auth and contains plaintext admin password.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-30140"]},
    # --- Tplink (router_vulns CSV) ---
    {"cve_id": "CVE-2020-17891", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer C1200", "description": "Cross-site scripting leading to code execution context. Router web interface suffers XSS; descriptions claim arbitrary code execution in browser/admin context.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-17891"]},
    {"cve_id": "CVE-2020-35576", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR841N", "description": "Command injection. Router command injection with public Exploit-DB PoC.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-35576", "https://www.exploit-db.com/exploits/50058"]},
    {"cve_id": "CVE-2020-8423", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR841N V10", "description": "Buffer overflow in httpd. Authenticated attacker can overflow httpd and execute arbitrary code.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8423"]},
    {"cve_id": "CVE-2020-9374", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR849N", "description": "Remote code execution. Public Exploit-DB proof of concept for remote code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-9374", "https://www.exploit-db.com/exploits/48155"]},
    {"cve_id": "CVE-2020-9375", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer C50 V3", "description": "Denial of service via crafted HTTP header. Crafted HTTP header can crash or deny service; NVD references public exploit writeups.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-9375"]},
    {"cve_id": "CVE-2022-0162", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR841N", "description": "Credentials sent base64/cleartext. Credentials are weakly protected during transmission/handling.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0162"]},
    {"cve_id": "CVE-2022-25061", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR840N", "description": "Command injection via IPv6 route parameter. Function oal_setIp6DefaultRoute vulnerable to command injection.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-25061"]},
    {"cve_id": "CVE-2022-25062", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR840N", "description": "Integer overflow causing DoS. Integer overflow can deny service in affected router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-25062"]},
    {"cve_id": "CVE-2022-25064", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR840N", "description": "Remote code execution via WAN config parameter. Function oal_wan6_setIpAddr can be abused for code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-25064"]},
    {"cve_id": "CVE-2022-40486", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer AX10 V1", "description": "Backup file import RCE. Authenticated attacker can upload crafted backup file and obtain code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-40486"]},
    {"cve_id": "CVE-2023-33538", "vendor": "tplink", "product": "multiple_home_routers", "affected_versions": "Archer AX21 and other router families reported", "description": "Command injection. Command injection in TP-Link router management stack; public exploitation and CISA KEV coverage discussed.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-33538"]},
    {"cve_id": "CVE-2023-50224", "vendor": "tplink", "product": "home_router", "affected_versions": "TL-WR841N", "description": "Improper authentication leading to information disclosure. Unauthenticated or weakly authenticated access can disclose sensitive information; later associated with real-world exploitation alerts.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-50224"]},
    {"cve_id": "CVE-2024-54134", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer C50", "description": "Improper signature verification. Weak signature verification may allow untrusted or modified firmware/objects.", "cvss_score": 0.0, "access_vector": "ADJACENT", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-54134"]},
    {"cve_id": "CVE-2024-57049", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer C20", "description": "Authentication bypass (disputed). Public GitHub exploit claims auth bypass on Archer C20; NVD marks dispute/low-confidence context.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-57049", "https://github.com/search?q=CVE-2024-57049"]},
    {"cve_id": "CVE-2025-15517", "vendor": "tplink", "product": "4g/5g_router", "affected_versions": "Archer NX200 / NX210 / NX500 / NX600", "description": "Missing authentication for privileged CGI actions. Missing authentication permits execution of privileged actions through CGI endpoints.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-15517"]},
    {"cve_id": "CVE-2025-15606", "vendor": "tplink", "product": "dsl_router", "affected_versions": "TD-W8961N", "description": "Denial of service. Attack can deny service on affected TD-W8961N router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-15606"]},
    {"cve_id": "CVE-2025-40634", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer AX50", "description": "Stack-based buffer overflow. Public disclosure indicates stack overflow with potential remote code execution.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-40634"]},
    {"cve_id": "CVE-2025-7850", "vendor": "tplink", "product": "business/soho_router", "affected_versions": "ER605 / ER706W-4G and related families", "description": "Command injection. Forescout-reported OS command injection affecting TP-Link routers in business/SOHO space.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-7850"]},
    {"cve_id": "CVE-2025-9377", "vendor": "tplink", "product": "home_router", "affected_versions": "Archer C7(EU) V5 / TL-WR841N/ND V11/V12", "description": "Authenticated remote code execution. CISA KEV-listed TP-Link router RCE affecting widely deployed EOL models.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-9377"]},
    # --- Zte (router_vulns CSV) ---
    {"cve_id": "CVE-2020-6862", "vendor": "zte", "product": "isp/home_router", "affected_versions": "F6x2W series", "description": "CAPTCHA bypass / sensitive information exposure. Information exposure and CAPTCHA weakness can facilitate unauthorized access attempts.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": True, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-6862", "https://www.exploit-db.com/exploits/48801"]},
    {"cve_id": "CVE-2022-45957", "vendor": "zte", "product": "isp_router", "affected_versions": "ZXHN-H108NS", "description": "Remote stack buffer overflow. Remote attacker can trigger stack overflow in ZTE router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-45957"]},
    {"cve_id": "CVE-2024-22066", "vendor": "zte", "product": "intelligent_multi-service_router", "affected_versions": "ZXR10 ZSR V2", "description": "Privilege escalation. Privilege escalation in ZTE intelligent multi-service router platform.", "cvss_score": 0.0, "access_vector": "LOCAL", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-22066"]},
    {"cve_id": "CVE-2026-34472", "vendor": "zte", "product": "home_router", "affected_versions": "ZXHN H188A", "description": "Credential disclosure. Unauthenticated attacker can disclose credentials from affected router.", "cvss_score": 0.0, "access_vector": "REMOTE", "exploit_available": False, "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-34472"]},


]


# =====================================================================
# Normalisation
# =====================================================================

def _normalize(value: str) -> str:
    """Collapse separators and lowercase for fuzzy matching."""
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _version_in_range(actual: str, affected: str) -> bool:
    """Heuristic version-in-range check: returns True if any token in
    *affected* matches a substring of *actual* (after normalisation)."""
    if not affected or not actual:
        return True  # no version constraint → assume match
    norm_actual = _normalize(actual)
    for token in re.split(r"[,;/|]+", affected):
        norm_token = _normalize(token)
        if norm_token and norm_token in norm_actual:
            return True
    return False


# =====================================================================
# Database loader
# =====================================================================

def _entry_from_mapping(raw: Dict[str, Any]) -> CVEEntry:
    """Build CVEEntry from dict (embedded list or JSON catalog)."""
    return CVEEntry(
        cve_id=raw["cve_id"],
        vendor=raw.get("vendor", ""),
        product=raw.get("product", ""),
        affected_versions=raw.get("affected_versions", ""),
        description=raw.get("description", ""),
        cvss_score=float(raw.get("cvss_score", 0.0)),
        access_vector=raw.get("access_vector", "REMOTE"),
        exploit_available=bool(raw.get("exploit_available", False)),
        references=list(raw.get("references", [])),
    )


def _load_embedded() -> List[CVEEntry]:
    """Load the embedded CVE catalog."""
    return [_entry_from_mapping(raw) for raw in _EMBEDDED_CVES]


def _load_poc_intel_cve_hints(repo_root: Path) -> List[CVEEntry]:
    """Load CVE IDs discovered in local third-party PoC mirrors (thin hints, lowest priority)."""

    path = repo_root / "resources" / "catalogs" / "embedded_third_party_poc_intel.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("embedded_third_party_poc_intel.json unreadable: %s", exc)
        return []
    # Bulk indices (tg12, ExploitDB mirrors) stay in JSON for tooling  -  not loaded into lookup RAM.
    skip_slugs = frozenset(
        {
            "tg12__PoC_CVEs",
            "exploit-database__exploitdb",
            "exploit-database__exploitdb-bin-sploits",
        }
    )
    cve_set: Set[str] = set()
    for repo in data.get("repositories") or []:
        if repo.get("local_slug") in skip_slugs:
            continue
        for cid in repo.get("cves_found") or []:
            if isinstance(cid, str) and cid.upper().startswith("CVE-"):
                cve_set.add(cid.upper())
    entries: List[CVEEntry] = []
    for cid in sorted(cve_set):
        entries.append(
            CVEEntry(
                cve_id=cid,
                vendor="upstream_poc_mirror",
                product="third_party_router_poc",
                affected_versions="",
                description="CVE referenciado em clone local third-party-router-poc; validar com NVD/PSIRT antes de usar.",
                cvss_score=0.0,
                access_vector="REMOTE",
                exploit_available=True,
                references=[],
            )
        )
    return entries


def _load_extended_json_catalog(repo_root: Path) -> List[CVEEntry]:
    """Load additional CVE rows from resources/catalogs/cve_extended_catalog.json."""
    path = repo_root / "resources" / "catalogs" / "cve_extended_catalog.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("cve_extended_catalog.json unreadable: %s", exc)
        return []
    entries: List[CVEEntry] = []
    for raw in data.get("entries", []):
        if not raw.get("cve_id"):
            continue
        try:
            entries.append(_entry_from_mapping(raw))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("skip bad CVE row %s: %s", raw.get("cve_id"), exc)
    return entries


def _merge_cve_entries(repo_root: Path) -> List[CVEEntry]:
    """Merge embedded CVEs with JSON extended catalog; extended overrides on same ID."""
    by_id: Dict[str, CVEEntry] = {}
    for entry in _load_embedded():
        by_id[entry.cve_id.upper()] = entry
    for entry in _load_extended_json_catalog(repo_root):
        by_id[entry.cve_id.upper()] = entry
    for entry in _load_poc_intel_cve_hints(repo_root):
        if entry.cve_id.upper() not in by_id:
            by_id[entry.cve_id.upper()] = entry
    return list(by_id.values())


def _load_module_cves(modules_root: Path) -> Dict[str, str]:
    """Scan module __info__ references for CVE IDs and map to module paths."""
    cve_to_module: Dict[str, str] = {}
    if not modules_root.exists():
        return cve_to_module

    for py_file in modules_root.rglob("*.py"):
        if py_file.name.startswith("__"):
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", content)
        relative = py_file.relative_to(modules_root).as_posix()
        for cve_id in cve_ids:
            cve_to_module.setdefault(cve_id.upper(), relative)
    return cve_to_module


class CVEDatabase:
    """Offline CVE database with vendor/product/version lookup."""

    def __init__(self, modules_root: Optional[Path] = None):
        repo_root = Path(__file__).resolve().parents[2]
        self._entries = _merge_cve_entries(repo_root)
        self._module_map: Dict[str, str] = {}

        if modules_root is None:
            candidate = repo_root / "modules"
            if candidate.exists():
                modules_root = candidate

        if modules_root:
            self._module_map = _load_module_cves(modules_root)

        # Enrich entries with module paths
        for entry in self._entries:
            cid = entry.cve_id.upper()
            if cid in self._module_map:
                entry.exf_module = self._module_map[cid]
                entry.exploit_available = True

    @property
    def total(self) -> int:
        return len(self._entries)

    @property
    def remote_count(self) -> int:
        return sum(1 for e in self._entries if e.is_remote)

    @property
    def exploitable_count(self) -> int:
        return sum(1 for e in self._entries if e.is_exploitable_by_exf)

    def lookup(
        self,
        vendor: str = "",
        product: str = "",
        version: str = "",
        banner: str = "",
        remote_only: bool = False,
    ) -> List[CVEEntry]:
        """Search CVE entries matching vendor/product/version or banner text.

        Args:
            vendor: Vendor name (fuzzy matched).
            product: Product name or model (fuzzy matched).
            version: Firmware/software version string.
            banner: Raw banner text (searched for vendor+product tokens).
            remote_only: If True, only return remotely exploitable CVEs.

        Returns:
            Sorted list of matching CVEEntry objects (highest CVSS first).
        """
        norm_vendor = _normalize(vendor)
        norm_product = _normalize(product)
        norm_banner = _normalize(banner)

        results: List[CVEEntry] = []

        for entry in self._entries:
            if remote_only and not entry.is_remote:
                continue

            entry_vendor = _normalize(entry.vendor)
            entry_product = _normalize(entry.product)

            vendor_match = False
            product_match = False

            # Vendor matching
            if norm_vendor:
                if entry_vendor in ("multi", "generic") or norm_vendor in entry_vendor or entry_vendor in norm_vendor:
                    vendor_match = True
            elif norm_banner:
                if entry_vendor in norm_banner or entry_vendor in ("multi", "generic"):
                    vendor_match = True
            else:
                vendor_match = True

            if not vendor_match:
                continue

            # Product matching
            if norm_product:
                if entry_product in ("multiple", "") or norm_product in entry_product or entry_product in norm_product:
                    product_match = True
                # Also check affected_versions field
                norm_affected = _normalize(entry.affected_versions)
                if norm_product in norm_affected:
                    product_match = True
            elif norm_banner:
                if entry_product in norm_banner or _normalize(entry.affected_versions) in norm_banner:
                    product_match = True
                if entry_product in ("multiple", ""):
                    product_match = True
            else:
                product_match = True

            if not product_match:
                continue

            # Version matching
            if version and entry.affected_versions:
                if not _version_in_range(version, entry.affected_versions):
                    continue

            results.append(entry)

        results.sort(key=lambda e: e.cvss_score, reverse=True)
        return results

    def lookup_by_banner(self, banner: str, remote_only: bool = False) -> List[CVEEntry]:
        """Convenience method: extract vendor/product tokens from banner and lookup."""
        return self.lookup(banner=banner, remote_only=remote_only)

    def summary(self) -> Dict[str, Any]:
        """Return database statistics."""
        vectors: Dict[str, int] = {}
        vendors: Set[str] = set()
        for e in self._entries:
            vectors[e.access_vector] = vectors.get(e.access_vector, 0) + 1
            vendors.add(e.vendor)
        return {
            "total_cves": self.total,
            "remote": self.remote_count,
            "exploitable_by_exf": self.exploitable_count,
            "access_vectors": vectors,
            "vendors_covered": len(vendors),
        }
