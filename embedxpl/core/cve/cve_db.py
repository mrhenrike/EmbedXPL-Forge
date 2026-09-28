"""Embedded CVE database and lookup engine for network devices.

Provides a curated, offline-first CVE database indexed by vendor, product
and version range, with access-vector classification (remote/local/physical)
and mapping to EmbedXPL-Forge exploit modules when available.

Also supports live enrichment from local JSON catalogs and the existing
module tree's __info__ metadata.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
# Embedded CVE catalog — curated for in-scope devices
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
    {"cve_id": "CVE-2014-9222", "vendor": "multi", "product": "rom0", "affected_versions": "Allegro RomPager < 4.34", "description": "Misfortune Cookie — RCE via HTTP cookie overflow in embedded devices", "cvss_score": 9.8, "access_vector": "REMOTE"},
    # --- Physical-only examples (not remotely exploitable) ---
    {"cve_id": "CVE-2020-27301", "vendor": "cisco", "product": "jabber", "affected_versions": "Jabber for Windows", "description": "DLL hijacking (requires local access)", "cvss_score": 7.8, "access_vector": "LOCAL"},
    {"cve_id": "CVE-2018-0150", "vendor": "cisco", "product": "ios_xe", "affected_versions": "IOS XE with hardcoded credentials", "description": "Hardcoded root credentials (console/physical access)", "cvss_score": 9.8, "access_vector": "PHYSICAL"},
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
    # Bulk indices (tg12, ExploitDB mirrors) stay in JSON for tooling — not loaded into lookup RAM.
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
