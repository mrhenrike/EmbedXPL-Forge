"""
CVE Catalog Loader — PrinterXPL-Forge
Loads the local cve_catalog.json for offline lookup; falls back to NVD API for unknown CVEs.

Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from typing import Optional

_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "cve_catalog.json")
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
_catalog: Optional[dict] = None


def _load_catalog() -> dict:
    global _catalog
    if _catalog is None:
        try:
            with open(os.path.realpath(_CATALOG_PATH), encoding="utf-8") as f:
                _catalog = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _catalog = {"cves": []}
    return _catalog


def get_all() -> list[dict]:
    """Return all CVE entries from the local catalog."""
    return _load_catalog().get("cves", [])


def lookup(cve_id: str) -> Optional[dict]:
    """
    Look up a CVE by ID (e.g. 'CVE-2024-47176').
    Returns local catalog entry if found, else queries NVD API.
    """
    cve_id = cve_id.upper().strip()
    for entry in get_all():
        if entry.get("id", "").upper() == cve_id:
            return entry
    return _nvd_lookup(cve_id)


def search(query: str, fields: Optional[list[str]] = None) -> list[dict]:
    """
    Full-text search across CVE entries.
    Optionally restrict search to specific fields (e.g. ['vendor', 'product']).
    """
    q = query.lower()
    results = []
    search_fields = fields or ["id", "vendor", "product", "description", "attack_type", "protocol"]
    for entry in get_all():
        for field in search_fields:
            val = str(entry.get(field, "")).lower()
            if q in val:
                results.append(entry)
                break
    return results


def filter_by(
    vendor: Optional[str] = None,
    attack_type: Optional[str] = None,
    protocol: Optional[str] = None,
    min_cvss: float = 0.0,
    port: Optional[int] = None,
    poc_only: bool = False,
) -> list[dict]:
    """Filter CVE catalog by vendor, attack type, protocol, CVSS score, port, or PoC availability."""
    results = []
    for entry in get_all():
        if vendor and vendor.lower() not in entry.get("vendor", "").lower():
            continue
        if attack_type and attack_type.lower() not in entry.get("attack_type", "").lower():
            continue
        if protocol and protocol.lower() not in entry.get("protocol", "").lower():
            continue
        if entry.get("cvss", 0.0) < min_cvss:
            continue
        if port is not None and entry.get("port") != port:
            continue
        if poc_only and not entry.get("poc_available", False):
            continue
        results.append(entry)
    return results


def get_by_xpl_module(module_path: str) -> list[dict]:
    """Return all CVEs that have a specific xpl module assigned."""
    return [e for e in get_all() if e.get("xpl_module") == module_path]


def catalog_summary() -> dict:
    """Return a summary of catalog statistics."""
    cves = get_all()
    vendors: dict[str, int] = {}
    attack_types: dict[str, int] = {}
    for e in cves:
        v = e.get("vendor", "Unknown").split("/")[0].strip()
        vendors[v] = vendors.get(v, 0) + 1
        a = e.get("attack_type", "Unknown").split("/")[0].strip()
        attack_types[a] = attack_types.get(a, 0) + 1
    return {
        "total": len(cves),
        "vendors": vendors,
        "attack_types": attack_types,
        "with_poc": sum(1 for e in cves if e.get("poc_available")),
        "with_xpl_module": sum(1 for e in cves if e.get("xpl_module")),
        "with_msf_module": sum(1 for e in cves if e.get("msf_module")),
    }


def _nvd_lookup(cve_id: str) -> Optional[dict]:
    """Query the NVD API for a CVE not in the local catalog."""
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id, re.I):
        return None
    try:
        url = _NVD_API.format(cve_id)
        req = urllib.request.Request(url, headers={"User-Agent": "PrinterXPL-Forge/4.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.load(resp)
        items = data.get("vulnerabilities", [])
        if not items:
            return None
        nvd = items[0].get("cve", {})
        desc = ""
        for d in nvd.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = nvd.get("metrics", {})
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                break
        return {
            "id": cve_id,
            "vendor": "Unknown (NVD)",
            "product": "Unknown",
            "attack_type": "Unknown",
            "protocol": "Unknown",
            "cvss": cvss,
            "year": int(cve_id.split("-")[1]),
            "description": desc,
            "poc_available": False,
            "xpl_module": None,
            "msf_module": None,
            "source": "nvd_api",
        }
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, ValueError):
        return None
