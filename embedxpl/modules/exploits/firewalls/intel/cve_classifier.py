"""
firewallxpl/modules/intel/cve_classifier.py - CVE Intelligence Classifier.

Classifies CVE entries by category (CWE type, product type, attack vector)
to help prioritize which exploit modules to run against a given target.

Native Python reimplementation from:
  submodules/Safelabs-Harpia/agent-usecase/domain/utils/cve_intelligence.py

Used for:
  - Prioritizing cred modules (auth_bypass CVEs first)
  - Filtering OT-relevant CVEs
  - Scoring attack surface by target fingerprint

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# CWE category mapping (adapted from Harpia agent-usecase)
# ---------------------------------------------------------------------------

CWE_CATEGORIES: Dict[str, List[str]] = {
    "injection": ["CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-611"],
    "auth_bypass": ["CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-303", "CWE-306", "CWE-307", "CWE-384"],
    "memory_corruption": ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-787"],
    "path_traversal": ["CWE-22", "CWE-23", "CWE-24", "CWE-25"],
    "insecure_deserialization": ["CWE-502"],
    "info_disclosure": ["CWE-200", "CWE-201", "CWE-209", "CWE-532"],
    "privilege_escalation": ["CWE-269", "CWE-272", "CWE-284"],
    "hardcoded_credentials": ["CWE-259", "CWE-798"],
    "default_credentials": ["CWE-1392", "CWE-1188"],
    "rce": ["CWE-94", "CWE-77", "CWE-78", "CWE-502", "CWE-470"],
    "dos": ["CWE-400", "CWE-770", "CWE-404", "CWE-772"],
}

# Product category mapping
PRODUCT_CATEGORIES: Dict[str, List[str]] = {
    "network_device": ["router", "switch", "firewall", "vpn", "gateway", "access point", "routeros"],
    "iot": ["camera", "nvr", "dvr", "thermostat", "sensor", "iot", "embedded", "firmware"],
    "ics_ot": ["plc", "scada", "hmi", "rtu", "dcs", "modbus", "s7", "profinet", "iec"],
    "web_server": ["apache", "nginx", "iis", "tomcat", "web application"],
    "printer": ["printer", "mfp", "cups", "jetdirect", "ipp", "pjl"],
    "vpn": ["vpn", "ssl vpn", "ipsec", "openvpn", "wireguard"],
    "firewall": ["firewall", "ngfw", "utm", "fortigate", "checkpoint", "palo alto", "asa"],
}

# CVSS vector components
CVSS_ATTACK_VECTORS = {
    "AV:N": "NETWORK",
    "AV:A": "ADJACENT_NETWORK",
    "AV:L": "LOCAL",
    "AV:P": "PHYSICAL",
}

CVSS_COMPLEXITY = {
    "AC:L": "LOW",
    "AC:H": "HIGH",
    "AC:M": "MEDIUM",
}

CVSS_PRIVILEGES = {
    "PR:N": "NONE",
    "PR:L": "LOW",
    "PR:H": "HIGH",
    "Au:N": "NONE",
    "Au:S": "SINGLE",
    "Au:M": "MULTIPLE",
}


@dataclass
class CveClassification:
    """CVE classification result."""
    cve_id: str
    cwe_categories: List[str] = field(default_factory=list)
    product_categories: List[str] = field(default_factory=list)
    attack_vector: str = "UNKNOWN"
    attack_complexity: str = "UNKNOWN"
    privileges_required: str = "UNKNOWN"
    is_network_exploitable: bool = False
    is_low_complexity: bool = False
    is_no_auth: bool = False
    priority_score: float = 0.0
    tags: List[str] = field(default_factory=list)


def categorize_cwe(cwe_id: str) -> List[str]:
    """Return category names for a given CWE ID."""
    categories = []
    for cat, cwes in CWE_CATEGORIES.items():
        if cwe_id in cwes:
            categories.append(cat)
    return categories


def categorize_products(description: str) -> List[str]:
    """Return product categories based on CVE description keywords."""
    desc_lower = description.lower()
    categories = []
    for cat, keywords in PRODUCT_CATEGORIES.items():
        if any(kw in desc_lower for kw in keywords):
            categories.append(cat)
    return categories


def extract_attack_vectors(cvss_vector: str) -> Dict[str, str]:
    """Parse CVSS v2/v3 vector string and extract attack properties.

    Args:
        cvss_vector: e.g. "AV:N/AC:L/Au:N/C:C/I:C/A:C" or
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    Returns:
        dict with access, complexity, privileges keys.
    """
    result = {"access": "UNKNOWN", "complexity": "UNKNOWN", "privileges": "UNKNOWN"}
    for comp, val in CVSS_ATTACK_VECTORS.items():
        if comp in cvss_vector:
            result["access"] = val
    for comp, val in CVSS_COMPLEXITY.items():
        if comp in cvss_vector:
            result["complexity"] = val
    for comp, val in CVSS_PRIVILEGES.items():
        if comp in cvss_vector:
            result["privileges"] = val
    return result


def classify_cve(
    cve_id: str,
    cwe_ids: Optional[List[str]] = None,
    description: str = "",
    cvss_vector: str = "",
    cvss_score: float = 0.0,
) -> CveClassification:
    """Classify a CVE entry and compute a priority score.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-12345").
        cwe_ids: List of CWE IDs associated with this CVE.
        description: CVE description text.
        cvss_vector: CVSS vector string.
        cvss_score: CVSS numerical score (0-10).

    Returns:
        CveClassification with categories and priority score.
    """
    cwe_cats: List[str] = []
    if cwe_ids:
        for cwe in cwe_ids:
            cwe_cats.extend(categorize_cwe(cwe))
    cwe_cats = list(set(cwe_cats))

    prod_cats = categorize_products(description) if description else []

    vectors = extract_attack_vectors(cvss_vector)
    is_network = vectors["access"] == "NETWORK"
    is_low = vectors["complexity"] in ("LOW", "MEDIUM")
    is_no_auth = vectors["privileges"] in ("NONE", "SINGLE")

    # Priority score: CVSS + bonuses for critical properties
    score = cvss_score
    if is_network:
        score += 1.0
    if is_low:
        score += 0.5
    if is_no_auth:
        score += 0.5
    if "auth_bypass" in cwe_cats or "hardcoded_credentials" in cwe_cats:
        score += 2.0
    if "rce" in cwe_cats or "injection" in cwe_cats:
        score += 1.5

    tags = []
    if "auth_bypass" in cwe_cats or "default_credentials" in cwe_cats:
        tags.append("try-creds-first")
    if "hardcoded_credentials" in cwe_cats:
        tags.append("hardcoded-creds")
    if "rce" in cwe_cats:
        tags.append("rce-potential")
    if "ics_ot" in prod_cats:
        tags.append("ot-target")
    if "network_device" in prod_cats:
        tags.append("network-device")

    return CveClassification(
        cve_id=cve_id,
        cwe_categories=cwe_cats,
        product_categories=prod_cats,
        attack_vector=vectors["access"],
        attack_complexity=vectors["complexity"],
        privileges_required=vectors["privileges"],
        is_network_exploitable=is_network,
        is_low_complexity=is_low,
        is_no_auth=is_no_auth,
        priority_score=min(score, 12.0),  # cap at 12
        tags=tags,
    )


def prioritize_modules(
    target_product: str,
    cve_catalog: List[Dict[str, Any]],
) -> List[Tuple[str, float]]:
    """Suggest XPL modules to try first based on CVE catalog and target product.

    Args:
        target_product: Product string from banner/fingerprint.
        cve_catalog: List of CVE dicts from cve_extended_catalog.json.

    Returns:
        List of (module_path, priority_score) tuples, sorted by priority.
    """
    product_lower = target_product.lower()
    scored: List[Tuple[str, float]] = []

    for entry in cve_catalog:
        description = entry.get("description", "")
        devices = entry.get("devices", [])
        modules = entry.get("modules", [])
        cvss = float(entry.get("cvss", 5.0))
        cwe_ids = [entry.get("cwe", "")] if entry.get("cwe") else []

        # Check if this CVE is relevant to the target
        relevant = False
        if any(product_lower in str(d).lower() for d in devices):
            relevant = True
        if not relevant and description:
            for kw in product_lower.split()[:3]:
                if len(kw) > 3 and kw in description.lower():
                    relevant = True
                    break

        if not relevant:
            continue

        classification = classify_cve(
            cve_id=entry.get("cve_id", ""),
            cwe_ids=cwe_ids,
            description=description,
            cvss_vector=entry.get("cvss_vector", ""),
            cvss_score=cvss,
        )

        for module in modules:
            scored.append((module, classification.priority_score))

    # Sort descending by score, deduplicate
    seen = set()
    result = []
    for module, score in sorted(scored, key=lambda t: -t[1]):
        if module not in seen:
            seen.add(module)
            result.append((module, score))

    return result
