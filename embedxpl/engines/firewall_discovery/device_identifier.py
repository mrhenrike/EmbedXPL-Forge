"""Device identification — matches scan results against FXF appliance catalog.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("firewallxpl.discovery.device_identifier")


@dataclass
class DeviceIdentification:
    """Result of device identification."""
    vendor: str = ""
    product: str = ""
    model: Optional[str] = None
    version: Optional[str] = None
    device_class: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    method: str = "heuristic"


SIGNATURES = [
    {"vendor": "fortinet", "product": "fortigate", "class": "perimeter",
     "indicators": ["fortios", "fortigate", "fgt_lang", "fortinet", "FortiWeb"]},
    {"vendor": "cisco", "product": "asa", "class": "perimeter",
     "indicators": ["cisco", "adaptive security", "webvpn", "asdm", "anyconnect"]},
    {"vendor": "paloalto", "product": "pan-os", "class": "perimeter",
     "indicators": ["palo alto", "pan-os", "globalprotect"]},
    {"vendor": "f5", "product": "bigip", "class": "lb",
     "indicators": ["big-ip", "bigip", "f5", "tmui"]},
    {"vendor": "citrix", "product": "netscaler", "class": "vpn",
     "indicators": ["citrix", "netscaler", "ns-root"]},
    {"vendor": "checkpoint", "product": "gaia", "class": "perimeter",
     "indicators": ["check point", "gaia", "cpuse"]},
    {"vendor": "juniper", "product": "junos", "class": "perimeter",
     "indicators": ["juniper", "junos", "j-web"]},
    {"vendor": "sonicwall", "product": "sonicos", "class": "perimeter",
     "indicators": ["sonicwall", "sonicos"]},
    {"vendor": "sophos", "product": "sfos", "class": "perimeter",
     "indicators": ["sophos", "sfos", "cyberoam"]},
    {"vendor": "watchguard", "product": "fireware", "class": "perimeter",
     "indicators": ["watchguard", "fireware"]},
    {"vendor": "zyxel", "product": "usg", "class": "perimeter",
     "indicators": ["zyxel", "zywall", "usg"]},
    {"vendor": "pfsense", "product": "pfsense", "class": "perimeter",
     "indicators": ["pfsense", "netgate"]},
    {"vendor": "barracuda", "product": "esg", "class": "waf",
     "indicators": ["barracuda"]},
    {"vendor": "imperva", "product": "securesphere", "class": "waf",
     "indicators": ["imperva", "securesphere"]},
    {"vendor": "aruba", "product": "clearpass", "class": "nac",
     "indicators": ["clearpass", "aruba"]},
    {"vendor": "pulse", "product": "connect-secure", "class": "vpn",
     "indicators": ["pulse secure", "pulse connect", "dana-na", "ivanti"]},
    # OT/ICS industrial firewalls
    {"vendor": "siemens", "product": "scalance", "class": "perimeter",
     "indicators": ["scalance", "siemens", "sinema", "ruggedcom"]},
    {"vendor": "hirschmann", "product": "eagle", "class": "perimeter",
     "indicators": ["hirschmann", "eagle", "belden"]},
    {"vendor": "phoenix", "product": "mguard", "class": "perimeter",
     "indicators": ["phoenix contact", "mguard", "fl mguard"]},
    {"vendor": "moxa", "product": "edr", "class": "perimeter",
     "indicators": ["moxa", "edr-g", "eds-"]},
    {"vendor": "schneider", "product": "connexium", "class": "perimeter",
     "indicators": ["schneider", "connexium", "tofino"]},
    {"vendor": "secomea", "product": "gatemanager", "class": "vpn",
     "indicators": ["secomea", "gatemanager", "sitemanager"]},
    {"vendor": "ewon", "product": "cosy", "class": "vpn",
     "indicators": ["ewon", "hms", "cosy", "flexy"]},
]


class DeviceIdentifier:
    """Matches scan fingerprints against FXF's supported device catalog."""

    def identify(self, host: Any) -> Optional[DeviceIdentification]:
        """Identify a discovered host against the FXF catalog."""
        evidence_text = self._collect_evidence(host)
        if not evidence_text:
            return None

        lower = evidence_text.lower()
        best: Optional[DeviceIdentification] = None
        best_score = 0.0

        for sig in SIGNATURES:
            matching = [ind for ind in sig["indicators"] if ind in lower]
            if matching:
                score = min(0.3 + 0.2 * len(matching), 0.95)
                if score > best_score:
                    best_score = score
                    best = DeviceIdentification(
                        vendor=sig["vendor"],
                        product=sig["product"],
                        device_class=sig["class"],
                        confidence=score,
                        evidence=[f"matched: {m}" for m in matching],
                        method="signature",
                    )
        return best

    @staticmethod
    def _collect_evidence(host: Any) -> str:
        """Aggregate all evidence strings from a discovered host."""
        parts = []
        if hasattr(host, "open_ports"):
            for port_info in host.open_ports:
                if isinstance(port_info, dict):
                    parts.append(port_info.get("product", ""))
                    parts.append(port_info.get("version", ""))
                    parts.append(port_info.get("banner", ""))
                    parts.append(port_info.get("extrainfo", ""))
        if hasattr(host, "mac_vendor") and host.mac_vendor:
            parts.append(host.mac_vendor)
        if hasattr(host, "hostname") and host.hostname:
            parts.append(host.hostname)
        return " ".join(p for p in parts if p)
