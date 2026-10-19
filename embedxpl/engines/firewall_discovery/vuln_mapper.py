"""Vulnerability mapper — matches identified devices to applicable FXF modules.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, List, Optional

from firewallxpl.core.exploit.utils import index_modules, MODULES_DIR

logger = logging.getLogger("firewallxpl.discovery.vuln_mapper")


@dataclass
class ModuleMatch:
    """A module applicable to a discovered device."""
    module_path: str
    severity: str = "medium"
    cve_ids: List[str] = field(default_factory=list)


@dataclass
class VulnMapResult:
    """Vulnerability mapping result for a device."""
    applicable_exploits: List[ModuleMatch] = field(default_factory=list)
    applicable_creds: List[ModuleMatch] = field(default_factory=list)
    risk_score: float = 0.0
    recommendation: str = ""


class VulnMapper:
    """Maps identified devices to applicable FXF modules and CVEs."""

    def __init__(self) -> None:
        self._modules = index_modules(MODULES_DIR)

    def map(self, identification: Any) -> VulnMapResult:
        """Map a device identification to applicable modules."""
        if not identification or not identification.vendor:
            return VulnMapResult(recommendation="Device not identified")

        vendor = identification.vendor.lower()
        device_class = identification.device_class.lower()

        exploits = []
        creds = []

        for mod in self._modules:
            mod_lower = mod.lower()
            if mod.startswith("exploits."):
                if vendor in mod_lower or device_class in mod_lower:
                    cve_ids = self._extract_cves(mod)
                    severity = "critical" if cve_ids else "medium"
                    exploits.append(ModuleMatch(
                        module_path=mod, severity=severity, cve_ids=cve_ids
                    ))
            elif mod.startswith("creds."):
                if vendor in mod_lower or device_class in mod_lower or "generic" in mod_lower:
                    creds.append(ModuleMatch(module_path=mod))

        risk = min(len(exploits) * 1.5 + len(creds) * 0.5, 10.0)
        level = "CRITICAL" if risk >= 8 else "HIGH" if risk >= 5 else "MEDIUM" if risk >= 2 else "LOW"

        return VulnMapResult(
            applicable_exploits=exploits,
            applicable_creds=creds,
            risk_score=risk,
            recommendation=f"{level} — {len(exploits)} exploits, {len(creds)} cred checks for {vendor}/{identification.product}",
        )

    @staticmethod
    def _extract_cves(module_path: str) -> List[str]:
        """Extract CVE IDs from module path name."""
        import re
        return re.findall(r"cve_\d{4}_\d+", module_path)
