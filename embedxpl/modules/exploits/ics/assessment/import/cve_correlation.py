"""ICS CVE Correlator — match host profiles against a CVE catalog.

Ported from Gridwolf backend cve_lookup.py (SafeLabs), adapted for offline
use against the IXF resources CVE data.  No external API calls at runtime.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Bundled ICS CVE offline database (ported from Gridwolf cve_lookup.py).
_BUNDLED_CVE_DATABASE: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-38876",
        "description": "Siemens S7-1500 TLS Certificate Verification Bypass allows unauthenticated remote code execution",
        "cvss_score": 9.8,
        "severity": "critical",
        "vendor": "Siemens",
        "product": "S7-1500",
        "affected_versions": "< V3.1.0",
        "remediation": "Update firmware to V3.1.0 or later. Apply network segmentation.",
        "cwe": "CWE-295",
        "references": ["https://cert-portal.siemens.com/productcert/"],
    },
    {
        "cve_id": "CVE-2024-32015",
        "description": "Modbus TCP protocol lacks authentication allowing unauthorized read/write to PLC registers",
        "cvss_score": 8.6,
        "severity": "high",
        "vendor": "Multiple",
        "product": "Modbus TCP Devices",
        "affected_versions": "All Modbus TCP implementations",
        "remediation": "Implement Modbus/TCP security extensions or network segmentation",
        "cwe": "CWE-306",
        "references": [],
    },
    {
        "cve_id": "CVE-2024-29104",
        "description": "Hardcoded credentials in HMI web interface allow complete device takeover",
        "cvss_score": 9.1,
        "severity": "critical",
        "vendor": "Schneider Electric",
        "product": "Magelis HMI",
        "affected_versions": "< V4.0.2",
        "remediation": "Update to V4.0.2. Change default credentials immediately.",
        "cwe": "CWE-798",
        "references": [],
    },
    {
        "cve_id": "CVE-2024-41203",
        "description": "Buffer overflow in DNP3 stack allows remote code execution on RTU firmware",
        "cvss_score": 7.5,
        "severity": "high",
        "vendor": "GE Digital",
        "product": "D20 RTU",
        "affected_versions": "< V7.20.1",
        "remediation": "Apply firmware patch V7.20.1",
        "cwe": "CWE-120",
        "references": [],
    },
    {
        "cve_id": "CVE-2024-35587",
        "description": "Insecure deserialization in OPC UA historian allows arbitrary code execution",
        "cvss_score": 8.1,
        "severity": "high",
        "vendor": "OSIsoft",
        "product": "PI Server",
        "affected_versions": "< 2024",
        "remediation": "Update to PI Server 2024. Restrict network access to historian.",
        "cwe": "CWE-502",
        "references": [],
    },
    {
        "cve_id": "CVE-2023-46280",
        "description": "Rockwell Automation ControlLogix improper input validation allows firmware manipulation",
        "cvss_score": 9.8,
        "severity": "critical",
        "vendor": "Rockwell Automation",
        "product": "ControlLogix 1756",
        "affected_versions": "< V33.016",
        "remediation": "Apply patch V33.016. Restrict CIP access with firewall rules.",
        "cwe": "CWE-20",
        "references": [],
    },
    {
        "cve_id": "CVE-2023-6408",
        "description": "Schneider Electric Modicon M340 allows unauthenticated Modbus writes to safety registers",
        "cvss_score": 9.1,
        "severity": "critical",
        "vendor": "Schneider Electric",
        "product": "Modicon M340",
        "affected_versions": "All versions",
        "remediation": "Implement Modbus TCP firewall rules. Enable access control lists.",
        "cwe": "CWE-306",
        "references": [],
    },
    {
        "cve_id": "CVE-2024-22039",
        "description": "Siemens SINEMA Remote Connect Server path traversal allows file read/write",
        "cvss_score": 7.2,
        "severity": "high",
        "vendor": "Siemens",
        "product": "SINEMA Remote Connect",
        "affected_versions": "< V3.2",
        "remediation": "Update to V3.2. Restrict management interface access.",
        "cwe": "CWE-22",
        "references": [],
    },
    {
        "cve_id": "CVE-2023-3595",
        "description": "Rockwell Automation EtherNet/IP stack vulnerability enables RCE via crafted CIP messages",
        "cvss_score": 9.8,
        "severity": "critical",
        "vendor": "Rockwell Automation",
        "product": "ControlLogix/GuardLogix",
        "affected_versions": "< V33.013",
        "remediation": "Apply patch immediately. Block CIP from untrusted networks.",
        "cwe": "CWE-787",
        "references": [],
    },
    {
        "cve_id": "CVE-2023-28489",
        "description": "ABB ASPECT BMS XSS and SSRF allowing unauthorized building management control",
        "cvss_score": 7.4,
        "severity": "high",
        "vendor": "ABB",
        "product": "ASPECT BMS",
        "affected_versions": "< 3.08.01",
        "remediation": "Update firmware. Restrict web interface access.",
        "cwe": "CWE-79",
        "references": [],
    },
    {
        "cve_id": "CVE-2017-6019",
        "description": "Schneider Electric Conext ComBox firmware prior to V3.03 BN 830 allows unauthenticated HTTP POST to cause device reboot (denial of service)",
        "cvss_score": 7.5,
        "severity": "high",
        "vendor": "Schneider Electric",
        "product": "Conext ComBox",
        "affected_versions": "< V3.03 BN 830",
        "remediation": "Update firmware to V3.03 BN 830 or later. Restrict HTTP management access.",
        "cwe": "CWE-306",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-6019",
            "https://ics-cert.us-cert.gov/advisories/ICSA-17-061-01",
        ],
    },
    {
        "cve_id": "CVE-2024-3400",
        "description": "Fortinet FortiGate firewall command injection in SSL-VPN (commonly used in OT DMZ)",
        "cvss_score": 9.8,
        "severity": "critical",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "affected_versions": "6.x - 7.4.2",
        "remediation": "Upgrade FortiOS immediately. Disable SSL-VPN if not needed.",
        "cwe": "CWE-78",
        "references": [],
    },
    {
        "cve_id": "CVE-2023-27357",
        "description": "Moxa EDR-G9010 industrial router allows unauthenticated command injection",
        "cvss_score": 8.8,
        "severity": "high",
        "vendor": "Moxa",
        "product": "EDR-G9010",
        "affected_versions": "< V3.0",
        "remediation": "Update firmware to V3.0+. Restrict management access.",
        "cwe": "CWE-78",
        "references": [],
    },
]

# Map well-known ICS service names to vendor/product hints for correlation.
_SERVICE_TO_VENDOR: dict[str, list[str]] = {
    "s7comm": ["Siemens"],
    "modbus": ["Schneider Electric", "Rockwell Automation", "Multiple"],
    "eip": ["Rockwell Automation"],
    "dnp3": ["GE Digital"],
    "opcua": ["OSIsoft"],
    "bacnet": ["Multiple"],
    "fins": ["OMRON"],
}


@dataclass
class Match:
    """A CVE match for a given host/service profile."""

    host: str
    port: int
    service: str
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    remediation: str
    cwe: str
    references: list[str] = field(default_factory=list)
    match_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "cve_id": self.cve_id,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "references": self.references,
            "match_reason": self.match_reason,
        }


class IcsCveCorrelator:
    """Correlate a host profile against an ICS CVE catalog.

    Uses the bundled CVE database by default.  An external JSON catalog can
    be loaded from ``cve_catalog_path`` to extend or override the built-in
    data.  The catalog must be a JSON array of objects with at minimum the
    keys: ``cve_id``, ``vendor``, ``product``, ``description``,
    ``cvss_score``, ``severity``.
    """

    def __init__(self, extra_catalog_path: Optional[str | Path] = None) -> None:
        self._catalog: list[dict[str, Any]] = list(_BUNDLED_CVE_DATABASE)
        if extra_catalog_path:
            self._load_catalog(Path(extra_catalog_path))

    def _load_catalog(self, path: Path) -> None:
        if not path.exists():
            logger.warning("CVE catalog not found: %s — using bundled data only", path)
            return
        try:
            with path.open(encoding="utf-8") as fh:
                records = json.load(fh)
            if not isinstance(records, list):
                logger.warning("CVE catalog at %s is not a JSON array — skipped", path)
                return
            self._catalog.extend(records)
            logger.debug("Loaded %d extra CVE records from %s", len(records), path)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to load CVE catalog %s: %s", path, exc)

    def correlate(
        self,
        host_profile: dict[str, Any],
        cve_catalog_path: Optional[str | Path] = None,
    ) -> list[Match]:
        """Match a host profile against the CVE catalog.

        Args:
            host_profile: Dict with keys such as ``host``, ``port``,
                ``service``, ``vendor``, ``product``, ``version``.
            cve_catalog_path: Optional path to an extra JSON CVE catalog to
                merge for this call (does not persist to the instance).

        Returns:
            List of :class:`Match` objects, highest CVSS score first.
        """
        catalog = list(self._catalog)
        if cve_catalog_path:
            extra_path = Path(cve_catalog_path)
            if extra_path.exists():
                try:
                    with extra_path.open(encoding="utf-8") as fh:
                        extra = json.load(fh)
                    if isinstance(extra, list):
                        catalog.extend(extra)
                except (OSError, json.JSONDecodeError) as exc:
                    logger.error("Cannot load extra catalog %s: %s", extra_path, exc)

        host = str(host_profile.get("host", ""))
        port = int(host_profile.get("port", 0))
        service = str(host_profile.get("service", "")).lower()
        vendor = str(host_profile.get("vendor", "")).lower()
        product = str(host_profile.get("product", "")).lower()
        explicit_cves: list[str] = [
            c.upper()
            for c in host_profile.get("cve_ids", host_profile.get("cves", []))
        ]

        matches: list[Match] = []
        seen_cves: set[str] = set()

        for cve in catalog:
            cve_id = str(cve.get("cve_id", ""))
            if cve_id in seen_cves:
                continue

            reason = self._match_reason(
                cve,
                vendor=vendor,
                product=product,
                service=service,
                explicit_cves=explicit_cves,
            )
            if reason is None:
                continue

            seen_cves.add(cve_id)
            matches.append(
                Match(
                    host=host,
                    port=port,
                    service=service,
                    cve_id=cve_id,
                    severity=str(cve.get("severity", "info")),
                    cvss_score=float(cve.get("cvss_score", 0.0)),
                    description=str(cve.get("description", "")),
                    remediation=str(cve.get("remediation", "")),
                    cwe=str(cve.get("cwe", "")),
                    references=list(cve.get("references", [])),
                    match_reason=reason,
                )
            )

        matches.sort(key=lambda m: m.cvss_score, reverse=True)
        return matches

    def correlate_findings(
        self,
        findings: list[Any],
        cve_catalog_path: Optional[str | Path] = None,
    ) -> list[Match]:
        """Correlate a list of :class:`IcsFinding` (or dicts) objects.

        Convenience wrapper that calls :meth:`correlate` for each finding and
        returns a flat, deduplicated, severity-sorted list.

        Args:
            findings: List of :class:`~scan_import_normalizer.IcsFinding` or
                dicts with at minimum ``host``, ``port``, ``service`` keys.
            cve_catalog_path: Optional extra CVE catalog path.

        Returns:
            Flat sorted list of :class:`Match` objects.
        """
        all_matches: list[Match] = []
        seen: set[tuple[str, int, str]] = set()

        for finding in findings:
            if hasattr(finding, "__dataclass_fields__"):
                profile = {
                    "host": finding.host,
                    "port": finding.port,
                    "service": finding.service,
                    "vendor": finding.product,
                    "product": finding.product,
                    "cve_ids": finding.cve_ids,
                }
            else:
                profile = dict(finding)

            for match in self.correlate(profile, cve_catalog_path):
                key = (match.host, match.port, match.cve_id)
                if key not in seen:
                    seen.add(key)
                    all_matches.append(match)

        all_matches.sort(key=lambda m: m.cvss_score, reverse=True)
        return all_matches

    # ── Private ──────────────────────────────────────────────────────────────

    @staticmethod
    def _match_reason(
        cve: dict[str, Any],
        vendor: str,
        product: str,
        service: str,
        explicit_cves: list[str],
    ) -> Optional[str]:
        """Return a human-readable match reason or None if no match."""
        cve_id = str(cve.get("cve_id", "")).upper()
        cve_vendor = str(cve.get("vendor", "")).lower()
        cve_product = str(cve.get("product", "")).lower()

        # Explicit CVE ID from scanner output.
        if explicit_cves and cve_id in explicit_cves:
            return "explicit CVE match from scanner output"

        # Vendor fuzzy match.
        if vendor and (vendor in cve_vendor or cve_vendor in vendor):
            return "vendor match: {!r} ~ {!r}".format(vendor, cve_vendor)

        # Product fuzzy match.
        if product and (product in cve_product or cve_product in product):
            return "product match: {!r} ~ {!r}".format(product, cve_product)

        # Service-to-vendor hint match.
        if service:
            vendor_hints = _SERVICE_TO_VENDOR.get(service, [])
            for hint in vendor_hints:
                hint_lower = hint.lower()
                if hint_lower in cve_vendor or cve_vendor in hint_lower:
                    return "service-to-vendor hint: service={!r} -> vendor={!r}".format(
                        service, hint
                    )

        return None
