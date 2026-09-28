"""ICS Scan Import Normalizer — parse Nmap XML output into IcsFinding records.

Parses Nmap XML without requiring Nmap or python-nmap at runtime.
Ported and adapted from Gridwolf backend scanner_parsers.py (SafeLabs).

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IcsFinding:
    """Normalised finding produced from an ICS network scan."""

    host: str
    port: int
    service: str
    protocol: str
    severity: str
    cve_ids: list[str] = field(default_factory=list)
    banner: str = ""
    product: str = ""
    version: str = ""
    extra: dict = field(default_factory=dict)

    # Map Nmap state to a conservative severity baseline.
    _PORT_STATE_SEVERITY: dict[str, str] = field(
        default_factory=lambda: {
            "open": "medium",
            "open|filtered": "low",
            "filtered": "info",
            "closed": "info",
        },
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        # Promote industrial protocol ports to higher baseline severity.
        _HIGH_RISK_PORTS = {102, 502, 2222, 4840, 20000, 44818, 47808, 9600}
        if self.port in _HIGH_RISK_PORTS and self.severity == "medium":
            self.severity = "high"


class ScanImportNormalizer:
    """Normalise external scanner output to :class:`IcsFinding` records.

    Designed to parse output files only — no runtime scanner dependency.
    """

    # Known ICS/OT service names per port, used when Nmap detection is absent.
    _ICS_SERVICE_MAP: dict[int, tuple[str, str]] = {
        20000: ("dnp3", "DNP3"),
        102: ("s7comm", "Siemens S7/ISO-TSAP"),
        502: ("modbus", "Modbus/TCP"),
        2222: ("eip", "EtherNet/IP"),
        44818: ("eip", "EtherNet/IP (UDP discovery)"),
        4840: ("opcua", "OPC UA"),
        47808: ("bacnet", "BACnet/IP"),
        9600: ("fins", "OMRON FINS"),
        1962: ("pcworx", "PCWorx"),
        789: ("red-lion", "Red Lion Controls"),
        18245: ("ge-srtp", "GE SRTP"),
        20547: ("proconos", "ProConOS"),
    }

    @staticmethod
    def from_nmap_xml(xml_path: str | Path) -> list[IcsFinding]:
        """Parse a Nmap XML output file and return a list of :class:`IcsFinding`.

        Args:
            xml_path: Path to a Nmap XML output file (``nmap -oX``).

        Returns:
            Ordered list of normalised findings, one per open port per host.

        Raises:
            FileNotFoundError: If the XML path does not exist.
            ValueError: If the file cannot be parsed as valid Nmap XML.
        """
        path = Path(xml_path)
        if not path.exists():
            raise FileNotFoundError("Nmap XML not found: {}".format(path))

        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            raise ValueError("Cannot parse Nmap XML at {}: {}".format(path, exc)) from exc

        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ValueError(
                "Not a Nmap XML file (root tag is {!r}, expected 'nmaprun')".format(root.tag)
            )

        findings: list[IcsFinding] = []
        for host_el in root.findall("host"):
            host_addr = ScanImportNormalizer._extract_host(host_el)
            if not host_addr:
                continue

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                finding = ScanImportNormalizer._parse_port_element(host_addr, port_el)
                if finding is not None:
                    findings.append(finding)

        logger.debug("Parsed %d findings from %s", len(findings), path)
        return findings

    @staticmethod
    def normalize_finding(raw: dict) -> IcsFinding:
        """Convert a raw finding dict (any format) to :class:`IcsFinding`.

        Accepts the dict schema used by Gridwolf scanner_parsers output:
        ``{title, severity, status, properties: {source, host, port, ...}}``
        as well as a flat dict with host/port keys.

        Args:
            raw: Arbitrary dict describing a scan finding.

        Returns:
            Normalised :class:`IcsFinding`.
        """
        props = raw.get("properties", raw)

        host = str(props.get("host", props.get("ip", props.get("address", ""))))
        try:
            port = int(props.get("port", 0))
        except (TypeError, ValueError):
            port = 0

        service = str(props.get("service", props.get("service_name", "unknown")))
        protocol = str(props.get("protocol", "tcp")).lower()

        severity = str(
            props.get("severity", raw.get("severity", "info"))
        ).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"

        cve_raw = props.get("cve_ids", props.get("cves", props.get("cve", [])))
        if isinstance(cve_raw, str):
            cve_ids = [c.strip() for c in cve_raw.split(",") if c.strip()]
        elif isinstance(cve_raw, list):
            cve_ids = [str(c) for c in cve_raw if c]
        else:
            cve_ids = []

        return IcsFinding(
            host=host,
            port=port,
            service=service,
            protocol=protocol,
            severity=severity,
            cve_ids=cve_ids,
            banner=str(props.get("banner", "")),
            product=str(props.get("product", "")),
            version=str(props.get("version", "")),
            extra={
                k: v
                for k, v in props.items()
                if k
                not in (
                    "host",
                    "ip",
                    "address",
                    "port",
                    "service",
                    "service_name",
                    "protocol",
                    "severity",
                    "cve_ids",
                    "cves",
                    "cve",
                    "banner",
                    "product",
                    "version",
                )
            },
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(host_el: ET.Element) -> Optional[str]:
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                return addr.get("addr")
        return None

    @staticmethod
    def _parse_port_element(host: str, port_el: ET.Element) -> Optional[IcsFinding]:
        state_el = port_el.find("state")
        if state_el is None:
            return None

        state = state_el.get("state", "unknown")
        if state not in ("open", "open|filtered"):
            return None

        try:
            port_num = int(port_el.get("portid", 0))
        except (TypeError, ValueError):
            port_num = 0

        protocol = (port_el.get("protocol") or "tcp").lower()

        service_el = port_el.find("service")
        if service_el is not None:
            service_name = service_el.get("name", "unknown")
            product = service_el.get("product", "")
            version = service_el.get("version", "")
            extra_info = service_el.get("extrainfo", "")
        else:
            # Fall back to well-known ICS port map.
            svc_info = ScanImportNormalizer._ICS_SERVICE_MAP.get(port_num)
            service_name = svc_info[0] if svc_info else "unknown"
            product = svc_info[1] if svc_info else ""
            version = ""
            extra_info = ""

        # Collect CVE IDs from Nmap script output (vuln scripts emit <elem key="ids">).
        cve_ids: list[str] = []
        for script_el in port_el.findall("script"):
            for elem in script_el.findall("elem"):
                key = elem.get("key", "")
                if key in ("ids", "cve", "CVE"):
                    raw_ids = elem.text or ""
                    for token in raw_ids.replace(",", " ").split():
                        token = token.strip()
                        if token.upper().startswith("CVE-"):
                            cve_ids.append(token.upper())

        # Derive baseline severity from port state + ICS context.
        _HIGH_RISK = {102, 502, 2222, 4840, 20000, 44818, 47808, 9600}
        if port_num in _HIGH_RISK:
            severity = "high"
        elif state == "open":
            severity = "medium"
        else:
            severity = "low"

        return IcsFinding(
            host=host,
            port=port_num,
            service=service_name,
            protocol=protocol,
            severity=severity,
            cve_ids=cve_ids,
            banner=extra_info,
            product=product,
            version=version,
        )
