"""Traffic enforcement device scanner and fingerprinter.

Discovers and fingerprints Kapsch RSU, Motorola Vigilant LPR,
Selea ANPR, and other traffic enforcement systems.

PREREQ: Network access to device management interfaces.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import socket
import ssl
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Optional, Dict
import ipaddress


@dataclass
class TrafficDevice:
    """Represents a discovered traffic enforcement device.

    Attributes:
        ip: Device IP address.
        vendor: Detected vendor name.
        model: Detected model (if available).
        open_ports: List of open TCP ports.
        banner: HTTP/SSH banner if captured.
        cves: List of applicable CVE identifiers.
        notes: Additional security notes.
    """

    ip: str
    vendor: str = "Unknown"
    model: str = ""
    open_ports: List[int] = field(default_factory=list)
    banner: str = ""
    cves: List[str] = field(default_factory=list)
    notes: str = ""


# Known fingerprints for traffic enforcement devices
FINGERPRINTS: Dict[str, Dict] = {
    "Kapsch": {
        "ports": [80, 443, 22, 8080, 8443],
        "http_patterns": ["kapsch", "roadisys", "its-rsu", "trafficom"],
        "cves": ["CVE-2025-25734", "CVE-2025-25735", "CVE-2025-25736"],
        "default_ports": [443, 8443],
    },
    "Motorola_Vigilant": {
        "ports": [80, 443, 22, 3389, 8080],
        "http_patterns": ["vigilant", "motorola", "lpr", "license plate"],
        "cves": ["CVE-2024-51023", "CVE-2024-51024"],
        "default_ports": [80, 443],
    },
    "Selea": {
        "ports": [80, 443, 22, 8080, 554],
        "http_patterns": ["selea", "targa", "anpr", "ocr"],
        "cves": ["CVE-2025-28934"],
        "default_ports": [80, 443],
    },
    "Jenoptik": {
        "ports": [80, 443, 22, 21],
        "http_patterns": ["jenoptik", "traffipax", "robot"],
        "cves": [],
        "default_ports": [80, 443],
    },
    "Vitronic": {
        "ports": [80, 443, 22, 8080],
        "http_patterns": ["vitronic", "poliscan", "enforcement"],
        "cves": [],
        "default_ports": [80, 443],
    },
}

TRAFFIC_DEFAULT_PORTS = [21, 22, 23, 80, 443, 554, 3389, 8080, 8443, 9000]


class TrafficEnforcementScanner:
    """Scanner for traffic enforcement systems.

    Discovers RSU, LPR, ANPR, and speed camera devices
    on the specified network range.

    Attributes:
        __info__: Module metadata.
    """

    __info__ = {
        "name": "Traffic Enforcement Device Scanner",
        "category": "vehicular_radar",
        "type": "scanner",
        "protocols": ["HTTP", "HTTPS", "SSH", "FTP", "RTSP"],
        "auth_required": False,
        "hw_req": ["Network access to target subnet"],
        "targets": [
            "Kapsch TrafficCom RSU",
            "Motorola Vigilant LPR cameras",
            "Selea Targa ANPR cameras",
            "Jenoptik TraffiCam",
            "Vitronic PoliScan",
        ],
    }

    def __init__(
        self,
        target_cidr: str = "192.168.1.0/24",
        timeout: float = 2.0,
        max_workers: int = 50,
    ) -> None:
        """Initialize scanner.

        Args:
            target_cidr: Target network CIDR or single IP.
            timeout: TCP connection timeout in seconds.
            max_workers: Max concurrent scan threads.
        """
        self.target_cidr = target_cidr
        self.timeout = timeout
        self.max_workers = max_workers

    def _check_port(self, ip: str, port: int) -> bool:
        """Check if a TCP port is open.

        Args:
            ip: Target IP address.
            port: TCP port number.

        Returns:
            True if port is open.
        """
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (OSError, ConnectionRefusedError):
            return False

    def _get_http_banner(self, ip: str, port: int, use_ssl: bool = False) -> str:
        """Fetch HTTP response to identify device.

        Args:
            ip: Target IP.
            port: HTTP port.
            use_ssl: Use HTTPS.

        Returns:
            Response text (first 500 chars) or empty string.
        """
        try:
            proto = "https" if use_ssl else "http"
            import urllib.request
            import urllib.error

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(
                f"{proto}://{ip}:{port}/",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            handler = (
                urllib.request.HTTPSHandler(context=ctx)
                if use_ssl
                else urllib.request.HTTPHandler()
            )
            opener = urllib.request.build_opener(handler)
            with opener.open(req, timeout=self.timeout) as resp:
                return resp.read(500).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _fingerprint_device(self, ip: str, open_ports: List[int]) -> TrafficDevice:
        """Fingerprint a device based on open ports and HTTP banners.

        Args:
            ip: Device IP address.
            open_ports: List of detected open ports.

        Returns:
            TrafficDevice with detected vendor and CVEs.
        """
        device = TrafficDevice(ip=ip, open_ports=open_ports)

        banner = ""
        for port in [80, 443, 8080, 8443]:
            if port in open_ports:
                use_ssl = port in [443, 8443]
                banner = self._get_http_banner(ip, port, use_ssl)
                if banner:
                    break

        device.banner = banner[:200]
        banner_lower = banner.lower()

        for vendor, info in FINGERPRINTS.items():
            if any(pat in banner_lower for pat in info["http_patterns"]):
                device.vendor = vendor
                device.cves = info["cves"]
                device.notes = f"Detected by HTTP banner match for {vendor}"
                break

        return device

    def scan(self) -> List[TrafficDevice]:
        """Scan target range for traffic enforcement devices.

        Returns:
            List of discovered TrafficDevice objects.
        """
        try:
            network = ipaddress.ip_network(self.target_cidr, strict=False)
            hosts = list(network.hosts())
        except ValueError:
            hosts = [ipaddress.ip_address(self.target_cidr)]

        discovered: List[TrafficDevice] = []

        def scan_host(ip_obj: ipaddress.IPv4Address) -> Optional[TrafficDevice]:
            ip = str(ip_obj)
            open_ports = []
            for port in TRAFFIC_DEFAULT_PORTS:
                if self._check_port(ip, port):
                    open_ports.append(port)
            if open_ports:
                return self._fingerprint_device(ip, open_ports)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(scan_host, host): host for host in hosts}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)

        return discovered

    def run(self) -> dict:
        """Run scan and return structured results dict.

        Returns:
            Dict with discovered device count and device detail list.
        """
        devices = self.scan()
        results = []
        for d in devices:
            results.append({
                "ip": d.ip,
                "vendor": d.vendor,
                "model": d.model,
                "open_ports": d.open_ports,
                "banner": d.banner[:100] if d.banner else "",
                "cves": d.cves,
                "notes": d.notes,
            })
        return {
            "target_cidr": self.target_cidr,
            "devices_found": len(results),
            "devices": results,
        }
