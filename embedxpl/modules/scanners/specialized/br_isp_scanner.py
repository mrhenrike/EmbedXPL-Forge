"""Brazilian ISP Device Scanner.

Fingerprints and identifies common ISP-deployed devices in Brazil:
Huawei HG8245, ZTE H108N/H267N/H298A, Intelbras IWR series,
TP-Link DSL, D-Link DSL, Fiberhome HG6245D.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
import concurrent.futures
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
import requests
from embedxpl.core.exploit import *


@dataclass
class DeviceFingerprint:
    """Fingerprint result for a single host."""

    ip: str
    port: int
    vendor: str = "Unknown"
    model: str = "Unknown"
    banner: str = ""
    server_header: str = ""
    open_ports: list[int] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


_FINGERPRINTS: list[dict[str, Any]] = [
    {
        "vendor": "Huawei",
        "models": ["HG8245", "HG8247"],
        "keywords": ["hg8245", "hg8247", "huawei", "epon", "gpon"],
        "default_creds": ("root", "admin"),
        "check_paths": ["/", "/html/index.asp"],
        "vulns": ["CVE-2013-2573 (if TP-Link)", "Default credentials exposure"],
    },
    {
        "vendor": "ZTE",
        "models": ["H108N", "H267N", "H268N", "H298A", "ZXDSL"],
        "keywords": ["zte", "h108n", "h267n", "h268n", "h298a", "zxhn", "zxdsl"],
        "default_creds": ("admin", "admin"),
        "check_paths": ["/", "/getpage.lua?pid=1000&ETHCheat=1"],
        "vulns": ["CVE-2026-34473 (DoS)", "CVE-2026-34474 (Cred Dump)"],
    },
    {
        "vendor": "Intelbras",
        "models": ["IWR 3000N", "IWR 5000N", "WRN240", "RF 301K"],
        "keywords": ["intelbras", "iwr", "wrn", "intelbrás"],
        "default_creds": ("admin", "admin"),
        "check_paths": ["/", "/cgi-bin/luci/rpc/sys"],
        "vulns": ["CVE-2021-22161 (LUCI RPC RCE)", "CVE-2021-32403 (DNS Hijack CSRF)"],
    },
    {
        "vendor": "TP-Link",
        "models": ["TD-W8968", "TD-W8970", "TL-WR841N"],
        "keywords": ["tp-link", "tplink", "td-w89", "tl-wr"],
        "default_creds": ("admin", "admin"),
        "check_paths": ["/"],
        "vulns": ["CVE-2013-2573 (Camera RCE)", "Default credentials"],
    },
    {
        "vendor": "D-Link",
        "models": ["DSL-2740E", "DSL-2750U", "DCS-932L"],
        "keywords": ["d-link", "dlink", "dsl-27", "dcs-932"],
        "default_creds": ("admin", ""),
        "check_paths": ["/", "/frame/GetConfig"],
        "vulns": ["CVE-2026-36983 (DCS-932L RCE)", "CVE-2025-5573 (CMD Inject)"],
    },
    {
        "vendor": "Fiberhome",
        "models": ["HG6245D", "AN5506-04"],
        "keywords": ["fiberhome", "hg6245", "an5506"],
        "default_creds": ("admin", "admin"),
        "check_paths": ["/"],
        "vulns": ["Default credentials exposure"],
    },
]

_COMMON_PORTS = [80, 8080, 8888, 443, 8443]


class Exploit(Exploit):
    """Brazilian ISP Device Scanner.

    Scans a target IP or CIDR range for common ISP-deployed devices
    and attempts to fingerprint vendor, model, and applicable CVEs.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Brazilian ISP Device Scanner",
        "description": (
            "Scans for and fingerprints common ISP-deployed devices in Brazil: "
            "Huawei HG8245, ZTE H108N/H267N/H298A, Intelbras IWR series, "
            "TP-Link DSL, D-Link DSL, Fiberhome HG6245D."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (),
        "devices": (
            "Huawei HG8245/HG8247",
            "ZTE ZXHN H108N/H267N/H268N/H298A",
            "Intelbras IWR 3000N/5000N",
            "D-Link DCS-932L/DSL series",
            "Fiberhome HG6245D",
        ),
    }

    target = OptIP("", "Target IPv4 address or CIDR (use OptString for CIDR)")
    port = OptPort(80, "Primary HTTP port to scan")
    threads = OptInteger(20, "Concurrent scan threads")

    def run(self) -> None:
        """Run the ISP device scan."""
        if not self.target:
            print_error("Set target to an IP address or CIDR range")
            return

        targets = self._expand_targets(str(self.target))
        print_status(f"Scanning {len(targets)} host(s) on port {self.port}")

        results: list[DeviceFingerprint] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.threads)) as pool:
            futures = {pool.submit(self._probe_host, ip): ip for ip in targets}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    results.append(result)

        if results:
            print_success(f"Found {len(results)} device(s)")
            rows = [
                (r.ip, r.port, r.vendor, r.model, ", ".join(r.vulnerabilities))
                for r in results
            ]
            print_table(
                ("IP", "Port", "Vendor", "Model", "CVEs/Vulns"),
                *rows,
            )
        else:
            print_info("No recognizable ISP devices found in scan range")

    @mute
    def check(self) -> bool:
        """Quick check for any device on the target."""
        try:
            s = socket.create_connection((str(self.target), int(self.port)), timeout=3)
            s.close()
            return True
        except Exception:
            return False

    def _expand_targets(self, target: str) -> list[str]:
        """Expand a single IP or CIDR to a list of host strings.

        Args:
            target: IPv4 address or CIDR notation.

        Returns:
            List of IP address strings.
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            return [str(h) for h in network.hosts()]
        except ValueError:
            return [target]

    def _probe_host(self, ip: str) -> DeviceFingerprint | None:
        """Probe a single host for ISP device fingerprints.

        Args:
            ip: Target IP address string.

        Returns:
            DeviceFingerprint if a known device is found, else None.
        """
        fp = DeviceFingerprint(ip=ip, port=int(self.port))
        try:
            r = requests.get(
                f"http://{ip}:{self.port}/",
                timeout=3,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return None

        fp.open_ports.append(int(self.port))
        fp.server_header = r.headers.get("Server", "")
        text_lower = (r.text or "").lower()
        server_lower = fp.server_header.lower()

        combined = text_lower + " " + server_lower
        for entry in _FINGERPRINTS:
            for kw in entry["keywords"]:
                if kw in combined:
                    fp.vendor = entry["vendor"]
                    fp.model = ", ".join(entry["models"])
                    fp.vulnerabilities = list(entry["vulns"])
                    return fp

        return None
