"""
firewallxpl/modules/intel/shodan_enricher.py - Shodan Host Profiler.

Queries the Shodan API to enrich target IP addresses with:
  - Open ports and services
  - Product/version banners
  - Known vulnerabilities (CVEs via Shodan vulns)
  - OS, organization, ASN, geolocation

Native implementation ported from:
  submodules/Safelabs-Operacao-Desenvolvimento/mnt-processing-shodan/
  submodules/Safelabs-Mantis/shodan-crawler/

Used as pre-scan intelligence layer for XPL-Forge audit.
No SafeLabs runtime dependencies.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Default rate limit (Shodan free tier: 1 req/sec)
_DEFAULT_RATE_SEC = 1.0


@dataclass
class ShodanService:
    """A single service/port discovered by Shodan."""
    port: int
    transport: str = "tcp"
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)


@dataclass
class ShodanHostProfile:
    """Complete Shodan profile for a target IP."""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    org: str = ""
    asn: str = ""
    country: str = ""
    city: str = ""
    os: str = ""
    services: List[ShodanService] = field(default_factory=list)
    total_vulns: int = 0
    all_vulns: List[str] = field(default_factory=list)
    last_update: str = ""
    error: str = ""

    @property
    def open_ports(self) -> List[int]:
        return [s.port for s in self.services]

    @property
    def products(self) -> List[str]:
        return [s.product for s in self.services if s.product]

    def get_services_on_port(self, port: int) -> List[ShodanService]:
        return [s for s in self.services if s.port == port]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "org": self.org,
            "asn": self.asn,
            "country": self.country,
            "os": self.os,
            "open_ports": self.open_ports,
            "products": self.products,
            "total_vulns": self.total_vulns,
            "all_vulns": self.all_vulns[:10],
        }


class ShodanEnricher:
    """Shodan host profiler for XPL-Forge pre-scan intelligence.

    Requires SHODAN_API_KEY environment variable or explicit api_key.
    Falls back gracefully when API key is unavailable.

    Usage:
        enricher = ShodanEnricher()
        if enricher.available:
            profile = enricher.get_host("1.2.3.4")
            suggestions = enricher.suggest_modules(profile)
    """

    SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

    def __init__(
        self,
        api_key: str = "",
        rate_limit_sec: float = _DEFAULT_RATE_SEC,
    ) -> None:
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self.rate_limit_sec = rate_limit_sec
        self._last_request = 0.0

    @property
    def available(self) -> bool:
        """Return True if API key and requests library are available."""
        return bool(self.api_key) and _REQUESTS

    def _rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit_sec:
            time.sleep(self.rate_limit_sec - elapsed)
        self._last_request = time.time()

    def get_host(self, ip: str) -> ShodanHostProfile:
        """Query Shodan for host information.

        Args:
            ip: Target IP address.

        Returns:
            ShodanHostProfile with discovered services and vulnerabilities.
        """
        if not self.available:
            return ShodanHostProfile(ip=ip, error="Shodan API key not configured or requests not installed")

        self._rate_limit()

        try:
            url = self.SHODAN_HOST_URL.format(ip=ip)
            resp = requests.get(
                url,
                params={"key": self.api_key},
                timeout=15,
            )

            if resp.status_code == 401:
                return ShodanHostProfile(ip=ip, error="Invalid Shodan API key")
            if resp.status_code == 404:
                return ShodanHostProfile(ip=ip, error="IP not found in Shodan")
            if resp.status_code != 200:
                return ShodanHostProfile(ip=ip, error=f"HTTP {resp.status_code}")

            data = resp.json()
            return self._parse_response(ip, data)

        except Exception as exc:
            return ShodanHostProfile(ip=ip, error=str(exc))

    def _parse_response(self, ip: str, data: Dict[str, Any]) -> ShodanHostProfile:
        """Parse Shodan API response into ShodanHostProfile."""
        profile = ShodanHostProfile(
            ip=ip,
            hostnames=data.get("hostnames", []),
            org=data.get("org", ""),
            asn=data.get("asn", ""),
            country=data.get("country_code", ""),
            city=data.get("city", ""),
            os=data.get("os", "") or "",
            last_update=data.get("last_update", ""),
        )

        # Process service data
        for svc in data.get("data", []):
            port = svc.get("port", 0)
            transport = svc.get("transport", "tcp")
            product = svc.get("product", "") or ""
            version = svc.get("version", "") or ""
            banner = svc.get("data", "")[:200] if svc.get("data") else ""
            cpe = svc.get("cpe", []) or []
            svc_vulns = list((svc.get("vulns") or {}).keys())

            profile.services.append(ShodanService(
                port=port,
                transport=transport,
                product=product,
                version=version,
                banner=banner,
                cpe=cpe if isinstance(cpe, list) else [cpe],
                vulns=svc_vulns,
            ))

        # Top-level vulns
        top_vulns = data.get("vulns", {}) or {}
        profile.all_vulns = list(top_vulns.keys())
        profile.total_vulns = len(profile.all_vulns)

        return profile

    def suggest_modules(self, profile: ShodanHostProfile) -> List[str]:
        """Suggest relevant XPL-Forge modules based on Shodan profile.

        Args:
            profile: Shodan host profile.

        Returns:
            List of module path suggestions (most relevant first).
        """
        suggestions = []
        products = " ".join(profile.products).lower()
        ports = set(profile.open_ports)

        # Firewall/perimeter
        if 443 in ports or 8443 in ports:
            if "fortigate" in products or "fortios" in products:
                suggestions.append("exploits/perimeter/fortinet/")
            if "palo alto" in products or "pan-os" in products:
                suggestions.append("exploits/perimeter/paloalto/")
            if "checkpoint" in products:
                suggestions.append("exploits/perimeter/checkpoint/")
            if "sonicwall" in products:
                suggestions.append("exploits/perimeter/sonicwall/")
            if "cisco" in products and "asa" in products:
                suggestions.append("exploits/perimeter/cisco/asa/")

        # VPN
        if any(p in products for p in ["ssl vpn", "vpn", "citrix", "pulse", "ivanti"]):
            suggestions.append("exploits/vpn/")

        # Router IoT
        if any(p in products for p in ["routeros", "mikrotik"]):
            suggestions.append("exploits/routers/mikrotik/")

        # Printers
        if 9100 in ports or 631 in ports:
            suggestions.append("exploits/printers/")

        # ICS/OT
        if 502 in ports:
            suggestions.append("exploits/ics/modbus/")
        if 102 in ports:
            suggestions.append("exploits/ics/siemens/")
        if 44818 in ports:
            suggestions.append("exploits/ics/rockwell/")

        # CVE-based suggestions
        for vuln in profile.all_vulns[:5]:
            suggestions.append(f"[CVE] {vuln}")

        return suggestions
