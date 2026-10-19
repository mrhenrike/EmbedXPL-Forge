"""Nmap scan engine wrapper via python-nmap.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from firewallxpl.core.discovery.scan_engines.base import DiscoveredHost, ScanEngine, ScanOptions

logger = logging.getLogger("firewallxpl.discovery.nmap")

try:
    import nmap
    _HAS_NMAP = True
except ImportError:
    _HAS_NMAP = False


class NmapEngine(ScanEngine):
    """Nmap-based scan engine using python-nmap library."""

    name = "nmap"
    requires_root = False

    def __init__(self) -> None:
        self.available = _HAS_NMAP
        self._scanner = nmap.PortScanner() if _HAS_NMAP else None

    async def discover_hosts(self, target: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Host discovery via Nmap -sn."""
        if not self._scanner:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_discover, target, options)

    def _sync_discover(self, target: str, options: ScanOptions) -> List[DiscoveredHost]:
        args = f"-sn -PE -PS443,22,80 -{options.timing}"
        try:
            self._scanner.scan(hosts=target, arguments=args)
        except Exception as exc:
            logger.error("Nmap discovery failed: %s", exc)
            return []

        hosts = []
        for ip in self._scanner.all_hosts():
            h = self._scanner[ip]
            host = DiscoveredHost(
                ip=ip,
                hostname=h.hostname() or None,
                mac=h.get("addresses", {}).get("mac"),
                mac_vendor=h.get("vendor", {}).get(h.get("addresses", {}).get("mac", ""), ""),
            )
            hosts.append(host)
        return hosts

    async def scan_services(self, hosts: List[str], ports: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Service scan via Nmap -sV."""
        if not self._scanner:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_service_scan, hosts, ports, options)

    def _sync_service_scan(self, hosts: List[str], ports: str, options: ScanOptions) -> List[DiscoveredHost]:
        target_str = " ".join(hosts)
        port_arg = ports if ports != "appliance" else "22,23,53,80,161,443,541,830,4443,8080,8443,9090,10443"
        args = f"-sV -{options.timing} -p {port_arg}"
        try:
            self._scanner.scan(hosts=target_str, arguments=args)
        except Exception as exc:
            logger.error("Nmap service scan failed: %s", exc)
            return []

        results = []
        for ip in self._scanner.all_hosts():
            h = self._scanner[ip]
            open_ports = []
            for proto in h.all_protocols():
                for port in h[proto]:
                    svc = h[proto][port]
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": svc.get("state", ""),
                        "service": svc.get("name", ""),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                    })
            host = DiscoveredHost(ip=ip, open_ports=open_ports, hostname=h.hostname() or None)
            results.append(host)
        return results
