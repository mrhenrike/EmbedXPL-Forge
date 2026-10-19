"""Built-in TCP connect scan engine — zero external dependencies.

Fallback when Nmap/Masscan are not available. Limited capability
(no OS fingerprint, no version intensity).

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Dict, List

from firewallxpl.core.discovery.scan_engines.base import DiscoveredHost, ScanEngine, ScanOptions

logger = logging.getLogger("firewallxpl.discovery.builtin")

APPLIANCE_PORTS = [22, 23, 53, 80, 161, 443, 541, 830, 4443, 8080, 8443, 9090, 10443]


class BuiltinEngine(ScanEngine):
    """Pure asyncio TCP connect scanner + basic banner grab."""

    name = "builtin"
    requires_root = False
    available = True

    async def discover_hosts(self, target: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Discover hosts via TCP connect probe on common ports."""
        import ipaddress
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except ValueError:
            ips = [target]

        if len(ips) > 1024:
            ips = ips[:1024]

        semaphore = asyncio.Semaphore(256)
        results: List[DiscoveredHost] = []

        async def _probe(ip: str) -> None:
            async with semaphore:
                for port in [443, 80, 22]:
                    try:
                        _, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=options.timeout
                        )
                        writer.close()
                        await writer.wait_closed()
                        results.append(DiscoveredHost(ip=ip, open_ports=[{"port": port, "state": "open"}]))
                        return
                    except (asyncio.TimeoutError, OSError):
                        continue

        await asyncio.gather(*[_probe(ip) for ip in ips], return_exceptions=True)
        return results

    async def scan_services(self, hosts: List[str], ports: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Scan services with TCP connect + banner grab."""
        port_list = APPLIANCE_PORTS if ports == "appliance" else [int(p) for p in ports.split(",")]
        semaphore = asyncio.Semaphore(128)
        results: List[DiscoveredHost] = []

        async def _scan_host(ip: str) -> DiscoveredHost:
            open_ports = []
            for port in port_list:
                async with semaphore:
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=options.timeout
                        )
                        banner = ""
                        try:
                            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                            banner = data.decode("utf-8", errors="ignore").strip()
                        except (asyncio.TimeoutError, Exception):
                            pass
                        writer.close()
                        await writer.wait_closed()
                        open_ports.append({
                            "port": port, "state": "open",
                            "service": _guess_service(port), "banner": banner,
                        })
                    except (asyncio.TimeoutError, OSError):
                        continue
            return DiscoveredHost(ip=ip, open_ports=open_ports)

        tasks = [_scan_host(ip) for ip in hosts]
        for host in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(host, DiscoveredHost):
                results.append(host)
        return results


def _guess_service(port: int) -> str:
    """Guess service name from port number."""
    services = {22: "ssh", 23: "telnet", 53: "dns", 80: "http", 161: "snmp",
                443: "https", 541: "fgfm", 830: "netconf", 4443: "https-alt",
                8080: "http-proxy", 8443: "https-alt", 9090: "webadmin", 10443: "https-alt"}
    return services.get(port, "unknown")
