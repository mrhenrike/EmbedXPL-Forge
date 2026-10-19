"""Discovery engine orchestrator — coordinates scan engines and FXF intelligence.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from firewallxpl.core.discovery.scan_engines.base import DiscoveredHost, ScanOptions
from firewallxpl.core.discovery.scan_engines.builtin_engine import BuiltinEngine
from firewallxpl.core.discovery.device_identifier import DeviceIdentifier
from firewallxpl.core.discovery.vuln_mapper import VulnMapper
from firewallxpl.core.discovery.tool_detector import detect_nmap

logger = logging.getLogger("firewallxpl.discovery.engine")


class DiscoveryEngine:
    """Orchestrates the full network discovery pipeline."""

    def __init__(self, engine_preference: str = "auto") -> None:
        self._engine_preference = engine_preference
        self._identifier = DeviceIdentifier()
        self._mapper = VulnMapper()
        self._scan_engine = None

    def _select_engine(self) -> None:
        """Select the best available scan engine."""
        if self._engine_preference == "nmap" or self._engine_preference == "auto":
            nmap_info = detect_nmap()
            if nmap_info.available:
                try:
                    from firewallxpl.core.discovery.scan_engines.nmap_engine import NmapEngine
                    self._scan_engine = NmapEngine()
                    if self._scan_engine.available:
                        logger.info("Using Nmap engine: %s", nmap_info.version)
                        return
                except ImportError:
                    pass

        self._scan_engine = BuiltinEngine()
        logger.info("Using builtin TCP connect engine (install Nmap for better results)")

    async def discover(self, target: str, options: Optional[ScanOptions] = None) -> List[DiscoveredHost]:
        """Run full discovery pipeline: hosts -> services -> identify -> vuln map."""
        if not self._scan_engine:
            self._select_engine()

        opts = options or ScanOptions()

        hosts = await self._scan_engine.discover_hosts(target, opts)
        logger.info("Discovered %d live hosts", len(hosts))

        if not hosts:
            return []

        host_ips = [h.ip for h in hosts]
        scanned = await self._scan_engine.scan_services(host_ips, opts.ports, opts)

        for host in scanned:
            ident = self._identifier.identify(host)
            if ident:
                host.identification = ident
                vuln_result = self._mapper.map(ident)
                host.applicable_modules = [e.module_path for e in vuln_result.applicable_exploits]
                host.applicable_cves = []
                for e in vuln_result.applicable_exploits:
                    host.applicable_cves.extend(e.cve_ids)
                host.risk_score = vuln_result.risk_score

        return scanned

    def discover_sync(self, target: str, options: Optional[ScanOptions] = None) -> List[DiscoveredHost]:
        """Synchronous wrapper for discover()."""
        return asyncio.run(self.discover(target, options))

    @property
    def engine_name(self) -> str:
        return self._scan_engine.name if self._scan_engine else "none"
