"""Abstract base class for scan engines.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DiscoveredHost:
    """Result from host/service discovery."""
    ip: str
    mac: Optional[str] = None
    mac_vendor: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    os_guess: Optional[str] = None
    response_time_ms: float = 0.0
    identification: Optional[Any] = None
    applicable_modules: List[str] = field(default_factory=list)
    applicable_cves: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class ScanOptions:
    """Options for scan execution."""
    ports: str = "appliance"
    timeout: float = 2.0
    timing: str = "T3"
    mode: str = "normal"
    http_probes: bool = True


class ScanEngine(ABC):
    """Unified interface for network scanning backends."""

    name: str = "base"
    requires_root: bool = False
    available: bool = False

    @abstractmethod
    async def discover_hosts(self, target: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Discover live hosts in target range."""
        ...

    @abstractmethod
    async def scan_services(self, hosts: List[str], ports: str, options: ScanOptions) -> List[DiscoveredHost]:
        """Scan services on discovered hosts."""
        ...
