"""Abstract base class for scan engines.

Author: André Henrique (@mrhenrike) | União Geek
"""


from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DiscoveredHost:
    """Result from host/service discovery."""
    ip: str
    mac: str | None = None
    mac_vendor: str | None = None
    hostname: str | None = None
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    os_guess: str | None = None
    response_time_ms: float = 0.0
    identification: Any | None = None
    applicable_modules: list[str] = field(default_factory=list)
    applicable_cves: list[str] = field(default_factory=list)
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
    async def discover_hosts(self, target: str, options: ScanOptions) -> list[DiscoveredHost]:
        """Discover live hosts in target range."""
        ...

    @abstractmethod
    async def scan_services(self, hosts: list[str], ports: str, options: ScanOptions) -> list[DiscoveredHost]:
        """Scan services on discovered hosts."""
        ...
