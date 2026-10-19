"""Network Discovery Engine for FirewallXPL-Forge.

Discovers hosts, scans services, identifies security appliances, and maps
vulnerabilities using Nmap/Masscan as external engines with FXF-specific
device identification and vuln mapping.

Author: André Henrique (@mrhenrike) | União Geek
"""

from firewallxpl.core.discovery.engine import DiscoveryEngine
from firewallxpl.core.discovery.device_identifier import DeviceIdentifier
from firewallxpl.core.discovery.vuln_mapper import VulnMapper

__all__ = ["DiscoveryEngine", "DeviceIdentifier", "VulnMapper"]
