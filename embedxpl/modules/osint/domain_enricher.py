"""
embedxpl/modules/osint/domain_enricher.py - Domain OSINT Enricher.

DNS resolution, WHOIS, subdomain enumeration, and reverse-IP lookup
for IoT/embedded device discovery.

Native implementation based on:
  submodules/Safelabs-Mantis/enrichment-data/code/app/utils/domainsuite.py

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

try:
    import dns.resolver  # type: ignore
    _DNSPYTHON = True
except ImportError:
    _DNSPYTHON = False

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False


@dataclass
class DomainProfile:
    """Domain/IP OSINT profile."""
    domain: str
    a_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    reverse_ips: List[str] = field(default_factory=list)
    blacklisted: bool = False
    error: str = ""


class DomainEnricher:
    """Domain OSINT enricher for IoT/embedded device discovery.

    Resolves DNS records, discovers subdomains, and checks IP reputation.
    Useful for mapping attack surface before active scanning.

    Usage:
        enricher = DomainEnricher()
        profile = enricher.resolve("vendor.iot.local")
        profile = enricher.reverse_ip("192.168.1.1")
    """

    BLACKLIST_RESOLVER = "9.9.9.9"  # Quad9 DNS

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def resolve(self, domain: str) -> DomainProfile:
        """Resolve all DNS record types for a domain.

        Args:
            domain: Hostname or IP to resolve.

        Returns:
            DomainProfile with DNS records.
        """
        profile = DomainProfile(domain=domain)

        if not _DNSPYTHON:
            # Fallback: basic socket resolution only
            try:
                addrs = socket.getaddrinfo(domain, None)
                profile.a_records = list(set(a[4][0] for a in addrs if a[0] == socket.AF_INET))
                profile.aaaa_records = list(set(a[4][0] for a in addrs if a[0] == socket.AF_INET6))
            except Exception as exc:
                profile.error = str(exc)
            return profile

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype, attr in [
            ("A", "a_records"),
            ("MX", "mx_records"),
            ("NS", "ns_records"),
            ("AAAA", "aaaa_records"),
        ]:
            try:
                answers = resolver.resolve(domain, rtype)
                values = []
                for r in answers:
                    val = str(r).rstrip(".")
                    if rtype == "MX":
                        val = str(r.exchange).rstrip(".")
                    values.append(val)
                setattr(profile, attr, values)
            except Exception:
                pass

        return profile

    def reverse_ip(self, ip: str) -> List[str]:
        """Find hostnames that resolve to this IP (reverse DNS + sonar).

        Args:
            ip: Target IP address.

        Returns:
            List of hostnames pointing to this IP.
        """
        results = []

        # PTR record (reverse DNS)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                results.append(hostname)
        except Exception:
            pass

        # Sonar.omnisint.io reverse-IP API
        if _REQUESTS:
            try:
                resp = requests.get(
                    f"https://sonar.omnisint.io/reverse/{ip}",
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        results.extend(data[:20])
            except Exception:
                pass

        return list(set(results))

    def subdomains(self, domain: str) -> List[str]:
        """Discover subdomains using Sonar API.

        Args:
            domain: Root domain to query.

        Returns:
            List of discovered subdomains.
        """
        if not _REQUESTS:
            return []
        try:
            resp = requests.get(
                f"https://sonar.omnisint.io/subdomains/{domain}",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data[:50]
        except Exception:
            pass
        return []

    def blacklist_check(self, domain: str) -> bool:
        """Check if domain is blacklisted via Quad9 DNS.

        Quad9 (9.9.9.9) blocks malicious domains.
        A NXDOMAIN response indicates the domain is blocked.

        Args:
            domain: Domain to check.

        Returns:
            True if blacklisted (NXDOMAIN from Quad9).
        """
        try:
            resolver = dns.resolver.Resolver() if _DNSPYTHON else None
            if resolver:
                resolver.nameservers = [self.BLACKLIST_RESOLVER]
                resolver.timeout = 3.0
                resolver.resolve(domain, "A")
                return False  # Got answer = not blocked
        except Exception:
            return True  # NXDOMAIN or error = likely blocked
        return False
