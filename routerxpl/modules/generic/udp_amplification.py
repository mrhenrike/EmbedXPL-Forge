"""UDP amplification test — identify open reflectors.

Probes common UDP services (DNS, NTP, SSDP, SNMP, Memcached, CharGen)
that can be exploited as amplification vectors in DDoS attacks.
Measures response size vs. request size to calculate amplification factor.

Use to audit whether services on the target device can be abused as
amplifiers against third parties.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import socket
import struct
from typing import Dict, Optional, Tuple

from routerxpl.core.exploit import *
from routerxpl.core.http.http_client import HTTPClient

__info__ = {
    "name": "UDP Amplification Factor Test",
    "description": (
        "Tests whether the target exposes UDP services that can be abused "
        "as DDoS amplification vectors (DNS, NTP, SSDP, SNMP, CharGen). "
        "Reports amplification factor (response bytes / request bytes)."
    ),
    "authors": ("André Henrique (@mrhenrike)",),
    "references": (
        "https://www.us-cert.gov/ncas/alerts/TA14-017A",
        "https://www.cloudflare.com/learning/ddos/udp-amplification-ddos-attack/",
    ),
}

# Minimal probes: (port, name, payload_hex)
_PROBES: Dict[str, Tuple[int, bytes]] = {
    "DNS": (53, bytes.fromhex(
        "0001010000010000000000000377777703777777036e657400001c0001"
    )),
    "NTP": (123, bytes.fromhex(
        "1b0004fa000100000001000000000000000000000000000000000000"
        "00000000c54f234b00000000"
    )),
    "SNMP": (161, bytes.fromhex(
        "302602010004067075626c6963a0190204000000000201000201003009"
        "300706052b060102"
    )),
    "SSDP": (1900, (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )),
    "CharGen": (19, b"X" * 1),
}


class Exploit(HTTPClient):
    """UDP amplification factor tester."""

    target  = OptIP("", "Target IPv4 address")
    timeout = OptPort(3, "UDP response timeout (seconds)")

    def run(self) -> None:
        """Test all probes and report amplification factors."""
        print_status(
            f"UDP amplification test against {self.target} "
            f"({len(_PROBES)} protocols)..."
        )
        vulnerable = []
        for name, (port, payload) in _PROBES.items():
            result = self._probe(name, port, payload)
            if result:
                req_size, resp_size, amp = result
                if amp >= 2.0:
                    print_success(
                        f"[AMPLIFIABLE] {name} UDP/{port}: "
                        f"{req_size}B → {resp_size}B (x{amp:.1f})"
                    )
                    vulnerable.append((name, port, amp))
                else:
                    print_status(
                        f"  {name} UDP/{port}: responded ({resp_size}B, "
                        f"amp x{amp:.1f} — below threshold)"
                    )
            else:
                print_status(f"  {name} UDP/{port}: no response")

        if vulnerable:
            print_success(
                f"\n{len(vulnerable)} amplifiable service(s) found: "
                + ", ".join(f"{n}/{p}" for n, p, _ in vulnerable)
            )
        else:
            print_error("No significant amplification vectors found")

    def _probe(
        self,
        name: str,
        port: int,
        payload: bytes,
    ) -> Optional[Tuple[int, int, float]]:
        """Send one UDP probe and return (req_size, resp_size, factor) or None."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(int(self.timeout))
        try:
            sock.sendto(payload, (self.target, port))
            data, _ = sock.recvfrom(65535)
            req = len(payload)
            resp = len(data)
            return req, resp, resp / max(req, 1)
        except socket.timeout:
            return None
        except Exception:
            return None
        finally:
            sock.close()

    def check(self) -> bool:
        """Check if any UDP service responds."""
        for name, (port, payload) in list(_PROBES.items())[:3]:
            if self._probe(name, port, payload):
                print_success(f"UDP service {name}/{port} is responsive")
                return True
        return False
