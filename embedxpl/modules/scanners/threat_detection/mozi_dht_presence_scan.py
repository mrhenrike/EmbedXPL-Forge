# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mozi DHT botnet presence detector.

Mozi is an IoT P2P botnet that operates on a modified BitTorrent DHT
(Kademlia) protocol.  Infected devices join the DHT swarm and communicate
peer-to-peer on UDP port 14836 (default) and secondarily on 48101.

This scanner sends a crafted DHT ``find_node`` query to the target UDP port
and inspects the response for Mozi-specific DHT protocol markers:
  - BEP-encoded response beginning with ``d1:`` (bencoded dict)
  - Node ID field ``2:id`` with 20-byte value (Kademlia node ID)
  - Absence of a standard BitTorrent tracker response

If the target responds with a well-formed DHT reply, it may be a Mozi peer.
Combined with checking for other infection indicators (Telnet exposure,
default creds) this module provides a multi-signal detection capability.

MITRE ATT&CK:
  T1095   — Non-Application Layer Protocol (P2P DHT)
  T1571   — Non-Standard Port (14836/UDP)
  T1590.001 — Gather Victim Network Information: IP Addresses

References:
  https://blog.netlab.360.com/mozi-another-botnet-using-dht/
  https://www.trendmicro.com/en_us/research/21/l/mozi-botnet-successor.html
  https://securelist.com/mozi-botnet/

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import struct
from typing import Optional

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptIP,
    OptInt,
    OptPort,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.scanners.threat_detection.mozi_dht_presence_scan")


def _make_find_node_query() -> bytes:
    """Build a minimal bencoded DHT find_node query (Kademlia BEP-5).

    Returns:
        Raw bencoded bytes ready to send over UDP.
    """
    tid = os.urandom(4)
    node_id = hashlib.sha1(os.urandom(20)).digest()  # random 20-byte node ID
    target_id = hashlib.sha1(os.urandom(20)).digest()

    # Bencode: d1:ad2:id20:<node_id>6:target20:<target_id>e1:q9:find_node1:t2:<tid>1:y1:qe
    query = (
        b"d1:ad2:id20:" + node_id +
        b"6:target20:" + target_id +
        b"e1:q9:find_node1:t2:" + tid +
        b"1:y1:qe"
    )
    return query


def _parse_dht_response(data: bytes) -> Optional[str]:
    """Determine if a UDP response looks like a Mozi DHT node reply.

    A genuine DHT find_node response is bencoded and begins with ``d1:``
    (dict).  Mozi uses the standard DHT wire format, so we check for:
      - Bencoded dict opening (``d``)
      - Presence of ``2:id`` field (node ID)
      - Response type ``y`` == ``r`` (response, not error)

    Args:
        data: Raw UDP response bytes.

    Returns:
        A string describing the detection, or None if not a DHT response.
    """
    if not data or data[0:1] != b"d":
        return None
    lower = data
    if b"2:id" not in lower:
        return None
    if b"1:y1:r" not in lower and b"1:y1:e" not in lower:
        return None
    # Extra: Mozi nodes embed config in a 'g' key
    is_mozi = b"1:g" in lower or b"mozi" in lower.lower()
    if is_mozi:
        return "Mozi DHT node (config key detected)"
    return "Standard DHT node -- may be Mozi peer (verify with additional indicators)"


class Exploit(BaseExploit):
    """Mozi DHT P2P botnet presence detector via UDP probe.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mozi DHT Botnet Presence Scanner",
        "description": (
            "Sends a crafted DHT find_node query to the target on UDP port 14836 "
            "(Mozi default) and 48101. Detects bencoded DHT responses consistent "
            "with Mozi P2P botnet node participation. Detection only."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://blog.netlab.360.com/mozi-another-botnet-using-dht/",
            "https://securelist.com/mozi-botnet/",
        ],
        "devices": [
            "Generic IoT / SOHO Routers",
            "IP Cameras",
            "NAS Devices",
            "Any Mozi-targeted device",
        ],
        "severity": "high",
        "apt_groups": ["Mozi Botnet"],
        "mitre": ["T1095", "T1571", "T1590.001"],
    }

    target = OptIP("", "Target IPv4 address to probe")
    port = OptPort(14836, "Primary Mozi DHT UDP port (default 14836)")
    alt_port = OptPort(48101, "Secondary Mozi DHT UDP port (default 48101)")
    timeout = OptInt(3, "UDP response timeout in seconds")

    @mute
    def check(self) -> bool:
        """Send a probe to both Mozi DHT ports and check for a DHT response.

        Returns:
            True if either port returns a valid DHT response.
        """
        for port in (self.port, self.alt_port):
            response = self._udp_probe(self.target, port)
            if response and _parse_dht_response(response):
                return True
        return False

    def run(self) -> None:
        """Execute Mozi DHT presence probe against primary and secondary ports."""
        print_status("[MoziScan] Probing {} for Mozi DHT presence...".format(self.target))

        detected = False
        for port, label in [(self.port, "primary"), (self.alt_port, "secondary")]:
            response = self._udp_probe(self.target, port)
            if response is None:
                print_info("[MoziScan] Port {}/udp ({}) -- no response (filtered or closed).".format(
                    port, label))
                continue

            verdict = _parse_dht_response(response)
            preview = repr(response[:64])
            resp_hash = hashlib.md5(response).hexdigest()

            if verdict:
                detected = True
                print_warning(
                    "[MoziScan] DHT RESPONSE on {}/udp ({}): {} | hash={} | data={}".format(
                        port, label, verdict, resp_hash, preview
                    )
                )
            else:
                print_info(
                    "[MoziScan] Port {}/udp ({}) responded but no DHT markers: hash={} | data={}".format(
                        port, label, resp_hash, preview
                    )
                )

        if detected:
            print_warning(
                "[MoziScan] {} may be a Mozi DHT peer. "
                "Confirm with botnet_c2_port_scan and mirai_default_creds_sweep.".format(self.target)
            )
            print_info("[MoziScan] Recommendation: block UDP 14836 and 48101 at perimeter; "
                       "reflash device firmware; rotate credentials.")
        else:
            print_success("[MoziScan] No Mozi DHT response detected on {}.".format(self.target))

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _udp_probe(self, host: str, port: int) -> Optional[bytes]:
        """Send a DHT find_node probe and return the raw response.

        Args:
            host: Target IP address.
            port: UDP port to probe.

        Returns:
            Raw response bytes, empty bytes if no data, or None on failure.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            query = _make_find_node_query()
            sock.sendto(query, (host, port))
            try:
                data, _ = sock.recvfrom(4096)
                return data
            except socket.timeout:
                return None
        except OSError:
            return None
        finally:
            sock.close()
