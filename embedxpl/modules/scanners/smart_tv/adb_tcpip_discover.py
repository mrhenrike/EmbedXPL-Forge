# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""ADB TCP/IP Discovery Scanner — port 5555 TCP + ADB CNXN banner probe.

Attempts a raw TCP connection to port 5555 and sends the ADB CNXN magic
packet to detect Android devices with ADB-over-TCP enabled.

CVE: N/A (open ADB is a misconfiguration, not an assigned CVE)
CVSS: N/A
Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_ADB_PORT = 5555

# ADB CNXN message layout (little-endian):
#   command   = 0x4e584e43  ('CNXN')
#   arg0      = ADB version (0x01000001)
#   arg1      = max_payload  (256 * 1024)
#   data_len  = len(banner)
#   crc32     = crc of banner bytes
#   magic     = command XOR 0xFFFFFFFF
_ADB_VERSION  = 0x01000001
_ADB_MAX_DATA = 256 * 1024
_CNXN_CMD     = 0x4E584E43
_CNXN_MAGIC   = _CNXN_CMD ^ 0xFFFFFFFF


def _crc32(data: bytes) -> int:
    """Compute the ADB packet CRC (sum of bytes mod 2^32).

    Args:
        data: Raw bytes to checksum.

    Returns:
        32-bit CRC value.
    """
    return sum(data) & 0xFFFFFFFF


def _build_cnxn(banner: str = "host::") -> bytes:
    """Build a raw ADB CNXN packet.

    Args:
        banner: System identity string sent in the ADB CONNECT packet.

    Returns:
        24-byte packet header followed by the banner bytes.
    """
    payload = banner.encode()
    crc     = _crc32(payload)
    header  = struct.pack(
        "<IIIIII",
        _CNXN_CMD,
        _ADB_VERSION,
        _ADB_MAX_DATA,
        len(payload),
        crc,
        _CNXN_MAGIC,
    )
    return header + payload


class Exploit(BaseExploit):
    """ADB TCP/IP Discovery Scanner — port 5555 CNXN banner probe.

    Performs a dual-stage check:
    1. Raw TCP connect to port 5555 to test reachability.
    2. Sends an ADB CNXN packet and waits for a response header that
       starts with a recognised ADB command word (CNXN / AUTH / OPEN).

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "ADB TCP/IP Discovery Scanner",
        "description": (
            "Probes port 5555 for Android Debug Bridge (ADB) over TCP. "
            "Sends ADB CNXN magic packet and inspects the response to identify "
            "devices with ADB network debugging enabled."
        ),
        "authors": (
            "Android Open Source Project",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://developer.android.com/studio/command-line/adb",
            "https://source.android.com/docs/core/connect/adb",
        ),
        "devices": ("Android TV", "Fire TV", "Generic Android"),
    }

    target  = OptIP("", "Target IPv4 address")
    port    = OptPort(5555, "ADB TCP port (default 5555)")
    timeout = OptInteger(3, "Socket timeout in seconds")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tcp_connect(self) -> bool:
        """Attempt a plain TCP connect to target:port.

        Returns:
            True if the connection succeeds, False otherwise.
        """
        try:
            sock = socket.create_connection((str(self.target), int(self.port)), timeout=self.timeout)
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _adb_cnxn_probe(self) -> Optional[str]:
        """Send an ADB CNXN packet and read the first 24 response bytes.

        Returns:
            Hex-encoded first 4 bytes of the response (the ADB command word)
            if a response is received, otherwise None.
        """
        try:
            sock = socket.create_connection((str(self.target), int(self.port)), timeout=self.timeout)
            sock.sendall(_build_cnxn())
            data = sock.recv(24)
            sock.close()
            if len(data) >= 4:
                return data[:4].hex()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the ADB TCP/IP discovery probe.

        Performs a TCP connect check followed by an ADB CNXN packet probe.
        Prints a success banner if ADB responds, or an error if the host
        is unreachable or does not speak ADB.
        """
        print_status("Probing {}:{} for ADB TCP/IP...".format(self.target, self.port))

        if not self._tcp_connect():
            print_error("TCP connect failed — port {} is closed or filtered.".format(self.port))
            return

        print_success("TCP port {} is OPEN on {}".format(self.port, self.target))

        response_hex = self._adb_cnxn_probe()
        if response_hex is None:
            print_warning("Port is open but no ADB response received — may be filtered.")
            return

        # ADB command words (little-endian bytes):
        #   CNXN = 43 4e 58 4e  AUTH = 41 55 54 48  OPEN = 4f 50 45 4e
        known = {"434e584e": "CNXN", "41555448": "AUTH", "4f50454e": "OPEN"}
        label = known.get(response_hex.upper(), "UNKNOWN ({})".format(response_hex))
        print_success(
            "ADB response on {}:{} — command={} → Device likely has ADB over TCP ENABLED".format(
                self.target, self.port, label
            )
        )

    @mute
    def check(self) -> bool:
        """Check whether the target responds to an ADB CNXN probe.

        Returns:
            True if the target returns any ADB response, False otherwise.
        """
        return self._adb_cnxn_probe() is not None
