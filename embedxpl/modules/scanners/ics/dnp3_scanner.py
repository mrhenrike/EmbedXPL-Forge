# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""DNP3 Scanner — Enumerate DNP3 Controllers (TCP/20000 and UDP/20000).

DNP3 (Distributed Network Protocol 3) is a serial/IP protocol used extensively
in SCADA systems for utilities (electric, water, oil & gas), substations, and
remote terminal units (RTUs).

The scanner sends a DNP3 Link-Layer Data-Link Control frame requesting the
remote device's data-link reset, which typically elicits an ACK response from
DNP3-enabled PLCs and RTUs, confirming their presence.

DNP3 has optional but rarely deployed authentication (Secure Authentication v5).
Most deployed DNP3 installations have no authentication.

References:
  - IEEE Std 1815-2012 (DNP3 Standard)
  - ICS-CERT Advisory ICSA-10-301-01
  - MITRE ATT&CK ICS: T0846, T0884

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_DNP3_TCP_PORT = 20000
_DNP3_UDP_PORT = 20000

# DNP3 Data Link Layer frame — Request Link Status (Function 0x09)
# Format: Start (2) + Length (1) + Control (1) + Dest (2) + Src (2) + CRC (2)
# Start bytes: 0x0564 (DNP3 magic)
# Length: 5 (Control + Dest + Src = 5 bytes)
# Control: 0xC9 = DIR=1, PRI=1, FCB=0, FCV=0, FC=0x09 (Request Link Status)
# Dest: 0x0000 (broadcast), Src: 0x0001 (master)
_DNP3_LINK_STATUS_REQ = bytes([
    0x05, 0x64,  # Start bytes (DNP3 magic)
    0x05,        # Length
    0xC9,        # Control: DIR, PRI, FC=Request Link Status
    0x00, 0x00,  # Destination address (0 = broadcast)
    0x01, 0x00,  # Source address (master = 1)
    0xCC, 0x5D,  # CRC (precomputed for this fixed frame)
])

# DNP3 Data Link Layer frame — Reset Link States (Function 0x00)
_DNP3_RESET_LINK = bytes([
    0x05, 0x64,
    0x05,
    0xC0,        # Control: DIR, PRI, FC=0x00 (Reset Link States)
    0x00, 0x00,
    0x01, 0x00,
    0xB3, 0x7E,  # CRC
])


def _dnp3_probe(host: str, port: int, request: bytes, udp: bool, timeout: int) -> Optional[bytes]:
    """Send DNP3 request over TCP or UDP and return response."""
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(request, (host, port))
            data, _ = sock.recvfrom(256)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.sendall(request)
            data = sock.recv(256)
        sock.close()
        return data
    except Exception:
        return None


def _parse_dnp3_response(data: bytes) -> str:
    """Extract meaningful info from a DNP3 link-layer response."""
    if len(data) < 8:
        return "partial response"
    if data[0] == 0x05 and data[1] == 0x64:
        ctrl = data[3]
        src = struct.unpack("<H", data[6:8])[0]
        fc = ctrl & 0x0F
        fc_names = {0x00: "Reset Link", 0x01: "Reset Link Ack", 0x09: "Request Link Status",
                    0x0B: "Link Status", 0x0F: "Not Supported"}
        fc_name = fc_names.get(fc, "FC=0x{:02X}".format(fc))
        return "Link frame from slave {} — {}".format(src, fc_name)
    return "unknown DNP3 frame ({} bytes)".format(len(data))


class Exploit(BaseExploit):
    """DNP3 ICS Controller Scanner — Link-layer enumeration of SCADA devices.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DNP3 ICS Controller Scanner",
        "description": (
            "Scans for DNP3 SCADA controllers on TCP/20000 and UDP/20000. Sends "
            "DNP3 Link-Layer Request Link Status frames to identify PLCs, RTUs, and "
            "IEDs used in utilities (electricity, water, oil & gas). Most DNP3 "
            "installations lack Secure Authentication v5."
        ),
        "authors": (
            "Reid Wightman (digitalbond)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://attack.mitre.org/techniques/T0884/",
            "https://github.com/digitalbond/Redpoint",
        ),
        "devices": (
            "DNP3 PLC", "RTU", "IED",
            "GE", "Siemens", "ABB", "Schweitzer Engineering", "Cooper Power",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(_DNP3_TCP_PORT, "DNP3 port (default 20000)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        found = False
        for proto_name, udp in [("TCP", False), ("UDP", True)]:
            port = self.port
            print_status("Probing DNP3 on {}:{} ({})...".format(self.target, port, proto_name))
            resp = _dnp3_probe(self.target, port, _DNP3_LINK_STATUS_REQ, udp, self.timeout)
            if resp:
                info = _parse_dnp3_response(resp)
                print_success(
                    "DNP3 device confirmed on {}:{}/{} — {}".format(
                        self.target, port, proto_name, info
                    )
                )
                found = True
            else:
                # Try Reset Link
                resp2 = _dnp3_probe(self.target, port, _DNP3_RESET_LINK, udp, self.timeout)
                if resp2:
                    print_success("DNP3 response to Reset Link on {}/{}: {}".format(
                        port, proto_name, _parse_dnp3_response(resp2)
                    ))
                    found = True

        if not found:
            print_error("No DNP3 response on {}:{} (TCP/UDP)".format(self.target, self.port))

    @mute
    def check(self) -> bool:
        resp = _dnp3_probe(self.target, self.port, _DNP3_LINK_STATUS_REQ, False, 4)
        if resp:
            return True
        resp2 = _dnp3_probe(self.target, self.port, _DNP3_LINK_STATUS_REQ, True, 4)
        return resp2 is not None
