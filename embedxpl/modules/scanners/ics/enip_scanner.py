# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""EtherNet/IP (ENIP) Scanner — ListIdentity UDP/TCP broadcast discovery.

Sends the EtherNet/IP ListIdentity encapsulation command (0x0063) to
UDP/44818 and optionally TCP/44818. This command causes any ENIP-capable
device on the network (Allen-Bradley PLCs, HMIs, drives, I/O modules) to
respond with their identity object including:
  - Product name, device type, vendor ID, revision
  - Serial number, IP address, product code

No authentication required — EtherNet/IP ListIdentity is an open broadcast
used for device discovery in factory automation environments.

Protocol: ENIP (EtherNet/IP) — ODVA standard
Default ports: TCP/UDP 44818

References:
  - ODVA EtherNet/IP Specification, Volume 1
  - Nmap script: enip-info.nse
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
from typing import List, Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

# ENIP ListIdentity request: Command=0x0063, Length=0, SessionHandle=0,
# Status=0, Sender Context=0, Options=0
_LIST_IDENTITY_REQ = struct.pack("<HHIIQII", 0x0063, 0, 0, 0, 0, 0, 0)

_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x06: "Ethernet Network Adapter",
    0x07: "General Purpose Discrete I/O",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x21: "Human-Machine Interface",
    0x24: "Modular I/O System",
    0x25: "CIP Safety Drive",
    0x27: "Encoder",
    0x29: "Managed Ethernet Switch",
    0x2A: "Motion Drive",
    0xC8: "Embedded Component",
}

_VENDOR_IDS = {
    0x01: "Rockwell Automation/Allen-Bradley",
    0x02: "Namco Controls Corp.",
    0x03: "Honeywell, Inc.",
    0x04: "Parker Hannifin Corp.",
    0x07: "Numatics, Inc.",
    0x08: "Digital",
    0x0C: "Allen-Bradley",
    0x10: "Control Technology Inc.",
    0x1D: "Turck, Inc.",
    0x22: "OMRON Corporation",
    0x29: "Mitsubishi Electric Corp.",
    0x2B: "Brooks Automation, Inc.",
    0x2C: "Eaton Corp.",
    0x33: "ABB Industrial Systems AB",
    0x3A: "Schneider Automation Inc.",
    0x4F: "Molex Incorporated",
    0x78: "Siemens AG",
}


def _send_list_identity_udp(target: str, port: int, timeout: int) -> Optional[bytes]:
    """Send ListIdentity over UDP and return raw response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_LIST_IDENTITY_REQ, (target, port))
        data, _ = sock.recvfrom(512)
        sock.close()
        return data
    except Exception:
        return None


def _send_list_identity_tcp(target: str, port: int, timeout: int) -> Optional[bytes]:
    """Send ListIdentity over TCP and return raw response."""
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.sendall(_LIST_IDENTITY_REQ)
        data = sock.recv(512)
        sock.close()
        return data
    except Exception:
        return None


def _parse_list_identity(data: bytes) -> dict:
    """Parse ENIP ListIdentity response into a device info dict.

    ENIP Encapsulation Header: 24 bytes
      Command (2), Length (2), Session Handle (4), Status (4),
      Sender Context (8), Options (4)
    Followed by CPF (Common Packet Format) items.
    """
    result: dict = {}
    if len(data) < 26:
        return result
    try:
        cmd, length = struct.unpack_from("<HH", data, 0)
        if cmd != 0x0063:
            return result

        offset = 24
        # CPF item count
        item_count = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        for _ in range(item_count):
            item_type, item_len = struct.unpack_from("<HH", data, offset)
            offset += 4
            if item_type == 0x000C:  # Identity item
                # Socket address (16 bytes), then identity
                sin_family, sin_port = struct.unpack_from(">HH", data, offset)
                sin_addr = socket.inet_ntoa(data[offset + 4: offset + 8])
                id_offset = offset + 16
                encap_proto = struct.unpack_from("<H", data, id_offset)[0]
                vendor_id, device_type, product_code = struct.unpack_from("<HHH", data, id_offset + 2)
                major_rev, minor_rev = struct.unpack_from("BB", data, id_offset + 8)
                status = struct.unpack_from("<H", data, id_offset + 10)[0]
                serial_number = struct.unpack_from("<I", data, id_offset + 12)[0]
                name_len = data[id_offset + 16]
                product_name = data[id_offset + 17: id_offset + 17 + name_len].decode("ascii", errors="replace")
                result["product_name"] = product_name
                result["vendor"] = _VENDOR_IDS.get(vendor_id, f"Vendor 0x{vendor_id:04X}")
                result["device_type"] = _DEVICE_TYPES.get(device_type, f"Type 0x{device_type:04X}")
                result["revision"] = f"{major_rev}.{minor_rev}"
                result["serial_number"] = f"0x{serial_number:08X}"
                result["ip_address"] = sin_addr
                result["status"] = f"0x{status:04X}"
            offset += item_len
    except Exception:
        pass
    return result


class Exploit(BaseExploit):
    """EtherNet/IP ListIdentity Scanner — ENIP device discovery via UDP/TCP.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "EtherNet/IP (ENIP) ListIdentity Scanner",
        "description": (
            "Sends the ENIP ListIdentity encapsulation command (0x0063) via UDP and TCP "
            "to port 44818. Identifies ENIP-capable devices: Allen-Bradley PLCs, HMIs, "
            "drives, I/O modules. No authentication required — ENIP discovery is open. "
            "Ported from ISF icssploit enip_scan.py using raw sockets (no Scapy)."
        ),
        "authors": (
            "wenzhe zhu <jtrkid[at]gmail.com> (ISF icssploit)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://github.com/nmap/nmap/blob/master/scripts/enip-info.nse",
            "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Rockwell Allen-Bradley ControlLogix / CompactLogix / MicroLogix",
            "Rockwell Allen-Bradley PowerFlex Drives",
            "OMRON NJ/NX PLCs",
            "Schneider Electric Modicon (ENIP-capable)",
            "Generic ENIP Ethernet Adapter",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(44818, "EtherNet/IP port (default 44818)")
    use_udp = OptBool(True, "Send ListIdentity via UDP (broadcast-capable)")
    use_tcp = OptBool(True, "Send ListIdentity via TCP (unicast)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        """Probe target for ENIP ListIdentity response."""
        print_status(f"[ENIP] Probing {self.target}:{self.port} for EtherNet/IP...")
        found = False

        if self.use_udp:
            data = _send_list_identity_udp(self.target, self.port, self.timeout)
            if data:
                info = _parse_list_identity(data)
                if info:
                    print_success(f"[ENIP] Device identified on {self.target}:{self.port}/UDP")
                    for key, val in info.items():
                        print_success(f"  {key}: {val}")
                    found = True
                else:
                    print_status(f"[ENIP] UDP response ({len(data)} bytes) — could not parse identity")
                    found = True

        if self.use_tcp:
            data = _send_list_identity_tcp(self.target, self.port, self.timeout)
            if data:
                info = _parse_list_identity(data)
                if info:
                    if not found:
                        print_success(f"[ENIP] Device identified on {self.target}:{self.port}/TCP")
                        for key, val in info.items():
                            print_success(f"  {key}: {val}")
                    found = True
                elif not found:
                    print_status(f"[ENIP] TCP response ({len(data)} bytes) — ENIP service present")
                    found = True

        if not found:
            print_error(f"[ENIP] No EtherNet/IP response from {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Return True if ENIP port responds."""
        return (
            _send_list_identity_udp(self.target, self.port, 3) is not None
            or _send_list_identity_tcp(self.target, self.port, 3) is not None
        )
