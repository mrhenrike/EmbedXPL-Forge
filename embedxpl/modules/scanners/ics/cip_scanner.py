# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Common Industrial Protocol (CIP) Scanner via EtherNet/IP encapsulation.

CIP (Common Industrial Protocol) runs over EtherNet/IP on TCP/44818.
This scanner establishes a TCP connection, sends a RegisterSession request
to obtain a session handle, then issues a SendRRData with a CIP GetAttributeAll
request to the Identity Object (Class 1, Instance 1) to retrieve:
  - Vendor ID, Device Type, Product Code
  - Revision (Major.Minor)
  - Serial Number, Product Name

No authentication is required on default factory configurations.

Protocol: CIP over EtherNet/IP
Default port: TCP/44818

References:
  - ODVA CIP Networks Library Vol. 1: Common Industrial Protocol
  - Wireshark dissector: epan/dissectors/packet-cip.c
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

# ENIP RegisterSession request (24-byte header + 4-byte data)
_REGISTER_SESSION_REQ = struct.pack("<HHIIQIIHH", 0x0065, 4, 0, 0, 0, 0, 0, 1, 0)

# CIP GetAttributeAll for Identity Object (Class 0x01, Instance 1)
# ENIP SendRRData: Command=0x006F
_VENDOR_IDS = {
    0x01: "Rockwell Automation/Allen-Bradley",
    0x22: "OMRON Corporation",
    0x29: "Mitsubishi Electric Corp.",
    0x3A: "Schneider Automation Inc.",
    0x4F: "Molex Incorporated",
    0x78: "Siemens AG",
    0x33: "ABB Industrial Systems AB",
    0x02: "Namco Controls Corp.",
}

_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x0E: "Programmable Logic Controller",
    0x21: "Human-Machine Interface",
    0x24: "Modular I/O System",
    0x02: "AC Drive",
    0x07: "General Purpose Discrete I/O",
}


def _make_send_rr_data(session: int, cip_data: bytes) -> bytes:
    """Build ENIP SendRRData encapsulation with CIP payload."""
    # CPF: Null address (0x0000, len=0) + Unconnected data (0x00B2, len=cip_len)
    cpf = struct.pack("<HH", 0x0000, 0)
    cpf += struct.pack("<HH", 0x00B2, len(cip_data)) + cip_data
    interface_handle = struct.pack("<IH", 0, 0)  # timeout=0
    body = interface_handle + struct.pack("<H", 2) + cpf
    header = struct.pack("<HHIIQII", 0x006F, len(body), session, 0, 0, 0, 0)
    return header + body


def _cip_get_attribute_all() -> bytes:
    """CIP GetAttributeAll request for Identity Object (Class 1, Instance 1)."""
    # Service 0x01 (GetAttributeAll) | Path (2 words): Class 0x20 0x01, Instance 0x24 0x01
    return bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])


def _scan_target(host: str, port: int, timeout: int) -> Optional[dict]:
    """Connect, register session, and perform CIP GetAttributeAll on Identity Object."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # RegisterSession
        sock.sendall(_REGISTER_SESSION_REQ)
        resp = sock.recv(512)
        if len(resp) < 28:
            sock.close()
            return None
        session_handle = struct.unpack_from("<I", resp, 4)[0]
        if session_handle == 0:
            sock.close()
            return None

        # SendRRData with CIP GetAttributeAll
        cip_req = _cip_get_attribute_all()
        req = _make_send_rr_data(session_handle, cip_req)
        sock.sendall(req)
        resp2 = sock.recv(512)
        sock.close()

        if len(resp2) < 46:
            return {"session_handle": hex(session_handle), "note": "RegisterSession OK, GetAttributeAll no data"}

        # Parse CPF response — skip ENIP header (24) + interface/timeout (6) + item_count (2)
        # + NullAddress item (4) + UnconnData item header (4) = 40 bytes from start of body
        body_offset = 24 + 6 + 2
        # NullAddress: 4 bytes, UnconnData hdr: 4 bytes, CIP reply starts at offset 40
        cip_start = body_offset + 4 + 4
        if cip_start >= len(resp2):
            return {"session_handle": hex(session_handle)}

        # CIP GetAttributeAll reply layout (Identity Object Attribute 1 data):
        # Service (1) + Reserved (1) + General Status (1)
        service_reply = resp2[cip_start]
        gen_status = resp2[cip_start + 2] if len(resp2) > cip_start + 2 else 0xFF
        if service_reply != 0x81 or gen_status != 0x00:
            return {"session_handle": hex(session_handle), "status": f"CIP reply 0x{service_reply:02X}/0x{gen_status:02X}"}

        # Attribute data starts at cip_start + 4 (service, reserved, status, additional_status)
        attr_offset = cip_start + 4
        if attr_offset + 10 > len(resp2):
            return {"session_handle": hex(session_handle)}

        vendor_id, device_type, product_code = struct.unpack_from("<HHH", resp2, attr_offset)
        major_rev, minor_rev = struct.unpack_from("BB", resp2, attr_offset + 6)
        status_bits = struct.unpack_from("<H", resp2, attr_offset + 8)[0]
        serial_number = struct.unpack_from("<I", resp2, attr_offset + 10)[0]
        name_len = resp2[attr_offset + 14] if attr_offset + 14 < len(resp2) else 0
        product_name = resp2[attr_offset + 15: attr_offset + 15 + name_len].decode("ascii", errors="replace")

        return {
            "product_name": product_name,
            "vendor": _VENDOR_IDS.get(vendor_id, f"Vendor 0x{vendor_id:04X}"),
            "device_type": _DEVICE_TYPES.get(device_type, f"Type 0x{device_type:04X}"),
            "revision": f"{major_rev}.{minor_rev}",
            "serial_number": f"0x{serial_number:08X}",
            "status": f"0x{status_bits:04X}",
            "ip_address": host,
        }
    except Exception:
        return None


class Exploit(BaseExploit):
    """CIP/EtherNet/IP Device Scanner — Identity Object enumeration.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "CIP (Common Industrial Protocol) EtherNet/IP Scanner",
        "description": (
            "Connects to TCP/44818, registers an ENIP session, then issues a CIP "
            "GetAttributeAll request to the Identity Object (Class 1, Instance 1). "
            "Returns vendor, product name, device type, revision, serial number. "
            "Ported from ISF icssploit cip_scan.py using raw sockets (no Scapy)."
        ),
        "authors": (
            "wenzhe zhu <jtrkid[at]gmail.com> (ISF icssploit)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
            "https://attack.mitre.org/techniques/T0846/",
        ),
        "devices": (
            "Rockwell Allen-Bradley ControlLogix / CompactLogix",
            "OMRON NJ/NX series PLCs",
            "Schneider Electric Modicon (ENIP/CIP capable)",
            "Generic CIP devices",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(44818, "EtherNet/IP CIP port (default 44818)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def run(self) -> None:
        """Enumerate CIP Identity Object on target."""
        print_status(f"[CIP] Scanning {self.target}:{self.port}...")
        info = _scan_target(self.target, self.port, self.timeout)
        if info:
            print_success(f"[CIP] Device found on {self.target}:{self.port}")
            for key, val in info.items():
                print_success(f"  {key}: {val}")
        else:
            print_error(f"[CIP] No CIP/ENIP response from {self.target}:{self.port}")

    @mute
    def check(self) -> bool:
        """Return True if CIP RegisterSession succeeds."""
        return _scan_target(self.target, self.port, 3) is not None
