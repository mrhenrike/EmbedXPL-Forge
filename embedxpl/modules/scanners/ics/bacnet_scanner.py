# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""BACnet/IP Scanner — Enumerate Building Automation Devices (Port 47808/UDP).

Scans for BACnet/IP devices on UDP port 47808 (0xBAC0).  BACnet (Building
Automation and Control Networks) is the ISO 16484-5 standard protocol used in
HVAC, lighting, access control, fire alarm, and other building automation systems.

The scanner sends a ``Who-Is`` broadcast request and listens for ``I-Am``
responses which identify:
  - Object Identifier (device instance number)
  - Maximum APDU length accepted
  - Segmentation capability
  - Vendor ID → Vendor Name lookup

BACnet/IP has no built-in authentication; any device that responds to Who-Is
is directly accessible for further queries.

References:
  - ANSI/ASHRAE Standard 135 (BACnet)
  - ICS-CERT Advisory ICSA-15-202-01
  - MITRE ATT&CK ICS: T0846 (Remote System Discovery)

Version: 1.0.0
"""

import socket
import struct
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_BACNET_PORT = 47808  # 0xBAC0

# BACnet Virtual Link Control (BVLC) + NPDU + APDU (Who-Is)
# BVLC: Type=0x81 (BACnet/IP), Func=0x0B (Original-Broadcast-NPDU), Len=12
# NPDU: Version=1, Control=0x20 (no dest, broadcast)
# APDU: Type=0x10 (Unconfirmed-Req), Service=0x08 (Who-Is)
_WHO_IS = bytes([
    0x81, 0x0B, 0x00, 0x0C,  # BVLC header
    0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF,  # NPDU
    0x10, 0x08,  # APDU: Unconfirmed-Req, Who-Is
])

# Common BACnet Vendor IDs
_VENDOR_NAMES = {
    0: "ASHRAE",
    5: "Siemens",
    7: "Trane",
    8: "Carrier",
    10: "Johnson Controls",
    16: "Honeywell",
    24: "Andover Controls",
    36: "Alerton",
    61: "Distech Controls",
    86: "Delta Controls",
    95: "Cylon Controls",
    135: "Automated Logic",
    149: "Reliable Controls",
    260: "KMC Controls",
    309: "Daikin",
    367: "Belimo",
}


def _parse_i_am(data: bytes) -> Optional[dict]:
    """Parse a BACnet I-Am response into device information."""
    if len(data) < 12:
        return None
    # Skip BVLC (4) + NPDU variable
    offset = 4
    # Skip NPDU
    npdu_control = data[offset + 1] if len(data) > offset + 1 else 0
    npdu_len = 2
    if npdu_control & 0x20:  # destination specifier
        npdu_len += 3 + data[offset + 3] if len(data) > offset + 3 else 0
    if npdu_control & 0x08:  # source specifier
        npdu_len += 3 + data[offset + npdu_len + 1] if len(data) > offset + npdu_len + 1 else 0
    offset += npdu_len

    if offset + 4 > len(data):
        return None

    # APDU
    apdu_type = (data[offset] >> 4) & 0x0F
    service = data[offset + 1] if offset + 1 < len(data) else 0
    if apdu_type != 1 or service != 0:  # Unconfirmed-Req, I-Am
        return None

    # Object Identifier (context tag 0, 4 bytes)
    offset += 2
    result = {}
    try:
        if offset + 5 <= len(data) and data[offset] == 0xC4:
            obj_id_raw = struct.unpack(">I", data[offset + 1: offset + 5])[0]
            result["DeviceInstance"] = obj_id_raw & 0x3FFFFF
            offset += 5
        # Max APDU length (context 1)
        if offset + 3 <= len(data) and data[offset] == 0x22:
            result["MaxAPDU"] = struct.unpack(">H", data[offset + 1: offset + 3])[0]
            offset += 3
        # Vendor ID (context 3)
        if offset + 3 <= len(data) and data[offset] == 0x21:
            vendor_id = data[offset + 1]
            result["VendorID"] = vendor_id
            result["VendorName"] = _VENDOR_NAMES.get(vendor_id, "Unknown(ID={})".format(vendor_id))
            offset += 2
    except Exception:
        pass
    return result


class Exploit(BaseExploit):
    """BACnet/IP Building Automation Scanner — Who-Is / I-Am enumeration.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BACnet/IP Scanner",
        "description": (
            "Scans for BACnet/IP building automation devices on UDP/47808. Sends a "
            "Who-Is broadcast and parses I-Am responses to identify device instance "
            "numbers, vendor IDs, and APDU capabilities. BACnet/IP has no authentication "
            "— all responding devices are directly accessible."
        ),
        "authors": (
            "Project Redpoint",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://attack.mitre.org/techniques/T0846/",
            "https://github.com/digitalbond/Redpoint",
        ),
        "devices": (
            "BACnet PLC", "BMS controller", "HVAC controller",
            "Honeywell", "Siemens", "Johnson Controls", "Trane",
        ),
    }

    target = OptIP("", "Target IPv4 address (or broadcast)")
    port = OptPort(_BACNET_PORT, "BACnet/IP port (default 47808)")
    timeout = OptInteger(5, "UDP response wait timeout in seconds")

    def run(self) -> None:
        print_status("Sending BACnet Who-Is to {}:{}...".format(self.target, self.port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(_WHO_IS, (self.target, self.port))
            responses = 0
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    info = _parse_i_am(data)
                    responses += 1
                    if info:
                        print_success(
                            "I-Am from {} — Device Instance: {}, Vendor: {}".format(
                                addr[0],
                                info.get("DeviceInstance", "?"),
                                info.get("VendorName", "?"),
                            )
                        )
                    else:
                        print_success("BACnet response from {} ({} bytes)".format(addr[0], len(data)))
                except socket.timeout:
                    break
            if responses == 0:
                print_error("No BACnet devices responded — port may be filtered or no device present")
        finally:
            sock.close()

    @mute
    def check(self) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(_WHO_IS, (self.target, self.port))
            data, _ = sock.recvfrom(256)
            return bool(data)
        except Exception:
            return False
        finally:
            sock.close()
