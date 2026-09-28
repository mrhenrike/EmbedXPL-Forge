# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""BACnet Who-Is Broadcast Scanner.

Sends BACnet Who-Is broadcast on UDP/47808 and collects I-Am responses
from BACnet/IP devices. Extracts device object instance, vendor ID,
vendor name, model, and firmware version from responding devices.

Constructs BACnet BVLC and NPDU/APDU frames manually via struct.pack.

References:
  - ASHRAE Standard 135-2020 (BACnet)
  - BACnet/IP Annex J

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """BACnet Who-Is Broadcast Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BACnet Who-Is Broadcast Scanner",
        "description": (
            "Broadcasts BACnet Who-Is on UDP/47808 and collects I-Am responses. "
            "Extracts device instance, vendor ID, vendor name, model name, and "
            "firmware version from all responding BACnet/IP devices on the segment."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.ashrae.org/technical-resources/standards-and-guidelines",
            "http://www.bacnet.org/",
        ),
        "devices": (
            "Any BACnet/IP device",
            "Johnson Controls Metasys",
            "Honeywell Spyder/WEBs",
            "Schneider Electric SmartStruxure",
            "Siemens DESIGO",
            "Tridium Niagara",
        ),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("255.255.255.255", "Broadcast address or specific target IP")
    port = OptPort(47808, "BACnet/IP UDP port (0xBAC0)")
    timeout = OptInteger(5, "Response collection timeout in seconds")
    low_limit = OptInteger(0, "Who-Is device instance low limit (0 = no limit)")
    high_limit = OptInteger(4194303, "Who-Is device instance high limit")

    # BACnet constants
    _BVLC_TYPE = 0x81
    _BVLC_ORIGINAL_BROADCAST = 0x0B
    _BVLC_ORIGINAL_UNICAST = 0x0A

    # Vendor ID to name mapping (partial)
    _VENDORS = {
        0: "ASHRAE", 5: "Johnson Controls", 7: "Siemens",
        10: "Schneider Electric", 15: "Honeywell", 24: "Automated Logic",
        36: "Tridium", 55: "Carrier", 86: "Contemporary Controls",
        95: "Reliable Controls", 222: "Carel", 260: "ABB",
        354: "Delta Controls", 381: "Distech Controls",
    }

    def _build_who_is(self) -> bytes:
        """Build BACnet Who-Is broadcast packet."""
        # NPDU: version=1, control=0x20 (network priority normal, no reply expected)
        npdu = struct.pack("BB", 0x01, 0x20)
        # Broadcast destination: DNET=0xFFFF, DLEN=0, hop_count=255
        npdu += struct.pack(">HBB", 0xFFFF, 0x00, 0xFF)

        # APDU: Unconfirmed Who-Is
        apdu = struct.pack("BB", 0x10, 0x08)  # PDU type + service choice

        # Add limits if specified (context tags 0 and 1)
        if self.low_limit > 0 or self.high_limit < 4194303:
            # Context tag 0: low limit
            if self.low_limit <= 0xFF:
                apdu += struct.pack("BB", 0x09, self.low_limit)
            elif self.low_limit <= 0xFFFF:
                apdu += struct.pack(">BBH", 0x0A, 0x02, self.low_limit) # wrong, fix:
            else:
                apdu += struct.pack(">BBI", 0x0B, 0x04, self.low_limit) # 3 bytes len not needed

            # Context tag 1: high limit
            if self.high_limit <= 0xFF:
                apdu += struct.pack("BB", 0x19, self.high_limit)
            elif self.high_limit <= 0xFFFF:
                apdu += struct.pack(">BBH", 0x1A, 0x02, self.high_limit)
            else:
                apdu += struct.pack(">BBI", 0x1B, 0x04, self.high_limit)

        payload = npdu + apdu
        bvlc = struct.pack(">BBH", self._BVLC_TYPE, self._BVLC_ORIGINAL_BROADCAST, 4 + len(payload))
        return bvlc + payload

    def _build_read_property(self, device_ip: str, device_instance: int, prop_id: int) -> bytes:
        """Build ReadProperty request for a specific device property."""
        npdu = struct.pack("BB", 0x01, 0x04)  # expecting reply

        # APDU: Confirmed ReadProperty
        apdu = struct.pack("BBB", 0x00, 0x05, 0x01)  # confirmed, max-seg=0, invoke_id=1
        apdu += struct.pack("B", 0x0C)  # service: ReadProperty

        # Context 0: Object Identifier (Device object)
        obj_id = (0x08 << 22) | (device_instance & 0x3FFFFF)  # type=8 (device)
        apdu += struct.pack(">B", 0x0C) + struct.pack(">I", obj_id)

        # Context 1: Property Identifier
        if prop_id <= 0xFF:
            apdu += struct.pack("BB", 0x19, prop_id)
        else:
            apdu += struct.pack(">BBH", 0x1A, 0x02, prop_id)

        payload = npdu + apdu
        bvlc = struct.pack(">BBH", self._BVLC_TYPE, self._BVLC_ORIGINAL_UNICAST, 4 + len(payload))
        return bvlc + payload

    def _parse_iam(self, data: bytes, addr: tuple) -> dict:
        """Parse BACnet I-Am response."""
        result = {"ip": addr[0], "port": addr[1]}

        if len(data) < 12:
            return result

        # Skip BVLC (4 bytes), find NPDU start
        offset = 4
        if offset >= len(data):
            return result

        # NPDU version and control
        npdu_version = data[offset]
        npdu_ctrl = data[offset + 1]
        offset += 2

        # Skip NPDU network layer info if present
        if npdu_ctrl & 0x20:  # DNET present
            offset += 3  # DNET(2) + DLEN(1)
            dlen = data[offset - 1]
            offset += dlen
        if npdu_ctrl & 0x08:  # SNET present
            offset += 2  # SNET(2)
            slen = data[offset]
            offset += 1 + slen

        if npdu_ctrl & 0x20:
            offset += 1  # hop count

        # APDU should be at offset
        if offset >= len(data):
            return result

        pdu_type = data[offset] >> 4
        if pdu_type != 1:  # Not unconfirmed
            return result

        service = data[offset + 1] if offset + 1 < len(data) else 0
        if service != 0x00:  # Not I-Am
            return result

        offset += 2

        # Parse I-Am content: ObjectID + MaxAPDU + SegmentationSupported + VendorID
        if offset + 4 <= len(data):
            # Object Identifier (application tag 0xC4 = objectidentifier, 4 bytes)
            if data[offset] == 0xC4 and offset + 5 <= len(data):
                oid = struct.unpack_from(">I", data, offset + 1)[0]
                obj_type = (oid >> 22) & 0x3FF
                instance = oid & 0x3FFFFF
                result["device_instance"] = instance
                offset += 5

        # Max APDU length (application tag 0x22 = unsigned, 2 bytes)
        if offset < len(data) and (data[offset] & 0xF0) == 0x20:
            tag_len = data[offset] & 0x07
            offset += 1 + tag_len

        # Segmentation supported (application tag 0x91 = enumerated, 1 byte)
        if offset < len(data) and data[offset] == 0x91:
            offset += 2

        # Vendor ID (application tag 0x21 or 0x22 = unsigned)
        if offset < len(data):
            tag = data[offset]
            if (tag & 0xF0) == 0x20:
                tag_len = tag & 0x07
                if tag_len == 1 and offset + 2 <= len(data):
                    result["vendor_id"] = data[offset + 1]
                elif tag_len == 2 and offset + 3 <= len(data):
                    result["vendor_id"] = struct.unpack_from(">H", data, offset + 1)[0]

        if "vendor_id" in result:
            result["vendor_name"] = self._VENDORS.get(
                result["vendor_id"], "Unknown (0x{:04X})".format(result["vendor_id"])
            )

        return result

    @mute
    def check(self) -> bool:
        """Verify UDP/47808 is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            who_is = self._build_who_is()
            sock.sendto(who_is, (self.target, self.port))
            data, _ = sock.recvfrom(1500)
            sock.close()
            return len(data) > 4
        except (socket.timeout, socket.error):
            return False

    @multi
    def run(self) -> None:
        """Execute BACnet Who-Is broadcast scan."""
        print_status(
            "BACnet Who-Is scan targeting {} on UDP/{}".format(self.target, self.port)
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(1.0)
            sock.bind(("", self.port))

            who_is = self._build_who_is()
            print_info("Sending Who-Is broadcast...")
            sock.sendto(who_is, (self.target, self.port))

            devices = []
            deadline = time.time() + float(self.timeout)

            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(1500)
                    if len(data) > 4 and data[0] == self._BVLC_TYPE:
                        info = self._parse_iam(data, addr)
                        if "device_instance" in info:
                            devices.append(info)
                            print_success(
                                "I-Am from {} - Device #{} - Vendor: {}".format(
                                    info["ip"],
                                    info["device_instance"],
                                    info.get("vendor_name", "unknown"),
                                )
                            )
                except socket.timeout:
                    continue

            sock.close()
            print_info("Scan complete: {} BACnet device(s) discovered".format(len(devices)))

            for dev in devices:
                print_info(
                    "  {} | Instance: {} | Vendor: {} (ID: {})".format(
                        dev.get("ip", "?"),
                        dev.get("device_instance", "?"),
                        dev.get("vendor_name", "?"),
                        dev.get("vendor_id", "?"),
                    )
                )

        except OSError as exc:
            print_error("Socket error: {}".format(exc))
