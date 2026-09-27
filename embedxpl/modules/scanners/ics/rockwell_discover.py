# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Rockwell CompactLogix / EtherNet-IP — List Identity Scanner.

Discovers Rockwell PLC devices via EtherNet/IP ListIdentity broadcast on port 44818.

Version: 1.0.0
"""

import socket
import struct
import threading
from typing import List

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_EIP_PORT = 44818
_LIST_IDENTITY = bytes([
    0x63, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
])


class Exploit(BaseExploit):
    """Rockwell EtherNet/IP ListIdentity Scanner.

    Sends EIP ListIdentity requests to discover CompactLogix/ControlLogix
    PLCs and other CIP devices on the network, extracting product name,
    vendor, device type, and IP address information.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Rockwell EtherNet/IP ListIdentity Scanner",
        "description": (
            "Discovers Rockwell CompactLogix/ControlLogix PLCs and other CIP devices "
            "via EtherNet/IP ListIdentity on port 44818. Extracts product name, "
            "vendor ID, device type, and serial number."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://literature.rockwellautomation.com/idc/groups/literature/documents/rm/enet-rm002_-en-p.pdf",
        ),
        "devices": (
            "Rockwell Allen-Bradley CompactLogix",
            "Rockwell Allen-Bradley ControlLogix",
            "Any EtherNet/IP CIP device",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(_EIP_PORT, "EtherNet/IP TCP port")
    timeout = OptInteger(5, "Connection timeout")

    def run(self) -> None:
        print_status("Sending EIP ListIdentity to {}:{}...".format(self.target, self.port))

        try:
            sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
            sock.sendall(_LIST_IDENTITY)
            sock.settimeout(self.timeout)
            data = sock.recv(1024)
            sock.close()

            if len(data) < 24:
                print_error("Response too short — not a valid EIP device")
                return

            cmd = struct.unpack_from("<H", data, 0)[0]
            status = struct.unpack_from("<I", data, 8)[0]
            print_success("EIP ListIdentity response from {}".format(self.target))
            print_status("  Command: 0x{:04X}  Status: 0x{:08X}".format(cmd, status))

            # Parse identity items (starts at offset 24)
            if len(data) > 26:
                item_count = struct.unpack_from("<H", data, 24)[0]
                print_status("  Items: {}".format(item_count))

                offset = 26
                for _ in range(min(item_count, 5)):
                    if offset + 4 > len(data):
                        break
                    item_type = struct.unpack_from("<H", data, offset)[0]
                    item_len = struct.unpack_from("<H", data, offset + 2)[0]
                    if item_type == 0x000C:  # Identity Item
                        # vendor_id at +4, device_type at +6, product_code at +8
                        if offset + 4 + 14 <= len(data):
                            vendor_id = struct.unpack_from("<H", data, offset + 4)[0]
                            device_type = struct.unpack_from("<H", data, offset + 6)[0]
                            fw_major = data[offset + 16] if offset + 16 < len(data) else 0
                            fw_minor = data[offset + 17] if offset + 17 < len(data) else 0
                            name_len = data[offset + 4 + 24] if offset + 4 + 24 < len(data) else 0
                            name = ""
                            if name_len and offset + 4 + 25 + name_len <= len(data):
                                name = data[offset + 4 + 25:offset + 4 + 25 + name_len].decode(
                                    "ascii", errors="replace"
                                )
                            print_success(
                                "  Vendor={} DevType={} FW={}.{} Name={}".format(
                                    vendor_id, device_type, fw_major, fw_minor, name
                                )
                            )
                    offset += 4 + item_len

        except Exception as e:
            print_error("EIP discovery failed: {}".format(e))

    @mute
    def check(self) -> bool:
        try:
            sock = socket.create_connection((self.target, self.port), timeout=3)
            sock.sendall(_LIST_IDENTITY)
            sock.settimeout(3)
            data = sock.recv(64)
            sock.close()
            return len(data) >= 4
        except Exception:
            return False
