# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""PROFINET DCP Identify All Scanner.

Discovers PROFINET devices on the local Layer 2 segment via DCP Identify
All multicast on raw Ethernet (EtherType 0x8892). Extracts device name,
IP configuration, MAC address, vendor ID, and device type.

Requires raw socket access (AF_PACKET on Linux).

References:
  - IEC 61158 / IEC 61784 (PROFINET)
  - PROFINET System Description

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """PROFINET DCP Identify All Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "PROFINET DCP Identify All Scanner",
        "description": (
            "Discovers PROFINET IO devices via DCP Identify All multicast "
            "on raw Ethernet frames. Extracts device name, IP, MAC, vendor "
            "ID, and device type from all responding PROFINET devices."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.profinet.com/",
            "https://www.profibus.com/technology/profinet/",
        ),
        "devices": (
            "Siemens S7-1200/S7-1500",
            "Siemens ET200SP/ET200MP",
            "Phoenix Contact PROFINET IO",
            "Beckhoff EK1100",
            "Wago 750-375",
            "Any PROFINET IO Device/Controller",
        ),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    interface = OptString("eth0", "Network interface for raw socket")
    timeout = OptInteger(5, "Response collection timeout in seconds")

    # PROFINET DCP constants
    _ETHERTYPE_PN = 0x8892
    _DCP_MULTICAST_DST = b"\x01\x0e\xcf\x00\x00\x00"
    _FRAME_ID_IDENTIFY_REQ = 0xFEFE
    _FRAME_ID_IDENTIFY_RSP = 0xFEFF
    _DCP_SVC_IDENTIFY = 0x05
    _DCP_SVC_TYPE_REQ = 0x00

    # Vendor database (partial)
    _VENDORS = {
        0x002A: "Siemens AG",
        0x00B0: "Phoenix Contact",
        0x0113: "Beckhoff Automation",
        0x0119: "Wago Kontakttechnik",
        0x0134: "Turck",
        0x015E: "Pilz",
        0x028A: "Murrelektronik",
    }

    def _get_src_mac(self) -> bytes:
        """Retrieve local MAC address from interface."""
        try:
            import fcntl
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(
                sock.fileno(), 0x8927,
                struct.pack("256s", self.interface.encode("utf-8")[:15])
            )
            sock.close()
            return info[18:24]
        except (ImportError, OSError):
            return b"\x02\x00\x00\x00\x00\x01"

    def _build_identify_all(self, src_mac: bytes) -> bytes:
        """Build DCP Identify All multicast Ethernet frame."""
        # Ethernet: dst(6) + src(6) + EtherType(2)
        eth = self._DCP_MULTICAST_DST + src_mac
        eth += struct.pack(">H", self._ETHERTYPE_PN)

        # DCP: FrameID(2) + ServiceID(1) + ServiceType(1) + Xid(4) +
        #      ResponseDelay(2) + DataLength(2)
        xid = int(time.time()) & 0xFFFFFFFF
        dcp = struct.pack(
            ">HBB I HH",
            self._FRAME_ID_IDENTIFY_REQ,
            self._DCP_SVC_IDENTIFY,
            self._DCP_SVC_TYPE_REQ,
            xid,
            0x0080,  # response delay (128 * 10ms)
            4,  # data length (block below)
        )

        # Block: identify all (option=0xFF, suboption=0xFF)
        block = struct.pack(">BBH", 0xFF, 0xFF, 0x0000)

        frame = eth + dcp + block
        # Pad to 60 bytes minimum
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))
        return frame

    def _parse_response(self, frame: bytes) -> dict:
        """Parse DCP Identify Response frame."""
        result = {}
        if len(frame) < 28:
            return result

        # Source MAC from Ethernet header
        src_mac = frame[6:12]
        result["mac"] = ":".join("{:02x}".format(b) for b in src_mac)

        # Verify EtherType
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype != self._ETHERTYPE_PN:
            return result

        # DCP header at offset 14
        frame_id = struct.unpack_from(">H", frame, 14)[0]
        if frame_id != self._FRAME_ID_IDENTIFY_RSP:
            return result

        data_len = struct.unpack_from(">H", frame, 22)[0]
        offset = 24
        end = min(offset + data_len, len(frame))

        while offset + 4 <= end:
            opt = frame[offset]
            subopt = frame[offset + 1]
            block_len = struct.unpack_from(">H", frame, offset + 2)[0]
            offset += 4

            if offset + block_len > end:
                break

            block_data = frame[offset:offset + block_len]

            # Parse block content based on option/suboption
            if opt == 0x02 and subopt == 0x01:
                # Name of Station (skip 2-byte block info)
                if len(block_data) >= 2:
                    result["name"] = block_data[2:].decode("ascii", errors="replace").rstrip("\x00")
            elif opt == 0x01 and subopt == 0x02:
                # IP parameter (skip 2 bytes block info)
                if len(block_data) >= 14:
                    ip = block_data[2:6]
                    mask = block_data[6:10]
                    gw = block_data[10:14]
                    result["ip"] = ".".join(str(b) for b in ip)
                    result["netmask"] = ".".join(str(b) for b in mask)
                    result["gateway"] = ".".join(str(b) for b in gw)
            elif opt == 0x02 and subopt == 0x02:
                # IP address (alternative encoding)
                if len(block_data) >= 14:
                    result["ip"] = ".".join(str(b) for b in block_data[2:6])
            elif opt == 0x02 and subopt == 0x03:
                # Device ID: Vendor ID (2) + Device ID (2)
                if len(block_data) >= 6:
                    vendor_id = struct.unpack_from(">H", block_data, 2)[0]
                    device_id = struct.unpack_from(">H", block_data, 4)[0]
                    result["vendor_id"] = vendor_id
                    result["device_id"] = device_id
                    result["vendor_name"] = self._VENDORS.get(
                        vendor_id, "Unknown (0x{:04X})".format(vendor_id)
                    )
            elif opt == 0x02 and subopt == 0x04:
                # Device role
                if len(block_data) >= 4:
                    role = struct.unpack_from(">H", block_data, 2)[0]
                    roles = []
                    if role & 0x01:
                        roles.append("IO-Device")
                    if role & 0x02:
                        roles.append("IO-Controller")
                    if role & 0x04:
                        roles.append("IO-Multidevice")
                    if role & 0x08:
                        roles.append("IO-Supervisor")
                    result["role"] = ", ".join(roles) if roles else "0x{:04X}".format(role)
            elif opt == 0x02 and subopt == 0x05:
                # Device options / instance
                if len(block_data) >= 2:
                    result["device_instance"] = block_data[2:].decode(
                        "ascii", errors="replace"
                    ).rstrip("\x00")

            # Align to 16-bit boundary
            offset += block_len
            if block_len % 2 != 0:
                offset += 1

        return result

    @mute
    def check(self) -> bool:
        """Verify raw socket capability."""
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self._ETHERTYPE_PN)
            )
            sock.bind((self.interface, 0))
            sock.close()
            return True
        except (OSError, AttributeError):
            return False

    def run(self) -> None:
        """Execute PROFINET DCP Identify All scan."""
        print_status("PROFINET DCP scan on interface {}".format(self.interface))

        if not self.check():
            print_error("Raw socket not available (requires root/AF_PACKET)")
            return

        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self._ETHERTYPE_PN)
            )
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)

            src_mac = self._get_src_mac()
            identify_frame = self._build_identify_all(src_mac)

            print_info("Sending DCP Identify All multicast...")
            sock.send(identify_frame)

            devices = []
            deadline = time.time() + float(self.timeout)

            while time.time() < deadline:
                try:
                    data = sock.recv(1518)
                    if len(data) < 28:
                        continue
                    info = self._parse_response(data)
                    if info and "mac" in info:
                        # Avoid duplicates
                        if not any(d["mac"] == info["mac"] for d in devices):
                            devices.append(info)
                            print_success(
                                "Device: {} | MAC: {} | IP: {} | Vendor: {} | Role: {}".format(
                                    info.get("name", "unnamed"),
                                    info["mac"],
                                    info.get("ip", "no-ip"),
                                    info.get("vendor_name", "unknown"),
                                    info.get("role", "?"),
                                )
                            )
                except socket.timeout:
                    continue

            sock.close()
            print_info(
                "Scan complete: {} PROFINET device(s) discovered".format(len(devices))
            )

        except OSError as exc:
            print_error("Socket error: {}".format(exc))
