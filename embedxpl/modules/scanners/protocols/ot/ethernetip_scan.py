# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""EtherNet/IP CIP List Identity and List Services Scanner.

Sends CIP (Common Industrial Protocol) List Identity and List Services
commands to enumerate Allen-Bradley and other EtherNet/IP devices.

References:
  - CIP Volume 2: EtherNet/IP Adaptation of CIP (ODVA)
  - EtherNet/IP Specification (ODVA)

Version: 1.0.0
"""

import socket
import struct

from embedxpl.core.exploit import *


_ENCAP_LIST_IDENTITY = 0x0063
_ENCAP_LIST_SERVICES = 0x0004
_ENCAP_HEADER_SIZE = 24
_CIP_ITEM_IDENTITY = 0x000C
_CIP_ITEM_SERVICES = 0x0100

_DEVICE_TYPES = {
    0x00: "Generic Device",
    0x02: "AC Drive",
    0x03: "Motor Overload",
    0x06: "Pneumatic Valve",
    0x07: "Communication Adapter",
    0x0C: "Communications Module",
    0x0E: "Programmable Logic Controller",
    0x10: "Position Controller",
    0x13: "DC Drive",
    0x15: "Contactor",
    0x1B: "Mass Flow Controller",
    0x21: "Safety Discrete I/O Device",
    0x2B: "Human-Machine Interface",
}

_STATUS_CODES = {
    0x0000: "Owned, configured, idle",
    0x0001: "Owned, configured, run",
    0x0010: "Unowned, unconfigured, idle",
    0x0030: "Owned, unconfigured, idle",
}


class Exploit(Exploit):
    """EtherNet/IP CIP List Identity and List Services Scanner.

    Sends UDP/TCP encapsulation commands to discover EtherNet/IP devices,
    extract product name, vendor, serial, and available CIP services.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "EtherNet/IP CIP Scanner",
        "description": (
            "Sends CIP List Identity and List Services commands via EtherNet/IP "
            "encapsulation on TCP/44818 and UDP/44818 to enumerate device identity, "
            "vendor, product name, serial number, and available services."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.odva.org/technology-standards/key-technologies/ethernet-ip/",
        ),
        "devices": (
            "Allen-Bradley ControlLogix",
            "Allen-Bradley CompactLogix",
            "Allen-Bradley MicroLogix",
            "Rockwell Automation",
            "Schneider Modicon M340",
        ),
        "severity": "info",
        "mitre": ["T0846", "T0802"],
        "status": "confirmed",
    }

    target = OptIP("", "Target EtherNet/IP device IP")
    port = OptPort(44818, "EtherNet/IP TCP/UDP port")
    timeout = OptInteger(5, "Socket timeout in seconds")
    use_udp = OptBool(True, "Use UDP for discovery (True) or TCP (False)")

    def _build_encap_header(self, command: int, data: bytes = b"") -> bytes:
        """Build EtherNet/IP encapsulation header."""
        return struct.pack(
            "<HHIIIQ",
            command,
            len(data),
            0x00000000,
            0x00000000,
            0x00000000,
            0x0000000000000000,
        ) + data

    def _send_encap_udp(self, command: int) -> bytes:
        """Send encapsulation command via UDP."""
        pkt = self._build_encap_header(command)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(self.timeout))
            sock.sendto(pkt, (self.target, int(self.port)))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return data
        except (socket.error, OSError):
            return b""

    def _send_encap_tcp(self, command: int) -> bytes:
        """Send encapsulation command via TCP."""
        pkt = self._build_encap_header(command)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, int(self.port)))
            sock.sendall(pkt)
            data = sock.recv(4096)
            sock.close()
            return data
        except (socket.error, OSError):
            return b""

    def _send_encap(self, command: int) -> bytes:
        """Send encapsulation command using configured transport."""
        if self.use_udp:
            return self._send_encap_udp(command)
        return self._send_encap_tcp(command)

    def _parse_encap_header(self, data: bytes) -> dict:
        """Parse encapsulation header."""
        if len(data) < _ENCAP_HEADER_SIZE:
            return {}
        command, length, session, status = struct.unpack("<HHII", data[:12])
        return {
            "command": command,
            "length": length,
            "session": session,
            "status": status,
        }

    def _parse_list_identity(self, data: bytes) -> dict:
        """Parse List Identity response."""
        result = {}
        if len(data) < _ENCAP_HEADER_SIZE + 4:
            return result

        payload = data[_ENCAP_HEADER_SIZE:]
        if len(payload) < 4:
            return result

        item_count = struct.unpack("<H", payload[0:2])[0]
        if item_count < 1:
            return result

        item_type = struct.unpack("<H", payload[2:4])[0]
        item_len = struct.unpack("<H", payload[4:6])[0]

        if item_type != _CIP_ITEM_IDENTITY or len(payload) < 6 + item_len:
            return result

        identity = payload[6:6 + item_len]
        if len(identity) < 33:
            return result

        result["encap_version"] = struct.unpack("<H", identity[0:2])[0]
        sock_family = struct.unpack(">H", identity[2:4])[0]
        sock_port = struct.unpack(">H", identity[4:6])[0]
        sock_addr = ".".join(str(b) for b in identity[6:10])
        result["socket_addr"] = "{}:{}".format(sock_addr, sock_port)

        result["vendor_id"] = struct.unpack("<H", identity[16:18])[0]
        result["device_type"] = struct.unpack("<H", identity[18:20])[0]
        result["device_type_name"] = _DEVICE_TYPES.get(
            result["device_type"], "Type 0x{:04X}".format(result["device_type"])
        )
        result["product_code"] = struct.unpack("<H", identity[20:22])[0]
        result["revision_major"] = identity[22]
        result["revision_minor"] = identity[23]
        result["status"] = struct.unpack("<H", identity[24:26])[0]
        result["status_text"] = _STATUS_CODES.get(
            result["status"], "0x{:04X}".format(result["status"])
        )
        result["serial"] = "{:08X}".format(struct.unpack("<I", identity[26:30])[0])

        name_len = identity[30]
        if 31 + name_len <= len(identity):
            result["product_name"] = identity[31:31 + name_len].decode(
                "ascii", errors="replace"
            )

        state_offset = 31 + name_len
        if state_offset < len(identity):
            result["state"] = identity[state_offset]

        return result

    def _parse_list_services(self, data: bytes) -> list:
        """Parse List Services response."""
        services = []
        if len(data) < _ENCAP_HEADER_SIZE + 2:
            return services

        payload = data[_ENCAP_HEADER_SIZE:]
        item_count = struct.unpack("<H", payload[0:2])[0]
        offset = 2

        for _ in range(item_count):
            if offset + 4 > len(payload):
                break
            item_type = struct.unpack("<H", payload[offset:offset + 2])[0]
            item_len = struct.unpack("<H", payload[offset + 2:offset + 4])[0]
            offset += 4
            if offset + item_len > len(payload):
                break
            item_data = payload[offset:offset + item_len]
            svc = {"type": item_type}
            if len(item_data) >= 4:
                svc["version"] = struct.unpack("<H", item_data[0:2])[0]
                svc["capability"] = struct.unpack("<H", item_data[2:4])[0]
            if len(item_data) >= 20:
                svc["name"] = item_data[4:20].decode("ascii", errors="replace").strip("\x00")
            services.append(svc)
            offset += item_len

        return services

    @mute
    def check(self) -> bool:
        """Verify EtherNet/IP port is reachable."""
        resp = self._send_encap(_ENCAP_LIST_IDENTITY)
        return len(resp) >= _ENCAP_HEADER_SIZE

    @multi
    def run(self) -> None:
        """Execute EtherNet/IP CIP discovery scan."""
        transport = "UDP" if self.use_udp else "TCP"
        print_status("Scanning EtherNet/IP at {}:{} ({})".format(
            self.target, self.port, transport
        ))

        identity_resp = self._send_encap(_ENCAP_LIST_IDENTITY)
        if not identity_resp or len(identity_resp) < _ENCAP_HEADER_SIZE:
            print_error("No response to List Identity command")
            return

        identity = self._parse_list_identity(identity_resp)
        if not identity:
            print_error("Failed to parse List Identity response")
            return

        print_success("EtherNet/IP device discovered")
        if identity.get("product_name"):
            print_info("Product: {}".format(identity["product_name"]))
        print_info("Vendor ID: {}".format(identity.get("vendor_id", "N/A")))
        print_info("Device type: {}".format(identity.get("device_type_name", "N/A")))
        print_info("Product code: {}".format(identity.get("product_code", "N/A")))
        print_info("Revision: {}.{}".format(
            identity.get("revision_major", 0), identity.get("revision_minor", 0)
        ))
        print_info("Serial: {}".format(identity.get("serial", "N/A")))
        print_info("Status: {}".format(identity.get("status_text", "N/A")))

        services_resp = self._send_encap(_ENCAP_LIST_SERVICES)
        if services_resp and len(services_resp) >= _ENCAP_HEADER_SIZE:
            services = self._parse_list_services(services_resp)
            if services:
                print_success("Available services ({})".format(len(services)))
                for svc in services:
                    cap = svc.get("capability", 0)
                    tcp_ok = bool(cap & 0x0020)
                    udp_ok = bool(cap & 0x0100)
                    transports = []
                    if tcp_ok:
                        transports.append("TCP")
                    if udp_ok:
                        transports.append("UDP")
                    print_info("  {} (v{}, {})".format(
                        svc.get("name", "unnamed"),
                        svc.get("version", 0),
                        "/".join(transports) if transports else "unknown transport",
                    ))
        else:
            print_info("List Services: no response")
