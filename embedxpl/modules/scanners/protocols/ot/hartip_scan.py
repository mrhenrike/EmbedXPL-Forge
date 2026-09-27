# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""HART-IP Server Discovery and Command 0 Scanner.

Discovers HART-IP servers on TCP/UDP 5094 and sends HART Command 0
(Read Unique Identifier) to extract device manufacturer, device type,
and firmware revision from HART field instruments.

References:
  - HART Communication Protocol Specification (FieldComm Group)
  - HART-IP Specification (IEC 62591)

Version: 1.0.0
"""

import socket
import struct

from embedxpl.core.exploit import *


_HART_IP_VERSION = 1
_HART_MSG_TYPE_REQUEST = 0
_HART_MSG_TYPE_RESPONSE = 1
_HART_MSG_TYPE_PUBLISH = 2

_HART_MSG_ID_SESSION_INIT = 0
_HART_MSG_ID_SESSION_CLOSE = 1
_HART_MSG_ID_KEEPALIVE = 2
_HART_MSG_ID_TOKEN_PASSING = 3

_HART_CMD_READ_UID = 0
_HART_CMD_READ_PRIM_VAR = 1
_HART_CMD_READ_TAG = 13

_HART_MANUFACTURERS = {
    0x00: "Not configured",
    0x1A: "Emerson (Rosemount)",
    0x26: "ABB",
    0x2A: "Honeywell",
    0x3E: "Endress+Hauser",
    0x44: "Siemens",
    0x4B: "Yokogawa",
    0x50: "Krohne",
    0x5A: "Vega",
    0x66: "Phoenix Contact",
}


class Exploit(Exploit):
    """HART-IP Server Discovery and Command 0 Scanner.

    Connects to HART-IP servers on TCP/5094 to initiate a session and
    send HART Command 0 (Read Unique Identifier) for device enumeration.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "HART-IP Server Discovery Scanner",
        "description": (
            "Discovers HART-IP servers on TCP/UDP 5094 and executes HART Command 0 "
            "(Read Unique Identifier) to extract manufacturer ID, device type, "
            "firmware revision, and unique device identifier from HART field instruments."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.fieldcommgroup.org/technologies/hart/hart-ip",
        ),
        "devices": (
            "HART-IP Gateways",
            "Emerson Rosemount",
            "Endress+Hauser",
            "ABB HART devices",
            "Yokogawa HART transmitters",
        ),
        "severity": "info",
        "mitre": ["T0846", "T0802"],
        "status": "confirmed",
    }

    target = OptIP("", "Target HART-IP server IP")
    port = OptPort(5094, "HART-IP TCP port")
    timeout = OptInteger(5, "Socket timeout in seconds")
    use_udp = OptBool(False, "Use UDP instead of TCP")

    _sequence = 0

    def _next_sequence(self) -> int:
        self._sequence = (self._sequence + 1) & 0xFFFF
        return self._sequence

    def _build_hartip_header(self, msg_type: int, msg_id: int, payload: bytes) -> bytes:
        """Build HART-IP encapsulation header."""
        seq = self._next_sequence()
        byte_count = 8 + len(payload)
        header = struct.pack(
            ">BBBHH",
            _HART_IP_VERSION,
            msg_type,
            msg_id,
            0x0000,
            seq,
        )
        header += struct.pack(">H", byte_count)
        return header + payload

    def _build_session_init(self) -> bytes:
        """Build Session Initiate request."""
        master_type = 1
        inactivity_timeout = struct.pack(">I", 30000)
        payload = struct.pack(">B", master_type) + inactivity_timeout
        return self._build_hartip_header(_HART_MSG_TYPE_REQUEST, _HART_MSG_ID_SESSION_INIT, payload)

    def _build_cmd0(self) -> bytes:
        """Build HART Command 0 (Read Unique Identifier) token-passing PDU."""
        delimiter = 0x82
        address = bytes([0x80, 0x00, 0x00, 0x00, 0x00])
        command = _HART_CMD_READ_UID
        byte_count = 0
        pdu = struct.pack(">B", delimiter) + address + struct.pack(">BB", command, byte_count)
        checksum = 0
        for b in pdu:
            checksum ^= b
        pdu += struct.pack(">B", checksum)
        return self._build_hartip_header(
            _HART_MSG_TYPE_REQUEST, _HART_MSG_ID_TOKEN_PASSING, pdu
        )

    def _tcp_connect(self) -> socket.socket:
        """Establish TCP connection to HART-IP server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(self.timeout))
        sock.connect((self.target, int(self.port)))
        return sock

    def _udp_socket(self) -> socket.socket:
        """Create UDP socket for HART-IP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(float(self.timeout))
        return sock

    def _send_recv_tcp(self, sock: socket.socket, data: bytes) -> bytes:
        """Send and receive via TCP."""
        sock.sendall(data)
        return sock.recv(4096)

    def _send_recv_udp(self, data: bytes) -> bytes:
        """Send and receive via UDP."""
        sock = self._udp_socket()
        sock.sendto(data, (self.target, int(self.port)))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return resp

    def _send_recv(self, sock, data: bytes) -> bytes:
        """Send/receive using configured transport."""
        if self.use_udp:
            return self._send_recv_udp(data)
        return self._send_recv_tcp(sock, data)

    def _parse_hartip_header(self, data: bytes) -> dict:
        """Parse HART-IP response header."""
        if len(data) < 8:
            return {}
        version, msg_type, msg_id, status, sequence = struct.unpack(">BBBHH", data[:7])
        byte_count = struct.unpack(">H", data[7:9])[0] if len(data) >= 9 else 0
        return {
            "version": version,
            "msg_type": msg_type,
            "msg_id": msg_id,
            "status": status,
            "sequence": sequence,
            "byte_count": byte_count,
        }

    def _parse_cmd0_response(self, data: bytes) -> dict:
        """Parse HART Command 0 response PDU."""
        result = {}
        if len(data) < 20:
            return result

        header = self._parse_hartip_header(data)
        if not header or header["msg_id"] != _HART_MSG_ID_TOKEN_PASSING:
            return result

        pdu_offset = 8
        if pdu_offset >= len(data):
            return result

        pdu = data[pdu_offset:]
        if len(pdu) < 8:
            return result

        delimiter = pdu[0]
        address = pdu[1:6]
        command = pdu[6]
        byte_count = pdu[7]

        if command != _HART_CMD_READ_UID or byte_count == 0:
            return result

        resp_data = pdu[8:8 + byte_count]
        if len(resp_data) < 2:
            return result

        resp_code = resp_data[0]
        device_status = resp_data[1]
        result["response_code"] = resp_code
        result["device_status"] = device_status

        if len(resp_data) >= 14:
            result["expansion_code"] = resp_data[2]
            manufacturer_id = resp_data[3]
            result["manufacturer_id"] = manufacturer_id
            result["manufacturer"] = _HART_MANUFACTURERS.get(
                manufacturer_id, "ID 0x{:02X}".format(manufacturer_id)
            )
            result["device_type"] = struct.unpack(">H", resp_data[4:6])[0]
            result["preambles_required"] = resp_data[6]
            result["universal_rev"] = resp_data[7]
            result["transmitter_rev"] = resp_data[8]
            result["software_rev"] = resp_data[9]
            result["hardware_rev"] = resp_data[10]
            result["flags"] = resp_data[11]
            if len(resp_data) >= 17:
                device_id = resp_data[14:17]
                result["device_id"] = device_id.hex().upper()

        return result

    @mute
    def check(self) -> bool:
        """Verify HART-IP port is reachable."""
        try:
            if self.use_udp:
                sock = self._udp_socket()
                sock.sendto(b"\x00", (self.target, int(self.port)))
                sock.close()
            else:
                sock = self._tcp_connect()
                sock.close()
            return True
        except (socket.error, OSError):
            return False

    @multi
    def run(self) -> None:
        """Execute HART-IP discovery and Command 0 scan."""
        transport = "UDP" if self.use_udp else "TCP"
        print_status("Scanning HART-IP at {}:{} ({})".format(
            self.target, self.port, transport
        ))

        if not self.check():
            print_error("HART-IP port {} not reachable".format(self.port))
            return

        sock = None
        try:
            if not self.use_udp:
                sock = self._tcp_connect()

            init_pkt = self._build_session_init()
            init_resp = self._send_recv(sock, init_pkt)
            init_header = self._parse_hartip_header(init_resp)

            if not init_header:
                print_error("No valid HART-IP response")
                return

            if init_header["status"] != 0:
                print_warning("Session init returned status {}".format(init_header["status"]))
            else:
                print_success("HART-IP session established (v{})".format(init_header["version"]))

            cmd0_pkt = self._build_cmd0()
            cmd0_resp = self._send_recv(sock, cmd0_pkt)
            device = self._parse_cmd0_response(cmd0_resp)

            if not device:
                print_warning("Command 0 response not parseable or empty")
                return

            print_success("HART device identified")
            if device.get("manufacturer"):
                print_info("Manufacturer: {}".format(device["manufacturer"]))
            print_info("Device type: 0x{:04X}".format(device.get("device_type", 0)))
            if device.get("device_id"):
                print_info("Device ID: {}".format(device["device_id"]))
            print_info("Universal rev: {}".format(device.get("universal_rev", "N/A")))
            print_info("Transmitter rev: {}".format(device.get("transmitter_rev", "N/A")))
            print_info("Software rev: {}".format(device.get("software_rev", "N/A")))
            print_info("Hardware rev: {}".format(device.get("hardware_rev", "N/A")))

        except (socket.error, OSError) as exc:
            print_error("Communication error: {}".format(exc))
        finally:
            if sock:
                sock.close()
