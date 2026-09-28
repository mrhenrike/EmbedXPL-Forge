# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""S7comm Device Information and CPU State Scanner.

Connects to Siemens S7 PLCs via the S7comm protocol on TCP/102 to
extract device info, CPU state, firmware version, and module data.

References:
  - Siemens S7comm protocol (reverse-engineered specification)
  - RFC 1006 (ISO-on-TCP / TPKT)

Version: 1.0.0
"""

import socket
import struct

from embedxpl.core.exploit import *


_TPKT_VERSION = 3
_COTP_CR = 0xE0
_COTP_DT = 0xF0
_S7_PROTOCOL_ID = 0x32
_S7_JOB = 0x01
_S7_ACK_DATA = 0x03
_S7_FUNC_READ_SZL = 0x44
_S7_USERDATA = 0x07

_COTP_CONNECT = (
    b"\x03\x00\x00\x16"
    b"\x11\xe0\x00\x00\x00\x01\x00"
    b"\xc0\x01\x0a"
    b"\xc1\x02\x01\x00"
    b"\xc2\x02\x01\x02"
)

_S7_SETUP = (
    b"\x03\x00\x00\x19"
    b"\x02\xf0\x80"
    b"\x32\x01\x00\x00\x04\x00\x00\x08\x00\x00"
    b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
)

_SZL_IDS = {
    0x0011: "Module Identification",
    0x001C: "Component Identification",
    0x0014: "CPU Characteristics",
    0x0019: "CPU Status",
    0x0074: "Module LED Status",
    0x0131: "Communication Parameters",
    0x0132: "CPU Protection Level",
}


class Exploit(Exploit):
    """S7comm Device Information and CPU State Scanner.

    Establishes COTP/TPKT session to Siemens S7 PLCs and reads SZL
    (System Status List) entries for device info, CPU state, and firmware.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "S7comm Device Information Scanner",
        "description": (
            "Connects to Siemens S7 PLCs via S7comm on TCP/102 to extract module "
            "identification, CPU state, firmware version, and protection level "
            "by reading SZL (System Status List) entries."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/thomas-wink/s7comm-dissector",
        ),
        "devices": (
            "Siemens S7-300", "Siemens S7-400", "Siemens S7-1200", "Siemens S7-1500",
        ),
        "severity": "info",
        "mitre": ["T0846", "T0802"],
        "status": "confirmed",
    }

    target = OptIP("", "Target S7 PLC IP address")
    port = OptPort(102, "S7comm TCP port (ISO-on-TCP)")
    timeout = OptInteger(5, "Socket timeout in seconds")
    rack = OptInteger(0, "PLC rack number")
    slot = OptInteger(2, "PLC slot number")

    def _tcp_connect(self) -> socket.socket:
        """Establish TCP connection to target."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(float(self.timeout))
        sock.connect((self.target, int(self.port)))
        return sock

    def _send_recv(self, sock: socket.socket, data: bytes) -> bytes:
        """Send data and receive TPKT-framed response."""
        sock.sendall(data)
        header = sock.recv(4)
        if len(header) < 4:
            return b""
        pkt_len = struct.unpack(">H", header[2:4])[0]
        remaining = pkt_len - 4
        payload = b""
        while len(payload) < remaining:
            chunk = sock.recv(remaining - len(payload))
            if not chunk:
                break
            payload += chunk
        return header + payload

    def _cotp_connect(self, sock: socket.socket) -> bool:
        """Establish COTP connection (ISO 8073 CR/CC)."""
        dst_tsap = (int(self.rack) << 4) | int(self.slot)
        cr = bytearray(_COTP_CONNECT)
        cr[15] = 0x01
        cr[17] = dst_tsap
        resp = self._send_recv(sock, bytes(cr))
        if len(resp) < 7:
            return False
        return resp[5] == 0xD0

    def _s7_negotiate(self, sock: socket.socket) -> bool:
        """S7comm communication setup (negotiate PDU size)."""
        resp = self._send_recv(sock, _S7_SETUP)
        if len(resp) < 12:
            return False
        return resp[8] == _S7_PROTOCOL_ID

    def _build_szl_request(self, szl_id: int, szl_index: int = 0x0000) -> bytes:
        """Build S7comm SZL read request."""
        s7_params = struct.pack(
            ">BBBBBBBBBBBH",
            0x00, 0x01, 0x12, 0x04, 0x11,
            _S7_FUNC_READ_SZL, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        )
        s7_data = struct.pack(">HHH", 0x0004, szl_id, szl_index)
        s7_header = struct.pack(
            ">BBHHHHH",
            _S7_PROTOCOL_ID, _S7_USERDATA,
            0x0000, 0x0001,
            len(s7_params), len(s7_data), 0x0000,
        )
        cotp_dt = b"\x02\xf0\x80"
        payload = cotp_dt + s7_header + s7_params + s7_data
        tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, len(payload) + 4) + payload
        return tpkt

    def _parse_szl_response(self, data: bytes) -> bytes:
        """Extract SZL data payload from S7comm response."""
        if len(data) < 27:
            return b""
        s7_offset = 7
        if data[s7_offset] != _S7_PROTOCOL_ID:
            return b""
        param_len = struct.unpack(">H", data[s7_offset + 6:s7_offset + 8])[0]
        data_len = struct.unpack(">H", data[s7_offset + 8:s7_offset + 10])[0]
        data_offset = s7_offset + 12 + param_len
        if data_offset + 4 > len(data):
            return b""
        return data[data_offset + 4:data_offset + data_len]

    def _read_szl(self, sock: socket.socket, szl_id: int) -> bytes:
        """Read a single SZL entry from the PLC."""
        req = self._build_szl_request(szl_id)
        resp = self._send_recv(sock, req)
        return self._parse_szl_response(resp)

    def _parse_module_id(self, data: bytes) -> dict:
        """Parse SZL 0x0011 (Module Identification)."""
        result = {}
        if len(data) < 28:
            return result
        result["order_number"] = data[2:22].decode("ascii", errors="replace").strip("\x00 ")
        result["firmware_version"] = "V{}.{}.{}".format(data[24], data[25], data[26])
        return result

    def _parse_component_id(self, data: bytes) -> dict:
        """Parse SZL 0x001C (Component Identification)."""
        result = {}
        if len(data) < 34:
            return result
        result["component_name"] = data[2:26].decode("ascii", errors="replace").strip("\x00 ")
        return result

    def _parse_cpu_state(self, data: bytes) -> str:
        """Parse SZL 0x0019 data for CPU run/stop state."""
        if len(data) < 4:
            return "Unknown"
        state_byte = data[2]
        states = {0x00: "Unknown", 0x01: "Stop", 0x02: "Startup", 0x04: "Run", 0x08: "Hold"}
        return states.get(state_byte, "Unknown (0x{:02x})".format(state_byte))

    def _parse_protection(self, data: bytes) -> str:
        """Parse SZL 0x0132 for CPU protection level."""
        if len(data) < 4:
            return "Unknown"
        level = data[2]
        levels = {
            0x00: "No protection",
            0x01: "Write protection",
            0x02: "Read/write protection",
            0x03: "Full protection",
        }
        return levels.get(level, "Level {} (0x{:02x})".format(level, level))

    @mute
    def check(self) -> bool:
        """Verify S7comm port is reachable."""
        try:
            sock = self._tcp_connect()
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    @multi
    def run(self) -> None:
        """Execute S7comm device information scan."""
        print_status("Scanning S7comm at {}:{} (rack={}, slot={})".format(
            self.target, self.port, self.rack, self.slot
        ))

        if not self.check():
            print_error("S7comm port {} not reachable".format(self.port))
            return

        try:
            sock = self._tcp_connect()
        except (socket.error, OSError) as exc:
            print_error("Connection failed: {}".format(exc))
            return

        try:
            if not self._cotp_connect(sock):
                print_error("COTP connection rejected")
                return
            print_success("COTP session established")

            if not self._s7_negotiate(sock):
                print_error("S7comm negotiation failed")
                return
            print_success("S7comm session established")

            module_data = self._read_szl(sock, 0x0011)
            if module_data:
                info = self._parse_module_id(module_data)
                if info.get("order_number"):
                    print_success("Order number: {}".format(info["order_number"]))
                if info.get("firmware_version"):
                    print_info("Firmware: {}".format(info["firmware_version"]))

            comp_data = self._read_szl(sock, 0x001C)
            if comp_data:
                comp = self._parse_component_id(comp_data)
                if comp.get("component_name"):
                    print_info("Component: {}".format(comp["component_name"]))

            state_data = self._read_szl(sock, 0x0019)
            cpu_state = self._parse_cpu_state(state_data) if state_data else "N/A"
            print_info("CPU state: {}".format(cpu_state))

            prot_data = self._read_szl(sock, 0x0132)
            protection = self._parse_protection(prot_data) if prot_data else "N/A"
            print_info("Protection: {}".format(protection))

        finally:
            sock.close()
