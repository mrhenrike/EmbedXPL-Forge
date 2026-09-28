"""
EmbedXPL-Forge — EtherNet/IP (CIP) Client
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Python 3 raw-socket implementation of EtherNet/IP Encapsulation and CIP.
Ported and modernised from ISF CIPClient (original: WenZhe Zhu / ICSsploit).

Default port: 44818 (TCP).  UDP discovery: 2222.
"""

import socket
import struct
import logging
from typing import Optional, Dict, Tuple


# EtherNet/IP command codes
ENIP_REGISTER_SESSION = 0x0065
ENIP_UNREGISTER_SESSION = 0x0066
ENIP_LIST_IDENTITY = 0x0063
ENIP_LIST_INTERFACES = 0x0064
ENIP_SEND_RR_DATA = 0x006F
ENIP_SEND_UNIT_DATA = 0x0070

DEVICE_TYPES: Dict[int, str] = {
    0x02: "AC Drive",
    0x07: "Generic Device",
    0x0C: "Communications Adapter",
    0x0E: "Programmable Logic Controller",
    0x10: "Overload Manager",
    0x13: "Safety Discrete I/O Device",
    0x24: "Managed Switch",
    0x25: "Safety Analog I/O Device",
    0x2A: "Drives & Soft-Starter",
    0x43: "Safety Drive Device",
}


class CIPClient:
    """EtherNet/IP / CIP session client for EmbedXPL ICS modules.

    Args:
        ip: Target IP address.
        port: EtherNet/IP TCP port (default 44818).
        timeout: Socket timeout in seconds (default 3.0).
    """

    def __init__(self, ip: str, port: int = 44818, timeout: float = 3.0) -> None:
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._session: int = 0
        self._logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Register an EtherNet/IP session.

        Returns:
            True if session registered, False otherwise.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._timeout)
            self._sock.connect((self._ip, self._port))
        except OSError as exc:
            self._logger.error("TCP connect failed: %s", exc)
            self._sock = None
            return False

        # RegisterSession request: command=0x65, length=4, session=0, status=0,
        # sender_context=0x0000000000000000, options=0, data=protocol 1, flags 0
        req = struct.pack("<HHIIQII", ENIP_REGISTER_SESSION, 4, 0, 0, 0, 0, 0x0001_0000)
        try:
            self._sock.sendall(req)
            rsp = self._sock.recv(28)
            if len(rsp) < 28:
                return False
            _cmd, _len, session, status = struct.unpack_from("<HHII", rsp)
            if status != 0:
                self._logger.warning("RegisterSession status=0x%08x", status)
            self._session = session
            return True
        except OSError as exc:
            self._logger.error("RegisterSession failed: %s", exc)
            return False

    def disconnect(self) -> None:
        """Unregister the EtherNet/IP session and close TCP."""
        if self._sock:
            if self._session:
                try:
                    req = struct.pack("<HHIIQII", ENIP_UNREGISTER_SESSION, 0, self._session, 0, 0, 0, 0)
                    self._sock.sendall(req)
                except OSError:
                    pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._session = 0

    def __enter__(self) -> "CIPClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _enip_header(self, command: int, data: bytes) -> bytes:
        """Build an ENIP encapsulation header + data.

        Returns:
            Serialised ENIP packet bytes.
        """
        return struct.pack("<HHIIQII",
                           command,
                           len(data),
                           self._session,
                           0,           # status
                           0,           # sender_context
                           0,           # options
                           0,           # reserved
                           ) + data

    def _send_recv_enip(self, command: int, data: bytes) -> Optional[bytes]:
        """Send an ENIP packet and return the response payload.

        Returns:
            Response payload bytes or None.
        """
        if not self._sock:
            self._logger.error("Not connected")
            return None
        pkt = self._enip_header(command, data)
        try:
            self._sock.sendall(pkt)
            header = self._sock.recv(24)
            if len(header) < 24:
                return None
            _cmd, length, _session, status = struct.unpack_from("<HHII", header)
            if status != 0:
                self._logger.warning("ENIP status=0x%08x", status)
                return None
            payload = b""
            remaining = length
            while remaining > 0:
                chunk = self._sock.recv(remaining)
                if not chunk:
                    break
                payload += chunk
                remaining -= len(chunk)
            return payload
        except OSError as exc:
            self._logger.error("I/O error: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Device discovery
    # ------------------------------------------------------------------ #

    @staticmethod
    def list_identity_udp(ip: str, port: int = 44818, timeout: float = 3.0) -> Optional[dict]:
        """Broadcast ListIdentity request via UDP and return device info.

        Args:
            ip: Target or broadcast IP.
            port: EtherNet/IP UDP port (default 44818).
            timeout: UDP receive timeout.

        Returns:
            Dict with device identity fields or None on no response.
        """
        pkt = struct.pack("<HHIIQII", ENIP_LIST_IDENTITY, 0, 0, 0, 0, 0, 0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (ip, port))
            data, _ = sock.recvfrom(1024)
            return CIPClient._parse_list_identity(data)
        except OSError:
            return None
        finally:
            sock.close()

    def list_identity(self) -> Optional[dict]:
        """Send ListIdentity over existing TCP session.

        Returns:
            Dict with device identity fields or None.
        """
        payload = self._send_recv_enip(ENIP_LIST_IDENTITY, b"")
        if payload:
            return self._parse_list_identity(payload)
        return None

    @staticmethod
    def _parse_list_identity(data: bytes) -> dict:
        """Parse ListIdentity response payload.

        Returns:
            Dict with vendor, device_type, product_name, serial, revision.
        """
        result: dict = {}
        try:
            offset = 24  # skip ENIP header
            if len(data) < offset + 2:
                return result
            item_count = struct.unpack_from("<H", data, offset)[0]
            offset += 2
            for _ in range(item_count):
                if offset + 4 > len(data):
                    break
                _type_id, item_len = struct.unpack_from("<HH", data, offset)
                offset += 4
                if item_len < 33:
                    offset += item_len
                    continue
                (encap_version, socket_addr, vendor_id, device_type,
                 product_code, major_rev, minor_rev, status, serial) = struct.unpack_from(
                    "<H4sHHHBBHI", data, offset)
                name_len = data[offset + 28]
                name = data[offset + 29:offset + 29 + name_len].decode("utf-8", errors="replace")
                result = {
                    "vendor_id": vendor_id,
                    "device_type": DEVICE_TYPES.get(device_type, hex(device_type)),
                    "product_code": product_code,
                    "revision": f"{major_rev}.{minor_rev}",
                    "status": hex(status),
                    "serial": hex(serial),
                    "product_name": name,
                }
                offset += item_len
        except (struct.error, UnicodeDecodeError):
            pass
        return result

    # ------------------------------------------------------------------ #
    # Unconnected messaging (SendRRData)
    # ------------------------------------------------------------------ #

    def send_rr_data(self, service: int, path: bytes, request_data: bytes = b"") -> Optional[bytes]:
        """Send an unconnected CIP explicit message (SendRRData).

        Args:
            service: CIP service code (e.g. 0x01 = GetAttributesAll).
            path: Encoded EPATH request path bytes.
            request_data: Optional additional request data.

        Returns:
            CIP response data bytes or None on error.
        """
        # CommonPacketFormat: Interface handle (4) + timeout (2) + item count (2)
        # Item 0: Null Address (type=0, len=0)
        # Item 1: Unconnected Data (type=0x00B2)
        cip_service = bytes([service, len(path) // 2]) + path + request_data
        item_0 = struct.pack("<HH", 0x0000, 0)
        item_1 = struct.pack("<HH", 0x00B2, len(cip_service)) + cip_service
        cpf = struct.pack("<IHH", 0, 0, 2) + item_0 + item_1
        payload = self._send_recv_enip(ENIP_SEND_RR_DATA, cpf)
        if payload is None or len(payload) < 10:
            return None
        # Skip interface handle(4) + timeout(2) + item count(2) + null item(4) + data item header(4)
        return payload[16:]
