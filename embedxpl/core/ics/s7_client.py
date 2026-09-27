"""
EmbedXPL-Forge — Siemens S7comm Client (ISO-on-TCP)
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Python 3 raw-socket implementation of S7comm over ISO-on-TCP (port 102).
Ported and modernised from ISF S7Client (original: WenZhe Zhu / ICSsploit).

Supports: session setup, SZL identity reads, PLC stop/start, block upload,
password authentication (S7 300/400 series).
"""

import socket
import struct
import logging
import time
from typing import Optional, Tuple


# S7comm constants
S7_PORT = 102

# TPKT / COTP helpers
def _build_tpkt(payload: bytes) -> bytes:
    """Wrap payload in RFC-1006 TPKT header (version=3)."""
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def _build_cotp_cr(src_tsap: bytes, dst_tsap: bytes) -> bytes:
    """Build COTP Connection Request PDU."""
    params = (
        b"\xc0\x01\x0a"                          # tpdu-size = 4096
        + bytes([0xc1, len(src_tsap)]) + src_tsap  # src-tsap
        + bytes([0xc2, len(dst_tsap)]) + dst_tsap  # dst-tsap
    )
    pdu_len = 6 + len(params)
    return bytes([pdu_len, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00]) + params


def _build_cotp_dt(payload: bytes) -> bytes:
    """Wrap S7 payload in a COTP Data PDU."""
    return b"\x02\xf0\x80" + payload


def _build_s7_setup_comm() -> bytes:
    """Build S7comm SetupCommunication request PDU."""
    return bytes([
        0x32, 0x01, 0x00, 0x00,   # S7 header: protocol, ROSCTR=Job, reserved, PDU ref
        0x04, 0xd2,               # PDU ref (LE)
        0x00, 0x08,               # param length
        0x00, 0x00,               # data length
        0xf0, 0x00,               # function SetupCommunication
        0x00, 0x03,               # max AMQ caller
        0x00, 0x03,               # max AMQ callee
        0x01, 0xe0,               # PDU length
    ])


class S7Client:
    """Siemens S7comm (S7-300/400) protocol client for EmbedXPL ICS modules.

    Communicates over ISO-on-TCP (COTP over TPKT) on port 102.

    Args:
        ip: Target PLC IP address.
        port: ISO-on-TCP port (default 102).
        rack: CPU rack number (default 0).
        slot: CPU slot number (default 2, e.g. S7-300 CPU in slot 2).
        timeout: Socket timeout in seconds (default 3.0).
    """

    def __init__(self, ip: str, port: int = 102, rack: int = 0,
                 slot: int = 2, timeout: float = 3.0) -> None:
        self._ip = ip
        self._port = port
        self._rack = rack
        self._slot = slot
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Establish ISO-on-TCP connection and negotiate S7 PDU size.

        Returns:
            True if connected and S7comm session established.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._timeout)
            self._sock.connect((self._ip, self._port))
        except OSError as exc:
            self._logger.error("TCP connect failed: %s", exc)
            return False

        src_tsap = b"\x01\x00"
        dst_tsap = bytes([0x01, self._rack * 0x20 + self._slot])

        # Step 1: COTP CR
        cotp_cr = _build_cotp_cr(src_tsap, dst_tsap)
        if not self._send(_build_tpkt(cotp_cr)):
            return False
        rsp = self._recv()
        if rsp is None:
            return False

        # Step 2: S7 SetupCommunication
        s7_setup = _build_cotp_dt(_build_s7_setup_comm())
        if not self._send(_build_tpkt(s7_setup)):
            return False
        rsp = self._recv()
        if rsp and len(rsp) >= 7 and rsp[5] == 0x32:
            self._connected = True
        return self._connected

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._connected = False

    def __enter__(self) -> "S7Client":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # Low-level I/O
    # ------------------------------------------------------------------ #

    def _send(self, data: bytes) -> bool:
        if not self._sock:
            return False
        try:
            self._sock.sendall(data)
            return True
        except OSError as exc:
            self._logger.error("Send error: %s", exc)
            return False

    def _recv(self) -> Optional[bytes]:
        if not self._sock:
            return None
        try:
            header = self._sock.recv(4)
            if len(header) < 4 or header[0] != 3:
                return None
            length = struct.unpack(">H", header[2:4])[0]
            data = b""
            remaining = length - 4
            while remaining > 0:
                chunk = self._sock.recv(remaining)
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            return data
        except OSError as exc:
            self._logger.error("Recv error: %s", exc)
            return None

    def _send_s7(self, s7_pdu: bytes) -> Optional[bytes]:
        """Send an S7 PDU wrapped in COTP+TPKT and return the raw response."""
        if not self._send(_build_tpkt(_build_cotp_dt(s7_pdu))):
            return None
        rsp = self._recv()
        if rsp and len(rsp) > 3:
            return rsp[3:]  # strip COTP DT header
        return None

    # ------------------------------------------------------------------ #
    # Password authentication (S7-300/400 protection levels)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hash_password(password: str) -> bytes:
        """Apply Siemens S7-300/400 password XOR-chain hash.

        Args:
            password: PLC plaintext password (1–8 characters).

        Returns:
            8-byte hashed password bytes.
        """
        pwd = (password + "\x20" * 8)[:8]
        result = bytearray(8)
        for i, ch in enumerate(pwd):
            val = ord(ch)
            if i < 2:
                val ^= 0x55
            else:
                val = val ^ 0x55 ^ result[i - 2]
            result[i] = val
        return bytes(result)

    def authenticate(self, password: str) -> bool:
        """Authenticate to a password-protected S7-300/400 PLC.

        Args:
            password: PLC plaintext password (max 8 characters).

        Returns:
            True if authentication succeeded.
        """
        if not self._connected:
            self._logger.error("Not connected")
            return False
        hashed = self._hash_password(password)
        # S7 UserData password function: ROSCTR=0x07, group=0x12, sub=0x01
        s7_pdu = bytes([
            0x32, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x0a,
            0x00, 0x01, 0x12, 0x08, 0x12, 0x41, 0x01, 0x00, 0x00, 0x00,
            0xff, 0x09, 0x00, 0x08,
        ]) + hashed
        rsp = self._send_s7(s7_pdu)
        if rsp and len(rsp) >= 12:
            return rsp[11] == 0x00  # error class == 0
        return False

    # ------------------------------------------------------------------ #
    # SZL (System Status List) read — identity / hardware info
    # ------------------------------------------------------------------ #

    def read_szl(self, szl_id: int, szl_index: int = 0) -> Optional[bytes]:
        """Read a SZL (System Status List) entry from the PLC.

        Args:
            szl_id: SZL ID (e.g. 0x0011 = order code, 0x001c = module info).
            szl_index: SZL index (default 0).

        Returns:
            Raw SZL data bytes or None.
        """
        if not self._connected:
            return None
        s7_pdu = struct.pack(">8sHHHHHHHH",
                             bytes([0x32, 0x07, 0x00, 0x00, 0x05, 0x01, 0x00, 0x08]),
                             0x0000,   # data length placeholder
                             0x0001, 0x12, 0x04, 0x11, 0x44, szl_id, szl_index)
        # Simplified: just return raw response for callers to parse
        s7_pdu = bytes([
            0x32, 0x07, 0x00, 0x00, 0x05, 0x01, 0x00, 0x08, 0x00, 0x08,
            0x00, 0x01, 0x12, 0x04, 0x11, 0x44,
        ]) + struct.pack(">HH", szl_id, szl_index)
        return self._send_s7(s7_pdu)

    def get_plc_info(self) -> dict:
        """Attempt to retrieve basic PLC identification.

        Returns:
            Dict with 'order_code', 'module_name', 'serial_number' (may be empty).
        """
        result: dict = {"order_code": "", "module_name": "", "serial_number": ""}
        rsp = self.read_szl(0x0011)
        if rsp and len(rsp) > 30:
            try:
                result["order_code"] = rsp[14:34].decode("ascii", errors="replace").rstrip("\x00 ")
            except Exception:
                pass
        rsp2 = self.read_szl(0x001c)
        if rsp2 and len(rsp2) > 30:
            try:
                result["module_name"] = rsp2[2:24].decode("ascii", errors="replace").rstrip("\x00 ")
            except Exception:
                pass
        return result

    # ------------------------------------------------------------------ #
    # PLC state control
    # ------------------------------------------------------------------ #

    def stop_plc(self) -> bool:
        """Send S7 STOP command to the PLC.

        Returns:
            True if the STOP request was sent successfully.
        """
        if not self._connected:
            return False
        s7_stop = bytes([
            0x32, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x10, 0x00, 0x00,
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50, 0x5f, 0x50,
            0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d,
        ])
        rsp = self._send_s7(s7_stop)
        return rsp is not None

    def start_plc(self) -> bool:
        """Send S7 START (warm restart) command to the PLC.

        Returns:
            True if the START request was sent successfully.
        """
        if not self._connected:
            return False
        s7_start = bytes([
            0x32, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x00,
            0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00,
            0x09, 0x50, 0x5f, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d,
        ])
        rsp = self._send_s7(s7_start)
        return rsp is not None
