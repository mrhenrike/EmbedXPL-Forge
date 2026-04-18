"""
EmbedXPL-Forge — Siemens S7comm+ Client (S7-1200/1500)
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Python 3 raw-socket implementation of S7comm+ (TIA v13+) over ISO-on-TCP.
Ported and modernised from ISF S7PlusClient (original: WenZhe Zhu / ICSsploit).

S7comm+ uses "SIMATIC-ROOT-ES" as dst-TSAP and adds an integrity layer
on top of S7comm.  This client provides session setup and basic probing.
"""

import socket
import struct
import logging
from typing import Optional


S7PLUS_DST_TSAP = b"SIMATIC-ROOT-ES"


def _build_tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def _build_cotp_cr(src_tsap: bytes, dst_tsap: bytes) -> bytes:
    params = (
        b"\xc0\x01\x0a"
        + bytes([0xc1, len(src_tsap)]) + src_tsap
        + bytes([0xc2, len(dst_tsap)]) + dst_tsap
    )
    pdu_len = 6 + len(params)
    return bytes([pdu_len, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00]) + params


def _build_cotp_dt(payload: bytes) -> bytes:
    return b"\x02\xf0\x80" + payload


class S7PlusClient:
    """Siemens S7comm+ (TIA S7-1200/1500) protocol client.

    Establishes an ISO-on-TCP session using the S7comm+ TSAP prefix
    ("SIMATIC-ROOT-ES") and provides low-level frame send/receive.

    Args:
        ip: Target PLC IP address.
        port: ISO-on-TCP port (default 102).
        timeout: Socket timeout in seconds (default 3.0).
    """

    def __init__(self, ip: str, port: int = 102, timeout: float = 3.0) -> None:
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._session: int = 0x0120
        self._seq: int = 1
        self._logger = logging.getLogger(self.__class__.__name__)

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #

    def connect(self) -> bool:
        """Establish ISO-on-TCP + S7comm+ setup handshake.

        Returns:
            True if connection succeeded, False otherwise.
        """
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self._timeout)
            self._sock.connect((self._ip, self._port))
        except OSError as exc:
            self._logger.error("TCP connect failed: %s", exc)
            return False

        src_tsap = b"\x01\x00"
        cotp_cr = _build_cotp_cr(src_tsap, S7PLUS_DST_TSAP)
        try:
            self._sock.sendall(_build_tpkt(cotp_cr))
            rsp = self._recv()
            if rsp is None:
                return False
        except OSError:
            return False

        # S7comm+ Init Data (minimal setup request)
        init_pdu = bytes([
            0x72, 0x01, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        rsp = self._send_recv_s7plus(init_pdu)
        if rsp is not None:
            self._connected = True
        return self._connected

    def disconnect(self) -> None:
        """Close the connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._connected = False

    def __enter__(self) -> "S7PlusClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------ #
    # Low-level I/O
    # ------------------------------------------------------------------ #

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

    def send_recv_s7plus(self, pdu: bytes) -> Optional[bytes]:
        """Public wrapper to send a raw S7comm+ PDU.

        Args:
            pdu: Raw S7comm+ PDU bytes.

        Returns:
            Response payload bytes (strip COTP header) or None.
        """
        return self._send_recv_s7plus(pdu)

    def _send_recv_s7plus(self, pdu: bytes) -> Optional[bytes]:
        """Internal: wrap in COTP+TPKT, send, and strip COTP from response."""
        if not self._sock:
            return None
        try:
            self._sock.sendall(_build_tpkt(_build_cotp_dt(pdu)))
            rsp = self._recv()
            if rsp and len(rsp) > 3:
                return rsp[3:]
            return None
        except OSError as exc:
            self._logger.error("I/O error: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Probe / identification
    # ------------------------------------------------------------------ #

    def probe(self) -> bool:
        """Send a lightweight S7comm+ version probe.

        Returns:
            True if a valid S7comm+ response is received.
        """
        if not self._connected:
            return False
        probe_pdu = bytes([0x72, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00])
        rsp = self._send_recv_s7plus(probe_pdu)
        return rsp is not None and len(rsp) >= 4 and rsp[0] == 0x72
