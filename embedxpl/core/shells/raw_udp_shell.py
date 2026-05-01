"""Raw UDP shell engine with lightweight retransmission.

Provides a shell transport over UDP with minimal reliability guarantees:
sequence numbers, acknowledgement packets, and configurable retransmit
logic to cope with packet loss on unreliable links.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellMode,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_DEFAULT_MTU = 1400
_HDR_FMT = "!IB"
_HDR_SIZE = struct.calcsize(_HDR_FMT)
_FLAG_DATA = 0x01
_FLAG_ACK = 0x02
_FLAG_FIN = 0x04
_MAX_RETRIES = 5
_RETRY_INTERVAL_S = 0.5


class RawUDPShell(ShellEngine):
    """Shell over UDP with simple reliability layer.

    Each datagram carries a 5-byte header: 4-byte sequence number (network
    order) and 1-byte flags field.  The receiver sends back an ACK with the
    same sequence number.  Unacknowledged packets are retransmitted up to
    *max_retries* times.

    Wire format::

        [seq:4][flags:1][payload:N]

    Flags:
        0x01 - DATA  (carries payload)
        0x02 - ACK   (acknowledges a sequence number)
        0x04 - FIN   (session teardown)

    Args:
        remote_host: Target IP / hostname.
        remote_port: UDP port.
        mode: ``ShellMode.REVERSE`` or ``ShellMode.BIND``.
        timeout: Socket timeout in seconds.
        mtu: Maximum payload per datagram (excluding header).
        max_retries: Retransmission attempts before declaring failure.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        mode: ShellMode = ShellMode.REVERSE,
        timeout: float = 30.0,
        mtu: int = _DEFAULT_MTU,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="raw_udp",
            timeout=timeout,
        )
        self._mode: ShellMode = mode
        self._mtu: int = max(64, mtu)
        self._max_retries: int = max(1, max_retries)
        self._sock: Optional[socket.socket] = None
        self._peer_addr: Optional[Tuple[str, int]] = None
        self._tx_seq: int = 0
        self._rx_seq: int = 0
        self._acked: Dict[int, bool] = {}
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Open the UDP socket and establish peer association.

        In reverse mode the engine binds and waits for the first inbound
        datagram to discover the peer address.  In bind mode it sends a
        probe datagram to associate the peer.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: On socket-level failures.
        """
        self._set_status(ShellStatus.CONNECTING)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)

            if self._mode == ShellMode.REVERSE:
                sock.bind(("0.0.0.0", self._remote_port))
                logger.info("UDP reverse: listening on 0.0.0.0:%d", self._remote_port)
                data, addr = sock.recvfrom(self._mtu + _HDR_SIZE)
                self._peer_addr = addr
                logger.info("UDP reverse: peer discovered at %s:%d", addr[0], addr[1])
                self._process_inbound(data)
            else:
                self._peer_addr = (self._remote_host, self._remote_port)
                probe = struct.pack(_HDR_FMT, 0, _FLAG_DATA) + b"PROBE"
                sock.sendto(probe, self._peer_addr)
                logger.info(
                    "UDP bind: probe sent to %s:%d",
                    self._remote_host,
                    self._remote_port,
                )

            self._sock = sock
            self._set_status(ShellStatus.CONNECTED)
            return True
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Send a command as one or more reliable UDP datagrams.

        Args:
            cmd: Command string.

        Returns:
            Total payload bytes sent (excluding headers).

        Raises:
            ShellIOError: If the socket is not ready or retransmission fails.
        """
        self._require_connected()
        payload = cmd.encode("utf-8", errors="replace")
        if not payload.endswith(b"\n"):
            payload += b"\n"

        total_sent = 0
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + self._mtu]
            offset += len(chunk)
            seq = self._next_tx_seq()
            pkt = struct.pack(_HDR_FMT, seq, _FLAG_DATA) + chunk

            if not self._send_reliable(seq, pkt):
                raise ShellIOError(
                    "Packet seq={} not acknowledged after {} retries".format(
                        seq, self._max_retries
                    )
                )
            total_sent += len(chunk)

        return total_sent

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive data from the UDP peer.

        Reassembles contiguous DATA datagrams and sends ACKs.

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
                data, addr = self._sock.recvfrom(self._mtu + _HDR_SIZE)  # type: ignore[union-attr]
            except socket.timeout:
                break
            except OSError as exc:
                self._set_status(ShellStatus.ERROR, str(exc))
                raise ShellIOError(str(exc)) from exc

            chunk = self._process_inbound(data)
            if chunk is not None:
                buf.extend(chunk)

        return buf.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Send FIN and close the UDP socket."""
        if self._sock is not None and self._peer_addr is not None:
            try:
                fin = struct.pack(_HDR_FMT, self._next_tx_seq(), _FLAG_FIN)
                self._sock.sendto(fin, self._peer_addr)
            except OSError:
                pass
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("RawUDPShell closed")

    def is_alive(self) -> bool:
        """Heuristic liveness check.

        UDP is connectionless, so this simply verifies the socket is open
        and a peer address is known.
        """
        return (
            self._status == ShellStatus.CONNECTED
            and self._sock is not None
            and self._peer_addr is not None
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _next_tx_seq(self) -> int:
        with self._lock:
            seq = self._tx_seq
            self._tx_seq = (self._tx_seq + 1) & 0xFFFFFFFF
        return seq

    def _send_reliable(self, seq: int, pkt: bytes) -> bool:
        """Transmit a packet with stop-and-wait retransmission."""
        for attempt in range(self._max_retries + 1):
            try:
                self._sock.sendto(pkt, self._peer_addr)  # type: ignore[union-attr]
            except OSError as exc:
                logger.warning("UDP send error (attempt %d): %s", attempt, exc)
                continue

            ack_deadline = time.monotonic() + _RETRY_INTERVAL_S
            while time.monotonic() < ack_deadline:
                remaining = max(0.0, ack_deadline - time.monotonic())
                ready, _, _ = select.select([self._sock], [], [], remaining)
                if not ready:
                    break
                try:
                    data, _ = self._sock.recvfrom(_HDR_SIZE + 16)  # type: ignore[union-attr]
                except OSError:
                    break
                if len(data) < _HDR_SIZE:
                    continue
                ack_seq, flags = struct.unpack_from(_HDR_FMT, data)
                if flags & _FLAG_ACK and ack_seq == seq:
                    return True

            logger.debug("Retransmit seq=%d attempt=%d", seq, attempt + 1)

        return False

    def _process_inbound(self, data: bytes) -> Optional[bytes]:
        """Parse an inbound datagram, send ACK if DATA, return payload."""
        if len(data) < _HDR_SIZE:
            return None
        seq, flags = struct.unpack_from(_HDR_FMT, data)
        payload = data[_HDR_SIZE:]

        if flags & _FLAG_ACK:
            self._acked[seq] = True
            return None

        if flags & _FLAG_DATA:
            ack = struct.pack(_HDR_FMT, seq, _FLAG_ACK)
            try:
                self._sock.sendto(ack, self._peer_addr)  # type: ignore[union-attr]
            except OSError:
                pass
            return payload

        if flags & _FLAG_FIN:
            logger.info("Received FIN from peer")
            self._set_status(ShellStatus.DISCONNECTED)
            return None

        return None

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
