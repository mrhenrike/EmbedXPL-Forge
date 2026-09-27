"""Abstract base class for all shell transport engines.

Defines the ShellEngine contract that every concrete shell implementation
must fulfill. Provides connection lifecycle management, I/O primitives,
interactive session support, and a unified status model.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import enum
import logging
import sys
import threading
import time
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class ShellStatus(enum.Enum):
    """Connection state for a shell transport."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


class ShellMode(enum.Enum):
    """Operational mode of the shell transport."""

    REVERSE = "reverse"
    BIND = "bind"


class ShellEngine(ABC):
    """Abstract base for shell transport engines.

    Concrete subclasses implement the actual transport (TCP, UDP, ICMP, DNS,
    MQTT, HTTP, etc.) while this base enforces a consistent public API.

    Args:
        remote_host: Target host address (IP or hostname).
        remote_port: Target port number (0 for portless transports like ICMP).
        transport_type: Human-readable transport label, e.g. "raw_tcp".
        timeout: Socket/IO timeout in seconds.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int,
        transport_type: str,
        timeout: float = 30.0,
    ) -> None:
        self._remote_host: str = remote_host
        self._remote_port: int = remote_port
        self._transport_type: str = transport_type
        self._timeout: float = max(1.0, timeout)
        self._status: ShellStatus = ShellStatus.DISCONNECTED
        self._error_detail: Optional[str] = None
        self._connect_ts: Optional[float] = None
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def remote_host(self) -> str:
        """Remote host address."""
        return self._remote_host

    @property
    def remote_port(self) -> int:
        """Remote port number."""
        return self._remote_port

    @property
    def transport_type(self) -> str:
        """Transport identifier string."""
        return self._transport_type

    @property
    def status(self) -> ShellStatus:
        """Current connection status."""
        return self._status

    @property
    def error_detail(self) -> Optional[str]:
        """Human-readable error description (None when no error)."""
        return self._error_detail

    @property
    def uptime_s(self) -> float:
        """Seconds since connection was established. 0.0 if not connected."""
        if self._connect_ts is None:
            return 0.0
        return time.monotonic() - self._connect_ts

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def _set_status(self, new_status: ShellStatus, detail: Optional[str] = None) -> None:
        """Thread-safe status transition.

        Args:
            new_status: Target status value.
            detail: Optional detail string (stored for ERROR status).
        """
        with self._lock:
            old = self._status
            self._status = new_status
            if new_status == ShellStatus.CONNECTED:
                self._connect_ts = time.monotonic()
                self._error_detail = None
            elif new_status == ShellStatus.ERROR:
                self._error_detail = detail
            elif new_status == ShellStatus.DISCONNECTED:
                self._connect_ts = None
                self._error_detail = None
        logger.debug(
            "[%s] %s:%d status %s -> %s%s",
            self._transport_type,
            self._remote_host,
            self._remote_port,
            old.value,
            new_status.value,
            " ({})".format(detail) if detail else "",
        )

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def connect(self) -> bool:
        """Establish the shell transport channel.

        Returns:
            True if the connection was established successfully.

        Raises:
            ShellConnectionError: On transport-level failures.
        """

    @abstractmethod
    def send(self, cmd: str) -> int:
        """Send a command string over the channel.

        Args:
            cmd: Command to send (newline appended automatically by
                 implementations that require it).

        Returns:
            Number of bytes sent.

        Raises:
            ShellIOError: If the channel is not connected or write fails.
        """

    @abstractmethod
    def recv(self, timeout: Optional[float] = None) -> str:
        """Receive output from the remote shell.

        Args:
            timeout: Optional override for the default receive timeout.

        Returns:
            Decoded string from the remote side. Empty string on timeout
            with no data.

        Raises:
            ShellIOError: If the channel is broken.
        """

    @abstractmethod
    def close(self) -> None:
        """Tear down the transport and release resources.

        Safe to call multiple times. Must not raise.
        """

    @abstractmethod
    def is_alive(self) -> bool:
        """Check if the remote side is still reachable.

        Returns:
            True if the transport layer considers the session alive.
        """

    # ------------------------------------------------------------------
    # Interactive loop (default implementation)
    # ------------------------------------------------------------------

    def interact(self, prompt: str = "shell> ") -> None:
        """Enter an interactive command loop.

        Reads commands from stdin, sends them through the transport,
        and prints received output to stdout. Type ``exit`` or press
        Ctrl-C / Ctrl-D to leave.

        Args:
            prompt: String displayed before each input line.
        """
        if self._status != ShellStatus.CONNECTED:
            logger.error("Cannot interact: shell is %s", self._status.value)
            return

        logger.info(
            "Interactive session on %s:%d via %s (type 'exit' to quit)",
            self._remote_host,
            self._remote_port,
            self._transport_type,
        )

        try:
            while self.is_alive():
                try:
                    cmd = input(prompt)
                except EOFError:
                    break

                stripped = cmd.strip()
                if stripped.lower() in ("exit", "quit"):
                    break
                if not stripped:
                    continue

                try:
                    self.send(cmd)
                except ShellIOError as exc:
                    logger.error("Send failed: %s", exc)
                    break

                output = self.recv(timeout=self._timeout)
                if output:
                    sys.stdout.write(output)
                    sys.stdout.flush()
        except KeyboardInterrupt:
            logger.info("Interactive session interrupted by user")
        finally:
            logger.info("Leaving interactive session")

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "ShellEngine":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        self.close()

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return "<{cls} {host}:{port} [{transport}] {status}>".format(
            cls=self.__class__.__name__,
            host=self._remote_host,
            port=self._remote_port,
            transport=self._transport_type,
            status=self._status.value,
        )


# ======================================================================
# Exceptions
# ======================================================================


class ShellError(Exception):
    """Base exception for shell engine errors."""


class ShellConnectionError(ShellError):
    """Raised when establishing or maintaining a connection fails."""


class ShellIOError(ShellError):
    """Raised on send/receive failures over an established channel."""


class ShellTimeoutError(ShellIOError):
    """Raised when an I/O operation exceeds the configured timeout."""
