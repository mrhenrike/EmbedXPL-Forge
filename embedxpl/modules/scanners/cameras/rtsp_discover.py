# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""RTSP Camera Discovery — Banner Probe on Port 554/8554.

Discovers IP cameras and streaming devices via RTSP protocol fingerprinting.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_RTSP_OPTIONS = (
    "OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
    "CSeq: 1\r\n"
    "User-Agent: EmbedXPL-Forge\r\n"
    "\r\n"
)


class Exploit(BaseExploit):
    """RTSP Camera Discovery Scanner.

    Sends RTSP OPTIONS requests to ports 554 and 8554 to discover IP cameras
    and streaming devices. Extracts Server header for fingerprinting.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "RTSP Camera Discovery Scanner",
        "description": (
            "Probes RTSP ports 554 and 8554 to discover IP cameras and streaming "
            "devices. Sends RTSP OPTIONS request and extracts Server header to "
            "fingerprint the device manufacturer and firmware."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://tools.ietf.org/html/rfc2326",
        ),
        "devices": (
            "Hikvision", "Dahua", "Axis", "Hanwha", "Vivotek",
            "Foscam", "Generic IP Camera",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(554, "RTSP port (554 or 8554)")
    timeout = OptInteger(5, "Connection timeout")

    def run(self) -> None:
        ports_to_try = [int(self.port)]
        if int(self.port) == 554:
            ports_to_try.append(8554)
        elif int(self.port) == 8554:
            ports_to_try.insert(0, 554)

        found_any = False
        for port in ports_to_try:
            result = self._probe_rtsp(self.target, port)
            if result:
                found_any = True

        if not found_any:
            print_error(
                "No RTSP service found on {} (ports {})".format(
                    self.target, ports_to_try
                )
            )

    def _probe_rtsp(self, host: str, port: int) -> bool:
        """Send RTSP OPTIONS to a specific host:port.

        Args:
            host: Target IP address.
            port: RTSP port.

        Returns:
            True if RTSP service responded.
        """
        request = _RTSP_OPTIONS.format(host=host, port=port)
        try:
            sock = socket.create_connection((host, port), timeout=float(self.timeout))
            sock.sendall(request.encode())
            sock.settimeout(float(self.timeout))
            response = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()

            if "RTSP/1.0" in response:
                # Extract Server header
                server = ""
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                        break
                print_success(
                    "RTSP on {}:{} — Server: {}".format(host, port, server or "(unknown)")
                )
                return True
        except Exception:
            pass
        return False

    @mute
    def check(self) -> bool:
        try:
            with socket.create_connection((self.target, int(self.port)), timeout=3):
                return True
        except Exception:
            return False
