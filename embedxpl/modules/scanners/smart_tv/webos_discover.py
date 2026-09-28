# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""LG WebOS SSAP Discovery Scanner — TCP probe on ports 3000/3001.

Probes LG Smart TVs running WebOS by attempting a minimal WebSocket
upgrade handshake over plain TCP to identify SSAP-enabled devices and
extract version banners from the HTTP 101 upgrade response.

Version: 1.0.0
"""

import socket
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_WS_HANDSHAKE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)

_READ_BYTES = 512
_CONNECT_TIMEOUT = 5


class Exploit(BaseExploit):
    """LG WebOS SSAP Service Discovery Scanner.

    Probes TCP ports 3000 (ws) and 3001 (wss) to detect LG WebOS devices
    exposing the Second Screen Application Protocol (SSAP). Sends a minimal
    WebSocket upgrade request and extracts version info from the response.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "LG WebOS SSAP Discovery Scanner",
        "description": (
            "Probes LG Smart TV ports 3000 (ws) and 3001 (wss) to detect "
            "SSAP WebSocket service. Sends a minimal HTTP Upgrade request and "
            "reads the banner response to identify WebOS firmware version."
        ),
        "authors": ("André Henrique (@mrhenrike) - EmbedXPL-Forge port",),
        "references": (
            "https://webostv.developer.lge.com/develop/app-developer-guide/communication-api",
            "https://github.com/Informatic/webos-ssap-web",
        ),
        "devices": ("LG Smart TV", "LG WebOS"),
    }

    target = OptIP("", "Target IPv4 address of the LG Smart TV")
    port = OptPort(3000, "Primary WebSocket port (3000=ws, 3001=wss)")
    timeout = OptInteger(5, "TCP connection timeout in seconds")

    def run(self) -> None:
        """Probe ports 3000 and 3001 for SSAP service presence."""
        print_status("Probing LG WebOS SSAP on {}...".format(self.target))

        for probe_port in (3000, 3001):
            banner = self._probe_port(probe_port)
            if banner is not None:
                proto = "wss" if probe_port == 3001 else "ws"
                print_success(
                    "SSAP port {}/{} open on {}".format(probe_port, proto, self.target)
                )
                version = self._extract_version(banner)
                if version:
                    print_success("WebOS version hint: {}".format(version))
                else:
                    print_status("Banner (first 200 chars): {}".format(
                        banner[:200].replace("\r\n", " | ")
                    ))
            else:
                print_error("Port {} closed or no response on {}".format(
                    probe_port, self.target
                ))

    def _probe_port(self, port: int) -> Optional[str]:
        """Attempt a WebSocket handshake on the given port.

        Args:
            port: TCP port to probe.

        Returns:
            Decoded response string, or None if the connection failed.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            payload = _WS_HANDSHAKE.format(host=self.target).encode()
            sock.sendall(payload)
            data = sock.recv(_READ_BYTES)
            sock.close()
            return data.decode("utf-8", errors="replace")
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        except Exception as exc:
            print_error("Probe error on port {}: {}".format(port, exc))
            return None

    @staticmethod
    def _extract_version(banner: str) -> str:
        """Extract WebOS version string from an HTTP banner.

        Args:
            banner: Raw HTTP response string.

        Returns:
            Version substring if found, otherwise empty string.
        """
        for line in banner.splitlines():
            lower = line.lower()
            if "webos" in lower or "lge" in lower or "server:" in lower:
                return line.strip()
        return ""

    @mute
    def check(self) -> bool:
        """Check if port 3000 responds to a WebSocket handshake.

        Returns:
            True if SSAP port 3000 appears open, False otherwise.
        """
        return self._probe_port(3000) is not None
