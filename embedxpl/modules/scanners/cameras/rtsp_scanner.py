# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""RTSP Camera Scanner — Enumerate RTSP-capable IP cameras on the network.

Scans for cameras exposing RTSP (Real Time Streaming Protocol) services on
the standard TCP ports 554 and 8554.  For each responsive host the scanner:

  1. Confirms RTSP service presence via an ``OPTIONS`` request.
  2. Fingerprints the camera vendor/model from the ``Server:`` header and
     session descriptor.
  3. Tests common default RTSP stream paths for unauthenticated access.
  4. Reports accessible streams with their full ``rtsp://`` URLs.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

import socket
import re
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_RTSP_PORTS = [554, 8554]

_DEFAULT_PATHS = [
    "/",
    "/live",
    "/live.sdp",
    "/live0.sdp",
    "/live1.sdp",
    "/h264",
    "/h264/ch1/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",
    "/onvif1",
    "/axis-media/media.amp",
    "/MediaInput/h264",
    "/PSIA/streaming/channels/1",
    "/stream1",
    "/stream2",
    "/ch0_0.h264",
    "/ch01.264",
    "/video1",
    "/video.h264",
    "/profile1/media.smp",
    "/mpeg4/media.amp",
]

_RTSP_OPTIONS = "OPTIONS rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL/1.0\r\n\r\n"
_RTSP_DESCRIBE = "DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: EmbedXPL/1.0\r\nAccept: application/sdp\r\n\r\n"


def _rtsp_request(host: str, port: int, request: str, timeout: int = 5) -> Optional[str]:
    """Send a raw RTSP request and return the response as text."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(request.encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        sock.close()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


class Exploit(BaseExploit):
    """RTSP Camera Scanner — Enumerates and fingerprints IP cameras via RTSP.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "RTSP Camera Scanner",
        "description": (
            "Scanner that discovers IP cameras exposing RTSP streams on TCP/554 and "
            "TCP/8554. Tests standard stream paths for unauthenticated access, "
            "fingerprints vendor/model from Server headers, and reports accessible "
            "rtsp:// URLs."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Cameras (RTSP)",
            "Hikvision",
            "Dahua",
            "AXIS",
            "Generic IP cameras",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(554, "Target RTSP port (554 or 8554)")
    timeout = OptInteger(5, "Socket timeout in seconds")

    def _check_options(self, port: int) -> Optional[str]:
        """Send RTSP OPTIONS and return response or None."""
        req = _RTSP_OPTIONS.format(host=self.target, port=port, path="/")
        return _rtsp_request(self.target, port, req, self.timeout)

    def _describe_path(self, port: int, path: str) -> Optional[str]:
        """Send RTSP DESCRIBE for a given path and return response."""
        req = _RTSP_DESCRIBE.format(host=self.target, port=port, path=path)
        return _rtsp_request(self.target, port, req, self.timeout)

    def _extract_server(self, response: str) -> str:
        """Extract Server header value from RTSP response."""
        m = re.search(r"Server:\s*(.+)", response, re.IGNORECASE)
        return m.group(1).strip() if m else "unknown"

    def run(self) -> None:
        ports_to_scan = [self.port] if self.port not in (0, 554) else _RTSP_PORTS
        if self.port == 554:
            ports_to_scan = _RTSP_PORTS

        for port in ports_to_scan:
            print_status("Probing RTSP on {}:{}...".format(self.target, port))
            resp = self._check_options(port)
            if resp is None:
                print_status("  Port {} closed or filtered".format(port))
                continue

            if "RTSP/1.0 200" not in resp and "RTSP/1.1 200" not in resp:
                print_status("  Port {} did not return RTSP 200 OK".format(port))
                continue

            server = self._extract_server(resp)
            print_success("RTSP service on port {} — Server: {}".format(port, server))

            for path in _DEFAULT_PATHS:
                desc_resp = self._describe_path(port, path)
                if desc_resp is None:
                    continue
                if "RTSP/1.0 200" in desc_resp or "RTSP/1.1 200" in desc_resp:
                    url = "rtsp://{}:{}{}" .format(self.target, port, path)
                    print_success("Unauthenticated stream accessible: {}".format(url))
                elif "401" in desc_resp:
                    url = "rtsp://{}:{}{}".format(self.target, port, path)
                    print_status("Stream requires auth: {} (try default creds)".format(url))

    @mute
    def check(self) -> bool:
        resp = self._check_options(self.port or 554)
        return resp is not None and "RTSP" in resp
