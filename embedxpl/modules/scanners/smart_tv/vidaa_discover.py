# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hisense VIDAA OS Discovery Scanner — HTTP banner probe.

Probes HTTP ports 80, 4444, and 8081 for Hisense/VIDAA OS banners in
response headers or body content to identify Hisense Smart TV devices.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""

import socket
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_PROBE_PORTS   = (80, 4444, 8081)
_VIDAA_MARKERS = (
    "hisense", "vidaa", "hsmart", "smarttv",
    "VIDAA", "Hisense", "HiOS", "TVSDK",
)


class Exploit(HTTPClient):
    """Hisense VIDAA OS Discovery Scanner — HTTP banner probe.

    Attempts HTTP GET / on the configured port (default 80) and also
    performs quick TCP banner grabs on ports 4444 and 8081 to detect
    Hisense/VIDAA OS fingerprints in response headers or body.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hisense VIDAA OS Discovery Scanner",
        "description": (
            "Probes HTTP ports 80, 4444, and 8081 for Hisense/VIDAA banners "
            "in response headers and body to identify Hisense Smart TV devices "
            "running VIDAA OS."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://www.hisense.com/",
            "https://www.vidaa.com/",
        ),
        "devices": ("Hisense Smart TV (VIDAA OS)",),
    }

    target  = OptIP("", "Target IPv4 address")
    port    = OptPort(80, "Primary HTTP probe port (default 80)")
    timeout = OptInteger(5, "HTTP/socket timeout in seconds")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _http_probe(self, probe_port: int) -> str | None:
        """Send GET / to a specific port and return the response text.

        Args:
            probe_port: TCP port number to probe.

        Returns:
            Combined header string + body (first 1000 chars), or None.
        """
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            scheme = "http"
            url    = f"{scheme}://{self.target}:{probe_port}/"
            resp   = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            header_str = " ".join(
                f"{k}: {v}" for k, v in resp.headers.items()
            )
            return header_str + " " + (resp.text[:1000] if resp.text else "")
        except Exception:
            return None

    def _tcp_banner(self, probe_port: int) -> str | None:
        """Grab a TCP banner by sending a minimal HTTP GET.

        Args:
            probe_port: TCP port to connect to.

        Returns:
            First 512 bytes of the server response, or None.
        """
        try:
            sock = socket.create_connection(
                (str(self.target), probe_port), timeout=float(self.timeout)
            )
            sock.sendall(b"GET / HTTP/1.0\r\nHost: " + str(self.target).encode() + b"\r\n\r\n")
            data = sock.recv(512)
            sock.close()
            return data.decode(errors="replace")
        except (TimeoutError, ConnectionRefusedError, OSError):
            return None

    def _has_vidaa_marker(self, text: str) -> bool:
        """Check whether a text string contains a Hisense/VIDAA fingerprint.

        Args:
            text: HTTP response or banner text to scan.

        Returns:
            True if any VIDAA marker is found (case-insensitive).
        """
        lower = text.lower()
        return any(m.lower() in lower for m in _VIDAA_MARKERS)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Probe all candidate ports for Hisense VIDAA banners.

        Tries HTTP GET / on port 80 (or the configured port), then TCP
        banner grabs on ports 4444 and 8081.  Reports whether each port
        contains a Hisense/VIDAA fingerprint.
        """
        print_status(f"Scanning {self.target} for Hisense VIDAA OS...")

        for probe_port in (int(self.port),) + tuple(
            p for p in _PROBE_PORTS if p != int(self.port)
        ):
            print_status(f"Probing port {probe_port}...")
            text = self._http_probe(probe_port) or self._tcp_banner(probe_port)
            if text is None:
                print_status(f"Port {probe_port} — no response.")
                continue
            if self._has_vidaa_marker(text):
                print_success(
                    f"Hisense / VIDAA OS fingerprint found on port {probe_port}!"
                )
                print_status(f"Banner excerpt: {text[:300]}")
            else:
                print_status(f"Port {probe_port} responded — no VIDAA marker detected.")

    @mute
    def check(self) -> bool:
        """Check whether the primary port returns a VIDAA marker.

        Returns:
            True if any VIDAA fingerprint is found in the response.
        """
        text = self._http_probe(int(self.port))
        if text and self._has_vidaa_marker(text):
            return True
        return False
