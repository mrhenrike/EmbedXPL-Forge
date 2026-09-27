# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Amazon Fire TV Discovery Scanner — ADB port 5555 + DIAL port 8008.

Discovers Amazon Fire TV devices by probing port 5555 (ADB) and port 8008
(DIAL app-list endpoint).  A DIAL response listing Fire TV apps confirms
the device identity.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""

import socket
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_ADB_PORT  = 5555
_DIAL_PORT = 8008
_FIRETV_APP_IDS = ("AmazonVideoApp", "AmazonMusic", "com.amazon", "amazon")


class Exploit(HTTPClient):
    """Amazon Fire TV Discovery — ADB port 5555 + DIAL port 8008 probe.

    Performs two independent discovery checks:
    1. TCP connect to port 5555 to detect open ADB.
    2. HTTP GET to ``http://target:8008/apps/`` (DIAL app list) to
       identify Amazon Fire TV via app-ID fingerprinting.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Amazon Fire TV Discovery Scanner",
        "description": (
            "Discovers Amazon Fire TV devices by probing ADB (port 5555) "
            "and the DIAL app-list endpoint (port 8008). Fingerprints the "
            "device via DIAL app identifiers."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://developer.amazon.com/docs/fire-tv/dial-integration.html",
            "https://developer.android.com/studio/command-line/adb",
        ),
        "devices": ("Amazon Fire TV",),
    }

    target      = OptIP("", "Target IPv4 address")
    port        = OptPort(_DIAL_PORT, "DIAL HTTP port (default 8008)")
    adb_port    = OptPort(_ADB_PORT, "ADB TCP port (default 5555)")
    timeout     = OptInteger(5, "TCP / HTTP timeout in seconds")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe_adb(self) -> bool:
        """Attempt a TCP connect to the ADB port.

        Returns:
            True if port ``adb_port`` is open and accepts connections.
        """
        try:
            sock = socket.create_connection(
                (str(self.target), int(self.adb_port)), timeout=float(self.timeout)
            )
            sock.close()
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _probe_dial(self) -> Optional[str]:
        """Fetch the DIAL app-list endpoint.

        Sends ``GET /apps/`` to port 8008 and returns the response body
        for fingerprinting.

        Returns:
            Response body string, or None if the request fails.
        """
        resp = self.http_request("GET", "/apps/")
        if resp and resp.status_code == 200:
            return resp.text
        return None

    def _fingerprint_dial(self, body: str) -> bool:
        """Determine whether the DIAL response matches Fire TV app IDs.

        Args:
            body: HTTP response body from the DIAL /apps/ endpoint.

        Returns:
            True if any known Fire TV app identifier is present.
        """
        lower = body.lower()
        return any(app_id.lower() in lower for app_id in _FIRETV_APP_IDS)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Probe ADB and DIAL endpoints to identify Fire TV devices.

        Prints the ADB port status and parses the DIAL app list to
        confirm or deny a Fire TV identity.
        """
        print_status("Probing Amazon Fire TV on {}...".format(self.target))

        adb_open = self._probe_adb()
        if adb_open:
            print_success("ADB port {}  OPEN — device may have debugging enabled.".format(
                self.adb_port
            ))
        else:
            print_status("ADB port {} is closed or filtered.".format(self.adb_port))

        print_status("Probing DIAL app list at http://{}:{}/apps/...".format(
            self.target, self.port
        ))
        dial_body = self._probe_dial()
        if dial_body is None:
            print_error("DIAL endpoint did not respond on port {}.".format(self.port))
        else:
            is_firetv = self._fingerprint_dial(dial_body)
            if is_firetv:
                print_success("Fire TV confirmed via DIAL app fingerprint!")
            else:
                print_warning("DIAL responded but no Amazon app identifiers found.")
            print_status("DIAL app list preview:\n{}".format(dial_body[:1000]))

    @mute
    def check(self) -> bool:
        """Check whether the DIAL endpoint is reachable on port 8008.

        Returns:
            True if ``GET /apps/`` returns HTTP 200.
        """
        resp = self.http_request("GET", "/apps/")
        return resp is not None and resp.status_code == 200
