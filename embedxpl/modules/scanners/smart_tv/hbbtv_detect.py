# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""HbbTV Scanner — HTTP probe for HbbTV service descriptor.

Probes the target HTTP server for HbbTV-related markers in response
headers and body, and checks for Application Information Table (AIT)
XML content indicating an active HbbTV service.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_HBBTV_HEADERS = (
    "hbbtv",
    "ait",
    "application/vnd.dvb.ait+xml",
)
_HBBTV_BODY_MARKERS = (
    "hbbtv",
    "dvb.ait",
    "urn:dvb:metadata:ait:app:2006",
    "HbbTV",
    "dvb_url",
    "HbbTV/1.",
    "HbbTV/2.",
)
_PROBE_PATHS = (
    "/",
    "/ait",
    "/hbbtv",
    "/ait.xml",
    "/hbbtv/ait.xml",
    "/upnp/description.xml",
)


class Exploit(HTTPClient):
    """HbbTV Service Scanner — HTTP header and AIT XML probe.

    Iterates over common HbbTV and AIT paths, inspecting HTTP response
    headers for ``HbbTV`` or ``application/vnd.dvb.ait+xml`` content-type
    markers, and scanning the response body for AIT XML indicators.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "HbbTV Service Scanner",
        "description": (
            "Probes HTTP port 80 for HbbTV service descriptors and AIT XML "
            "responses.  Detects Hybrid Broadcast Broadband TV capabilities "
            "via response headers and body fingerprinting."
        ),
        "authors": (
            "HbbTV Association",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://www.hbbtv.org/",
            "https://www.etsi.org/deliver/etsi_ts/102700_102799/102796/01.04.07_60/"
            "ts_102796v010407p.pdf",
        ),
        "devices": (
            "Samsung", "LG", "Philips", "Panasonic",
            "Sony", "Toshiba", "Hisense",
        ),
    }

    target = OptIP("", "Target IPv4 address (Smart TV)")
    port   = OptPort(80, "HTTP port (default 80)")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _has_hbbtv_header(self, resp) -> bool:
        """Check whether HTTP response headers contain HbbTV markers.

        Args:
            resp: ``requests.Response`` object.

        Returns:
            True if any HbbTV-related header key or value is present.
        """
        for key, val in resp.headers.items():
            combined = "{}: {}".format(key, val).lower()
            if any(m.lower() in combined for m in _HBBTV_HEADERS):
                return True
        return False

    def _has_hbbtv_body(self, text: str) -> bool:
        """Check whether the response body contains HbbTV or AIT markers.

        Args:
            text: HTTP response body text.

        Returns:
            True if any body marker is present.
        """
        lower = text.lower()
        return any(m.lower() in lower for m in _HBBTV_BODY_MARKERS)

    def _probe_path(self, path: str) -> bool:
        """Send GET to a path and check response for HbbTV indicators.

        Args:
            path: URL path to probe.

        Returns:
            True if HbbTV markers are detected in headers or body.
        """
        resp = self.http_request("GET", path)
        if resp is None:
            return False

        header_match = self._has_hbbtv_header(resp)
        body_text    = resp.text or ""
        body_match   = self._has_hbbtv_body(body_text)

        if header_match or body_match:
            print_success(
                "HbbTV marker found at {}:{}{} (HTTP {}){}{}".format(
                    self.target, self.port, path, resp.status_code,
                    " [header]" if header_match else "",
                    " [body]"   if body_match   else "",
                )
            )
            if resp.headers.get("Content-Type"):
                print_status("  Content-Type: {}".format(resp.headers["Content-Type"]))
            if body_match and body_text:
                print_status("  Body excerpt: {}".format(body_text[:400]))
            return True

        return False

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Probe all candidate paths for HbbTV service descriptors.

        Iterates through ``_PROBE_PATHS`` and reports any path where
        HbbTV markers are detected in the response.
        """
        print_status("Scanning {}:{} for HbbTV service descriptors...".format(
            self.target, self.port
        ))

        found = False
        for path in _PROBE_PATHS:
            if self._probe_path(path):
                found = True

        if not found:
            print_error("No HbbTV markers found on {}:{}.".format(self.target, self.port))

    @mute
    def check(self) -> bool:
        """Check whether the target HTTP server serves HbbTV content.

        Returns:
            True if any probe path returns an HbbTV marker.
        """
        for path in _PROBE_PATHS:
            resp = self.http_request("GET", path)
            if resp is None:
                continue
            if self._has_hbbtv_header(resp) or self._has_hbbtv_body(resp.text or ""):
                return True
        return False
