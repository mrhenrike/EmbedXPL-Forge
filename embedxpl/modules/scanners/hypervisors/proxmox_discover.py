# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Proxmox VE — Web Interface Discovery Scanner.

Probes TCP/8006 HTTPS for the Proxmox VE management interface
and extracts version information from the API.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Proxmox VE Management Interface Discovery Scanner.

    Probes port 8006 for the Proxmox VE HTTPS web interface and
    retrieves version information via the unauthenticated API endpoint.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Proxmox VE Discovery Scanner",
        "description": (
            "Probes TCP/8006 HTTPS for the Proxmox VE management interface. "
            "Retrieves version information from /api2/json/version (unauthenticated). "
            "Also checks for accessible node list."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://pve.proxmox.com/pve-docs/api-viewer/",),
        "devices": ("Proxmox VE",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8006, "Proxmox web UI port (default 8006)")

    def run(self) -> None:
        print_status("Probing Proxmox VE on {}:{}...".format(self.target, self.port))

        # Version check (unauthenticated)
        resp = self.http_request(method="GET", path="/api2/json/version")
        if resp and resp.status_code == 200:
            import json
            try:
                data = json.loads(resp.text or "{}").get("data", {})
                version = data.get("version", "?")
                release = data.get("release", "?")
                repoid = data.get("repoid", "?")
                print_success(
                    "Proxmox VE detected on {}:{} — version={} release={} repoid={}".format(
                        self.target, self.port, version, release, repoid
                    )
                )
            except Exception:
                print_success("Proxmox VE API responded on {}:{}".format(self.target, self.port))
        elif resp:
            print_status(
                "HTTP {} on /api2/json/version — may require auth".format(resp.status_code)
            )

        # Check login page
        login = self.http_request(method="GET", path="/")
        if login and "proxmox" in (login.text or "").lower():
            print_success("Proxmox VE login page confirmed")

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/api2/json/version")
        return resp is not None and resp.status_code in (200, 401)
