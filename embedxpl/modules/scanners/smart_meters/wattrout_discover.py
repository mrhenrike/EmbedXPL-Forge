# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""WATTrouter Solar Inverter / Energy Manager — HTTP Discovery Scanner.

Discovers WATTrouter devices via HTTP probe on ports 8081 and 50000.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """WATTrouter Solar Energy Manager Discovery Scanner.

    Probes HTTP ports 8081 and 50000 for WATTrouter solar energy management
    devices. Extracts firmware version and device model from the web interface.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "WATTrouter Solar Device Discovery",
        "description": (
            "Probes HTTP ports 8081 and 50000 for WATTrouter solar energy management "
            "devices. Fingerprints model, firmware version, and configuration. "
            "WATTrouter devices have no authentication by default."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.wattrouter.com/",),
        "devices": ("WATTrouter M", "WATTrouter Mx", "WATTrouter ECO"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8081, "HTTP port (try 8081 or 50000)")

    _PROBE_PATHS = ["/", "/info.xml", "/status.xml", "/api/status", "/cgi-bin/info"]

    def run(self) -> None:
        print_status("Scanning WATTrouter on {}:{}...".format(self.target, self.port))

        for path in self._PROBE_PATHS:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code == 200:
                text = resp.text or ""
                print_success("Response on {} ({}):".format(path, len(text)))
                print_status(text[:300])
                if "wattrouter" in text.lower():
                    print_success("WATTrouter device confirmed at {}:{}".format(
                        self.target, self.port
                    ))
                break
            elif resp:
                print_status("{} — HTTP {}".format(path, resp.status_code))

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
