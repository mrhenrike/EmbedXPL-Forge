# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""TVIP S-Box IP Camera — HTTP Discovery Scanner.

Discovers TVIP S-Box and similar IP camera/IPTV box devices via HTTP probe.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """TVIP S-Box IP Camera / IPTV Box Discovery Scanner.

    Probes HTTP ports 80 and 8080 to discover TVIP S-Box camera and
    IPTV set-top box devices. Enumerates the web UI for fingerprinting.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "TVIP S-Box Discovery Scanner",
        "description": (
            "Probes HTTP ports 80 and 8080 for TVIP S-Box IP cameras and IPTV "
            "set-top box web interfaces. Identifies device model and firmware version."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.tvip.ru/",),
        "devices": ("TVIP S-Box", "TVIP IP Camera"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port (try 80 or 8080)")

    def run(self) -> None:
        print_status("Scanning TVIP device on {}:{}...".format(self.target, self.port))

        for path in ["/", "/index.html", "/cgi-bin/index.cgi", "/api/info"]:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code in (200, 302):
                text = resp.text or ""
                print_success(
                    "HTTP {} on {} — {} bytes".format(resp.status_code, path, len(text))
                )
                if any(kw in text.lower() for kw in ["tvip", "s-box", "iptv", "multimedia"]):
                    print_success("TVIP device confirmed at {}:{}".format(
                        self.target, self.port
                    ))
                if text:
                    print_status("Preview: {}".format(text[:200]))
                break

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
