# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""SOHO Router Universal Discovery Scanner.

Identifies common SOHO/CPE routers by probing HTTP management interface
and extracting fingerprint from response headers and body.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_FINGERPRINTS = {
    "netis": ["netis", "wf2419", "wf2409"],
    "gl-inet": ["gl-inet", "gl.inet", "openwrt", "luci"],
    "zte": ["zte", "f670", "zxhn"],
    "tenda": ["tenda", "tendawifi"],
    "linksys": ["linksys", "jnap"],
    "aitemi": ["aitemi", "a3004"],
    "tp-link": ["tp-link", "tplink", "tdw"],
    "d-link": ["d-link", "dlink", "dir-"],
    "huawei": ["huawei", "hg8", "hg556"],
    "zte_home": ["c300", "c600", "vdsl"],
}


class Exploit(HTTPClient):
    """SOHO Router Universal HTTP Discovery Scanner.

    Probes the HTTP management interface to fingerprint SOHO/CPE routers
    from multiple vendors. Extracts model info from title and server headers.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "SOHO Router Universal HTTP Discovery",
        "description": (
            "Probes HTTP management port (80/8080) to fingerprint SOHO and CPE "
            "routers from Netis, GL-iNet, ZTE, Tenda, Linksys, Aitemi, and others. "
            "Extracts model info from page title and Server header."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (),
        "devices": ("Netis", "GL-iNet", "ZTE", "Tenda", "Linksys", "Aitemi", "TP-Link", "D-Link"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port")

    def run(self) -> None:
        print_status("Scanning SOHO router on {}:{}...".format(self.target, self.port))

        for path in ["/", "/login.html", "/login", "/index.html"]:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code in (200, 302, 401):
                text = (resp.text or "").lower()
                server = resp.headers.get("Server", "") if resp.headers else ""
                title = ""
                for line in (resp.text or "").split("\n"):
                    if "<title" in line.lower():
                        title = line.strip()
                        break

                vendor_match = "unknown"
                for vendor, keywords in _FINGERPRINTS.items():
                    if any(kw in text for kw in keywords):
                        vendor_match = vendor
                        break

                print_success(
                    "{}:{} → Vendor: {} | Server: {} | Title: {}".format(
                        self.target, self.port, vendor_match, server, title[:60]
                    )
                )
                return

        print_error("No HTTP management interface found on {}:{}".format(self.target, self.port))

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
