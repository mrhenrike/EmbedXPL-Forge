# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras CCTV — Boa Web Server (EOL) Detection Scanner.

Detects Boa HTTP server via banner fingerprinting on Intelbras CCTV devices.
Boa has been end-of-life since 2005 (v0.94.14rc21) with known unpatched CVEs.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Intelbras Boa Web Server (EOL) Detection Scanner.

    Probes the HTTP server banner to detect Boa HTTP server presence.
    Reports known CVEs and EOL status when detected.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras Boa Web Server (EOL) Detection",
        "description": (
            "Detects the end-of-life Boa HTTP server on Intelbras CCTV devices. "
            "Boa has not been maintained since 2005 and has known CVEs including "
            "CVE-2005-2970 (DoS) and CVE-2009-4496 (directory traversal). "
            "Ref: INTELBRAS-2026-003."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "http://www.boa.org/",
            "https://nvd.nist.gov/vuln/detail/CVE-2005-2970",
            "https://nvd.nist.gov/vuln/detail/CVE-2009-4496",
        ),
        "devices": (
            "Intelbras VIP 3230 B SD",
            "Intelbras MHDX 3108",
            "Intelbras MHDX 1108 G3",
            "Intelbras MHDX 1004-C",
            "Intelbras NVD 3316-P",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")

    def run(self) -> None:
        print_status(
            "Probing for Boa web server on {}:{}...".format(self.target, self.port)
        )

        resp = self.http_request(method="GET", path="/")
        if resp is None:
            print_error("No HTTP response from {}:{}".format(self.target, self.port))
            return

        server = resp.headers.get("Server", "")
        boa_detected = "boa" in server.lower()

        if boa_detected:
            print_success("Boa web server detected: {}".format(server))
            print_success("WARNING: Boa is END-OF-LIFE since February 2005")
            print_success("Known CVEs: CVE-2005-2970 (DoS), CVE-2009-4496 (traversal)")
            print_status(
                "Run exploits/cameras/intelbras/ modules for exploitation"
            )
        else:
            print_status("Server header: {}".format(server or "(empty)"))

        for path in ["/doc/", "/doc/index.html", "/cgi-bin/"]:
            resp2 = self.http_request(method="GET", path=path)
            if resp2 and resp2.status_code == 200:
                text = resp2.text or ""
                if "boa" in text.lower():
                    print_success(
                        "Boa reference found in {} response body".format(path)
                    )
                    boa_detected = True

        if not boa_detected:
            print_status("Boa web server NOT detected on {}:{}".format(
                self.target, self.port
            ))

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        if resp and "boa" in resp.headers.get("Server", "").lower():
            return True
        return False
