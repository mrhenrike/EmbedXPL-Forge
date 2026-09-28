# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""NAS Universal Discovery Scanner — HTTP/AFP/SMB.

Discovers NAS devices by probing common management and protocol ports.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_NAS_PORTS = [
    (80, "tcp", "HTTP Web UI"),
    (443, "tcp", "HTTPS Web UI"),
    (445, "tcp", "SMB"),
    (548, "tcp", "AFP (Apple Filing Protocol)"),
    (873, "tcp", "rsync"),
    (5000, "tcp", "Synology DSM HTTP"),
    (5001, "tcp", "Synology DSM HTTPS"),
    (8080, "tcp", "QNAP HTTP"),
    (8443, "tcp", "QNAP HTTPS"),
]


class Exploit(HTTPClient):
    """NAS Universal Discovery Scanner.

    Probes common NAS management and protocol ports to discover
    QNAP, Synology, and other NAS devices.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NAS Universal Discovery Scanner",
        "description": (
            "Probes common NAS ports (HTTP/HTTPS/SMB/AFP/rsync) to discover "
            "QNAP, Synology, Hitachi HNAS, and other NAS devices. "
            "Extracts web UI fingerprints to identify vendor."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (),
        "devices": ("QNAP", "Synology", "Hitachi HNAS", "Western Digital NAS"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "Primary HTTP port")
    timeout = OptInteger(2, "Port probe timeout")

    def run(self) -> None:
        print_status("Scanning NAS on {}...".format(self.target))

        for port, proto, desc in _NAS_PORTS:
            try:
                with socket.create_connection(
                    (self.target, port), timeout=float(self.timeout)
                ):
                    print_success("Port {}/{} open — {}".format(port, proto, desc))
            except Exception:
                pass

        for path in ["/", "/cgi-bin/authLogin.cgi", "/webapi/query.cgi"]:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code in (200, 302):
                text = (resp.text or "").lower()
                vendor = "Unknown NAS"
                for kw, vend in [("qnap", "QNAP"), ("synology", "Synology"), ("hitachi", "Hitachi HNAS")]:
                    if kw in text:
                        vendor = vend
                        break
                print_success("Web UI detected on {} — Vendor: {}".format(path, vendor))
                break

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
