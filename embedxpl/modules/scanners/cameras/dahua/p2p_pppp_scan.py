# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Dahua CCTV — PPPP P2P Cloud Module Scanner.

Detects Dahua devices using the PPPP/iLnkP2P cloud relay protocol,
which is vulnerable to UID enumeration (CVE-2019-11219) and session
key bypass (CVE-2019-11220).

DAHUA-2026-004 | CWE-330 | CVSSv3.1 7.5
Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Dahua CCTV PPPP P2P Cloud Scanner.

    Detects presence of PPPP/iLnkP2P cloud relay on Dahua devices.
    Affected devices are remotely accessible via P2P UID enumeration.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Dahua PPPP P2P Cloud Scanner (DAHUA-2026-004)",
        "description": (
            "DAHUA-2026-004 — Detects PPPP/iLnkP2P cloud relay protocol on "
            "Dahua devices. The PPPP protocol is vulnerable to UID enumeration "
            "(CVE-2019-11219) and session key bypass (CVE-2019-11220), enabling "
            "remote access to video feeds without authentication."
        ),
        "authors": (
            "Paul Marrapese (CVE-2019-11219/11220)",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11219",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11220",
            "https://hacked.camera/",
        ),
        "devices": (
            "Dahua IPC-HX2(1)XXX-Edison Entry V2.680",
            "Dahua devices with PPPP/iLnkP2P cloud module",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port")

    _PPPP_PORTS = [32100, 32108, 50000]

    _P2P_MARKERS = [
        "pppp", "ilnkp2p", "cs2network", "p2pid", "tutk",
        "iotcplatform", "cloudlink",
    ]

    def run(self) -> None:
        print_status("Scanning Dahua device at {} for PPPP P2P protocol...".format(self.target))
        found = False

        resp = self.http_request(method="GET", path="/")
        if resp and resp.text:
            text_lower = resp.text.lower()
            for marker in self._P2P_MARKERS:
                if marker in text_lower:
                    found = True
                    print_success("P2P marker '{}' found in web interface".format(marker))

        for p2p_port in self._PPPP_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target, p2p_port))
                sock.close()
                found = True
                print_success("PPPP port {} is OPEN".format(p2p_port))
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        if found:
            print_success(
                "[VULN] Device may be vulnerable to CVE-2019-11219/11220 "
                "(PPPP UID enumeration + session key bypass)"
            )
        else:
            print_error("No PPPP/P2P indicators found at {}".format(self.target))

    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None
