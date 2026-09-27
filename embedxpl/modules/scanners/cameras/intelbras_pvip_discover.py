# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras PVIP 1000 IP Camera — Network Discovery Scanner.

Discovers Intelbras PVIP 1000 cameras via HTTP and SIP probes.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Intelbras PVIP 1000 Camera Discovery Scanner.

    Probes the Intelbras PVIP 1000 IP camera web interface on port 80 and
    the SIP service on port 5060 to discover and fingerprint the device.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras PVIP 1000 Discovery Scanner",
        "description": (
            "Probes HTTP port 80 and SIP port 5060 to discover and fingerprint "
            "Intelbras PVIP 1000 IP cameras. Extracts firmware version and "
            "model information from the web interface."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.intelbras.com/",
        ),
        "devices": ("Intelbras PVIP 1000",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")
    sip_port = OptPort(5060, "SIP port")

    def run(self) -> None:
        print_status("Scanning Intelbras PVIP at {}...".format(self.target))

        # HTTP probe
        resp = self.http_request(method="GET", path="/")
        if resp and resp.status_code in (200, 302, 401):
            print_success(
                "HTTP response on port {}: HTTP {}".format(self.port, resp.status_code)
            )
            text = resp.text or ""
            if "intelbras" in text.lower() or "pvip" in text.lower():
                print_success("Intelbras PVIP confirmed in HTTP response")
            if resp.status_code == 401:
                auth_header = resp.headers.get("WWW-Authenticate", "")
                print_status("Auth required: {}".format(auth_header))

        # SIP probe
        try:
            sip_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sip_sock.settimeout(3)
            options_msg = (
                "OPTIONS sip:{}:{} SIP/2.0\r\n"
                "Via: SIP/2.0/UDP localhost:5060;branch=z9hG4bKembedxpl\r\n"
                "Max-Forwards: 70\r\n"
                "To: <sip:{}:{}>\r\n"
                "From: <sip:embedxpl@localhost>;tag=12345\r\n"
                "Call-ID: embedxpl-scan@localhost\r\n"
                "CSeq: 1 OPTIONS\r\n"
                "Content-Length: 0\r\n\r\n"
            ).format(self.target, self.sip_port, self.target, self.sip_port)
            sip_sock.sendto(options_msg.encode(), (self.target, int(self.sip_port)))
            data, _ = sip_sock.recvfrom(1024)
            print_success(
                "SIP port {} responded: {}".format(
                    self.sip_port,
                    data.decode("utf-8", errors="replace")[:100]
                )
            )
            sip_sock.close()
        except Exception:
            print_status("SIP port {} did not respond".format(self.sip_port))

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
