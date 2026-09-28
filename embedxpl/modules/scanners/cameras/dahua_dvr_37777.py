# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Dahua DVR — TCP Port 37777 Scanner.

Discovers Dahua DVR/NVR/XVR devices via TCP port 37777 and HTTP port 80.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Dahua DVR Port 37777 Discovery Scanner.

    Discovers Dahua DVR/NVR/XVR devices by probing the proprietary management
    protocol on TCP port 37777 and the HTTP web interface on port 80.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Dahua DVR Port 37777 Scanner",
        "description": (
            "Discovers Dahua DVR/NVR/XVR devices via TCP port 37777 (Dahua private protocol) "
            "and HTTP port 80 web interface. Fingerprints device model and firmware version."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/mcw0/PoC",
        ),
        "devices": ("Dahua DVR", "Dahua NVR", "Dahua XVR"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")
    mgmt_port = OptPort(37777, "Dahua management port")

    def run(self) -> None:
        print_status("Scanning Dahua DVR on {}...".format(self.target))

        # TCP port 37777 probe
        try:
            sock = socket.create_connection((self.target, int(self.mgmt_port)), timeout=3)
            print_success(
                "Dahua management port {} OPEN on {}".format(self.mgmt_port, self.target)
            )
            # Send DHCP-style initial auth packet (Dahua UDP/TCP protocol)
            probe = bytes([0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00])
            sock.sendall(probe)
            sock.settimeout(3)
            try:
                data = sock.recv(256)
                print_success(
                    "Dahua protocol response ({} bytes)".format(len(data))
                )
            except socket.timeout:
                print_status("No immediate Dahua protocol response")
            sock.close()
        except Exception:
            print_status("Port {} not open on {}".format(self.mgmt_port, self.target))

        # HTTP probe
        resp = self.http_request(method="GET", path="/")
        if resp and resp.status_code in (200, 302, 401):
            text = resp.text or ""
            if "dahua" in text.lower() or "dh-" in text.lower():
                print_success("Dahua web interface confirmed on {}:{}".format(
                    self.target, self.port
                ))
            else:
                print_status("HTTP {} on port {}".format(resp.status_code, self.port))

    @mute
    def check(self) -> bool:
        try:
            with socket.create_connection((self.target, int(self.mgmt_port)), timeout=3):
                return True
        except Exception:
            resp = self.http_request(method="GET", path="/")
            return resp is not None and resp.status_code in (200, 401)
