# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""BMC/IPMI Universal Scanner — Redfish + IPMI UDP Discovery.

Discovers BMC/IPMI management interfaces on servers.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_IPMI_PROBE = (
    b"\x06\x00\xff\x07"
    b"\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5"
)


class Exploit(HTTPClient):
    """BMC/IPMI Universal Discovery Scanner.

    Probes for BMC/IPMI interfaces via UDP/623 (IPMI) and HTTPS Redfish
    API (/redfish/v1/) to discover Dell iDRAC, HP iLO, ASUS ASMB8,
    and Supermicro BMC cards.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BMC/IPMI Universal Discovery Scanner",
        "description": (
            "Probes IPMI UDP/623 and HTTPS Redfish API to discover BMC management "
            "interfaces on servers. Identifies Dell iDRAC, HP iLO, ASUS ASMB8, "
            "and Supermicro BMC."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (),
        "devices": ("Dell iDRAC", "HP iLO", "ASUS ASMB8", "Supermicro BMC"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(443, "HTTPS Redfish port")
    ssl = OptBool(True, "Use HTTPS")
    ipmi_port = OptPort(623, "IPMI UDP port")

    def run(self) -> None:
        print_status("Scanning BMC/IPMI on {}...".format(self.target))

        # IPMI UDP probe
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(_IPMI_PROBE, (self.target, int(self.ipmi_port)))
            data, _ = sock.recvfrom(256)
            if data:
                print_success("IPMI service active on {}:{} ({} bytes)".format(
                    self.target, self.ipmi_port, len(data)
                ))
        except Exception:
            pass

        # Redfish HTTPS probe
        resp = self.http_request(method="GET", path="/redfish/v1/")
        if resp and resp.status_code in (200, 401):
            text = resp.text or ""
            vendor = "Unknown BMC"
            for kw, vend in [
                ("idrac", "Dell iDRAC"),
                ("ilo", "HP iLO"),
                ("supermicro", "Supermicro"),
                ("asus", "ASUS ASMB"),
            ]:
                if kw in text.lower():
                    vendor = vend
                    break
            print_success(
                "Redfish API detected on {}:{} — Vendor: {}".format(
                    self.target, self.port, vendor
                )
            )

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/redfish/v1/")
        return resp is not None and resp.status_code in (200, 401)
