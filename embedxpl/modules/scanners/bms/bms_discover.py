# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""BMS (Building Management System) Universal Discovery Scanner.

Probes common BMS ports for ABB Cylon, ScadaFlex, Siemens,
and similar building automation devices.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_BMS_PORTS = [
    (80, "tcp", "HTTP Web UI"),
    (443, "tcp", "HTTPS Web UI"),
    (47808, "udp", "BACnet"),
    (1911, "tcp", "Niagara Fox"),
    (4911, "tcp", "Niagara Fox TLS"),
    (9090, "tcp", "Tridium/Niagara HTTP"),
    (102, "tcp", "S7comm (Siemens)"),
    (20000, "tcp", "DNP3"),
    (2222, "tcp", "EtherNet/IP (alt)"),
]

_BACNET_WHO_IS = (
    b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"
)


class Exploit(BaseExploit):
    """BMS Universal Discovery Scanner.

    Probes common BMS/SCADA ports to discover ABB Cylon Aspect, ScadaFlex,
    Tridium Niagara, and other building automation devices.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "BMS Universal Discovery Scanner",
        "description": (
            "Probes common BMS/SCADA ports including BACnet UDP/47808, "
            "Niagara Fox TCP/1911, and HTTP management to discover building "
            "automation controllers (ABB Cylon, ScadaFlex, Tridium Niagara)."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (),
        "devices": (
            "ABB Cylon Aspect", "ScadaFlex II", "Tridium Niagara",
            "Siemens DESIGO", "Honeywell WEBs",
        ),
    }

    target = OptIP("", "Target IPv4 address")
    timeout = OptInteger(2, "Port probe timeout")

    def run(self) -> None:
        print_status("Scanning BMS/SCADA on {}...".format(self.target))

        for port, proto, desc in _BMS_PORTS:
            if proto == "udp":
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(float(self.timeout))
                    if port == 47808:
                        sock.sendto(_BACNET_WHO_IS, (self.target, port))
                    else:
                        sock.sendto(b"\x00", (self.target, port))
                    data, _ = sock.recvfrom(256)
                    if data:
                        print_success("UDP/{} open — {} (BACnet response: {} bytes)".format(
                            port, desc, len(data)
                        ))
                except Exception:
                    pass
            else:
                try:
                    with socket.create_connection(
                        (self.target, port), timeout=float(self.timeout)
                    ):
                        print_success("TCP/{} open — {}".format(port, desc))
                except Exception:
                    pass

    @mute
    def check(self) -> bool:
        for port in [80, 1911, 47808]:
            try:
                if port == 47808:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1)
                    sock.sendto(_BACNET_WHO_IS, (self.target, port))
                    sock.recvfrom(64)
                    return True
                else:
                    with socket.create_connection((self.target, port), timeout=1):
                        return True
            except Exception:
                pass
        return False
