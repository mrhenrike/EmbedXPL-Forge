# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""HP Printer — Raw Print Port 9100 Scanner.

Discovers HP and other printers with the raw print (JetDirect) port 9100 open.

Version: 1.0.0
"""

import socket

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

_PJL_INFO_REQUEST = b"@PJL INFO ID\r\n\x1b%-12345X@PJL\r\n@PJL INFO ID\r\n\x1b%-12345X\r\n"


class Exploit(BaseExploit):
    """HP Raw Print Port 9100 Scanner.

    Scans for open HP JetDirect / raw print port 9100. Sends a PJL INFO ID
    query to extract the printer model and firmware version.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "HP Raw Print Port 9100 Scanner",
        "description": (
            "Discovers printers with open raw print (JetDirect) port 9100. "
            "Sends a PJL INFO ID query to fingerprint the printer model and firmware. "
            "Open port 9100 allows unauthenticated raw document printing."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.hackingprinters.com/index.php/PJL",
        ),
        "devices": ("HP LaserJet", "HP OfficeJet", "HP DesignJet", "Generic PJL Printer"),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(9100, "Raw print (JetDirect) port")
    timeout = OptInteger(5, "Connection timeout")

    def run(self) -> None:
        print_status("Probing raw print port on {}:{}...".format(self.target, self.port))

        try:
            sock = socket.create_connection((self.target, self.port), timeout=self.timeout)
            sock.sendall(_PJL_INFO_REQUEST)
            sock.settimeout(float(self.timeout))

            response = b""
            try:
                while len(response) < 2048:
                    chunk = sock.recv(512)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()

            if response:
                text = response.decode("utf-8", errors="replace")
                print_success("Printer responded on {}:{}".format(self.target, self.port))
                lines = [l.strip() for l in text.split("\n") if l.strip()]
                for line in lines[:10]:
                    print_status("  {}".format(line))
                print_status(
                    "Port 9100 is open — raw printing and PJL attacks are possible"
                )
            else:
                print_status(
                    "Port {} open but no PJL response — may be non-HP or filtered".format(
                        self.port
                    )
                )
        except ConnectionRefusedError:
            print_error("Port {} is closed on {}".format(self.port, self.target))
        except Exception as e:
            print_error("Probe error: {}".format(e))

    @mute
    def check(self) -> bool:
        try:
            with socket.create_connection((self.target, self.port), timeout=3):
                return True
        except Exception:
            return False
