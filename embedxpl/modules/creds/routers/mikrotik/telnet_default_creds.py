from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault
from embedxpl.resources import wordlists


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Mikrotik Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Mikrotik Router Telnet service."
                       "If valid credentials are found they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Mikrotik Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist(
        wordlists.mikrotik_api,
        "User:Pass or file with default credentials (file://)",
    )