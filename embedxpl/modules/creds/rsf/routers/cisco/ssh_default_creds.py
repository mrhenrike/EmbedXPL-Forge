# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek

from embedxpl.core.exploit import *
# SKIPPED: from routersploit.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "Cisco Router Default SSH Creds",
        "description": "Module performs dictionary attack against Cisco Router SSH service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",
# SKIPPED:             "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Cisco Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")
