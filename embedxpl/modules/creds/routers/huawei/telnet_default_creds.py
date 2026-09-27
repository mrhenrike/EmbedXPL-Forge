from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Huawei Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Huawei Router Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Huawei Router",
        ),
    }

    target = OptIP("", "Targe IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("file://wordlists/vendors/huawei_defaults.txt", "User:Pass or file with default credentials (file://)")
