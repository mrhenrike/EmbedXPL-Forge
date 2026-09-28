from embedxpl.modules.scanners.autopwn import Exploit


class Exploit(Exploit):
    __info__ = {
        "name": "Misc Scanner",
        "description": "Module that scans for generic device vulnerabilities and weaknesses.",
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "devices": (
            "Misc Device",
        ),
    }

    modules = ["perimeter", "waf", "vpn", "nac", "lb", "generic"]
