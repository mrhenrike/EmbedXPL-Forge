from embedxpl.modules.scanners.autopwn import Exploit


class Exploit(Exploit):
    __info__ = {
        "name": "Router Scanner",
        "description": "Module that scans for routers vulnerablities and weaknesses.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Router",
        ),
    }

    modules = ["generic", "routers"]
