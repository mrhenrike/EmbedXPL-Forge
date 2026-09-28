# Author: André Henrique (LinkedIn/X: @mrhenrike)
from embedxpl.modules.scanners.autopwn import Exploit


class Exploit(Exploit):
    """Camera Scanner — Auto-discovers camera vulnerabilities and weak credentials.

    Runs all exploit and credential modules tagged for the 'cameras' category
    against the target.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Camera Scanner",
        "description": "Module that scans for camera vulnerabilities and weaknesses.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge port",
        ),
        "devices": (
            "Cameras",
        ),
    }

    modules = ["generic", "cameras"]
