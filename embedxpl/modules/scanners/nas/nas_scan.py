# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""NAS Scanner — AutoPwn-style discovery and exploitation of NAS devices.

Runs all exploit and credential modules tagged for the 'nas' category
against the target, delegating to individual NAS exploit modules.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 1.0.0
"""

from embedxpl.modules.scanners.autopwn import Exploit


class Exploit(Exploit):
    """NAS Scanner — Auto-discovers NAS vulnerabilities and weak credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "NAS Scanner",
        "description": (
            "Module that scans for NAS device vulnerabilities and weak credentials. "
            "Covers QNAP, Synology, WD My Cloud, Seagate Business NAS, and other "
            "network-attached storage devices."
        ),
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "devices": (
            "NAS",
            "QNAP",
            "Synology",
            "WD My Cloud",
            "Seagate",
        ),
    }

    modules = ["generic", "nas"]
