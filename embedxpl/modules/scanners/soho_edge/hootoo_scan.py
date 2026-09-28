from embedxpl.modules.scanners.autopwn import Exploit as BaseScanner
from embedxpl.core.exploit import OptString

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek


class Exploit(BaseScanner):
    """Scanner implementation for HooToo vulnerabilities."""

    __info__ = {
        "name": "HooToo Scanner",
        "description": "Scanner module for HooToo routers",
        "authors": (
            'Tao "depierre" Sauvage',
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "http://blog.ioactive.com/2018/04/hootoo-tripmate-routers-are-cute-but.html",
            "https://www.ioactive.com/pdfs/HooToo_Security_Advisory_FINAL_4.19.18.pdf",
        ),
        "devices": (
            "HooToo TripMate",
        ),
    }

    # Keep scoped to routers/misc only (camera scope is intentionally excluded in EmbedXPL-Forge).
    modules = ["routers", "misc"]
    vendor = OptString("hootoo", "Vendor concerned (default: hootoo)")