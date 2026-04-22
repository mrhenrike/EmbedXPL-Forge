#!/usr/bin/env python3
# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge NSE Script Manager — CLI entry point.

Commands
--------
install     Copy NSE scripts to Nmap's script directory and update db.
uninstall   Remove EmbedXPL NSE scripts from Nmap's script directory.
list        List installed EmbedXPL NSE scripts.
run         Run one or more NSE scripts via nmap.
info        Show info for a specific NSE script.

Usage::

    python -m embedxpl.nse install
    python -m embedxpl.nse list
    python -m embedxpl.nse run --target 192.168.1.0/24 --scripts all
    python -m embedxpl.nse run --target 192.168.1.100 --scripts rtsp-discover,hikvision-vuln
    python -m embedxpl.nse uninstall

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

import sys
from embedxpl.nse.manager import NSEManager


def main() -> None:
    """CLI entry point for ``python -m embedxpl.nse``."""
    mgr = NSEManager()
    mgr.cli(sys.argv[1:])


if __name__ == "__main__":
    main()
