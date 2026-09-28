#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
"""EmbedXPL-Forge NSE Script Manager -- CLI entry point.

Invoked via:
    embedxpl-nse <command>   (pip entry point)
    python -m embedxpl.nse <command>   (direct module)

Commands:
    install     Validate Nmap, locate scripts dir, copy .nse files, update db.
                If Nmap is not installed: prints local file paths and exits cleanly.
    uninstall   Remove EmbedXPL NSE scripts from Nmap's scripts directory.
    list        List all EmbedXPL NSE scripts with installation status.
    check       Validate Nmap installation and scripts directory.
    run         Run one or more NSE scripts via nmap against a target.
    info        Show info and header for a specific NSE script.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 2.0.0
"""

import sys
from embedxpl.nse.manager import NSEManager


def main() -> None:
    """CLI entry point for both ``embedxpl-nse`` and ``python -m embedxpl.nse``."""
    mgr = NSEManager()
    mgr.cli(sys.argv[1:])


if __name__ == "__main__":
    main()
