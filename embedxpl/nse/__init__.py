# Author: Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
"""EmbedXPL-Forge -- Nmap NSE Script Manager package.

Install, list, and run EmbedXPL custom NSE scripts with automatic Nmap detection.

Usage::

    embedxpl-nse install          # install to nmap scripts dir (validates nmap first)
    embedxpl-nse install --force  # overwrite existing
    embedxpl-nse list             # show all scripts and their status
    embedxpl-nse check            # validate nmap installation only
    embedxpl-nse run --target 192.168.1.0/24 --scripts all
    embedxpl-nse run --target 10.0.0.1 --scripts perimeter-vuln,router-vuln
    embedxpl-nse uninstall
    embedxpl-nse info hikvision-vuln

    python -m embedxpl.nse install    # alternative invocation

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 2.0.0
"""

from embedxpl.nse.manager import NSEManager

__all__ = ["NSEManager"]
__version__ = "2.0.0"
