"""Styled banner with hardware and module summary.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from typing import Dict, List

from firewallxpl.core.tui.console import console, has_rich

if has_rich:
    from rich.panel import Panel
    from rich.text import Text


ASCII_ART = r"""
 ______ __  __ ______ ___  _       _____
|  ____|\ \/ /|  ____|__ \| |     |  ____| 
| |__    \  / | |__ ___) | |     | |__  ___  _ __ __ _  ___
|  __|   /  \ |  __|___/ /| |    |  __|/ _ \| '__/ _` |/ _ \
| |     / /\ \| |   / /__| |____| |  | (_) | | | (_| |  __/
|_|    /_/  \_\_|  |_____|______|_|   \___/|_|  \__, |\___|
                                                 __/ |
                                                |___/
"""


def render_banner(
    version: str,
    module_counts: Dict[str, int],
    hw_summary: List[str] = None,
) -> None:
    """Render the FXF startup banner."""
    if has_rich:
        banner_text = Text(ASCII_ART, style="bold cyan")
        info_lines = [
            f"  Version    : {version}",
            f"  Author     : Andr\u00e9 Henrique (@mrhenrike) | Uni\u00e3o Geek",
            "",
        ]
        counts = " | ".join(f"{k}: {v}" for k, v in sorted(module_counts.items()))
        info_lines.append(f"  Modules    : {counts}")

        if hw_summary:
            info_lines.append("")
            for line in hw_summary:
                info_lines.append(f"  {line}")

        content = banner_text
        console.print(content)
        console.print(Panel("\n".join(info_lines), border_style="cyan", title="FirewallXPL-Forge"))
    else:
        print(ASCII_ART)
        print(f"  Version: {version}")
        counts = " | ".join(f"{k}: {v}" for k, v in sorted(module_counts.items()))
        print(f"  Modules: {counts}")
        if hw_summary:
            for line in hw_summary:
                print(f"  {line}")
        print()
