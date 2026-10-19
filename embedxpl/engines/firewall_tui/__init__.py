"""Terminal User Interface for FirewallXPL-Forge using Rich.

Provides styled console output, tables, progress bars, panels, and
an optional full-screen dashboard. Falls back to ANSI if Rich is absent.

Author: André Henrique (@mrhenrike) | União Geek
"""

from firewallxpl.core.tui.console import console, has_rich

__all__ = ["console", "has_rich"]
