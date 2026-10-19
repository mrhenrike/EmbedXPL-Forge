"""FXF theme definitions for Rich console.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

DARK_THEME = {
    "success": "bold green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold cyan",
    "module": "bold magenta",
    "vendor": "bold blue",
    "cve": "red",
    "timing": "dim",
    "header": "bold white on dark_blue",
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold green",
}

LIGHT_THEME = {
    "success": "bold dark_green",
    "error": "bold dark_red",
    "warning": "bold orange3",
    "info": "bold blue",
    "module": "bold purple",
    "vendor": "bold dark_blue",
    "cve": "dark_red",
    "timing": "dim",
    "header": "bold white on blue",
    "critical": "bold white on dark_red",
    "high": "bold dark_red",
    "medium": "bold orange3",
    "low": "bold dark_green",
}

SEVERITY_STYLES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
