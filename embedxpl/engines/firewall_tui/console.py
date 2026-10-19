"""Central Rich console singleton with FXF theme.

If Rich is not installed, provides a lightweight fallback that passes
output through to stdout with basic ANSI coloring.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import sys
from typing import Any

has_rich: bool = False

try:
    from rich.console import Console
    from rich.theme import Theme

    fxf_theme = Theme({
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "info": "bold cyan",
        "module": "bold magenta",
        "vendor": "bold blue",
        "cve": "red",
        "timing": "dim",
        "header": "bold white on dark_blue",
    })

    console = Console(theme=fxf_theme, highlight=True)
    has_rich = True

except ImportError:

    class _FallbackConsole:
        """Minimal fallback when Rich is not available."""

        def print(self, *args: Any, **kwargs: Any) -> None:
            style = kwargs.pop("style", "")
            text = " ".join(str(a) for a in args)
            if "error" in str(style):
                text = "\033[91m" + text + "\033[0m"
            elif "success" in str(style):
                text = "\033[92m" + text + "\033[0m"
            elif "warning" in str(style):
                text = "\033[93m" + text + "\033[0m"
            elif "info" in str(style):
                text = "\033[94m" + text + "\033[0m"
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

        def rule(self, title: str = "", **kwargs: Any) -> None:
            width = 60
            if title:
                pad = (width - len(title) - 2) // 2
                print("-" * pad + " " + title + " " + "-" * pad)
            else:
                print("-" * width)

        def status(self, *args: Any, **kwargs: Any) -> "_FallbackContext":
            return _FallbackContext()

    class _FallbackContext:
        def __enter__(self) -> "_FallbackContext":
            return self
        def __exit__(self, *args: Any) -> None:
            pass

    console = _FallbackConsole()  # type: ignore
