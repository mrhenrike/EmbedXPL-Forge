"""Rich table formatters for module listings, scan results, and options.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from typing import Any, List, Sequence, Tuple

from firewallxpl.core.tui.console import console, has_rich

if has_rich:
    from rich.table import Table


def render_results_table(
    headers: Sequence[str],
    rows: List[Tuple[Any, ...]],
    title: str = "",
) -> None:
    """Render a results table with colored severity."""
    if has_rich:
        table = Table(title=title, show_lines=True, border_style="cyan")
        for h in headers:
            table.add_column(h, style="bold")
        for row in rows:
            str_row = [str(c) for c in row]
            table.add_row(*str_row)
        console.print(table)
    else:
        if title:
            print(f"\n--- {title} ---")
        print(" | ".join(str(h) for h in headers))
        print("-" * 60)
        for row in rows:
            print(" | ".join(str(c) for c in row))


def render_options_table(options: List[Tuple[str, str, str, str]]) -> None:
    """Render module options table (name, current, required, description)."""
    if has_rich:
        table = Table(title="Module Options", border_style="blue")
        table.add_column("Name", style="bold cyan")
        table.add_column("Current", style="green")
        table.add_column("Required", style="yellow")
        table.add_column("Description")
        for name, current, required, desc in options:
            table.add_row(name, current, required, desc)
        console.print(table)
    else:
        print("\n--- Module Options ---")
        for name, current, required, desc in options:
            print(f"  {name:20s} = {current:15s} [{required}] {desc}")


def render_module_list(modules: List[Tuple[str, str]], title: str = "Modules") -> None:
    """Render a list of modules with paths and descriptions."""
    if has_rich:
        table = Table(title=title, border_style="magenta")
        table.add_column("Path", style="module")
        table.add_column("Name")
        for path, name in modules:
            table.add_row(path, name)
        console.print(table)
    else:
        print(f"\n--- {title} ---")
        for path, name in modules:
            print(f"  {path:50s} {name}")
