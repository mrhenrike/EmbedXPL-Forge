"""Interactive prompt helpers with Rich auto-complete support.

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

from typing import List, Optional

from firewallxpl.core.tui.console import console, has_rich


def styled_prompt(text: str, default: str = "") -> str:
    """Display a styled prompt and get user input."""
    if has_rich:
        from rich.prompt import Prompt
        return Prompt.ask(text, default=default)
    return input(f"{text} [{default}]: ").strip() or default


def confirm_prompt(text: str, default: bool = True) -> bool:
    """Display a yes/no confirmation prompt."""
    if has_rich:
        from rich.prompt import Confirm
        return Confirm.ask(text, default=default)
    answer = input(f"{text} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "s", "sim")


def select_prompt(text: str, choices: List[str], default: str = "") -> str:
    """Display a selection prompt with choices."""
    if has_rich:
        from rich.prompt import Prompt
        return Prompt.ask(text, choices=choices, default=default)
    print(f"{text}")
    for i, c in enumerate(choices, 1):
        print(f"  {i}. {c}")
    answer = input(f"Choose [{default}]: ").strip()
    if not answer:
        return default
    try:
        idx = int(answer) - 1
        if 0 <= idx < len(choices):
            return choices[idx]
    except ValueError:
        if answer in choices:
            return answer
    return default
