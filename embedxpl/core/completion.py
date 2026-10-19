"""Shell tab-completion support for EmbedXPL CLI.

Provides argparse-based completion via argcomplete for the `exf`
console script. Falls back gracefully when argcomplete is not installed.

Usage in shell:
    eval "$(register-python-argcomplete exf)" (bash/zsh)
    register-python-argcomplete --shell fish exf | source (fish)
"""

from __future__ import annotations

import argparse
from typing import List, Optional


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser for tab completion."""
    parser = argparse.ArgumentParser(
        prog="exf",
        description="EmbedXPL-Forge: embedded device exploitation framework",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("shell", help="Start interactive shell")

    use_p = sub.add_parser("use", help="Select a module")
    use_p.add_argument("module", help="Module path (e.g. exploits/routers/...)")

    sub.add_parser("modules", help="List available modules")
    sub.add_parser("show", help="Show current module options")

    search_p = sub.add_parser("search", help="Search modules by keyword")
    search_p.add_argument("keyword", help="Search term")

    run_p = sub.add_parser("run", help="Run the selected module")
    run_p.add_argument("--target", "-t", help="Target host or IP")
    run_p.add_argument("--port", "-p", type=int, help="Target port")

    sub.add_parser("version", help="Show version information")
    sub.add_parser("plugins", help="List loaded plugins")

    return parser


def enable_completion(parser: Optional[argparse.ArgumentParser] = None) -> None:
    """Activate argcomplete on the given parser if available."""
    if parser is None:
        parser = build_parser()
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass


def get_module_completions(prefix: str, modules: List[str]) -> List[str]:
    """Filter module paths matching a prefix for completion."""
    return [m for m in modules if m.startswith(prefix)]
