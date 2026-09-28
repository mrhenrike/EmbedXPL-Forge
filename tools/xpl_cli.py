#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Global CLI bootstrap for XPL-Forge entry points (flags, colors, doctor, interactive)."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ProductInfo:
    name: str
    slug: str
    version: str
    cli_name: str
    min_python: Tuple[int, int] = (3, 8)
    pip_package: Optional[str] = None
    setup_hint: str = "./setup_venv.sh  or  pip install -r requirements.txt"


class _C:
    B = "\033[1m"
    G = "\033[32m"
    Y = "\033[33m"
    C = "\033[36m"
    M = "\033[35m"
    R = "\033[0m"
    RED = "\033[31m"


def _init_color(disable: bool = False) -> None:
    if disable or not sys.stdout.isatty():
        for attr in ("B", "G", "Y", "C", "M", "R", "RED"):
            setattr(_C, attr, "")
        return
    try:
        import colorama

        colorama.init()
    except ImportError:
        pass


def _has_flag(args: Sequence[str], *flags: str) -> bool:
    return any(f in args for f in flags)


def _strip_global_flags(rest: List[str]) -> List[str]:
    skip = {
        "-h", "--help", "-V", "--version", "-i", "--interactive",
        "--doctor", "--check", "--env-check", "--no-color",
    }
    return [x for x in rest if x not in skip]


def resolve_mode(argv: Sequence[str]) -> Tuple[str, bool]:
    """Return (mode, no_color). mode: interactive|passthrough|doctor|help|version."""
    rest = list(argv[1:])
    no_color = _has_flag(rest, "--no-color")
    _init_color(no_color)

    if _has_flag(rest, "--doctor", "--check", "--env-check"):
        return "doctor", no_color
    if _has_flag(rest, "-V", "--version"):
        return "version", no_color
    if _has_flag(rest, "-i", "--interactive"):
        return "interactive", no_color
    if _has_flag(rest, "-h", "--help") and not _has_flag(rest, "-m", "--module"):
        return "help", no_color
    if not rest or not _strip_global_flags(rest):
        return "interactive", no_color
    return "passthrough", no_color


def print_banner(product: ProductInfo) -> None:
    c = _C
    print(
        f"\n{c.B}{c.C}╔══════════════════════════════════════════════════════════════╗\n"
        f"║  {product.name:<58}║\n"
        f"║  {('v' + product.version):<58}║\n"
        f"╚══════════════════════════════════════════════════════════════╝{c.R}\n"
    )


def print_help(product: ProductInfo) -> None:
    c = _C
    pkg = product.pip_package or product.slug
    print_banner(product)
    print(
        f"{c.Y}Usage:{c.R}\n"
        f"  {product.cli_name}                              Interactive shell (default)\n"
        f"  {product.cli_name} -i, --interactive             Force interactive mode\n"
        f"  {product.cli_name} -m <module> -s \"opt val\"       Run module non-interactively\n"
        f"  {product.cli_name} --doctor                       Dependency & module check\n"
        f"  {product.cli_name} -V, --version                  Show version\n"
        f"  {product.cli_name} -h, --help                     Show this help\n"
        f"\n{c.Y}Global flags:{c.R}\n"
        f"  -h, --help              Show help\n"
        f"  -V, --version           Show version\n"
        f"  -i, --interactive       Launch interactive shell\n"
        f"  --doctor, --check       Environment / dependency check\n"
        f"  --no-color              Disable ANSI colors\n"
        f"\n{c.Y}Module flags (non-interactive):{c.R}\n"
        f"  -m, --module <path>     Module path (e.g. scanners/autopwn)\n"
        f"  -s, --set \"opt val\"     Set module option (repeatable)\n"
        f"  -T, --targets <file>    Multi-target scan from file\n"
        f"  --infra <type>          Infrastructure scan mode\n"
        f"  --context <ctx>         Scan context (with --infra)\n"
        f"\n{c.Y}Setup:{c.R}\n"
        f"  {product.setup_hint}\n"
        f"  pip install {pkg}\n"
    )


def print_version(product: ProductInfo) -> None:
    print(f"{product.name} v{product.version}")


def run_doctor() -> int:
    from tools.env_doctor import main as doctor_main

    return int(doctor_main())


def bootstrap(argv: Sequence[str], product: ProductInfo, launcher: Callable[[List[str]], None]) -> None:
    """Parse global flags, then invoke launcher(argv) for interactive or passthrough."""
    if sys.version_info < product.min_python:
        print(
            f"{product.name} requires Python {product.min_python[0]}.{product.min_python[1]}+ "
            f"(detected {sys.version_info.major}.{sys.version_info.minor})"
        )
        raise SystemExit(1)

    mode, _no_color = resolve_mode(argv)

    if mode == "help":
        print_help(product)
        return
    if mode == "version":
        print_version(product)
        return
    if mode == "doctor":
        raise SystemExit(run_doctor())

    if mode == "interactive":
        launcher([argv[0]])
        return

    cleaned = [argv[0]] + _strip_global_flags(list(argv[1:]))
    launcher(cleaned if len(cleaned) > 1 else [argv[0]])
