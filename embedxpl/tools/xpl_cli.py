"""Global CLI bootstrap for XPL-Forge entry points (flags, colors, doctor, interactive)."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple


@dataclass
class ProductInfo:
    name: str
    slug: str
    version: str
    cli_name: str
    min_python: Tuple[int, int]
    pip_package: Optional[str] = None
    setup_hint: str = "./setup_venv.sh  or  pip install -r requirements.txt"


class _C:
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    RESET = "\033[0m"
    RED = "\033[31m"
    disable = False

    @classmethod
    def B(cls, s: str) -> str:
        return "" if cls.disable else cls.BOLD + s + cls.RESET

    @classmethod
    def g(cls, s: str) -> str:
        return "" if cls.disable else cls.GREEN + s + cls.RESET


def _init_color(no_color: bool) -> None:
    _C.disable = no_color or not sys.stdout.isatty()


def _has_flag(args: Sequence[str], *flags: str) -> bool:
    return any(a in flags for a in args)


def _strip_global_flags(argv: Sequence[str]) -> List[str]:
    skip = {"-h", "--help", "-V", "--version", "--no-color", "--doctor", "--check", "--env-check", "-i", "--interactive"}
    return [a for a in argv if a not in skip]


def resolve_mode(argv: Sequence[str]) -> Tuple[str, bool]:
    """Return (mode, no_color). mode: interactive|passthrough|doctor|help|version."""
    no_color = _has_flag(argv, "--no-color")
    if _has_flag(argv, "--doctor", "--check", "--env-check"):
        return "doctor", no_color
    if _has_flag(argv, "-V", "--version"):
        return "version", no_color
    if _has_flag(argv, "-h", "--help") and not _has_flag(argv, "-m", "--module"):
        return "help", no_color
    if _has_flag(argv, "-i", "--interactive"):
        return "interactive", no_color
    return "passthrough", no_color


def print_banner(product: ProductInfo) -> None:
    name_v = f"{product.name}  v{product.version}"
    pad = 60
    print(f"\n╔{'═' * pad}╗")
    print(f"║  {name_v:<{pad - 2}}║")
    print(f"╚{'═' * pad}╝\n")


def print_help(product: ProductInfo) -> None:
    p = product.cli_name
    print("\nUsage:\n")
    print(f"  {p}                              Interactive shell (default)")
    print(f"  {p} -i, --interactive             Force interactive mode")
    print(f'  {p} -m <module> -s "opt val"       Run module non-interactively')
    print(f"  {p} --doctor                       Dependency & module check")
    print(f"  {p} -V, --version                  Show version")
    print(f"  {p} -h, --help                     Show this help")
    print("\nGlobal flags:\n")
    print("  -h, --help              Show help")
    print("  -V, --version           Show version")
    print("  -i, --interactive       Launch interactive shell")
    print("  --doctor, --check       Environment / dependency check")
    print("  --no-color              Disable ANSI colors")
    print("\nModule flags (non-interactive):\n")
    print("  -m, --module <path>     Module path (e.g. scanners/autopwn)")
    print('  -s, --set "opt val"     Set module option (repeatable)')
    print("  -T, --targets <file>    Multi-target scan from file")
    print("  --infra <type>          Infrastructure scan mode")
    print("  --context <ctx>         Scan context (with --infra)\n")
    if product.pip_package:
        print(f"Setup:\n\n  pip install {product.pip_package}\n")


def print_version(product: ProductInfo) -> int:
    print(f"{product.cli_name} v{product.version}")
    return 0


def run_doctor(product: ProductInfo) -> None:
    print(f"[{product.cli_name}] Running environment check …")
    ok = True
    ver = sys.version_info
    if ver < product.min_python:
        print(f"  ✗ Python {product.min_python[0]}.{product.min_python[1]}+ required (detected {sys.version})")
        ok = False
    else:
        print(f"  ✓ Python {sys.version}")
    deps = ["requests", "paramiko", "rich", "colorama", "scapy", "psutil"]
    for dep in deps:
        try:
            __import__(dep)
            print(f"  ✓ {dep}")
        except ImportError:
            print(f"  ✗ {dep} (missing)")
            ok = False
    if ok:
        print("Environment OK.")
    else:
        print(f"\nFix: {product.setup_hint}")


def bootstrap(
    argv: Sequence[str],
    product: ProductInfo,
    launcher: Callable[[List[str]], None],
) -> None:
    """Parse global flags, then invoke launcher(argv) for interactive or passthrough."""
    ver = sys.version_info
    if ver < product.min_python:
        print(
            f"{product.name} requires Python "
            f"{product.min_python[0]}.{product.min_python[1]}+ "
            f"(detected {sys.version})"
        )
        raise SystemExit(1)

    mode, no_color = resolve_mode(list(argv[1:]))
    _init_color(no_color)

    if mode == "help":
        print_banner(product)
        print_help(product)
        raise SystemExit(0)
    if mode == "version":
        print_version(product)
        raise SystemExit(0)
    if mode == "doctor":
        run_doctor(product)
        raise SystemExit(0)

    launcher(list(argv))
