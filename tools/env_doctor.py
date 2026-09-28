#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Environment diagnostics for EmbedXPL-Forge runtime dependencies.

Exit codes:
  0 -- all required and optional deps present, framework healthy
  1 -- optional deps missing (degraded mode, some modules unavailable)
  2 -- required deps missing or core import failure (framework broken)
"""

from __future__ import annotations

import importlib
import os
import platform
import sys
from typing import Dict, List, Tuple

# ------------------------------------------------------------------ #
# Dependency manifests
# ------------------------------------------------------------------ #

REQUIRED_DEPS: Tuple[Tuple[str, str], ...] = (
    ("requests",    "requests"),
    ("paramiko",    "paramiko"),
    ("pysnmp",      "pysnmp"),
    ("pycryptodome","Crypto"),
    ("rich",        "rich"),
    ("aiohttp",     "aiohttp"),
    ("psutil",      "psutil"),
    ("colorama",    "colorama"),
    ("scapy",       "scapy"),
)

OPTIONAL_DEPS: Tuple[Tuple[str, str, str], ...] = (
    ("python-nmap",  "nmap",       "network scanning (nmap wrapper)"),
    ("telnetlib3",   "telnetlib3", "Telnet support on Python 3.13+"),
    ("numpy",        "numpy",      "ML features"),
    ("scikit-learn", "sklearn",    "ML features"),
    ("yaml/PyYAML",  "yaml",       "infra_profiles / firmware_sources parsing"),
)

CORE_SUBSYSTEMS: Tuple[Tuple[str, str], ...] = (
    ("embedxpl.core.exploit",      "Exploit base class + mute + print_*"),
    ("embedxpl.core.http.http_client", "HTTPClient"),
    ("embedxpl.core.orchestrator", "InfraOrchestrator / ScanPlan"),
    ("embedxpl.core.discovery",    "Network discovery engine"),
    ("embedxpl.core.pool",         "SmartPool execution engine"),
    ("embedxpl.core.engine",       "AsyncScanEngine"),
)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _check_import(import_name: str) -> Tuple[bool, str]:
    """Attempt to import a module and return (ok, version_or_error)."""
    try:
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", "n/a")
        return True, str(version)
    except Exception as exc:
        return False, str(exc)


def _count_modules() -> Dict[str, int]:
    """Count .py files (excluding __init__) per top-level module category."""
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "embedxpl", "modules")
    counts: Dict[str, int] = {}
    if not os.path.isdir(base):
        return counts
    for category in sorted(os.listdir(base)):
        cat_path = os.path.join(base, category)
        if not os.path.isdir(cat_path):
            continue
        total = 0
        for root, dirs, files in os.walk(cat_path):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            total += sum(1 for f in files if f.endswith(".py") and f != "__init__.py")
        if total:
            counts[category] = total
    return counts


def _telnet_ok() -> Tuple[bool, str]:
    """Check telnet backend appropriate for current Python version."""
    if sys.version_info >= (3, 13):
        ok, info = _check_import("telnetlib3")
        return ok, "telnetlib3: " + ("OK" if ok else "MISSING -- pip install telnetlib3")
    ok, info = _check_import("telnetlib")
    return ok, "telnetlib (stdlib): OK" if ok else "telnetlib: MISSING"


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #

def main() -> int:
    """Run all environment checks and report status."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="env_doctor",
        description="EmbedXPL-Forge environment diagnostics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (exit code only)")
    args = parser.parse_args()

    if args.quiet:
        code = 0
        for _, import_name in REQUIRED_DEPS:
            ok, _ = _check_import(import_name)
            if not ok:
                code = 2
        tel_ok, _ = _telnet_ok()
        if not tel_ok:
            code = 2
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        for module_path, _ in CORE_SUBSYSTEMS:
            ok, _ = _check_import(module_path)
            if not ok:
                code = 2
        return code

    _W = "\033[33m"   # yellow
    _E = "\033[31m"   # red
    _G = "\033[32m"   # green
    _R = "\033[0m"    # reset
    _B = "\033[1m"    # bold

    # Disable colours on Windows when colorama is unavailable.
    try:
        import colorama
        colorama.init()
    except ImportError:
        _W = _E = _G = _R = _B = ""

    print("{}EmbedXPL-Forge -- Environment Doctor{}".format(_B, _R))
    print("python_version  = {}".format(platform.python_version()))
    print("platform        = {}".format(platform.platform()))
    print("executable      = {}".format(sys.executable))
    print()

    exit_code = 0

    # 1. Required dependencies
    print("{}___ Required dependencies ____________________________________{}".format(_B, _R))
    req_fail: List[str] = []
    for pkg_name, import_name in REQUIRED_DEPS:
        ok, info = _check_import(import_name)
        mark = "{}OK  {}".format(_G, _R) if ok else "{}FAIL{}".format(_E, _R)
        print("  [{}]  {:20s}  {}".format(mark, pkg_name, info if ok else _E + info[:60] + _R))
        if not ok:
            req_fail.append(pkg_name)

    # Telnet backend (version-dependent)
    tel_ok, tel_msg = _telnet_ok()
    mark = "{}OK  {}".format(_G, _R) if tel_ok else "{}WARN{}".format(_W, _R)
    print("  [{}]  {:20s}  {}".format(mark, "telnet-backend", tel_msg))
    if not tel_ok:
        req_fail.append("telnet-backend")

    if req_fail:
        exit_code = 2
        print()
        print("{}FATAL: {} required dep(s) missing -- framework will not start:{}".format(
            _E, len(req_fail), _R))
        print("  pip install {}".format(" ".join(req_fail)))
    print()

    # 2. Optional dependencies
    print("{}___ Optional dependencies ____________________________________{}".format(_B, _R))
    opt_fail: List[str] = []
    for pkg_name, import_name, description in OPTIONAL_DEPS:
        ok, info = _check_import(import_name)
        mark = "{}OK  {}".format(_G, _R) if ok else "{}WARN{}".format(_W, _R)
        print("  [{}]  {:20s}  {}  ({})".format(
            mark, pkg_name,
            info if ok else _W + "not installed" + _R,
            description))
        if not ok:
            opt_fail.append(pkg_name)

    if opt_fail and exit_code == 0:
        exit_code = 1
    print()

    # 3. Core subsystem imports
    print("{}___ Core subsystem imports ___________________________________{}".format(_B, _R))
    core_fail: List[str] = []
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    for module_path, description in CORE_SUBSYSTEMS:
        ok, info = _check_import(module_path)
        mark = "{}OK  {}".format(_G, _R) if ok else "{}FAIL{}".format(_E, _R)
        print("  [{}]  {}  ({})".format(mark, module_path, description))
        if not ok:
            core_fail.append(module_path)
            exit_code = 2

    print()

    # 4. Module inventory
    print("{}___ Module inventory _________________________________________{}".format(_B, _R))
    counts = _count_modules()
    total = sum(counts.values())
    if counts:
        for category, n in sorted(counts.items(), key=lambda x: -x[1]):
            bar = "#" * min(n // 5, 40)
            print("  {:12s}  {:4d}  {}".format(category, n, bar))
        print()
        print("  {}Total modules: {:,}{}".format(_B, total, _R))
    else:
        print("  {}WARNING: Could not locate embedxpl/modules directory{}".format(_W, _R))
    print()

    # 5. Summary
    print("{}___ Summary __________________________________________________{}".format(_B, _R))
    if exit_code == 0:
        print("  {}STATUS: HEALTHY -- all deps present, {} modules ready{}".format(_G, total, _R))
    elif exit_code == 1:
        print("  {}STATUS: DEGRADED -- optional deps missing, core functional ({} modules){}".format(
            _W, total, _R))
        print("  Modules requiring missing deps will be skipped at runtime.")
        print("  Install all: pip install -r requirements.txt")
    else:
        print("  {}STATUS: BROKEN -- required deps or core imports failed{}".format(_E, _R))
        print("  Run: pip install embedxpl  or  pip install -r requirements.txt")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
