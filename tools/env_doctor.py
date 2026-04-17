#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Environment diagnostics for EmbedXPL-Forge runtime dependencies."""

from __future__ import annotations

import importlib
import platform
import sys
from typing import List, Tuple


REQUIRED_IMPORTS: Tuple[str, ...] = (
    "requests",
    "paramiko",
    "pysnmp",
    "Crypto",
    "setuptools",
)


def _check_import(name: str) -> Tuple[str, bool, str]:
    try:
        module = importlib.import_module(name)
    except Exception as err:
        return name, False, str(err)
    version = getattr(module, "__version__", "n/a")
    return name, True, str(version)


def main() -> int:
    print("EmbedXPL-Forge Environment Doctor")
    print("python_version={}".format(platform.python_version()))
    print("platform={}".format(platform.platform()))
    print("executable={}".format(sys.executable))

    results: List[Tuple[str, bool, str]] = [_check_import(name) for name in REQUIRED_IMPORTS]
    print("")
    print("Dependency checks:")
    for name, ok, info in results:
        state = "OK" if ok else "FAIL"
        print("- {}: {} ({})".format(name, state, info))

    failures = [item for item in results if not item[1]]
    if failures:
        print("")
        print("Missing/broken dependencies detected.")
        print("Fix suggestion:")
        print("python -m pip install -r requirements.txt")
        return 1

    print("")
    print("Environment looks ready for EmbedXPL-Forge.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
