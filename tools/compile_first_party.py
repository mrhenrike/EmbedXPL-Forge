#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Byte-compile first-party RouterXPL Python only.

Vendored trees under ``routerxpl/resources/`` (PoC mirrors, MIBs, etc.) are **not**
compiled: many upstream exploits target Python 2 or are intentionally broken.

Use this in CI or pre-commit instead of ``python -m compileall routerxpl``.
"""

from __future__ import annotations

import compileall
import logging
import sys
from pathlib import Path


LOGGER = logging.getLogger("compile_first_party")


def main() -> int:
    """Compile core, modules, libs, package entrypoints, and ``tools/*.py``."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    repo = Path(__file__).resolve().parents[1]
    rx = repo / "routerxpl"

    dirs = [
        rx / "core",
        rx / "modules",
        rx / "libs",
    ]
    ok = True

    for d in dirs:
        if not d.is_dir():
            LOGGER.warning("Skip missing directory: %s", d)
            continue
        LOGGER.info("compile_dir %s", d.relative_to(repo))
        if not compileall.compile_dir(str(d), quiet=1, legacy=False):
            ok = False

    for py in sorted(rx.glob("*.py")):
        if py.is_file():
            LOGGER.info("compile_file %s", py.relative_to(repo))
            if not compileall.compile_file(str(py), quiet=1, legacy=False):
                ok = False

    tools = repo / "tools"
    if tools.is_dir():
        for py in sorted(tools.glob("*.py")):
            LOGGER.info("compile_file %s", py.relative_to(repo))
            if not compileall.compile_file(str(py), quiet=1, legacy=False):
                ok = False

    root_py = repo / "rxf.py"
    if root_py.is_file():
        LOGGER.info("compile_file rxf.py")
        if not compileall.compile_file(str(root_py), quiet=1, legacy=False):
            ok = False

    if ok:
        LOGGER.info("First-party compileall OK.")
        return 0
    LOGGER.error("First-party compileall reported failures.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
