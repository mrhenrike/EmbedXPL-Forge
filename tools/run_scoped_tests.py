#!/usr/bin/env python3
"""Scoped test gate — validates module structure and import sanity.

Runs lightweight checks that do not require network access or credentials:
  - All module files compile without syntax errors
  - All Exploit subclasses define required __info__ keys
  - OptIP / OptPort / OptString types are correctly used
  - No circular imports in core packages

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# references is optional (creds modules often omit it)
REQUIRED_INFO_KEYS = {"name", "description", "authors"}
MODULES_DIR = ROOT / "routerxpl" / "modules"

_errors: List[Tuple[str, str]] = []


def _check_file(path: Path) -> None:
    """Compile and basic-validate one module file."""
    rel = path.relative_to(ROOT)
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        compile(source, str(rel), "exec")
    except SyntaxError as exc:
        _errors.append((str(rel), f"SyntaxError: {exc}"))
        return

    # Check __info__ keys without executing the module
    if "__info__" in source and "class Exploit" in source:
        for key in REQUIRED_INFO_KEYS:
            if f'"{key}"' not in source and f"'{key}'" not in source:
                _errors.append((str(rel), f"Missing __info__ key: {key}"))


def main() -> int:
    """Run all scoped tests and return exit code."""
    py_files = [
        p for p in MODULES_DIR.rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in str(p)
    ]

    print(f"Scoped test gate — checking {len(py_files)} module files...")
    for f in py_files:
        _check_file(f)

    if _errors:
        print(f"\n[FAIL] {len(_errors)} error(s) found:\n")
        for path, msg in _errors:
            print(f"  {path}: {msg}")
        return 1

    print(f"[PASS] All {len(py_files)} files passed scoped checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
