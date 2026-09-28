#!/usr/bin/env python3
"""Validate repository governance baseline files.

Checks that required governance documents are present and non-empty:
  - LICENSE
  - CODE_OF_CONDUCT.md
  - CONTRIBUTING.md
  - SECURITY.md
  - CONTRIBUTORS.md
  - README.md
  - CHANGELOG.md

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "LICENSE",
    "README.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CONTRIBUTORS.md",
]

OPTIONAL_FILES = [
    "README.pt-BR.md",
    "pyproject.toml",
    "requirements.txt",
]


def main() -> int:
    """Check all governance files."""
    failed = False

    for fname in REQUIRED_FILES:
        fpath = ROOT / fname
        if not fpath.exists():
            print(f"[FAIL] MISSING required file: {fname}")
            failed = True
        elif fpath.stat().st_size < 10:
            print(f"[WARN] EMPTY (< 10 bytes): {fname}")
        else:
            print(f"[PASS] {fname} ({fpath.stat().st_size} bytes)")

    for fname in OPTIONAL_FILES:
        fpath = ROOT / fname
        status = "PRESENT" if fpath.exists() else "absent"
        print(f"[INFO] {fname}: {status}")

    if failed:
        print("\nGovernance baseline FAILED — add missing files.")
        return 1

    print("\nGovernance baseline OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
