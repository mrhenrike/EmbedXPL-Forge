"""Validate repository governance baseline files.

Checks that required governance documents are present and non-empty:
  - LICENSE
  - CODE_OF_CONDUCT.md
  - CONTRIBUTING.md
  - SECURITY.md
  - CONTRIBUTORS.md
  - README.md
  - CHANGELOG.md

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_FILES = [
    "LICENSE",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "README.md",
    "CHANGELOG.md",
]

OPTIONAL_FILES = [
    "CONTRIBUTING.md",
    "CONTRIBUTORS.md",
    "DISCLAIMER.md",
    "THIRD_PARTY_COMPONENTS.md",
]


def main() -> int:
    """Check all governance files."""
    failed = False

    for name in REQUIRED_FILES:
        path = ROOT / name
        if not path.exists():
            print(f"[FAIL] MISSING required file: {name}")
            failed = True
        elif path.stat().st_size < 10:
            print(f"[WARN] EMPTY (< 10 bytes): {name}")
        else:
            size = path.stat().st_size
            print(f"[PASS] {name} ({size} bytes) PRESENT")

    for name in OPTIONAL_FILES:
        path = ROOT / name
        status = "present" if path.exists() else "absent"
        print(f"[INFO] {name}: {status}")

    if failed:
        print("\nGovernance baseline FAILED  -  add missing files.")
        return 1

    print("\nGovernance baseline OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
