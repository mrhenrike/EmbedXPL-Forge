#!/usr/bin/env python3
"""Validate that the module catalog meets minimum coverage thresholds.

Ensures the framework maintains a baseline of vendor and CVE coverage
that meets the documented yearly minimums.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MINIMUMS: Dict[str, int] = {
    "total_exploit_modules": 400,
    "total_cve_entries": 300,
    "unique_vendors_exploits": 35,
    "cred_modules": 60,
}


def count_exploit_modules() -> int:
    """Count non-__init__ .py files under exploits/."""
    base = ROOT / "routerxpl" / "modules" / "exploits"
    return sum(
        1 for p in base.rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in str(p)
    )


def count_cve_entries() -> int:
    """Count entries in the CVE catalog."""
    catalog = ROOT / "routerxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"
    if not catalog.exists():
        return 0
    with catalog.open() as f:
        data = json.load(f)
    entries = data if isinstance(data, list) else data.get("entries", [])
    return len(entries)


def count_vendors() -> int:
    """Count vendor folders under exploits/routers/."""
    base = ROOT / "routerxpl" / "modules" / "exploits" / "routers"
    return sum(
        1 for d in base.iterdir()
        if d.is_dir() and d.name != "__pycache__"
    )


def count_cred_modules() -> int:
    """Count non-__init__ .py files under creds/."""
    base = ROOT / "routerxpl" / "modules" / "creds"
    return sum(
        1 for p in base.rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in str(p)
    )


def main() -> int:
    """Run all threshold checks."""
    actuals = {
        "total_exploit_modules": count_exploit_modules(),
        "total_cve_entries": count_cve_entries(),
        "unique_vendors_exploits": count_vendors(),
        "cred_modules": count_cred_modules(),
    }

    failed = False
    for key, minimum in MINIMUMS.items():
        actual = actuals[key]
        status = "PASS" if actual >= minimum else "FAIL"
        if status == "FAIL":
            failed = True
        print(f"[{status}] {key}: {actual} (min={minimum})")

    if failed:
        print("\nMarket priority minimums NOT met.")
        return 1

    print("\nAll market priority minimums met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
