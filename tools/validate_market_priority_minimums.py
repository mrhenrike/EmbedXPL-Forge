"""Validate that the module catalog meets minimum coverage thresholds.

Ensures the framework maintains a baseline of vendor and CVE coverage
that meets the documented yearly minimums.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MINIMUMS: Dict[str, int] = {
    "total_exploit_modules": 100,
    "total_cve_entries": 50,
    "unique_vendors_exploits": 10,
    "cred_modules": 1,
}


def count_exploit_modules() -> int:
    """Count non-__init__.py files under exploits/."""
    exploits_dir = ROOT / "embedxpl" / "modules" / "exploits"
    if not exploits_dir.exists():
        return 0
    return sum(
        1 for f in exploits_dir.rglob("*.py")
        if f.name != "__init__.py" and "__pycache__" not in f.parts
    )


def count_cve_entries() -> int:
    catalog = ROOT / "embedxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"
    if not catalog.exists():
        return 0
    try:
        data = json.loads(catalog.read_text(encoding="utf-8"))
        entries = data if isinstance(data, list) else data.get("entries", [])
        return len(entries)
    except Exception:
        return 0


def count_unique_vendors() -> int:
    exploits_dir = ROOT / "embedxpl" / "modules" / "exploits"
    if not exploits_dir.exists():
        return 0
    vendors = {d.name for d in exploits_dir.iterdir() if d.is_dir() and d.name != "__pycache__"}
    return len(vendors)


def count_cred_modules() -> int:
    creds_dir = ROOT / "embedxpl" / "modules"
    if not creds_dir.exists():
        return 0
    return sum(1 for f in creds_dir.rglob("*cred*") if f.suffix == ".py")


def main() -> int:
    counts: Dict[str, int] = {
        "total_exploit_modules": count_exploit_modules(),
        "total_cve_entries": count_cve_entries(),
        "unique_vendors_exploits": count_unique_vendors(),
        "cred_modules": count_cred_modules(),
    }

    failed = False
    for key, minimum in MINIMUMS.items():
        actual = counts.get(key, 0)
        status = "OK" if actual >= minimum else "FAIL"
        print(f"[{status}] {key}: {actual} (min {minimum})")
        if actual < minimum:
            failed = True

    if failed:
        print("\nMarket priority minimums NOT met.", file=sys.stderr)
        return 1
    print("\nAll market priority minimums met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
