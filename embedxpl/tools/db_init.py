"""EmbedXPL DB Init — seed script.

Creates ~/.embedxpl/exf.db from scratch and optionally populates the
module_cache table by scanning the local EmbedXPL module tree.

Usage::

    # First-time setup
    python -m embedxpl.tools.db_init

    # Also index modules into cache (for instant search startup)
    python -m embedxpl.tools.db_init --index-modules

    # Specific workspace
    python -m embedxpl.tools.db_init --workspace my-pentest

    # Show DB stats
    python -m embedxpl.tools.db_init --stats

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import argparse
import importlib
import inspect
import pkgutil
import re
import sys
from pathlib import Path

# Bootstrap: allow running as script from repo root
_REPO = Path(__file__).resolve().parents[3]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from embedxpl.core.database import EXFDatabase  # noqa: E402


def index_modules(db: EXFDatabase, verbose: bool = False) -> int:
    """Scan embedxpl.modules and populate module_cache table."""
    print("[*] Scanning embedxpl modules for cache...")
    cve_pat = re.compile(r"CVE-\d{4}-\d+", re.I)
    count = 0

    try:
        import embedxpl.modules as base_pkg
    except ImportError:
        print("[!] Could not import embedxpl.modules")
        return 0

    base_path = getattr(base_pkg, "__path__", None)
    if not base_path:
        return 0

    for finder, module_name, ispkg in pkgutil.walk_packages(base_path, prefix="embedxpl.modules."):
        try:
            mod = importlib.import_module(module_name)
        except Exception:
            continue

        info: dict = {}
        for attr_name, obj in inspect.getmembers(mod, inspect.isclass):
            if hasattr(obj, "__info__") and isinstance(getattr(obj, "__info__", None), dict):
                info = obj.__info__
                break

        name    = info.get("name", "")
        desc    = info.get("description", "")[:300]
        cves    = [m.upper() for m in cve_pat.findall(module_name + " " + name + " " + desc)]
        cves    = list(dict.fromkeys(cves))
        vendors = info.get("vendors", []) or []

        # Category from path
        parts = module_name.split(".")
        category = parts[3] if len(parts) > 3 else ""  # modules.exploits.<category>

        db.cache_module(module_name, name, desc, cves, vendors, category)
        count += 1
        if verbose and count % 100 == 0:
            print(f"  {count} modules indexed...")

    db._conn.commit()
    print(f"[*] Module cache: {count} entries")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="EmbedXPL DB init / seed script")
    parser.add_argument("--workspace", "-w", default="default",
                        help="Workspace name to create/select (default: 'default')")
    parser.add_argument("--index-modules", "-i", action="store_true",
                        help="Scan and cache all modules for instant search")
    parser.add_argument("--stats", "-s", action="store_true",
                        help="Show DB stats and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    db = EXFDatabase()
    db.workspace(args.workspace)

    print(f"[*] EXFDatabase: {db._path}")
    print(f"[*] Workspace: {args.workspace}")

    if args.index_modules:
        index_modules(db, verbose=args.verbose)

    if args.stats or True:
        db.stats(print_it=True)

    db.close()
    print("[*] Done.")


if __name__ == "__main__":
    main()
