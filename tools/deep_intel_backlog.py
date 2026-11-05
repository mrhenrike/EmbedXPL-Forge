"""Deep intel backlog  -  non-gating enrichment pass.

Scans the module catalog for stub entries (missing CVSS, product, description)
and prints a backlog report. Does NOT fail CI  -  informational only.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "embedxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"


def main() -> None:
    """Produce backlog report  -  always exits 0 (non-gating)."""
    if not CATALOG.exists():
        print("Catalog not found  -  skipping deep intel pass.")
        return

    try:
        data = json.loads(CATALOG.read_text(encoding="utf-8"))
        entries = data if isinstance(data, list) else data.get("entries", [])
    except Exception as exc:
        print(f"[WARN] Could not parse catalog: {exc}")
        return

    total = len(entries)
    enriched = sum(
        1 for e in entries
        if e.get("cvss_score") and e.get("description") and e.get("product")
    )
    backlog = total - enriched

    print("Deep intel backlog report:")
    print(f"  Total entries : {total}")
    print(f"  Enriched      : {enriched}")
    print(f"  Backlog       : {backlog}")


if __name__ == "__main__":
    main()
    sys.exit(0)
