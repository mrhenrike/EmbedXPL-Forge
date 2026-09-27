#!/usr/bin/env python3
"""Deep intel backlog — non-gating enrichment pass.

Scans the module catalog for stub entries (missing CVSS, product, description)
and prints a backlog report. Does NOT fail CI — informational only.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "embedxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"


def main() -> int:
    """Produce backlog report — always exits 0 (non-gating)."""
    if not CATALOG.exists():
        print("Catalog not found — skipping deep intel pass.")
        return 0

    with CATALOG.open() as f:
        data = json.load(f)

    entries = data if isinstance(data, list) else data.get("entries", [])
    stubs = [
        e for e in entries
        if not e.get("cvss_score") or not e.get("description") or not e.get("product")
    ]

    total = len(entries)
    stub_count = len(stubs)
    enriched = total - stub_count

    print(f"Deep intel backlog report:")
    print(f"  Total entries : {total}")
    print(f"  Enriched      : {enriched}")
    print(f"  Stub (missing fields): {stub_count}")

    if stubs:
        print(f"\n  Top 10 stub entries:")
        for e in stubs[:10]:
            print(f"    {e.get('cve_id','?')} — {e.get('vendor','?')}/{e.get('product','?')}")

    print("\nDeep intel pass complete (non-gating).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
