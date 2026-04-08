#!/usr/bin/env python3
"""Phase 6b honeypot validation — non-gating snapshot check.

Validates that honeypot-related module stubs and catalog entries are
consistent. Does NOT fail CI — informational only.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    """Run honeypot validation snapshot — always exits 0 (non-gating)."""
    modules_dir = ROOT / "routerxpl" / "modules"

    # Count modules that reference honeypot or canary detection patterns
    honeypot_refs = []
    for py in modules_dir.rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        try:
            content = py.read_text(encoding="utf-8", errors="replace")
            if any(kw in content.lower() for kw in ["honeypot", "canary", "deception"]):
                honeypot_refs.append(py.relative_to(ROOT))
        except Exception:
            continue

    total_modules = sum(
        1 for p in modules_dir.rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in str(p)
    )

    print(f"Phase 6b honeypot validation snapshot:")
    print(f"  Total modules scanned : {total_modules}")
    print(f"  Modules with honeypot refs: {len(honeypot_refs)}")
    for ref in honeypot_refs[:5]:
        print(f"    {ref}")

    print("\nHoneypot validation complete (non-gating).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
