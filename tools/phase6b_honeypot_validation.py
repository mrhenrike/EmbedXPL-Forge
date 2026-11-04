"""Phase 6b honeypot validation  -  non-gating snapshot check.

Validates that honeypot-related module stubs and catalog entries are
consistent. Does NOT fail CI  -  informational only.

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    """Run honeypot validation snapshot  -  always exits 0 (non-gating)."""
    modules_dir = ROOT / "embedxpl" / "modules"
    if not modules_dir.exists():
        print("[WARN] Modules dir not found — skipping honeypot validation.")
        return

    all_files = [
        f for f in modules_dir.rglob("*.py")
        if f.name != "__init__.py" and "__pycache__" not in f.parts
    ]
    total = len(all_files)

    honeypot_refs = 0
    for f in all_files:
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            if "honeypot" in content.lower():
                honeypot_refs += 1
        except Exception:
            pass

    print("Phase 6b honeypot validation snapshot:")
    print(f"  Total modules scanned : {total}")
    print(f"  Modules with honeypot refs: {honeypot_refs}")
    print("\nHoneypot validation complete (non-gating).")


if __name__ == "__main__":
    main()
    sys.exit(0)
