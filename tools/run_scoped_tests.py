"""Scoped test gate  -  validates module structure and import sanity.

Runs lightweight checks that do not require network access or credentials:
  - All module files compile without syntax errors (hard gate)
  - All native Exploit subclasses define minimum __info__ keys (soft warning)

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REQUIRED_INFO_KEYS = {"name", "description"}  # minimum for all native exploit modules
MODULES_DIR = ROOT / "embedxpl" / "modules"
_errors: List[Tuple[str, str]] = []
_warnings: List[Tuple[str, str]] = []

# Directories excluded from all checks (lab/research code, pycache)
_SKIP_DIRS = {"__pycache__", "lab", "malware_research"}
_SKIP_PATTERNS: tuple[str, ...] = ()  # all edb_* are now Python 3 valid


def check_module_file(path: Path) -> None:
    """Compile and basic-validate one module file."""
    rel = str(path.relative_to(ROOT))
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        compile(source, str(path), "exec")
    except SyntaxError as exc:
        _errors.append((rel, f"SyntaxError: {exc}"))
        return

    # Soft warning: check __info__ completeness for native exploit modules only
    # (not creds helpers, not ExploitDB bridge wrappers)
    is_native_exploit = (
        "class Exploit" in source
        and "exploits" in path.parts
        and not path.name.startswith("edb_")
    )
    if is_native_exploit:
        for key in REQUIRED_INFO_KEYS:
            if f'"{key}"' not in source and f"'{key}'" not in source:
                _warnings.append((rel, f"Missing __info__ key: {key}"))


def run() -> int:
    """Run all scoped tests and return exit code."""
    if not MODULES_DIR.exists():
        print(f"[WARN] Modules dir not found: {MODULES_DIR}")
        return 0

    files = [
        f for f in MODULES_DIR.rglob("*.py")
        if f.name != "__init__.py"
        and not any(skip in f.parts for skip in _SKIP_DIRS)
        and not any(f.name.startswith(pat) for pat in _SKIP_PATTERNS)
    ]

    for f in files:
        check_module_file(f)

    if _warnings:
        print(f"[WARN] {len(_warnings)} __info__ warning(s) (non-blocking):")
        for path, msg in _warnings[:10]:
            print(f"  {path}: {msg}")
        if len(_warnings) > 10:
            print(f"  ... and {len(_warnings) - 10} more")

    if _errors:
        print(f"[FAIL] {len(_errors)} scoped test error(s):")
        for path, msg in _errors:
            print(f"  {path}: {msg}")
        return 1

    print(f"[OK] Scoped tests passed — {len(files)} module files checked.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
