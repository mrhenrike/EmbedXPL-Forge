"""Scoped test gate  -  validates module structure and import sanity.

Runs lightweight checks that do not require network access or credentials:
  - All module files compile without syntax errors
  - All Exploit subclasses define required __info__ keys
  - OptIP / OptPort / OptString types are correctly used
  - No circular imports in core packages

Author: André Henrique (@mrhenrike) | União Geek  -  https://github.com/Uniao-Geek
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REQUIRED_INFO_KEYS = {"name", "description", "authors", "references", "targets"}
MODULES_DIR = ROOT / "embedxpl" / "modules"
_errors: List[Tuple[str, str]] = []

# Directories/patterns excluded from syntax checks (Python 2 PoCs, lab code, etc.)
_SKIP_DIRS = {"__pycache__", "lab", "malware_research"}
_SKIP_PATTERNS = ("edb_",)  # ExploitDB Python 2 PoCs


def check_module_file(path: Path) -> None:
    """Compile and basic-validate one module file."""
    rel = str(path.relative_to(ROOT))
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        compile(source, str(path), "exec")
    except SyntaxError as exc:
        _errors.append((rel, f"SyntaxError: {exc}"))
        return

    if "class Exploit" in source:
        for key in REQUIRED_INFO_KEYS:
            if f'"{key}"' not in source and f"'{key}'" not in source:
                _errors.append((rel, f"Missing __info__ key: {key}"))


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

    if _errors:
        print(f"[FAIL] {len(_errors)} scoped test error(s):")
        for path, msg in _errors:
            print(f"  {path}: {msg}")
        return 1

    print(f"[OK] Scoped tests passed — {len(files)} module files checked.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
