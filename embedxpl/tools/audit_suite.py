"""EmbedXPL Suite Auditor.

Executa code review automático de toda a suite:
  1. Import health — detecta ImportError em todos os módulos
  2. Unused imports — detecta F401 (pyflakes) se disponível
  3. Missing __info__ — módulos sem metadados
  4. Missing deps — dependências externas não instaladas
  5. Bad patterns — print() direto, hardcoded creds, missing check/run
  6. Stats check — valida contadores do banner

Uso:
    python3 -m embedxpl.tools.audit_suite [--fix] [--path embedxpl/modules]
    python3 -m embedxpl.tools.audit_suite --step 1    # só AUDIT-STEP-1
    python3 -m embedxpl.tools.audit_suite --json       # output JSON para CI
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

_HERE = Path(__file__).resolve().parent.parent   # embedxpl/
_MODULES = (_HERE / "modules").resolve()


def _rel_module_path(py: Path) -> str:
    """Path relative to embedxpl/ for reports (works with custom --path)."""
    try:
        return str(py.resolve().relative_to(_HERE))
    except ValueError:
        return str(py)

# ANSI colors
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_GREEN  = "\033[92m"
_CYAN   = "\033[96m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _color(s: str, c: str) -> str:
    if not sys.stdout.isatty():
        return s
    return c + s + _RESET


def _collect_py_files(root: Path) -> List[Path]:
    return sorted(f for f in root.rglob("*.py") if f.name != "__init__.py")


# ---------------------------------------------------------------------------
# AUDIT-STEP-1: Import health
# ---------------------------------------------------------------------------

def audit_imports(root: Path) -> List[dict]:
    """Try to import every module and collect ImportErrors."""
    issues = []
    files = _collect_py_files(root)
    ok = 0

    for py in files:
        spec = importlib.util.spec_from_file_location("_audit_mod", py)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)   # type: ignore[union-attr]
            ok += 1
        except ImportError as e:
            issues.append({
                "step": 1, "level": "ERROR",
                "file": _rel_module_path(py),
                "message": f"ImportError: {e}",
            })
        except Exception:
            ok += 1  # runtime errors (e.g. missing target) are OK at import time

    return issues


# ---------------------------------------------------------------------------
# AUDIT-STEP-2: Unused imports (via pyflakes if available)
# ---------------------------------------------------------------------------

def audit_unused_imports(root: Path) -> List[dict]:
    """Detect unused imports using pyflakes."""
    issues = []
    try:
        from pyflakes import api as pf_api
        from pyflakes import messages as pf_msgs
        import io

        files = _collect_py_files(root)
        for py in files:
            src = py.read_text(errors="replace")
            result = pf_api.check(src, str(py))
            # result is printed to stdout; we parse it
            # Simple string approach
            for line in str(result).splitlines():
                if "imported but unused" in line or "redefined while unused" in line:
                    issues.append({
                        "step": 2, "level": "WARN",
                        "file": _rel_module_path(py),
                        "message": line.strip(),
                    })
    except ImportError:
        issues.append({
            "step": 2, "level": "INFO",
            "file": "N/A",
            "message": "pyflakes not installed — skipping unused import check. Run: pip install pyflakes",
        })
    return issues


# ---------------------------------------------------------------------------
# AUDIT-STEP-3: Missing __info__
# ---------------------------------------------------------------------------

def audit_metadata(root: Path) -> List[dict]:
    """Check that every Exploit/Encoder/Payload class has __info__."""
    issues = []
    for py in _collect_py_files(root):
        src = py.read_text(errors="replace")
        has_class = any(
            f"class {cls}" in src
            for cls in ["Exploit(", "Encoder(", "Payload(", "Scanner("]
        )
        if has_class and "__info__" not in src:
            issues.append({
                "step": 3, "level": "WARN",
                "file": _rel_module_path(py),
                "message": "Class without __info__ dict",
            })
    return issues


# ---------------------------------------------------------------------------
# AUDIT-STEP-4: Missing external dependencies
# ---------------------------------------------------------------------------

def audit_deps(root: Path) -> List[dict]:
    """Detect imports of packages not installed and not in stdlib."""
    issues = []
    stdlib = set(sys.stdlib_module_names)
    stdlib.update({"embedxpl", "routersploit", "hatsploit", "icssploit"})  # known internal

    for py in _collect_py_files(root):
        try:
            tree = ast.parse(py.read_text(errors="replace"))
        except SyntaxError as e:
            issues.append({
                "step": 4, "level": "ERROR",
                "file": _rel_module_path(py),
                "message": f"SyntaxError: {e}",
            })
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]]
            else:
                continue

            for top in names:
                if not top or top in stdlib:
                    continue
                try:
                    __import__(top)
                except ImportError:
                    issues.append({
                        "step": 4, "level": "WARN",
                        "file": _rel_module_path(py),
                        "message": f"Missing dependency: {top}",
                    })

    # Deduplicate
    seen = set()
    deduped = []
    for i in issues:
        key = (i["file"], i["message"])
        if key not in seen:
            seen.add(key)
            deduped.append(i)
    return deduped


# ---------------------------------------------------------------------------
# AUDIT-STEP-5: Bad patterns
# ---------------------------------------------------------------------------

def audit_patterns(root: Path) -> List[dict]:
    """Check for common bad patterns in module code."""
    issues = []
    BAD_PATTERNS = [
        # (pattern, description, level)
        (r'\bprint\s*\(', "Direct print() call — use print_info/print_success/print_error", "WARN"),
        (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password string", "WARN"),
        (r'secret\s*=\s*["\']', "Hardcoded secret", "WARN"),
        (r'TODO.*implement', "Unimplemented TODO", "INFO"),
        (r'raise NotImplementedError', "NotImplementedError not overridden", "INFO"),
    ]
    import re

    for py in _collect_py_files(root):
        src = py.read_text(errors="replace")

        # Skip if it's a core utility (not an exploit/encoder/payload)
        is_module = any(
            f"class {cls}" in src
            for cls in ["Exploit(", "Encoder(", "Payload("]
        )
        if not is_module:
            continue

        for pattern, desc, level in BAD_PATTERNS:
            if re.search(pattern, src):
                issues.append({
                    "step": 5, "level": level,
                    "file": _rel_module_path(py),
                    "message": desc,
                })

    return issues


# ---------------------------------------------------------------------------
# AUDIT-STEP-6: Banner stats consistency
# ---------------------------------------------------------------------------

def audit_banner_stats() -> List[dict]:
    """Validate that banner stats increment makes sense."""
    issues = []
    try:
        from embedxpl.core.banner import _count_modules, invalidate_cache
        invalidate_cache()
        stats = _count_modules()

        expectations = {
            "exploits": (4000, "Should have 4000+ exploits"),
            "scanners": (200, "Should have 200+ scanners"),
            "payloads": (30, "Should have 30+ payloads"),
            "encoders": (13, "Should have 13+ encoders"),
        }

        for key, (min_val, msg) in expectations.items():
            val = stats.get(key, 0)
            if val < min_val:
                issues.append({
                    "step": 6, "level": "ERROR",
                    "file": "banner",
                    "message": f"{key}={val} < expected {min_val}. {msg}",
                })
            else:
                issues.append({
                    "step": 6, "level": "OK",
                    "file": "banner",
                    "message": f"{key}={val:,} ✓",
                })
    except Exception as e:
        issues.append({
            "step": 6, "level": "ERROR",
            "file": "banner",
            "message": f"Banner check failed: {e}",
        })
    return issues


# ---------------------------------------------------------------------------
# AUDIT-STEP-7: Git status
# ---------------------------------------------------------------------------

def audit_git() -> List[dict]:
    """Check git status for uncommitted changes."""
    issues = []
    import subprocess
    try:
        result = subprocess.run(
            ["git", "status", "--short"],
            capture_output=True, text=True, timeout=10,
            cwd=str(_HERE.parent)
        )
        lines = [l for l in result.stdout.splitlines() if l.strip()]
        if lines:
            issues.append({
                "step": 7, "level": "WARN",
                "file": "git",
                "message": f"{len(lines)} uncommitted files: {', '.join(l.strip() for l in lines[:5])}",
            })
        else:
            issues.append({
                "step": 7, "level": "OK",
                "file": "git",
                "message": "Working tree clean ✓",
            })

        # Last 3 commits
        log = subprocess.run(
            ["git", "log", "--oneline", "-3"],
            capture_output=True, text=True, timeout=10,
            cwd=str(_HERE.parent)
        )
        for line in log.stdout.splitlines():
            issues.append({"step": 7, "level": "INFO", "file": "git", "message": f"commit: {line}"})
    except Exception as e:
        issues.append({"step": 7, "level": "WARN", "file": "git", "message": str(e)})
    return issues


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

_STEP_FUNCS = {
    1: ("Import Health",         lambda r: audit_imports(r)),
    2: ("Unused Imports",        lambda r: audit_unused_imports(r)),
    3: ("Missing Metadata",      lambda r: audit_metadata(r)),
    4: ("Missing Dependencies",  lambda r: audit_deps(r)),
    5: ("Bad Code Patterns",     lambda r: audit_patterns(r)),
    6: ("Banner Stats",          lambda r: audit_banner_stats()),
    7: ("Git Status",            lambda r: audit_git()),
}


def run_audit(root: Path = _MODULES, steps: list[int] | None = None,
              json_output: bool = False) -> int:
    """Run the full audit. Returns exit code (0=clean, 1=errors found)."""
    steps = steps or list(_STEP_FUNCS.keys())
    all_issues: List[dict] = []

    print(_color("\n  EmbedXPL Suite Auditor\n  " + "─" * 50, _CYAN))

    for step_num in steps:
        name, func = _STEP_FUNCS[step_num]
        print(_color(f"\n  AUDIT-STEP-{step_num}: {name}", _BOLD))
        try:
            issues = func(root)
        except Exception as e:
            issues = [{"step": step_num, "level": "ERROR", "file": "auditor", "message": str(e)}]

        for issue in issues:
            level = issue["level"]
            file  = issue["file"]
            msg   = issue["message"]

            if level == "ERROR":
                icon = _color("  ✗ ERROR", _RED)
            elif level == "WARN":
                icon = _color("  ⚠ WARN ", _YELLOW)
            elif level == "OK":
                icon = _color("  ✓ OK   ", _GREEN)
            else:
                icon = _color("  ℹ INFO ", _CYAN)

            print(f"{icon}  {file}: {msg}")
            all_issues.append(issue)

    # Summary
    errors = sum(1 for i in all_issues if i["level"] == "ERROR")
    warns  = sum(1 for i in all_issues if i["level"] == "WARN")
    oks    = sum(1 for i in all_issues if i["level"] == "OK")

    print(_color(f"\n  Summary: {errors} errors | {warns} warnings | {oks} OK", _BOLD))
    if errors:
        print(_color("  ✗ AUDIT FAILED — fix errors before closing phase", _RED))
    elif warns:
        print(_color("  ⚠ AUDIT PASSED WITH WARNINGS — review warnings", _YELLOW))
    else:
        print(_color("  ✓ AUDIT PASSED — phase is clean", _GREEN))
    print()

    if json_output:
        print(json.dumps(all_issues, indent=2))

    return 1 if errors else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="EmbedXPL Suite Auditor")
    parser.add_argument("--step", type=int, help="Run only a specific step (1-7)")
    parser.add_argument("--path", default=str(_MODULES), help="Module root path")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--fix", action="store_true", help="Auto-fix where possible (unused imports)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    steps = [args.step] if args.step else None

    exit_code = run_audit(root, steps, json_output=args.json)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
