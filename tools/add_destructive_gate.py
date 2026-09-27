#!/usr/bin/env python3
"""
Bulk migration: add destructive_gate to EmbedXPL exploit modules
that have revshell capability but no safety gate.

Run from EmbedXPL-Forge root:
  python3 tools/add_destructive_gate.py [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

# Modules to patch
TARGET_PATTERNS = ["reverse.shell", "_REVSHELL", r"lhost.*lport", r"nc -e", r"bash.*\/dev\/tcp", r"spawn.*shell"]

# Import to inject
GATE_IMPORT = "from embedxpl.core.exploit.option import OptBool"
GATE_OPTION = '    destructive_gate = OptBool(False, "Set True to enable payload/shell delivery on authorized targets")\n'

# Guard snippet to inject at start of run()
GATE_GUARD = '''        # Safety gate: block destructive payload delivery unless explicitly enabled
        _deliver_shell = bool(getattr(self, 'destructive_gate', False))
        _lhost = str(getattr(self, 'lhost', '') or '')
        if _lhost and not _deliver_shell:
            from embedxpl.core.exploit.printer import print_warning
            print_warning(
                "[GATE] Reverse shell delivery BLOCKED. "
                "Set destructive_gate=True on authorized targets only."
            )
            return
'''


def has_revshell(content: str) -> bool:
    for pat in TARGET_PATTERNS:
        if re.search(pat, content, re.IGNORECASE):
            return True
    return False


def already_patched(content: str) -> bool:
    return "destructive_gate" in content or "DestructiveGate" in content


def patch_module(path: Path, dry_run: bool = False) -> bool:
    """Add destructive_gate to a module. Returns True if patched."""
    content = path.read_text(encoding="utf-8", errors="replace")

    if not has_revshell(content):
        return False
    if already_patched(content):
        return False

    new_content = content

    # 1. Add OptBool import if not present
    if "OptBool" not in new_content:
        # Find existing option import line
        import_match = re.search(r"from embedxpl\.core\.exploit.*?import.*?$", new_content, re.MULTILINE)
        if import_match:
            end = import_match.end()
            # Check if OptBool is in the same import
            line = import_match.group(0)
            if "option" in line and "Option" in line and "OptBool" not in line:
                # Add OptBool to existing option import
                new_content = new_content[:end] + ", OptBool" if "OptBool" not in line else new_content
            elif "option" not in line:
                # Inject new import after existing one
                new_content = (
                    new_content[:end] + "\n" + GATE_IMPORT + new_content[end:]
                )
        else:
            # Add after first import block
            new_content = GATE_IMPORT + "\n" + new_content

    # 2. Add destructive_gate option after last Option declaration
    # Find position after class attributes (OptIP, OptPort, OptString, OptBool)
    last_opt = None
    for m in re.finditer(r"^\s+(target|lhost|lport|port|timeout|cmd|payload|user|password|thread)\s*=\s*Opt\w+", 
                          new_content, re.MULTILINE):
        last_opt = m

    if last_opt:
        insert_at = new_content.index("\n", last_opt.end()) + 1
        new_content = new_content[:insert_at] + GATE_OPTION + new_content[insert_at:]

    # 3. Add gate guard at the start of run()
    run_match = re.search(r"^\s+def run\(self\)[^:]*:\s*\n", new_content, re.MULTILINE)
    if run_match:
        # Find first non-docstring, non-empty line after def run():
        after_def = run_match.end()
        # Check if there's a docstring
        stripped_after = new_content[after_def:].lstrip()
        if stripped_after.startswith('"""') or stripped_after.startswith("'''"):
            # Skip docstring
            quote = '"""' if stripped_after.startswith('"""') else "'''"
            docstring_end = new_content.find(quote, after_def + 3) + 3
            docstring_end = new_content.index("\n", docstring_end) + 1
            insert_at = docstring_end
        else:
            insert_at = after_def

        new_content = new_content[:insert_at] + GATE_GUARD + new_content[insert_at:]

    if new_content == content:
        return False

    if not dry_run:
        path.write_text(new_content, encoding="utf-8")

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")
    args = parser.parse_args()

    exploit_dirs = BASE / "embedxpl" / "modules" / "exploits"
    if not exploit_dirs.exists():
        print(f"[!] Not found: {exploit_dirs}")
        sys.exit(1)

    patched = 0
    skipped = 0
    errors = 0

    for py_file in sorted(exploit_dirs.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue
        try:
            result = patch_module(py_file, dry_run=args.dry_run)
            rel = py_file.relative_to(BASE)
            if result:
                patched += 1
                print(f"  [{'DRY' if args.dry_run else 'OK'}] {rel}")
            else:
                skipped += 1
        except Exception as exc:
            errors += 1
            print(f"  [ERR] {py_file.name}: {exc}")

    print(f"\nResults: patched={patched} skipped={skipped} errors={errors}")


if __name__ == "__main__":
    main()
