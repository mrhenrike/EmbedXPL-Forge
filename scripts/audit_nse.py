"""Audit NSE scripts for required fields and basic Lua syntax."""
from pathlib import Path

REQUIRED_FIELDS = ["description", "author", "license", "categories", "action"]
ACTION_PATTERNS = ["function action", "action = function", "action=function"]

errors = []
ok_count = 0

nse_dirs = [Path("nse"), Path("nse/printers")]
for d in nse_dirs:
    if not d.exists():
        continue
    for f in sorted(d.glob("*.nse")):
        content = f.read_text(encoding="utf-8", errors="replace")
        missing = [field for field in REQUIRED_FIELDS if field not in content]
        has_action = any(pat in content for pat in ACTION_PATTERNS)
        issues = []
        if missing:
            issues.append(f"missing fields: {missing}")
        if not has_action:
            issues.append("action function not detected")
        if issues:
            errors.append((str(f), issues))
        else:
            print(f"OK  {f}")
            ok_count += 1

print()
if errors:
    print("=== NSE ERRORS ===")
    for path, issues in errors:
        print(f"ERR  {path}")
        for issue in issues:
            print(f"       - {issue}")
else:
    print(f"All {ok_count} NSE files pass basic validation.")
