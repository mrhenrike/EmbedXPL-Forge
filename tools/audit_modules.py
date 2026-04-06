"""Automated module quality auditor for RouterXPL-Forge.

Scans all exploit modules and classifies them into quality tiers:
  Tier S: Full exploit logic, specific paths/payloads, real check
  Tier A: Has real logic but may be generic or incomplete
  Tier B: Boilerplate stub with generic template
  Tier C: Pure stub, minimal or broken

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

import json
import os
import re
import sys
from collections import defaultdict

MODULES_ROOT = os.path.join(os.path.dirname(__file__), "..", "routerxpl", "modules")

STUB_TEMPLATE_PATTERNS = [
    'response = self.http_request(method="GET", path="/")',
    "response.status_code in (200, 301, 302, 401)",
    "print_info(response.text[:2000])",
]


def audit_module(filepath):
    """Analyze a single module file and return audit data."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    lines = content.splitlines()
    line_count = len(lines)

    rel = filepath.replace("\\", "/")
    parts = rel.split("/")
    vendor = ""
    for i, p in enumerate(parts):
        if p == "routers" and i + 1 < len(parts):
            vendor = parts[i + 1]
            break

    has_run = "def run(" in content
    has_check = "def check(" in content
    custom_methods = len(re.findall(r"def (?!run|check|__)\w+\(self", content))

    has_specific_path = bool(re.search(r'path="/[a-zA-Z]', content))
    has_payload = "payload" in content.lower() or "inject" in content.lower()
    specific_imports = ["import re", "import json", "import base64",
                        "import hashlib", "Crypto", "paramiko",
                        "telnetlib", "socket"]
    has_specific_import = any(x in content for x in specific_imports)
    auth_tokens = ["login", "session", "cookie", "token", "auth"]
    has_auth_logic = any(x in content for x in auth_tokens)
    extract_tokens = ["findall", "json.loads", "BeautifulSoup"]
    has_data_extraction = any(x in content for x in extract_tokens)

    is_generic_template = all(pat in content for pat in STUB_TEMPLATE_PATTERNS)
    has_todo = "TODO" in content
    has_pass_stub = "pass  #" in content or "# stub" in content.lower()

    cves = re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)

    # Scoring
    score = 0
    if has_run:
        score += 1
    if has_check:
        score += 1
    if has_specific_path:
        score += 3
    if custom_methods > 0:
        score += 2 * min(custom_methods, 3)
    if has_payload:
        score += 2
    if has_specific_import:
        score += 1
    if has_auth_logic:
        score += 2
    if has_data_extraction:
        score += 2
    if line_count > 150:
        score += 3
    elif line_count > 80:
        score += 1

    if is_generic_template:
        score -= 5
    if has_todo:
        score -= 2
    if has_pass_stub:
        score -= 3

    if score >= 8:
        tier = "S"
    elif score >= 4:
        tier = "A"
    elif score >= 0 and has_run and has_check:
        tier = "B"
    else:
        tier = "C"

    return {
        "file": rel,
        "vendor": vendor,
        "lines": line_count,
        "tier": tier,
        "score": score,
        "cves": cves[:5],
        "custom_methods": custom_methods,
        "has_specific_path": has_specific_path,
        "is_generic_template": is_generic_template,
    }


def main():
    """Run audit and print report."""
    results = {"S": [], "A": [], "B": [], "C": []}
    all_modules = []
    vendors = defaultdict(lambda: {"S": 0, "A": 0, "B": 0, "C": 0, "total": 0})

    for root, _dirs, files in os.walk(MODULES_ROOT):
        for fname in sorted(files):
            if not fname.endswith(".py") or fname == "__init__.py":
                continue
            filepath = os.path.join(root, fname)
            entry = audit_module(filepath)
            results[entry["tier"]].append(entry)
            all_modules.append(entry)
            v = entry["vendor"]
            if v:
                vendors[v][entry["tier"]] += 1
                vendors[v]["total"] += 1

    total = len(all_modules)

    print("=" * 70)
    print("RouterXPL-Forge Module Audit Report")
    print("=" * 70)
    print()
    print("Total modules scanned: {}".format(total))
    print()

    labels = {
        "S": "Full exploit logic",
        "A": "Partial/real logic",
        "B": "Generic stub template",
        "C": "Pure stub/minimal",
    }
    print("Tier breakdown:")
    for tier in ("S", "A", "B", "C"):
        count = len(results[tier])
        pct = (count / total * 100) if total else 0
        print("  Tier {} ({}): {} modules ({:.1f}%)".format(
            tier, labels[tier], count, pct))

    print()
    print("Top vendors by total modules:")
    top = sorted(vendors.items(), key=lambda x: -x[1]["total"])[:25]
    for v, c in top:
        print("  {:<15} total={:<4} S={:<3} A={:<3} B={:<3} C={:<3}".format(
            v, c["total"], c["S"], c["A"], c["B"], c["C"]))

    print()
    generic_count = sum(1 for m in all_modules if m["is_generic_template"])
    print("Generic template stubs (identical boilerplate): {}".format(generic_count))

    print()
    print("=== Tier S examples (top 10 by score) ===")
    for e in sorted(results["S"], key=lambda x: -x["score"])[:10]:
        print("  [{:>3}pt] {} ({} lines, {} custom methods)".format(
            e["score"], os.path.basename(e["file"]), e["lines"],
            e["custom_methods"]))

    print()
    print("=== Tier C examples (bottom 10 by score) ===")
    for e in sorted(results["C"], key=lambda x: x["score"])[:10]:
        print("  [{:>3}pt] {} ({} lines)".format(
            e["score"], os.path.basename(e["file"]), e["lines"]))

    report_path = os.path.join(MODULES_ROOT, "audit_report.json")
    report = {
        "summary": {
            "total": total,
            "tier_S": len(results["S"]),
            "tier_A": len(results["A"]),
            "tier_B": len(results["B"]),
            "tier_C": len(results["C"]),
            "generic_stubs": generic_count,
        },
        "vendors": dict(vendors),
        "modules": results,
    }
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print()
    print("Detailed report saved to: {}".format(report_path))


if __name__ == "__main__":
    main()
