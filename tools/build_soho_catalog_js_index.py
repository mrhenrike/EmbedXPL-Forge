#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Emit ``soho_catalog_js_index.json`` from bundled ``includes/scripts.js``."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from routerxpl.core.soho_exploit_catalog import index_catalog_script_functions, resolve_soho_catalog_root


def main() -> int:
    repo = _REPO_ROOT
    root = resolve_soho_catalog_root()
    scripts = root / "includes" / "scripts.js"
    out_path = repo / "routerxpl" / "resources" / "catalogs" / "soho_catalog_js_index.json"

    entries = index_catalog_script_functions(scripts)

    try:
        scripts_rel = scripts.relative_to(repo)
        scripts_display = str(scripts_rel).replace("\\", "/")
    except ValueError:
        scripts_display = str(scripts).replace("\\", "/")

    payload = {
        "catalog_root": str(root).replace("\\", "/"),
        "scripts_js": scripts_display,
        "function_count": len(entries),
        "functions": entries,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
