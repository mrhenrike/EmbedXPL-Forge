"""EmbedXPL Search Engine — shim para canonical search_base.

Canonical: XPL-Suite/tools/search_base.py
"""
from __future__ import annotations
import sys
from pathlib import Path

_SUITE_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if _SUITE_TOOLS.is_dir() and str(_SUITE_TOOLS) not in sys.path:
    sys.path.insert(0, str(_SUITE_TOOLS))

from search_base import make_search_api, ModuleRecord  # noqa: F401

search, search_cve, search_vendor, search_category, print_results = make_search_api("embedxpl.modules")

if __name__ == "__main__":
    import sys as _sys
    query = " ".join(_sys.argv[1:]) if len(_sys.argv) > 1 else "cve"
    print(f"[*] Searching: {query!r}")
    results = search(query)
    print_results(results, query)
