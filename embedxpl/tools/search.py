"""EmbedXPL Search Engine — MSF-style module discovery.

Usage:
    from embedxpl.tools.search import search, search_cve, search_vendor

    # Busca livre (keyword em nome, desc, CVE, vendor, categoria)
    results = search("dlink")
    results = search("dlink rce 2024")
    results = search("cve-2021-36260")   # Hikvision RCE

    # Busca direta por CVE
    results = search_cve("CVE-2024-4577")

    # Busca por vendor
    results = search_vendor("hikvision")

    # AutoPwn por segmento
    results = search("type:router host:192.168.0.1")

CLI (python -m embedxpl):
    exf> search dlink
    exf> search type:printer
    exf> search cve-2021-36260
    exf> search vendor:fortinet severity:critical

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

_EMBEDXPL_ROOT = Path(__file__).resolve().parents[2]
_MODULES_ROOT = _EMBEDXPL_ROOT / "embedxpl" / "modules"

# ---------------------------------------------------------------------------
# Module record
# ---------------------------------------------------------------------------

@dataclass
class ModuleRecord:
    path: str                   # embedxpl.modules.exploits.routers.dlink.cve_2021_xxxxx
    name: str                   # CVE-2021-XXXXX D-Link RCE
    description: str = ""
    authors: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    vendors: list[str] = field(default_factory=list)
    platform: str = ""
    severity: str = ""
    category: str = ""          # routers / cameras / firewalls / ics / printers / wireless
    file_path: str = ""
    rank: int = 0               # relevance score for display order

    def display_path(self) -> str:
        """Short display path like MSF: exploits/routers/dlink/cve_xxx"""
        parts = self.path.split(".")
        try:
            idx = parts.index("modules") + 1
            return "/".join(parts[idx:])
        except ValueError:
            return self.path

    def __str__(self) -> str:
        cve_str = ", ".join(self.cves[:2]) + ("..." if len(self.cves) > 2 else "")
        return f"  {self.display_path():<60} {cve_str:<25} {self.name[:50]}"


# ---------------------------------------------------------------------------
# Module scanner
# ---------------------------------------------------------------------------

def _iter_modules(base_pkg: str = "embedxpl.modules") -> Iterator[str]:
    """Yield all importable module paths under base_pkg."""
    try:
        base = importlib.import_module(base_pkg)
    except ImportError:
        return
    base_path = getattr(base, "__path__", None)
    if not base_path:
        return
    for finder, name, ispkg in pkgutil.walk_packages(base_path, prefix=base_pkg + "."):
        yield name


def _extract_info(module_path: str) -> Optional[ModuleRecord]:
    """Import a module and extract its metadata."""
    try:
        mod = importlib.import_module(module_path)
    except Exception:
        return None

    # Get source file
    file_path = getattr(mod, "__file__", "") or ""

    # Look for __info__ dict or class-level attributes
    info = getattr(mod, "__info__", {}) or {}

    # Also look for the main Exploit class
    exploit_cls = None
    for name, obj in inspect.getmembers(mod, inspect.isclass):
        if hasattr(obj, "__info__"):
            exploit_cls = obj
            info = obj.__info__ if isinstance(obj.__info__, dict) else info
            break

    name = info.get("name", "") or info.get("title", "")
    description = info.get("description", "") or info.get("desc", "")
    authors = info.get("authors", []) or info.get("author", [])
    if isinstance(authors, str):
        authors = [authors]
    platform = info.get("platform", "")
    rank = info.get("rank", 0) or 0

    # Extract CVEs from module path + description + __info__
    cve_text = f"{module_path} {name} {description} {file_path}"
    if "references" in info:
        for ref in info.get("references", []):
            if isinstance(ref, str):
                cve_text += " " + ref
    cves = list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d+", cve_text, re.I)))
    cves = [c.upper() for c in cves]

    # Determine vendor/category from path
    parts = module_path.split(".")
    category = ""
    vendors = []
    try:
        idx = parts.index("exploits") if "exploits" in parts else \
              parts.index("scanners") if "scanners" in parts else \
              parts.index("creds") if "creds" in parts else -1
        if idx >= 0 and idx + 1 < len(parts):
            category = parts[idx + 1]  # routers, cameras, firewalls, etc.
        if idx >= 0 and idx + 2 < len(parts):
            vendors = [parts[idx + 2]]  # dlink, hikvision, fortinet, etc.
    except ValueError:
        pass

    # Extract vendors from __info__
    info_vendors = info.get("vendors", []) or []
    vendors = list(dict.fromkeys(vendors + info_vendors))

    if not name and not cves:
        # Minimal record from path only
        filename = parts[-1].replace("_", " ").replace("cve ", "CVE-")
        name = filename[:60]

    return ModuleRecord(
        path=module_path,
        name=name or parts[-1],
        description=description,
        authors=authors,
        cves=cves,
        vendors=vendors,
        platform=platform,
        severity="critical" if any(c for c in cves) else "",
        category=category,
        file_path=file_path,
        rank=rank,
    )


# ---------------------------------------------------------------------------
# Search API
# ---------------------------------------------------------------------------

_MODULE_CACHE: Optional[list[ModuleRecord]] = None


def _get_cache(rebuild: bool = False) -> list[ModuleRecord]:
    global _MODULE_CACHE
    if _MODULE_CACHE is None or rebuild:
        print("[*] Indexando módulos EmbedXPL (primeira execução — aguarde)...")
        records = []
        for path in _iter_modules():
            rec = _extract_info(path)
            if rec:
                records.append(rec)
        _MODULE_CACHE = records
        print(f"[*] {len(records)} módulos indexados.")
    return _MODULE_CACHE


def search(
    query: str,
    limit: int = 50,
    category: Optional[str] = None,
) -> list[ModuleRecord]:
    """
    MSF-style search. Supports:
      search dlink
      search cve-2021-36260
      search type:router
      search vendor:fortinet
      search type:printer severity:critical
    """
    records = _get_cache()

    # Parse filter tokens
    tokens = []
    filter_type = None
    filter_vendor = None
    filter_severity = None
    filter_cve = None

    for tok in query.lower().split():
        if tok.startswith("type:"):
            filter_type = tok[5:]
        elif tok.startswith("vendor:"):
            filter_vendor = tok[7:]
        elif tok.startswith("severity:"):
            filter_severity = tok[9:]
        elif tok.startswith("cve-") or re.match(r"cve-\d{4}-\d+", tok, re.I):
            filter_cve = tok.upper()
            if not filter_cve.startswith("CVE-"):
                filter_cve = "CVE-" + filter_cve[4:]
        else:
            tokens.append(tok)

    keyword = " ".join(tokens)
    results = []

    for rec in records:
        score = 0
        searchable = " ".join([
            rec.path.lower(),
            rec.name.lower(),
            rec.description.lower(),
            " ".join(rec.cves).lower(),
            " ".join(rec.vendors).lower(),
            rec.category.lower(),
        ])

        # Apply filters
        if filter_type and filter_type not in rec.category.lower():
            continue
        if filter_vendor and not any(filter_vendor in v.lower() for v in rec.vendors) \
                and filter_vendor not in rec.path.lower():
            continue
        if filter_severity:
            if filter_severity == "critical" and not rec.cves:
                continue
        if filter_cve:
            if filter_cve not in [c.upper() for c in rec.cves]:
                continue
        if category and category.lower() not in rec.category.lower():
            continue

        # Keyword scoring
        if keyword:
            for word in keyword.split():
                if word in searchable:
                    score += 10
                    if word in rec.path.lower():
                        score += 5
                    if word in " ".join(rec.cves).lower():
                        score += 8
                    if any(word in v.lower() for v in rec.vendors):
                        score += 7
            if score == 0:
                continue
        else:
            score = 1  # no keyword = show all matching filters

        rec.rank = score
        results.append(rec)

    results.sort(key=lambda r: r.rank, reverse=True)
    return results[:limit]


def search_cve(cve_id: str) -> list[ModuleRecord]:
    """Find all modules covering a specific CVE."""
    cve_norm = cve_id.upper().strip()
    if not cve_norm.startswith("CVE-"):
        cve_norm = "CVE-" + cve_norm
    return search(cve_norm, limit=20)


def search_vendor(vendor: str) -> list[ModuleRecord]:
    """Find all modules for a specific vendor."""
    return search(f"vendor:{vendor}", limit=100)


def search_category(cat: str) -> list[ModuleRecord]:
    """Find all modules for a category (routers, cameras, printers, firewalls, ics, wireless)."""
    return search(f"type:{cat}", limit=200)


# ---------------------------------------------------------------------------
# CLI display (MSF-style)
# ---------------------------------------------------------------------------

def print_results(results: list[ModuleRecord], query: str = "") -> None:
    """Print search results MSF-style."""
    if not results:
        print(f"\n[-] No modules found for: {query!r}")
        return

    print(f"\n{'='*100}")
    print(f"  {'Module Path':<60} {'CVEs':<25} {'Name'}")
    print(f"  {'-'*58} {'-'*23} {'-'*30}")
    for rec in results:
        cve_str = ", ".join(rec.cves[:2])
        if len(rec.cves) > 2:
            cve_str += f" (+{len(rec.cves)-2})"
        print(f"  {rec.display_path():<60} {cve_str:<25} {rec.name[:50]}")
    print(f"{'='*100}")
    print(f"  {len(results)} module(s) found")
    print()


# ---------------------------------------------------------------------------
# Direct run for testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "dlink"
    print(f"[*] Searching: {query!r}")
    results = search(query)
    print_results(results, query)
