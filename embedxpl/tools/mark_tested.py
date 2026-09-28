"""EmbedXPL — Module Test-Status Marker.

Scans ALL .py files under embedxpl/modules/, determines whether each module
has been tested/confirmed in a real environment, and writes the result to
embedxpl/data/module_test_status.json.

Decision logic (in priority order):
  1. kev              — Any CVE referenced by the module is in the CISA KEV list.
  2. rsf_public_framework  — Module path contains /rsf_  (RouterSploit-absorbed).
  3. hatsploit_public_framework — Module path contains /hatsploit (HatSploit-absorbed).
  4. isf_public_framework  — Module path contains /isf_  (ISF-absorbed).
  5. known_real_target  — Module lives under cameras/hikvision/, cameras/dahua/,
                          cameras/intelbras/ AND has at least one CVE reference.
  6. public_poc        — Any CVE is in embedxpl/data/cve_catalog.db with covered=1.
  7. False / None       — Everything else: tested=False (stub/theoretical).

Output:
  embedxpl/data/module_test_status.json

Usage::
    python -m embedxpl.tools.mark_tested            # normal run
    python -m embedxpl.tools.mark_tested --update-db # also updates module_cache in EXFDatabase

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent          # embedxpl/tools/
_ROOT = _HERE.parent                             # embedxpl/
_MODULES_DIR = _ROOT / "modules"
_DATA_DIR = _ROOT / "data"
_OUT_FILE = _DATA_DIR / "module_test_status.json"
_KEV_FILE = _DATA_DIR / "cisa_kev.json"
_CVE_DB = _DATA_DIR / "cve_catalog.db"

# CISA KEV feed URL
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Regex to find CVE IDs in source files
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# ---------------------------------------------------------------------------
# KEV loader
# ---------------------------------------------------------------------------

def _load_kev_set() -> set[str]:
    """Load CISA KEV CVE IDs into a set.  Falls back to fetch if not cached."""
    # 1. Try local cache
    if _KEV_FILE.exists():
        try:
            data = json.loads(_KEV_FILE.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return {v["cveID"].upper() for v in vulns if "cveID" in v}
        except Exception as e:
            print(f"[!] Could not parse {_KEV_FILE}: {e}", file=sys.stderr)

    # 2. Try to fetch from CISA
    print(f"[*] Fetching CISA KEV from {_KEV_URL} …")
    try:
        with urllib.request.urlopen(_KEV_URL, timeout=15) as resp:
            raw = resp.read()
        data = json.loads(raw)
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _KEV_FILE.write_bytes(raw)
        print(f"[+] KEV cached to {_KEV_FILE}")
        vulns = data.get("vulnerabilities", [])
        return {v["cveID"].upper() for v in vulns if "cveID" in v}
    except Exception as e:
        print(f"[!] KEV fetch failed: {e}. Proceeding without KEV data.", file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# CVE catalog loader (optional)
# ---------------------------------------------------------------------------

def _load_covered_cves() -> set[str]:
    """Load CVEs with covered=1 from the local cve_catalog.db if it exists."""
    if not _CVE_DB.exists():
        return set()
    try:
        conn = sqlite3.connect(str(_CVE_DB))
        rows = conn.execute("SELECT cve_id FROM cves WHERE covered=1").fetchall()
        conn.close()
        return {r[0].upper() for r in rows}
    except Exception as e:
        print(f"[!] Could not read cve_catalog.db: {e}", file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# Module scanner
# ---------------------------------------------------------------------------

def _extract_cves(path: Path) -> list[str]:
    """Return list of normalised CVE IDs found in a Python source file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    return list({m.upper() for m in _CVE_RE.findall(text)})


def _classify(
    rel_path: str,
    cves: list[str],
    kev_set: set[str],
    covered_cves: set[str],
) -> tuple[bool | None, str]:
    """Return (tested, evidence) for a single module.

    Returns:
        (True, evidence_label) — confirmed tested
        (False, '')            — untested / stub
    """
    lower = rel_path.lower()

    # 1. KEV
    kev_hits = [c for c in cves if c in kev_set]
    if kev_hits:
        return True, "kev"

    # 2. RouterSploit-absorbed
    if "/rsf_" in lower or "\\rsf_" in lower or "/rsf/" in lower or "/creds/rsf" in lower:
        return True, "rsf_public_framework"

    # 3. HatSploit-absorbed
    if "hatsploit" in lower:
        return True, "hatsploit_public_framework"

    # 4. ISF-absorbed
    if "/isf_" in lower or "\\isf_" in lower or "isf_absorbed" in lower:
        return True, "isf_public_framework"

    # 5. Known real-target folders with CVEs (Hikvision / Dahua / Intelbras exploits)
    is_known_target = any(
        x in lower
        for x in (
            "cameras/hikvision",
            "cameras/dahua",
            "cameras/intelbras",
            "exploits/cameras/hikvision",
            "exploits/cameras/dahua",
            "exploits/cameras/intelbras",
        )
    )
    if is_known_target and cves:
        return True, "known_real_target"

    # 6. CVE in local catalog with covered=1 → public PoC
    poc_hits = [c for c in cves if c in covered_cves]
    if poc_hits:
        return True, "public_poc"

    # 7. Untested
    return False, ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(update_db: bool = False, verbose: bool = False) -> dict:
    """Run the full marking pass and return a summary dict."""
    kev_set = _load_kev_set()
    covered_cves = _load_covered_cves()

    print(f"[*] KEV entries loaded  : {len(kev_set):,}")
    print(f"[*] Covered CVEs loaded : {len(covered_cves):,}")

    status: dict[str, dict] = {}
    counts: dict[str, int] = {
        "kev": 0,
        "rsf_public_framework": 0,
        "hatsploit_public_framework": 0,
        "isf_public_framework": 0,
        "known_real_target": 0,
        "public_poc": 0,
        "untested": 0,
        "total": 0,
    }

    py_files = sorted(_MODULES_DIR.rglob("*.py"))

    for fpath in py_files:
        if fpath.name in ("__init__.py",):
            continue
        rel = str(fpath.relative_to(_ROOT.parent))  # relative to repo root
        cves = _extract_cves(fpath)

        # relative path for classification (use the part under modules/)
        rel_mod = str(fpath.relative_to(_ROOT)).replace("\\", "/")

        tested, evidence = _classify(rel_mod, cves, kev_set, covered_cves)
        status[rel] = {
            "tested": tested,
            "evidence": evidence,
            "cves": cves,
        }
        counts["total"] += 1
        if tested:
            counts[evidence] = counts.get(evidence, 0) + 1
        else:
            counts["untested"] += 1

        if verbose:
            badge = "[TESTED]" if tested else "[UNTESTED]"
            print(f"  {badge:<12} {evidence:<32} {rel}")

    tested_total = counts["total"] - counts["untested"]

    print(f"\n[*] Scan complete.")
    print(f"    Total modules   : {counts['total']:,}")
    print(f"    Tested          : {tested_total:,}")
    print(f"    Untested        : {counts['untested']:,}")
    print(f"\n    Evidence breakdown:")
    for k, v in counts.items():
        if k in ("total", "untested"):
            continue
        if v:
            print(f"      {k:<35} {v:,}")

    # Write JSON
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    out = {
        "_meta": {
            "total": counts["total"],
            "tested": tested_total,
            "untested": counts["untested"],
            "evidence_counts": {k: v for k, v in counts.items() if k not in ("total",)},
        },
        "modules": status,
    }
    _OUT_FILE.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Written: {_OUT_FILE}")

    # Optionally update DB
    if update_db:
        _update_database(status)

    return out["_meta"]


def _update_database(status: dict[str, dict]) -> None:
    """Push tested status into the EXFDatabase module_cache."""
    try:
        from embedxpl.core.database import EXFDatabase
        db = EXFDatabase()
        updated = 0
        for rel_path, info in status.items():
            # Convert file path → python module path
            # e.g. embedxpl/modules/exploits/cameras/... → embedxpl.modules.exploits.cameras...
            parts = rel_path.replace("\\", "/").split("/")
            try:
                mod_idx = parts.index("embedxpl")
                mod_path = ".".join(parts[mod_idx:]).removesuffix(".py")
            except ValueError:
                continue
            db.update_module_test_status(
                mod_path,
                info["tested"],
                info["evidence"],
            )
            updated += 1
        db.close()
        print(f"[+] Updated {updated:,} entries in EXFDatabase module_cache.")
    except Exception as e:
        print(f"[!] DB update failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mark EmbedXPL modules as tested/untested based on KEV/RSF/ISF/PoC data."
    )
    parser.add_argument(
        "--update-db", action="store_true",
        help="Also update EXFDatabase module_cache with tested status.",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print every module as it is processed.",
    )
    args = parser.parse_args()
    run(update_db=args.update_db, verbose=args.verbose)


if __name__ == "__main__":
    main()
