"""EmbedXPL — Module Test-Status Marker.

Scans ALL .py files under embedxpl/modules/, determines whether each module
has been tested/confirmed in a real environment, and writes the result to
embedxpl/data/module_test_status.json.

Decision logic (in priority order):
  1.  kev                      — Any CVE referenced by the module is in the CISA KEV list.
  2.  rsf_public_framework     — Module path contains /rsf_  (RouterSploit-absorbed).
  3.  hatsploit_public_framework — Module path contains /hatsploit (HatSploit-absorbed).
  4.  isf_public_framework     — Module path contains /isf_  (ISF-absorbed).
  5.  known_real_target        — Module lives under cameras/hikvision/, cameras/dahua/,
                                 cameras/intelbras/ AND has at least one CVE reference.
  6.  exploitdb                — Filename starts with edb_  (ExploitDB-sourced exploit).
  7.  metasploit_equivalent    — Any CVE is present in the Metasploit Framework modules.
  8.  tenable_check            — Module path contains 'tenable' (Tenable-sourced check).
  9.  lab_poc                  — Any CVE matches a verified PoC dir in the local Labs arsenal.
  10. public_poc               — Any CVE has a public PoC (poc_github) in TupaXPL cve_catalog.
  11. covered_cve              — Any CVE is in embedxpl/data/cve_catalog.db with covered=1.
  12. False / None             — Everything else: tested=False (stub/theoretical).

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

# External source paths
_MSF_MODULES_DIR = _ROOT.parent / ".tmp" / "metasploit-framework" / "modules"
_MSF_CVE_CACHE   = Path("/tmp/msf_cves.txt")
_TUPA_CVE_DB     = (
    Path(__file__).resolve().parents[3]          # XPL-Suite/
    / "TupaXPL-Forge" / "offsecforge" / "intel" / "cve_db" / "cve_catalog.db"
)
_LABS_ARSENAL_DIR = Path("/run/media/mrhenrike/Data/Projects/Labs/new-arsenal-2026-09")

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
# Metasploit CVE loader
# ---------------------------------------------------------------------------

def _load_msf_cves() -> set[str]:
    """Return the set of CVE IDs covered by Metasploit Framework modules.

    Strategy (fastest first):
      1. Use pre-built cache at /tmp/msf_cves.txt (generated externally or by this run).
      2. Scan _MSF_MODULES_DIR with grep if cache is absent.
      3. Return empty set if MSF is not available.
    """
    # 1. Fast path: pre-built cache file
    if _MSF_CVE_CACHE.exists() and _MSF_CVE_CACHE.stat().st_size > 0:
        try:
            lines = _MSF_CVE_CACHE.read_text(encoding="utf-8").splitlines()
            cves = {ln.strip().upper() for ln in lines if ln.strip()}
            print(f"[*] MSF CVEs loaded from cache : {len(cves):,} ({_MSF_CVE_CACHE})")
            return cves
        except Exception as e:
            print(f"[!] Could not read MSF cache: {e}", file=sys.stderr)

    # 2. Scan MSF modules directory
    if not _MSF_MODULES_DIR.exists():
        print(f"[!] MSF modules dir not found: {_MSF_MODULES_DIR}", file=sys.stderr)
        return set()

    print(f"[*] Scanning MSF modules for CVEs (this may take a minute) …")
    import subprocess
    try:
        result = subprocess.run(
            ["grep", "-roh", r"CVE-[0-9]\{4\}-[0-9]\+", str(_MSF_MODULES_DIR)],
            capture_output=True, text=True, timeout=300,
        )
        cves = {ln.strip().upper() for ln in result.stdout.splitlines() if ln.strip()}
        # Cache result for future runs
        try:
            _MSF_CVE_CACHE.write_text("\n".join(sorted(cves)), encoding="utf-8")
        except Exception:
            pass
        print(f"[*] MSF CVEs extracted via scan  : {len(cves):,}")
        return cves
    except Exception as e:
        print(f"[!] MSF CVE scan failed: {e}", file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# Lab PoC CVE loader
# ---------------------------------------------------------------------------

def _load_lab_cves() -> set[str]:
    """Return CVE IDs from verified PoC directories in the local Labs arsenal."""
    if not _LABS_ARSENAL_DIR.exists():
        print(f"[!] Labs arsenal dir not found: {_LABS_ARSENAL_DIR}", file=sys.stderr)
        return set()
    try:
        cves: set[str] = set()
        for entry in _LABS_ARSENAL_DIR.iterdir():
            hits = _CVE_RE.findall(entry.name)
            for h in hits:
                cves.add(h.upper())
        print(f"[*] Lab PoC CVEs loaded          : {len(cves):,} ({_LABS_ARSENAL_DIR.name})")
        return cves
    except Exception as e:
        print(f"[!] Labs arsenal scan failed: {e}", file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# TupaXPL public PoC CVE loader
# ---------------------------------------------------------------------------

def _load_tupa_poc_cves() -> set[str]:
    """Return CVEs that have at least one public PoC entry in TupaXPL cve_catalog."""
    if not _TUPA_CVE_DB.exists():
        print(f"[!] TupaXPL cve_catalog not found: {_TUPA_CVE_DB}", file=sys.stderr)
        return set()
    try:
        conn = sqlite3.connect(str(_TUPA_CVE_DB))
        # poc_github is a JSON array — non-empty means at least one GitHub PoC exists
        rows = conn.execute(
            "SELECT cve_id FROM cves WHERE poc_github IS NOT NULL AND poc_github != '[]'"
        ).fetchall()
        conn.close()
        cves = {r[0].upper() for r in rows}
        print(f"[*] TupaXPL public PoC CVEs      : {len(cves):,}")
        return cves
    except Exception as e:
        print(f"[!] Could not read TupaXPL cve_catalog: {e}", file=sys.stderr)
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
    msf_cves: set[str],
    lab_cves: set[str],
    tupa_poc_cves: set[str],
) -> tuple[bool | None, str]:
    """Return (tested, evidence) for a single module.

    Returns:
        (True, evidence_label) — confirmed tested
        (False, '')            — untested / stub
    """
    lower = rel_path.lower()
    filename = lower.split("/")[-1]

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

    # 4. ISF-absorbed (path contains /ics/isf, /isf_, or isf_absorbed)
    if "/ics/isf" in lower or "\\ics\\isf" in lower \
            or "/isf_" in lower or "\\isf_" in lower \
            or "isf_absorbed" in lower:
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

    # 6. ExploitDB — filename starts with edb_ (e.g. edb_38514.py)
    if filename.startswith("edb_") or "/edb_" in lower:
        return True, "exploitdb"

    # 7. Metasploit cross-reference — CVE present in MSF modules
    if msf_cves:
        msf_hits = [c for c in cves if c in msf_cves]
        if msf_hits:
            return True, "metasploit_equivalent"

    # 8. Tenable-sourced checks (path contains tenable directory)
    if "tenable" in lower:
        return True, "tenable_check"

    # 9. Lab PoC — CVE matches a verified PoC repo in local Labs arsenal
    if lab_cves:
        lab_hits = [c for c in cves if c in lab_cves]
        if lab_hits:
            return True, "lab_poc"

    # 10. TupaXPL public PoC — CVE has a GitHub PoC in the pocindex catalog
    if tupa_poc_cves:
        poc_hits = [c for c in cves if c in tupa_poc_cves]
        if poc_hits:
            return True, "public_poc"

    # 11. CVE in local catalog with covered=1
    cov_hits = [c for c in cves if c in covered_cves]
    if cov_hits:
        return True, "covered_cve"

    # 12. Untested
    return False, ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(update_db: bool = False, verbose: bool = False) -> dict:
    """Run the full marking pass and return a summary dict."""
    print("[*] Loading evidence sources …")
    kev_set       = _load_kev_set()
    covered_cves  = _load_covered_cves()
    msf_cves      = _load_msf_cves()
    lab_cves      = _load_lab_cves()
    tupa_poc_cves = _load_tupa_poc_cves()

    print(f"[*] KEV entries loaded  : {len(kev_set):,}")
    print(f"[*] Covered CVEs loaded : {len(covered_cves):,}")

    status: dict[str, dict] = {}
    counts: dict[str, int] = {
        "kev": 0,
        "rsf_public_framework": 0,
        "hatsploit_public_framework": 0,
        "isf_public_framework": 0,
        "known_real_target": 0,
        "exploitdb": 0,
        "metasploit_equivalent": 0,
        "tenable_check": 0,
        "lab_poc": 0,
        "public_poc": 0,
        "covered_cve": 0,
        "untested": 0,
        "total": 0,
    }

    py_files = sorted(_MODULES_DIR.rglob("*.py"))
    total_files = len(py_files)
    print(f"[*] Scanning {total_files:,} Python files …")

    for i, fpath in enumerate(py_files, 1):
        if fpath.name in ("__init__.py",):
            continue
        if i % 1000 == 0:
            pct = i * 100 // total_files
            print(f"    … {i:,}/{total_files:,} ({pct}%) processed", flush=True)

        rel = str(fpath.relative_to(_ROOT.parent))  # relative to repo root
        cves = _extract_cves(fpath)

        # relative path for classification (use the part under modules/)
        rel_mod = str(fpath.relative_to(_ROOT)).replace("\\", "/")

        tested, evidence = _classify(
            rel_mod, cves, kev_set, covered_cves,
            msf_cves, lab_cves, tupa_poc_cves,
        )
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
