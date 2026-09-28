"""EmbedXPL Suite Sync Tool.

One-way sync from specialized XPL Suite tools into EmbedXPL.
Run after any specialized tool release to keep EmbedXPL up-to-date.

Usage:
    python -m embedxpl.tools.sync_from_suite [options]

    --dry-run          Show what would be copied, no writes
    --target TOOL      Sync only one tool (wireless|printer|firewall|industrial|wordlist)
    --force            Overwrite even if destination is newer
    --verbose          Show every file processed
    --check-imports    Validate all rewritten imports compile

Workflow:
    New vuln printer discovered
    → module created in PrinterXPL-Forge (canonical)
    → PrinterXPL released vX.Y.Z
    → python -m embedxpl.tools.sync_from_suite --target printer
    → EmbedXPL released vN.M.P

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Root paths
# ---------------------------------------------------------------------------

_SELF       = Path(__file__).resolve()
# parents: [0]=tools/, [1]=embedxpl/, [2]=EmbedXPL-Forge/, [3]=XPL-Suite/
_EMBEDXPL   = _SELF.parents[2]           # EmbedXPL-Forge/
_SUITE_ROOT = _EMBEDXPL.parent           # XPL-Suite/
_MANIFEST   = _EMBEDXPL / ".sync_manifest.json"

# ---------------------------------------------------------------------------
# Sync map: (source_relative_to_suite, dest_relative_to_embedxpl_pkg)
# ---------------------------------------------------------------------------

SYNC_MAP: dict[str, dict] = {
    "wireless": {
        "src":  _SUITE_ROOT / "WirelessXPL-Forge" / "wirelessxpl" / "modules",
        "dst":  _EMBEDXPL  / "embedxpl" / "modules" / "exploits" / "wireless",
        "pkg_rewrite": {
            "wirelessxpl.core":    "embedxpl.core",
            "wirelessxpl.modules": "embedxpl.modules",
            "wirelessxpl.libs":    "embedxpl.libs",
            "wirelessxpl.resources": "embedxpl.resources",
            "from wirelessxpl":    "from embedxpl",
            "import wirelessxpl":  "import embedxpl",
        },
        "include_subdirs": ["exploits", "auditors", "generic"],
        "skip_subdirs": [],
        "description": "WirelessXPL → wireless/ + auditors/ (WiFi, BLE, drones, RF)",
    },
    "printer": {
        "src":  _SUITE_ROOT / "PrinterXPL-Forge" / "printerxpl" / "modules",
        "dst":  _EMBEDXPL  / "embedxpl" / "modules" / "exploits" / "printers",
        "pkg_rewrite": {
            "printerxpl.core":    "embedxpl.core",
            "printerxpl.modules": "embedxpl.modules",
            "printerxpl.libs":    "embedxpl.libs",
            "from printerxpl":    "from embedxpl",
            "import printerxpl":  "import embedxpl",
        },
        "include_subdirs": ["exploits", "scanners"],
        "skip_subdirs": [],
        "description": "PrinterXPL → printers/ (HP, Canon, Ricoh, CUPS, PJL, PCL)",
    },
    "firewall": {
        "src":  _SUITE_ROOT / "FirewallXPL-Forge" / "firewallxpl" / "modules",
        "dst":  _EMBEDXPL  / "embedxpl" / "modules" / "exploits" / "firewalls",
        "pkg_rewrite": {
            "firewallxpl.core":    "embedxpl.core",
            "firewallxpl.modules": "embedxpl.modules",
            "firewallxpl.libs":    "embedxpl.libs",
            "from firewallxpl":    "from embedxpl",
            "import firewallxpl":  "import embedxpl",
        },
        "include_subdirs": ["exploits", "creds", "generic", "intel", "encoders"],
        "skip_subdirs": [],
        "description": "FirewallXPL → firewalls/ (NGFW, UTM, IDS, IPS, NAC, LB, VPN, WAF)",
    },
    "industrial": {
        "src":  _SUITE_ROOT / "IndustrialXPL-Forge" / "industrialxpl" / "modules",
        "dst":  _EMBEDXPL  / "embedxpl" / "modules" / "exploits" / "ics",
        "pkg_rewrite": {
            "industrialxpl.core":    "embedxpl.core",
            "industrialxpl.modules": "embedxpl.modules",
            "industrialxpl.libs":    "embedxpl.libs",
            "from industrialxpl":    "from embedxpl",
            "import industrialxpl":  "import embedxpl",
        },
        "include_subdirs": ["exploits", "cve", "assessment", "creds", "encoders"],
        "skip_subdirs": [],
        "description": "IndustrialXPL → ics/ (Modbus, S7comm, DNP3, OPC-UA, PLC, SCADA)",
    },
    "wordlist": {
        "src":  _SUITE_ROOT / "WordlistXPL-Forge" / "wfh_modules",
        "dst":  _EMBEDXPL  / "embedxpl" / "engines" / "wordlists",
        "pkg_rewrite": {
            "wfh_modules": "embedxpl.engines.wordlists",
            "from wfh_modules": "from embedxpl.engines.wordlists",
            "import wfh_modules": "import embedxpl.engines.wordlists",
        },
        "include_subdirs": None,  # all
        "skip_subdirs": ["__pycache__"],
        "description": "WordlistXPL engines → engines/wordlists/ (generators, analyzers, fuzzing)",
    },
    "wordlist_data": {
        "src":  _SUITE_ROOT / "WordlistXPL-Forge" / "passwords",
        "dst":  _EMBEDXPL  / "embedxpl" / "data" / "wordlists" / "passwords",
        "pkg_rewrite": {},   # data files — no rewrite
        "include_subdirs": None,
        "skip_subdirs": [],
        "description": "WordlistXPL passwords → data/wordlists/passwords/",
    },
    "wordlist_usernames": {
        "src":  _SUITE_ROOT / "WordlistXPL-Forge" / "usernames",
        "dst":  _EMBEDXPL  / "embedxpl" / "data" / "wordlists" / "usernames",
        "pkg_rewrite": {},
        "include_subdirs": None,
        "skip_subdirs": [],
        "description": "WordlistXPL usernames → data/wordlists/usernames/",
    },
    "wordlist_fuzzing": {
        "src":  _SUITE_ROOT / "WordlistXPL-Forge" / "fuzzing",
        "dst":  _EMBEDXPL  / "embedxpl" / "data" / "wordlists" / "fuzzing",
        "pkg_rewrite": {},
        "include_subdirs": None,
        "skip_subdirs": [],
        "description": "WordlistXPL fuzzing → data/wordlists/fuzzing/",
    },
}

# File extensions to process for import rewriting
_REWRITE_EXTS = {".py"}

# Extensions to copy as-is (no rewrite)
_COPY_EXTS = {
    ".txt", ".yaml", ".yml", ".json", ".xml", ".csv",
    ".md", ".rst", ".nse", ".lua", ".rb", ".sh", ".bash",
    ".pcap", ".cap", ".bin", ".lst", ".list",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _load_manifest() -> dict:
    if _MANIFEST.exists():
        try:
            return json.loads(_MANIFEST.read_text())
        except Exception:
            pass
    return {"synced": {}, "last_sync": None, "stats": {}}


def _save_manifest(manifest: dict) -> None:
    _MANIFEST.write_text(json.dumps(manifest, indent=2))


def _rewrite_imports(content: str, rewrite_map: dict[str, str]) -> str:
    """Replace package prefixes in import statements."""
    for old, new in rewrite_map.items():
        content = content.replace(old, new)
    return content


def _validate_python(path: Path) -> Optional[str]:
    """Return syntax error string or None if valid."""
    try:
        ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        return None
    except SyntaxError as e:
        return str(e)


def _should_skip(path: Path, include_subdirs: Optional[list]) -> bool:
    """Return True if this file should be skipped based on include_subdirs filter."""
    if include_subdirs is None:
        return False
    # Check if any parent part matches include_subdirs
    parts = path.parts
    for part in parts:
        if part in include_subdirs:
            return False
    # If none of the path parts are in include_subdirs, check if it's a top-level file
    return True


# ---------------------------------------------------------------------------
# Core sync function
# ---------------------------------------------------------------------------

def sync_target(
    target_name: str,
    config: dict,
    dry_run: bool = False,
    force: bool = False,
    verbose: bool = False,
    check_imports: bool = False,
) -> dict:
    """Sync one source directory to EmbedXPL. Returns stats dict."""
    src: Path = config["src"]
    dst: Path = config["dst"]
    rewrite_map: dict = config.get("pkg_rewrite", {})
    include_subdirs: Optional[list] = config.get("include_subdirs")
    skip_subdirs: list = config.get("skip_subdirs", [])

    if not src.exists():
        print(f"  [SKIP] Source not found: {src}")
        return {"copied": 0, "skipped": 0, "conflicts": 0, "errors": 0}

    if not dry_run:
        dst.mkdir(parents=True, exist_ok=True)
        # Ensure __init__.py exists
        init = dst / "__init__.py"
        if not init.exists():
            init.write_text(
                f'"""EmbedXPL — {target_name} modules (synced from specialized tool).\n'
                f'# authorized use only\n"""\n'
            )

    stats = {"copied": 0, "skipped": 0, "conflicts": 0, "errors": 0, "rewrites": 0}
    manifest = _load_manifest()
    synced = manifest.setdefault("synced", {})

    for src_file in sorted(src.rglob("*")):
        if not src_file.is_file():
            continue

        # Skip __pycache__, skip_subdirs, hidden files
        rel = src_file.relative_to(src)
        parts = rel.parts
        if any(p in skip_subdirs or p == "__pycache__" or p.startswith(".") for p in parts):
            continue
        if src_file.suffix == ".pyc":
            continue

        # Apply include_subdirs filter for multi-subdir sources
        if include_subdirs is not None and len(parts) > 1:
            if parts[0] not in include_subdirs:
                if verbose:
                    print(f"  [SKIP-DOMAIN] {rel}")
                stats["skipped"] += 1
                continue

        # Destination path
        dst_file = dst / rel
        src_hash = _file_hash(src_file)
        manifest_key = str(dst_file)

        # Conflict check: destination exists and is newer than last sync
        if dst_file.exists() and not force:
            prev_hash = synced.get(manifest_key, {}).get("src_hash")
            if prev_hash == src_hash:
                if verbose:
                    print(f"  [UNCHANGED] {rel}")
                stats["skipped"] += 1
                continue
            # Check if dest was locally modified
            dst_hash = _file_hash(dst_file)
            prev_dst_hash = synced.get(manifest_key, {}).get("dst_hash")
            if prev_dst_hash and dst_hash != prev_dst_hash:
                if verbose:
                    print(f"  [CONFLICT]  {rel} — dest modified locally, keeping")
                stats["conflicts"] += 1
                continue

        ext = src_file.suffix
        if verbose:
            action = "DRY-RUN" if dry_run else "COPY"
            print(f"  [{action}] {rel}")

        if not dry_run:
            dst_file.parent.mkdir(parents=True, exist_ok=True)

            if ext in _REWRITE_EXTS and rewrite_map:
                # Rewrite imports
                content = src_file.read_text(encoding="utf-8", errors="replace")
                rewritten = _rewrite_imports(content, rewrite_map)
                if rewritten != content:
                    stats["rewrites"] += 1
                dst_file.write_text(rewritten, encoding="utf-8")
                if check_imports:
                    err = _validate_python(dst_file)
                    if err:
                        print(f"  [SYNTAX-ERR] {dst_file.name}: {err}")
                        stats["errors"] += 1
            else:
                shutil.copy2(src_file, dst_file)

            # Update manifest
            synced[manifest_key] = {
                "src": str(src_file),
                "src_hash": src_hash,
                "dst_hash": _file_hash(dst_file),
                "synced_at": datetime.now().isoformat(),
                "target": target_name,
            }

        stats["copied"] += 1

    if not dry_run:
        manifest["last_sync"] = datetime.now().isoformat()
        manifest["stats"][target_name] = stats
        _save_manifest(manifest)

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync specialized XPL Suite tools into EmbedXPL (one-way)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            f"  {name:<20} {cfg['description']}"
            for name, cfg in SYNC_MAP.items()
        ),
    )
    parser.add_argument(
        "--target", "-t",
        choices=list(SYNC_MAP.keys()) + ["all"],
        default="all",
        help="Which tool to sync (default: all)",
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview only, no writes")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite even if dest is newer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show every file")
    parser.add_argument("--check-imports", action="store_true", help="Validate rewritten Python syntax")
    args = parser.parse_args()

    targets = SYNC_MAP if args.target == "all" else {args.target: SYNC_MAP[args.target]}

    print(f"{'='*65}")
    print(f"  EmbedXPL Suite Sync — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Suite root: {_SUITE_ROOT}")
    print(f"  EmbedXPL:   {_EMBEDXPL}")
    if args.dry_run:
        print("  *** DRY RUN — no files will be written ***")
    print(f"{'='*65}\n")

    total = {"copied": 0, "skipped": 0, "conflicts": 0, "errors": 0, "rewrites": 0}

    for name, config in targets.items():
        print(f"[{name}] {config['description']}")
        print(f"  src: {config['src']}")
        print(f"  dst: {config['dst']}")
        stats = sync_target(
            name, config,
            dry_run=args.dry_run,
            force=args.force,
            verbose=args.verbose,
            check_imports=args.check_imports,
        )
        print(f"  → copied:{stats['copied']} skipped:{stats['skipped']} "
              f"conflicts:{stats['conflicts']} rewrites:{stats.get('rewrites',0)} "
              f"errors:{stats['errors']}\n")
        for k in total:
            total[k] += stats.get(k, 0)

    print(f"{'─'*65}")
    print(f"  TOTAL  copied:{total['copied']} skipped:{total['skipped']} "
          f"conflicts:{total['conflicts']} rewrites:{total['rewrites']} errors:{total['errors']}")
    if not args.dry_run:
        print(f"  Manifest: {_MANIFEST}")
    print(f"{'─'*65}")

    if total["errors"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
