#!/usr/bin/env python3
"""
verify_checksums.py — Embedded Firmware Research Lab checksum verifier
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Reads manifests/download_manifest.yaml and verifies that every recorded file
exists on disk and its SHA256 matches the stored value.

Usage:
    python scripts/verify_checksums.py
    python scripts/verify_checksums.py --category tv
    python scripts/verify_checksums.py --brand samsung
    python scripts/verify_checksums.py --verbose
    python scripts/verify_checksums.py --update-missing   # re-hash missing SHA256 entries
"""

import argparse
import hashlib
import io
import sys
from pathlib import Path

import yaml

# Ensure UTF-8 output on Windows consoles
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Paths ──────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_FILE = REPO_ROOT / "manifests" / "download_manifest.yaml"

# ── Helpers ────────────────────────────────────────────────────────────────────


def load_manifest() -> dict:
    if not MANIFEST_FILE.exists():
        print(f"[ERROR] Manifest not found: {MANIFEST_FILE}", file=sys.stderr)
        sys.exit(1)
    with open(MANIFEST_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def save_manifest(manifest: dict) -> None:
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


# ── Verifier ───────────────────────────────────────────────────────────────────


def verify(
    category_filter: str | None,
    brand_filter: str | None,
    verbose: bool,
    update_missing: bool,
) -> bool:
    manifest = load_manifest()
    entries = manifest.get("downloads", [])

    if not entries:
        print("[INFO] Manifest has no entries. Nothing to verify.")
        return True

    results = {
        "pass": 0,
        "fail_missing_file": 0,
        "fail_hash_mismatch": 0,
        "skip_pending": 0,
        "skip_unavailable": 0,
        "skip_failed": 0,
        "skip_no_hash": 0,
        "updated": 0,
    }
    updated_entries = []

    for entry in entries:
        brand = entry.get("brand", "")
        category = entry.get("category", "")
        status = entry.get("status", "ok")
        filename = entry.get("filename", "")
        filepath_str = entry.get("filepath", "")
        stored_sha256 = entry.get("sha256", "")

        # Filters
        if category_filter and category.lower() != category_filter.lower():
            updated_entries.append(entry)
            continue
        if brand_filter and brand_filter.lower() not in brand.lower():
            updated_entries.append(entry)
            continue

        label = f"{brand}/{filename}"

        # Skip entries that were not (yet) downloaded locally
        if status == "pending_manual_download":
            results["skip_pending"] += 1
            if verbose:
                print(f"  [SKIP] {label} — status=pending_manual_download")
            updated_entries.append(entry)
            continue
        if status == "unavailable":
            results["skip_unavailable"] += 1
            if verbose:
                print(f"  [SKIP] {label} — status=unavailable")
            updated_entries.append(entry)
            continue
        if status == "failed":
            results["skip_failed"] += 1
            if verbose:
                print(f"  [SKIP] {label} — status=failed (previous download error)")
            updated_entries.append(entry)
            continue

        # Resolve file path
        if filepath_str:
            file_path = REPO_ROOT / filepath_str
        else:
            # Derive from category/brand/filename
            file_path = REPO_ROOT / "downloads" / category / brand / filename

        # Check file exists
        if not file_path.exists():
            results["fail_missing_file"] += 1
            print(f"  [FAIL] FILE MISSING: {label}")
            print(f"         Expected at: {file_path}")
            updated_entries.append(entry)
            continue

        # Check SHA256
        if not stored_sha256:
            if update_missing:
                new_hash = sha256_file(file_path)
                entry["sha256"] = new_hash
                entry["size_bytes"] = file_path.stat().st_size
                results["updated"] += 1
                print(f"  [UPDATE] {label} — SHA256 added: {new_hash[:16]}...")
            else:
                results["skip_no_hash"] += 1
                if verbose:
                    print(f"  [SKIP] {label} — no SHA256 in manifest (use --update-missing)")
            updated_entries.append(entry)
            continue

        actual_hash = sha256_file(file_path)
        if actual_hash == stored_sha256:
            results["pass"] += 1
            if verbose:
                size = human_size(file_path.stat().st_size)
                print(f"  [PASS] {label} ({size})")
        else:
            results["fail_hash_mismatch"] += 1
            print(f"  [FAIL] HASH MISMATCH: {label}")
            print(f"         Stored : {stored_sha256}")
            print(f"         Actual : {actual_hash}")

        updated_entries.append(entry)

    if update_missing and results["updated"] > 0:
        manifest["downloads"] = updated_entries
        save_manifest(manifest)
        print(f"\n[manifest] Updated {results['updated']} entries with SHA256.")

    # Summary
    total_checked = results["pass"] + results["fail_missing_file"] + results["fail_hash_mismatch"]
    print("\n" + "-" * 60)
    print("Checksum Verification Summary")
    print("-" * 60)
    print(f"  PASS                : {results['pass']}")
    print(f"  FAIL (missing file) : {results['fail_missing_file']}")
    print(f"  FAIL (hash mismatch): {results['fail_hash_mismatch']}")
    print(f"  SKIP (pending DL)   : {results['skip_pending']}")
    print(f"  SKIP (unavailable)  : {results['skip_unavailable']}")
    print(f"  SKIP (prev failed)  : {results['skip_failed']}")
    print(f"  SKIP (no hash)      : {results['skip_no_hash']}")
    if results["updated"]:
        print(f"  UPDATED             : {results['updated']}")
    print("-" * 60)

    fail_total = results["fail_missing_file"] + results["fail_hash_mismatch"]
    if fail_total == 0 and total_checked > 0:
        print(f"  RESULT: ALL {total_checked} CHECKED FILES PASSED ✓")
        return True
    elif total_checked == 0:
        print("  RESULT: No files to verify (all skipped or filtered).")
        return True
    else:
        print(f"  RESULT: {fail_total} FAILURE(S) — investigate before proceeding")
        return False


# ── Argument parser ────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_checksums.py",
        description="Embedded Firmware Research Lab — SHA256 manifest verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Verify all entries:
    python scripts/verify_checksums.py

  Verbose output (show all PASS entries):
    python scripts/verify_checksums.py --verbose

  Verify only TV firmware:
    python scripts/verify_checksums.py --category tv

  Verify only Samsung entries:
    python scripts/verify_checksums.py --brand samsung

  Re-hash files with missing SHA256:
    python scripts/verify_checksums.py --update-missing
        """,
    )
    parser.add_argument("--category", choices=["tv", "cctv", "router", "os"], help="Filter by category")
    parser.add_argument("--brand", help="Filter by brand (partial match)")
    parser.add_argument("--verbose", action="store_true", help="Show PASS lines as well as FAIL")
    parser.add_argument(
        "--update-missing",
        action="store_true",
        help="Compute and store SHA256 for manifest entries missing a hash",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print(f"[verify] Reading manifest: {MANIFEST_FILE}")
    ok = verify(
        category_filter=args.category,
        brand_filter=args.brand,
        verbose=args.verbose,
        update_missing=args.update_missing,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
