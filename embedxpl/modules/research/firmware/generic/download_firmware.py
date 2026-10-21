#!/usr/bin/env python3
"""
download_firmware.py — Embedded Firmware Research Lab downloader
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

CLI wrapper for downloading firmware from sources registered in catalog/firmware_sources.yaml.
All downloads go to downloads/<category>/<brand>/ within this repository.
Temp files use .tmp/ (project-local — corporate EDR policy, no system temp dirs).

Usage:
    python scripts/download_firmware.py --list-sources
    python scripts/download_firmware.py --list-sources --brand samsung
    python scripts/download_firmware.py --brand samsung --model CU8000 --category tv --dry-run
    python scripts/download_firmware.py --url <url> --brand samsung --model CU8000 --category tv
    python scripts/download_firmware.py --brand openwrt --category router
"""

import argparse
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import yaml

# Ensure UTF-8 output on Windows consoles (avoids UnicodeEncodeError for → etc.)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Paths ──────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
SOURCES_YAML = CATALOG_DIR / "firmware_sources.yaml"
DOWNLOADS_DIR = REPO_ROOT / "downloads"
MANIFESTS_DIR = REPO_ROOT / "manifests"
MANIFEST_FILE = MANIFESTS_DIR / "download_manifest.yaml"
TMP_DIR = REPO_ROOT / ".tmp"

# Enforce project-local temp dir (no system temp)
TMP_DIR.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP_DIR)
tempfile.tempdir = str(TMP_DIR)

# ── YAML helpers ───────────────────────────────────────────────────────────────


def load_sources() -> dict:
    if not SOURCES_YAML.exists():
        print(f"[ERROR] Sources file not found: {SOURCES_YAML}", file=sys.stderr)
        sys.exit(1)
    with open(SOURCES_YAML, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_manifest() -> dict:
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    if not MANIFEST_FILE.exists():
        return {"downloads": []}
    with open(MANIFEST_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "downloads" not in data:
        data["downloads"] = []
    return data


def save_manifest(manifest: dict) -> None:
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ── SHA256 ─────────────────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Download validation ────────────────────────────────────────────────────────

_HTML_SIGNATURES = [b"<!DOCTYPE", b"<html", b"<HTML", b"Error 404", b"Access Denied"]


def validate_download(path: Path, min_size_bytes: int = 1024) -> tuple[bool, str]:
    """Return (ok, reason). Checks size and that file is not an HTML error page."""
    if not path.exists():
        return False, "file does not exist"
    size = path.stat().st_size
    if size < min_size_bytes:
        return False, f"file too small ({size} bytes), likely an error page"
    with open(path, "rb") as f:
        header = f.read(512)
    for sig in _HTML_SIGNATURES:
        if sig in header:
            return False, f"file looks like HTML (contains '{sig.decode(errors='replace')}')"
    return True, "ok"


# ── Downloader ─────────────────────────────────────────────────────────────────


def download_file(url: str, dest: Path, retries: int = 3, timeout: int = 300) -> bool:
    """Download url to dest using curl, with retry logic. Returns True on success."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, retries + 1):
        print(f"  [download] Attempt {attempt}/{retries}: {url}")
        cmd = [
            "curl",
            "--location",
            "--retry", "2",
            "--retry-delay", "3",
            "--connect-timeout", "30",
            "--max-time", str(timeout),
            "--progress-bar",
            "--output", str(dest),
            url,
        ]
        try:
            result = subprocess.run(
                cmd,
                check=False,
                timeout=timeout + 30,
            )
        except FileNotFoundError:
            # curl not found — try wget
            cmd = [
                "wget",
                "--tries=3",
                "--timeout=30",
                f"--output-document={dest}",
                url,
            ]
            try:
                result = subprocess.run(cmd, check=False, timeout=timeout + 30)
            except FileNotFoundError:
                print(
                    "  [ERROR] Neither curl nor wget found. "
                    "Install curl (https://curl.se) or wget and retry.",
                    file=sys.stderr,
                )
                return False
            except subprocess.TimeoutExpired:
                print(f"  [ERROR] wget timed out on attempt {attempt}", file=sys.stderr)
                continue
        except subprocess.TimeoutExpired:
            print(f"  [ERROR] Download timed out on attempt {attempt}", file=sys.stderr)
            continue

        if result.returncode == 0:
            ok, reason = validate_download(dest)
            if ok:
                return True
            print(f"  [WARN] Download validation failed: {reason}. Retrying...")
            dest.unlink(missing_ok=True)
        else:
            print(f"  [WARN] curl/wget returned code {result.returncode}. Retrying...")

    return False


# ── Manifest entry builder ─────────────────────────────────────────────────────


def build_manifest_entry(
    file_path: Path,
    brand: str,
    model: str,
    category: str,
    source_url: str,
    status: str = "ok",
    reason: str = "",
) -> dict:
    entry: dict = {
        "filename": file_path.name,
        "filepath": file_path.relative_to(REPO_ROOT).as_posix(),
        "brand": brand,
        "model": model,
        "category": category,
        "source_url": source_url,
        "download_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
    }
    if status == "ok" and file_path.exists():
        entry["sha256"] = sha256_file(file_path)
        entry["size_bytes"] = file_path.stat().st_size
    if reason:
        entry["reason"] = reason
    return entry


def append_manifest_entry(entry: dict) -> None:
    manifest = load_manifest()
    new_fp = entry.get("filepath", "")
    new_fn = entry.get("filename", "")
    # Deduplicate by filepath (unique, always set); fall back to filename if missing
    manifest["downloads"] = [
        e for e in manifest["downloads"]
        if (e.get("filepath") or e.get("filename")) != (new_fp or new_fn)
    ]
    manifest["downloads"].append(entry)
    save_manifest(manifest)


# ── CLI commands ───────────────────────────────────────────────────────────────


def cmd_status(brand_filter: str | None = None, category_filter: str | None = None) -> None:
    """Print a quick summary of the download manifest."""
    manifest = load_manifest()
    entries = manifest.get("downloads", [])
    if not entries:
        print("[status] Manifest is empty.")
        return

    total_size = 0
    by_status: dict[str, int] = {}
    rows = []
    for e in entries:
        cat = e.get("category", "")
        brand = e.get("brand", "")
        if category_filter and cat.lower() != category_filter.lower():
            continue
        if brand_filter and brand_filter.lower() not in brand.lower():
            continue
        st = e.get("status", "ok")
        by_status[st] = by_status.get(st, 0) + 1
        size = e.get("size_bytes", 0) or 0
        total_size += size
        rows.append((cat, brand, e.get("filename", ""), st, size))

    if not rows:
        print("[status] No entries match the given filters.")
        return

    print(f"\n{'Category':<8}  {'Brand':<14}  {'Filename':<55}  {'Status':<24}  {'Size':>10}")
    print("-" * 120)
    for cat, brand, fname, st, size in sorted(rows, key=lambda r: (r[0], r[1])):
        size_str = _human_size(size) if size else "-"
        print(f"{cat:<8}  {brand:<14}  {fname:<55}  {st:<24}  {size_str:>10}")

    print("-" * 120)
    print(f"\n  Total entries    : {len(rows)}")
    for st, count in sorted(by_status.items()):
        print(f"  {st:<24}: {count}")
    print(f"\n  On-disk size     : {_human_size(total_size)}")


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def cmd_list_sources(brand_filter: str | None) -> None:
    sources = load_sources()
    for key, entry in sources.items():
        if not isinstance(entry, dict):
            continue
        if brand_filter and brand_filter.lower() not in key.lower():
            continue
        label = entry.get("label", key)
        access = entry.get("access", "unknown")
        category = entry.get("download_category", "—")
        print(f"\n[{key}] {label}")
        print(f"  Category : {category}")
        print(f"  Access   : {access}")
        official = entry.get("official", {})
        if isinstance(official, dict) and "url" in official:
            print(f"  Official : {official['url']}")
            if "note" in official:
                print(f"             {official['note']}")
        for src in entry.get("community", []):
            print(f"  Community: {src['url']}")
            if "note" in src:
                print(f"             {src['note']}")
        fmt = entry.get("format", "")
        if fmt:
            print(f"  Format   : {fmt}")
        note = entry.get("note", "")
        if note and len(str(note)) < 200:
            print(f"  Note     : {note}")


def _resolve_filename_from_url(url: str, model: str, brand: str) -> str:
    """
    Extract a meaningful filename from a URL.
    Handles Samsung-style CDN URLs (ContentsFile.aspx?...VPath=...filename.zip)
    and other URLs where the path component is a generic server script.
    """
    parsed = urllib.parse.urlparse(url)
    path_name = Path(parsed.path).name

    # If the URL has a meaningful filename in its path (e.g. firmware.zip), use it
    # "Generic" server-side scripts that don't represent real filenames
    generic_stems = {"contentsfile", "downloadfile", "download", "get", "file", "getfile", "dl"}
    if path_name and "." in path_name and path_name.lower().split(".")[0] not in generic_stems:
        return path_name

    # Try extracting from query params — Samsung uses VPath=...%2Ffilename.zip
    params = urllib.parse.parse_qs(parsed.query)
    for key in ("VPath", "vpath", "filepath", "file", "name", "filename"):
        if key in params:
            encoded_path = params[key][0]
            decoded = urllib.parse.unquote(encoded_path)
            candidate = Path(decoded).name
            if candidate and "." in candidate:
                return candidate

    # Fall back: use brand_model as filename with .bin extension
    safe_model = re.sub(r"[^\w\-.]", "_", model)
    safe_brand = re.sub(r"[^\w\-.]", "_", brand)
    return f"{safe_brand}_{safe_model}.bin"


def cmd_download(
    brand: str,
    model: str,
    category: str,
    url: str | None,
    dry_run: bool,
    force: bool,
) -> None:
    sources = load_sources()

    # Find matching source entry
    brand_key = None
    for key in sources:
        if brand.lower() in key.lower():
            brand_key = key
            break

    if brand_key is None:
        print(f"[ERROR] Brand '{brand}' not found in {SOURCES_YAML.name}.", file=sys.stderr)
        print("       Use --list-sources to see available brands.", file=sys.stderr)
        sys.exit(1)

    source = sources[brand_key]

    # Resolve download URL
    if url:
        resolved_url = url
    else:
        # Try to derive URL from source entry
        official = source.get("official", {})
        if isinstance(official, dict) and "url" in official:
            resolved_url = official["url"]
        else:
            community = source.get("community", [])
            if community:
                resolved_url = community[0]["url"]
            else:
                print(
                    f"[ERROR] No URL available for brand '{brand}'. "
                    "Provide --url explicitly.",
                    file=sys.stderr,
                )
                sys.exit(1)

    # Derive filename from URL or model
    dest_filename = _resolve_filename_from_url(resolved_url, model, brand_key)

    dest_path = DOWNLOADS_DIR / category / brand_key / dest_filename

    print(f"[info] Brand    : {brand_key}")
    print(f"[info] Model    : {model}")
    print(f"[info] Category : {category}")
    print(f"[info] URL      : {resolved_url}")
    print(f"[info] Dest     : {dest_path}")

    if dry_run:
        print("[dry-run] No download performed.")
        return

    if dest_path.exists() and not force:
        print(f"[skip] File already exists: {dest_path}")
        print("       Use --force to re-download.")
        return

    print(f"[download] Starting download...")
    success = download_file(resolved_url, dest_path)

    if success:
        entry = build_manifest_entry(dest_path, brand_key, model, category, resolved_url, "ok")
        append_manifest_entry(entry)
        print(f"[OK] Downloaded: {dest_path.name}")
        print(f"     SHA256    : {entry['sha256']}")
        print(f"     Size      : {entry['size_bytes']:,} bytes")
        print(f"[manifest] Updated: {MANIFEST_FILE}")
    else:
        entry = build_manifest_entry(
            dest_path, brand_key, model, category, resolved_url,
            "failed", "download failed after retries"
        )
        append_manifest_entry(entry)
        print(f"[FAIL] Download failed for {brand}/{model}. Recorded in manifest as 'failed'.")
        sys.exit(2)


def cmd_download_direct(
    url: str,
    brand: str,
    model: str,
    category: str,
    dry_run: bool,
    force: bool,
) -> None:
    """Download from an explicit URL, no catalog lookup required."""
    dest_filename = _resolve_filename_from_url(url, model, brand)

    dest_path = DOWNLOADS_DIR / category / brand / dest_filename

    print(f"[info] Brand    : {brand}")
    print(f"[info] Model    : {model}")
    print(f"[info] Category : {category}")
    print(f"[info] URL      : {url}")
    print(f"[info] Dest     : {dest_path}")

    if dry_run:
        print("[dry-run] No download performed.")
        return

    if dest_path.exists() and not force:
        print(f"[skip] File already exists: {dest_path}")
        return

    success = download_file(url, dest_path)
    if success:
        entry = build_manifest_entry(dest_path, brand, model, category, url, "ok")
        append_manifest_entry(entry)
        print(f"[OK] Downloaded: {dest_path.name}")
        print(f"     SHA256    : {entry['sha256']}")
        print(f"     Size      : {entry['size_bytes']:,} bytes")
    else:
        entry = build_manifest_entry(
            dest_path, brand, model, category, url,
            "failed", "download failed after retries"
        )
        append_manifest_entry(entry)
        print(f"[FAIL] Download failed. Recorded in manifest.")
        sys.exit(2)


# ── Argument parser ────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="download_firmware.py",
        description="Embedded Firmware Research Lab — firmware downloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List all sources:
    python scripts/download_firmware.py --list-sources

  List sources for a specific brand:
    python scripts/download_firmware.py --list-sources --brand samsung

  Show manifest download status table:
    python scripts/download_firmware.py --status

  Dry-run (print URL, no download):
    python scripts/download_firmware.py --brand samsung --model CU8000 --category tv --dry-run

  Download from catalog source URL:
    python scripts/download_firmware.py --brand openwrt --model x86-64 --category router

  Download from explicit URL:
    python scripts/download_firmware.py --url https://example.com/fw.zip \\
        --brand samsung --model CU8000 --category tv

  Force re-download:
    python scripts/download_firmware.py --url https://example.com/fw.zip \\
        --brand samsung --model CU8000 --category tv --force
        """,
    )
    parser.add_argument("--list-sources", action="store_true", help="List firmware sources from catalog")
    parser.add_argument("--status", action="store_true", help="Show manifest download summary table")
    parser.add_argument("--brand", help="Brand key (e.g. samsung, lg, openwrt, hikvision)")
    parser.add_argument("--model", default="unknown", help="Model identifier (e.g. CU8000, DS-2CD2183G2-IS)")
    parser.add_argument("--category", choices=["tv", "cctv", "router", "os"], help="Device category")
    parser.add_argument("--url", help="Explicit download URL (overrides catalog URL)")
    parser.add_argument("--dry-run", action="store_true", help="Print download info without downloading")
    parser.add_argument("--force", action="store_true", help="Re-download even if file exists")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_sources:
        cmd_list_sources(args.brand)
        return

    if args.status:
        cmd_status(brand_filter=args.brand, category_filter=args.category)
        return

    if args.url and not args.brand:
        parser.error("--url requires --brand")
    if args.url and not args.category:
        parser.error("--url requires --category")

    if args.url:
        cmd_download_direct(
            url=args.url,
            brand=args.brand,
            model=args.model,
            category=args.category,
            dry_run=args.dry_run,
            force=args.force,
        )
        return

    if not args.brand:
        parser.error("--brand is required (or use --list-sources)")
    if not args.category:
        parser.error("--category is required")

    cmd_download(
        brand=args.brand,
        model=args.model,
        category=args.category,
        url=None,
        dry_run=args.dry_run,
        force=args.force,
    )


if __name__ == "__main__":
    main()
