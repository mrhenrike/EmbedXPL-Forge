#!/usr/bin/env python3
"""
intelbras_download.py — Intelbras firmware downloader for Embedded Firmware Research Lab
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Downloads Intelbras CCTV firmware from official portal and known CDN patterns.
Uses download_firmware.py primitives for actual download + manifest updates.

Usage:
    python scripts/intelbras_download.py --list
    python scripts/intelbras_download.py --download-all
    python scripts/intelbras_download.py --download-model "VIP 3230 B SD"
    python scripts/intelbras_download.py --download-url <url> --model "VIP 3230 B SD"
"""

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "catalog" / "firmware_sources.yaml"
MANIFEST_FILE = REPO_ROOT / "manifests" / "download_manifest.yaml"
DOWNLOADS_DIR = REPO_ROOT / "downloads" / "cctv" / "intelbras"
TMP_DIR = REPO_ROOT / ".tmp"
ENV_FILE = REPO_ROOT / ".env"

TMP_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP_DIR)
tempfile.tempdir = str(TMP_DIR)

PORTAL_BASE = "https://www.intelbras.com/pt-br"
DOWNLOAD_PAGE = f"{PORTAL_BASE}/ajuda-download/download"
FAQ_PAGE = f"{PORTAL_BASE}/ajuda-download/faq"
CDN_BASE = "https://backend.intelbras.com/sites/default/files"

MODEL_SLUG_MAP = {
    "PVIP 1000":       "camera-ip-videoporteiro-pvip-1000",
    "VIP 1130 D":      "camera-dome-compativel-com-a-tecnologia-poe-vip-1130-d",
    "VIP S3020 G2":    "camera-ip-bullet-full-hd-vip-s3020-g2",
    "VIP 3230 B SD":   "camera-ip-full-hd-vip-3230-b",
    "VIP 3330 B":      "camera-ip-bullet-vip-3330-b",
    "VIP 5000 IA":     "camera-ip-inteligencia-artificial-vip-5000-ia",
    "VIP 1024 D G2":   "camera-dome-ip-hd-vip-1024-d-g2",
    "MHDX 1004-C":     "gravador-de-video-digital-multi-hd-mhdx-1004-c",
    "MHDX 1108-C":     "gravador-de-video-digital-multi-hd-mhdx-1108-c",
    "MHDX 3108":       "gravador-digital-de-video-mhdx-3108",
    "MHDX 1108 G3":    "gravador-de-video-digital-multi-hd-mhdx-1108-g3",
    "NVD 1208 P":      "gravador-digital-de-imagem-nvd-1208-p",
    "NVD 3316-P":      "gravador-digital-de-imagem-nvd-3316-p",
    "NVD 3332-P4":     "gravador-digital-de-imagem-nvd-3332-p4",
    "NVD 1432-P":      "gravador-digital-de-imagem-nvd-1432-p",
}


def load_env() -> dict:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def load_catalog_models() -> list[dict]:
    with open(CATALOG, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("intelbras", {}).get("target_models", [])


def load_manifest() -> dict:
    if not MANIFEST_FILE.exists():
        return {"downloads": []}
    with open(MANIFEST_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "downloads" not in data:
        data["downloads"] = []
    return data


def save_manifest(manifest: dict) -> None:
    MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        yaml.dump(manifest, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_model(model: str) -> str:
    return re.sub(r"[^\w\-.]", "_", model)


def build_filename(model: str, ext: str = ".zip") -> str:
    return f"intelbras_{sanitize_model(model)}_firmware{ext}"


def download_file(url: str, dest: Path, timeout: int = 300) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, 4):
        print(f"  [download] Attempt {attempt}/3: {url[:120]}")
        cmd = [
            "curl", "--location", "--retry", "2", "--retry-delay", "3",
            "--connect-timeout", "30", "--max-time", str(timeout),
            "--progress-bar", "--output", str(dest), url,
        ]
        try:
            result = subprocess.run(cmd, check=False, timeout=timeout + 30)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        if result.returncode == 0 and dest.exists():
            size = dest.stat().st_size
            if size < 1024:
                print(f"  [WARN] File too small ({size} bytes)")
                dest.unlink(missing_ok=True)
                continue
            with open(dest, "rb") as f:
                header = f.read(512)
            if any(sig in header for sig in [b"<!DOCTYPE", b"<html", b"<HTML"]):
                print("  [WARN] File is HTML page, not firmware")
                dest.unlink(missing_ok=True)
                continue
            return True
    return False


def append_manifest_entry(model: str, filepath: Path, url: str, status: str, reason: str = ""):
    manifest = load_manifest()
    fp_str = filepath.relative_to(REPO_ROOT).as_posix()
    manifest["downloads"] = [
        e for e in manifest["downloads"]
        if e.get("filepath") != fp_str
    ]
    entry = {
        "filename": filepath.name,
        "filepath": fp_str,
        "brand": "intelbras",
        "model": model,
        "category": "cctv",
        "source_url": url,
        "download_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
    }
    if status == "ok" and filepath.exists():
        entry["sha256"] = sha256_file(filepath)
        entry["size_bytes"] = filepath.stat().st_size
    if reason:
        entry["reason"] = reason
    manifest["downloads"].append(entry)
    save_manifest(manifest)
    return entry


def try_portal_download(model: str, slug: str) -> tuple[bool, str]:
    """Attempt to find and download firmware from the Intelbras portal.
    Returns (success, url_used)."""
    urls_to_try = []

    download_url = f"{DOWNLOAD_PAGE}/{slug}"
    faq_url = f"{FAQ_PAGE}/{slug}"
    urls_to_try.append(download_url)
    urls_to_try.append(faq_url)

    slug_variants = [slug]
    for suffix in ["-g2", "-g3", "-g4", "-c"]:
        if not slug.endswith(suffix):
            slug_variants.append(f"{slug}{suffix}")

    for sv in slug_variants:
        for base in [DOWNLOAD_PAGE, FAQ_PAGE]:
            candidate = f"{base}/{sv}"
            if candidate not in urls_to_try:
                urls_to_try.append(candidate)

    filename = build_filename(model)
    dest = DOWNLOADS_DIR / filename

    for page_url in urls_to_try:
        print(f"  [probe] Trying page: {page_url}")
        tmp_html = TMP_DIR / f"intelbras_page_{sanitize_model(model)}.html"
        cmd = [
            "curl", "--location", "--silent", "--max-time", "30",
            "--output", str(tmp_html), page_url,
        ]
        try:
            result = subprocess.run(cmd, check=False, timeout=40)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        if result.returncode != 0 or not tmp_html.exists():
            continue

        html = tmp_html.read_text(encoding="utf-8", errors="replace")
        tmp_html.unlink(missing_ok=True)

        fw_urls = re.findall(
            r'href=["\']?(https?://backend\.intelbras\.com/[^"\'>\s]+\.zip)["\']?',
            html, re.IGNORECASE
        )
        if not fw_urls:
            fw_urls = re.findall(
                r'href=["\']?(https?://[^"\'>\s]+(?:firmware|fw|atualizacao)[^"\'>\s]*\.zip)["\']?',
                html, re.IGNORECASE
            )

        if fw_urls:
            fw_url = fw_urls[-1]
            print(f"  [found] Firmware URL: {fw_url}")
            if download_file(fw_url, dest):
                return True, fw_url

    return False, ""


def download_direct(model: str, url: str) -> bool:
    filename = build_filename(model)
    dest = DOWNLOADS_DIR / filename
    if dest.exists():
        print(f"  [skip] Already exists: {dest.name}")
        return True
    if download_file(url, dest):
        entry = append_manifest_entry(model, dest, url, "ok")
        print(f"  [OK] {dest.name} — {entry.get('size_bytes', 0):,} bytes")
        return True
    else:
        append_manifest_entry(model, dest, url, "failed", "download failed")
        return False


def download_model(model: str) -> bool:
    slug = MODEL_SLUG_MAP.get(model)
    if not slug:
        print(f"  [ERROR] No slug mapping for model: {model}")
        return False

    filename = build_filename(model)
    dest = DOWNLOADS_DIR / filename
    if dest.exists():
        size = dest.stat().st_size
        if size > 1024:
            print(f"  [skip] Already exists: {dest.name} ({size:,} bytes)")
            return True

    print(f"\n{'='*70}")
    print(f"  Model: {model}")
    print(f"  Slug:  {slug}")
    print(f"{'='*70}")

    success, url_used = try_portal_download(model, slug)

    if success:
        entry = append_manifest_entry(model, dest, url_used, "ok")
        print(f"  [OK] Downloaded: {dest.name}")
        print(f"       SHA256: {entry.get('sha256', 'N/A')}")
        print(f"       Size:   {entry.get('size_bytes', 0):,} bytes")
        return True
    else:
        page_url = f"{DOWNLOAD_PAGE}/{slug}"
        append_manifest_entry(
            model, dest, page_url, "pending_manual_download",
            "Portal requires JS rendering or direct link not found in HTML; "
            "manual download via browser required"
        )
        print(f"  [PENDING] {model} — needs manual download via browser")
        return False


def cmd_list():
    models = load_catalog_models()
    print(f"\nIntelbras target models ({len(models)} total):\n")
    print(f"{'Model':<20} {'Year':<6} {'Subcategory':<12} {'Platform':<24} {'Slug mapped'}")
    print("-" * 90)
    for m in models:
        name = m["model"]
        has_slug = "YES" if name in MODEL_SLUG_MAP else "NO"
        print(f"{name:<20} {m.get('year','?'):<6} {m.get('subcategory','?'):<12} {m.get('platform_estimate','TBD'):<24} {has_slug}")


def cmd_download_all():
    models = load_catalog_models()
    results = {"ok": [], "pending": [], "failed": []}

    for m in models:
        name = m["model"]
        success = download_model(name)
        if success:
            results["ok"].append(name)
        else:
            results["pending"].append(name)

    print(f"\n{'='*70}")
    print("DOWNLOAD SUMMARY")
    print(f"{'='*70}")
    print(f"  Downloaded:  {len(results['ok'])}")
    print(f"  Pending:     {len(results['pending'])}")
    if results["ok"]:
        print(f"\n  OK: {', '.join(results['ok'])}")
    if results["pending"]:
        print(f"\n  PENDING (manual): {', '.join(results['pending'])}")


def main():
    parser = argparse.ArgumentParser(
        prog="intelbras_download.py",
        description="Intelbras CCTV firmware downloader",
    )
    parser.add_argument("--list", action="store_true", help="List target models")
    parser.add_argument("--download-all", action="store_true", help="Download all models")
    parser.add_argument("--download-model", help="Download specific model")
    parser.add_argument("--download-url", help="Direct URL for download")
    parser.add_argument("--model", help="Model name (with --download-url)")
    args = parser.parse_args()

    if args.list:
        cmd_list()
    elif args.download_all:
        cmd_download_all()
    elif args.download_model:
        download_model(args.download_model)
    elif args.download_url:
        if not args.model:
            parser.error("--download-url requires --model")
        download_direct(args.model, args.download_url)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
