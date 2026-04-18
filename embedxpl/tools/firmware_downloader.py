# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Firmware Downloader CLI Wrapper — EmbedXPL-Forge.

Resolves vendor firmware sources from firmware_sources.yaml and downloads
firmware files from public portals or direct URLs.

Usage:
    python -m embedxpl.tools.firmware_downloader --vendor hikvision --model DS-2CD2143G2-I
    python -m embedxpl.tools.firmware_downloader --list
    python -m embedxpl.tools.firmware_downloader --vendor tplink --url <direct_url>

Version: 1.0.0
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import urlretrieve, Request
from urllib.error import URLError, HTTPError
import urllib.request

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("firmware_downloader")

_RESOURCES_DIR = Path(__file__).parent.parent / "resources"
_SOURCES_FILE = _RESOURCES_DIR / "firmware_sources.yaml"
_DEFAULT_OUTPUT_DIR = Path.cwd() / "firmware_downloads"


def load_sources() -> Dict[str, Any]:
    """Load firmware_sources.yaml.

    Returns:
        Dict mapping vendor keys to their metadata.

    Raises:
        FileNotFoundError: If firmware_sources.yaml cannot be found.
        yaml.YAMLError: If the YAML is malformed.
    """
    with open(_SOURCES_FILE, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data.get("vendors", {})


def list_vendors(sources: Dict[str, Any]) -> None:
    """Print all available vendor entries.

    Args:
        sources: Loaded vendor dictionary from firmware_sources.yaml.
    """
    log.info("Available firmware sources (%d vendors):", len(sources))
    for key, info in sources.items():
        login_flag = "[requires-login]" if info.get("requires_login") else ""
        print(
            "  {:20s} — {:15s} {} {}".format(
                key,
                info.get("category", "unknown"),
                info.get("name", ""),
                login_flag,
            )
        )


def resolve_vendor(sources: Dict[str, Any], vendor_key: str) -> Optional[Dict[str, Any]]:
    """Find a vendor entry by key (case-insensitive).

    Args:
        sources: Loaded vendor dictionary.
        vendor_key: Vendor identifier to look up.

    Returns:
        Vendor metadata dict, or None if not found.
    """
    return sources.get(vendor_key.lower())


def download_firmware(url: str, dest_dir: Path, filename: Optional[str] = None) -> Path:
    """Download a firmware file from a URL to disk.

    Args:
        url: Direct firmware download URL.
        dest_dir: Destination directory for the downloaded file.
        filename: Optional filename override; inferred from URL if omitted.

    Returns:
        Path to the downloaded file.

    Raises:
        URLError: On network failures.
        HTTPError: On HTTP error responses.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        filename = url.rstrip("/").split("/")[-1] or "firmware.bin"

    dest_path = dest_dir / filename

    log.info("Downloading: %s → %s", url, dest_path)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; EmbedXPL-Forge/2.0; firmware-downloader)"
        )
    }
    req = Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 65536
            with open(dest_path, "wb") as fout:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    fout.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        sys.stdout.write("\r  Progress: {}% ({}/{} bytes)".format(
                            pct, downloaded, total
                        ))
                        sys.stdout.flush()
        print()
        log.info("Download complete: %s (%d bytes)", dest_path, downloaded)
    except HTTPError as e:
        log.error("HTTP %s: %s", e.code, url)
        raise
    except URLError as e:
        log.error("URL error: %s", e.reason)
        raise

    return dest_path


def main() -> None:
    """Entry point for the firmware downloader CLI.

    Parses command-line arguments and dispatches to download or list actions.
    """
    parser = argparse.ArgumentParser(
        prog="firmware_downloader",
        description="EmbedXPL-Forge — Firmware Downloader CLI",
    )
    parser.add_argument("--list", action="store_true", help="List all known firmware sources")
    parser.add_argument("--vendor", type=str, help="Vendor key (e.g. hikvision, tplink)")
    parser.add_argument("--model", type=str, default="", help="Device model name (informational)")
    parser.add_argument("--url", type=str, default="", help="Direct firmware download URL")
    parser.add_argument(
        "--output", type=str, default=str(_DEFAULT_OUTPUT_DIR),
        help="Output directory for downloads (default: ./firmware_downloads)"
    )
    parser.add_argument("--filename", type=str, default="", help="Override output filename")

    args = parser.parse_args()

    try:
        sources = load_sources()
    except FileNotFoundError:
        log.error("firmware_sources.yaml not found at %s", _SOURCES_FILE)
        sys.exit(1)

    if args.list:
        list_vendors(sources)
        sys.exit(0)

    if not args.vendor and not args.url:
        parser.print_help()
        sys.exit(1)

    output_dir = Path(args.output)

    if args.url:
        download_firmware(
            url=args.url,
            dest_dir=output_dir,
            filename=args.filename or None,
        )
        return

    vendor_info = resolve_vendor(sources, args.vendor)
    if vendor_info is None:
        log.error("Unknown vendor: '%s'. Use --list to see available vendors.", args.vendor)
        sys.exit(1)

    log.info("Vendor: %s (%s)", vendor_info.get("name"), vendor_info.get("category"))
    log.info("Portal: %s", vendor_info.get("portal_url"))

    if vendor_info.get("requires_login"):
        log.warning(
            "This vendor requires portal login. Automatic download not supported. "
            "Visit: %s",
            vendor_info.get("portal_url")
        )
        if args.model:
            log.info("Model requested: %s", args.model)
        sys.exit(0)

    if args.model:
        log.info("Model: %s", args.model)
        log.info("Portal URL for manual download: %s", vendor_info.get("portal_url"))
        if vendor_info.get("notes"):
            log.info("Notes: %s", vendor_info["notes"])
    else:
        log.info("No model specified. Visit portal for direct links: %s", vendor_info.get("portal_url"))

    log.info("Use --url <direct_url> to download a specific firmware file.")


if __name__ == "__main__":
    main()
