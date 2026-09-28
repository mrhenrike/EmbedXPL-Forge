"""One-time extraction script for iSpy camera database.

Fetches camera URL templates from iSpy/ispyconnect.com and saves them
to embedxpl/data/camera_db.json for offline use by CameraURLGenerator.

Usage:
    python -m embedxpl.tools.build_camera_db

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations
import json
import re
import sys
import time
from pathlib import Path

import requests

_OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "camera_db.json"
_ISPY_BASE = "https://www.ispyconnect.com"
_CAMERAS_URL = f"{_ISPY_BASE}/cameras"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def fetch_vendor_list(session: requests.Session) -> list[str]:
    """Fetch the list of camera vendors from iSpy.

    Args:
        session: Requests session to use.

    Returns:
        List of vendor slug strings.
    """
    resp = session.get(_CAMERAS_URL, headers=_HEADERS, timeout=20)
    resp.raise_for_status()
    vendors = re.findall(r'/camera/([a-z0-9_-]+)(?:"|\s)', resp.text, re.IGNORECASE)
    return list(dict.fromkeys(vendors))


def fetch_vendor_cameras(session: requests.Session, vendor: str) -> list[dict]:
    """Fetch camera entries for a specific vendor.

    Args:
        session: Requests session to use.
        vendor: Vendor slug string.

    Returns:
        List of camera dicts with model, type, protocol, url_template, port.
    """
    url = f"{_ISPY_BASE}/camera/{vendor}"
    try:
        resp = session.get(url, headers=_HEADERS, timeout=20)
        if resp.status_code != 200:
            return []
    except Exception:
        return []

    html = resp.text
    cameras: list[dict] = []

    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
    for row in rows:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
        if len(cells) < 3:
            continue
        model = re.sub(r'<[^>]+>', '', cells[0]).strip()
        cam_type = re.sub(r'<[^>]+>', '', cells[1]).strip() if len(cells) > 1 else ""
        url_template = re.sub(r'<[^>]+>', '', cells[2]).strip() if len(cells) > 2 else ""
        if not model or not url_template:
            continue

        protocol = "rtsp" if url_template.startswith("rtsp://") else "http"
        port_m = re.search(r':(\d{2,5})/', url_template)
        default_port = int(port_m.group(1)) if port_m else (554 if protocol == "rtsp" else 80)

        cameras.append({
            "model": model,
            "type": cam_type,
            "protocol": protocol,
            "url_template": url_template,
            "default_port": default_port,
        })

    return cameras


def build_db() -> dict:
    """Build the complete camera database from iSpy.

    Returns:
        Dict mapping vendor slugs to lists of camera entry dicts.
    """
    session = requests.Session()
    db: dict[str, list[dict]] = {}

    print("Fetching vendor list...")
    try:
        vendors = fetch_vendor_list(session)
    except Exception as exc:
        print(f"ERROR fetching vendor list: {exc}")
        return db

    print(f"Found {len(vendors)} vendors. Fetching camera data...")
    for i, vendor in enumerate(vendors, 1):
        print(f"  [{i}/{len(vendors)}] {vendor}...", end=" ", flush=True)
        cameras = fetch_vendor_cameras(session, vendor)
        if cameras:
            db[vendor] = cameras
            print(f"{len(cameras)} cameras")
        else:
            print("(none)")
        time.sleep(0.5)

    return db


def main() -> None:
    """Entry point for the build_camera_db script."""
    _OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    db = build_db()
    if not db:
        print("ERROR: No camera data collected. Check network connectivity.")
        sys.exit(1)

    total = sum(len(v) for v in db.values())
    print(f"\nCollected {len(db)} vendors, {total} camera models total.")

    with open(_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

    print(f"Database written to: {_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
