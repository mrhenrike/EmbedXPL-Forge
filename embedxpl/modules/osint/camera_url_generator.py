"""Camera URL generator from the iSpy camera database.

Loads camera_db.json and generates stream URLs by substituting
placeholder tokens with runtime values.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations
import base64
import json
from dataclasses import dataclass
from pathlib import Path
from embedxpl.core.exploit import *

_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "camera_db.json"


@dataclass
class CameraURL:
    """Generated camera stream URL with metadata."""

    vendor: str
    model: str
    url_type: str
    protocol: str
    url: str
    default_port: int


class CameraURLGenerator:
    """Generates camera stream URLs from the iSpy camera database.

    Loads the local camera_db.json (built by build_camera_db.py) and
    substitutes placeholder tokens in URL templates.

    Supported tokens:
        [USERNAME]  - URL-encoded username
        [PASSWORD]  - URL-encoded password
        [AUTH]      - base64(username:password) for HTTP Basic
        [CHANNEL]   - channel number (default 1)
        [WIDTH]     - frame width (default 640)
        [HEIGHT]    - frame height (default 480)

    Example:
        gen = CameraURLGenerator()
        urls = gen.generate("192.168.1.10", "hikvision", "DS-2CD2T47G2",
                            "admin", "admin123")
    """

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize and load camera database.

        Args:
            db_path: Path to camera_db.json. Defaults to embedxpl/data/camera_db.json.

        Raises:
            FileNotFoundError: If the database file does not exist.
        """
        path = db_path or _DB_PATH
        if not path.exists():
            raise FileNotFoundError(
                f"Camera database not found at {path}. "
                "Run: python -m embedxpl.tools.build_camera_db"
            )
        with open(path, encoding="utf-8") as f:
            self._db: dict[str, list[dict]] = json.load(f)

    def generate(
        self,
        ip: str,
        vendor: str,
        model: str = "",
        username: str = "admin",
        password: str = "",
        channel: int = 1,
        width: int = 640,
        height: int = 480,
    ) -> list[CameraURL]:
        """Generate stream URLs for a camera.

        Args:
            ip: Camera IP address.
            vendor: Vendor slug (e.g. "hikvision", "dahua").
            model: Model name substring for filtering (empty = all models).
            username: Authentication username.
            password: Authentication password.
            channel: Channel number.
            width: Frame width.
            height: Frame height.

        Returns:
            List of CameraURL dataclass instances.
        """
        vendor_lower = vendor.lower()
        vendor_data = self._db.get(vendor_lower)
        if vendor_data is None:
            for k in self._db:
                if vendor_lower in k or k in vendor_lower:
                    vendor_data = self._db[k]
                    break

        if not vendor_data:
            return []

        cameras = vendor_data
        if model:
            model_lower = model.lower()
            cameras = [c for c in cameras if model_lower in c.get("model", "").lower()]

        auth_b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
        replacements = {
            "[USERNAME]": username,
            "[PASSWORD]": password,
            "[AUTH]": auth_b64,
            "[CHANNEL]": str(channel),
            "[WIDTH]": str(width),
            "[HEIGHT]": str(height),
            "ip_address": ip,
        }

        results: list[CameraURL] = []
        seen_urls: set[str] = set()

        for cam in cameras:
            template = cam.get("url_template", "")
            if not template:
                continue

            url = template
            for token, value in replacements.items():
                url = url.replace(token, value)

            port_str = cam.get("default_port", 80)
            url = url.replace("ip_address", ip)

            if url not in seen_urls:
                seen_urls.add(url)
                results.append(
                    CameraURL(
                        vendor=vendor,
                        model=cam.get("model", "Unknown"),
                        url_type=cam.get("type", ""),
                        protocol=cam.get("protocol", ""),
                        url=url,
                        default_port=int(port_str),
                    )
                )

        return results

    def list_vendors(self) -> list[str]:
        """Return sorted list of available vendor slugs.

        Returns:
            Alphabetically sorted list of vendor strings.
        """
        return sorted(self._db.keys())

    def search_model(self, model: str) -> list[tuple[str, str]]:
        """Search for a model across all vendors.

        Args:
            model: Model name substring to search for.

        Returns:
            List of (vendor, model_name) tuples for all matching entries.
        """
        model_lower = model.lower()
        results: list[tuple[str, str]] = []
        for vendor, cameras in self._db.items():
            for cam in cameras:
                if model_lower in cam.get("model", "").lower():
                    results.append((vendor, cam["model"]))
        return results


class Exploit(Exploit):
    """Camera URL Generator Interactive Module.

    Interactive module wrapping CameraURLGenerator for use within the
    EmbedXPL-Forge shell. Generates stream URLs for a target camera.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "Camera URL Generator from iSpy Database",
        "description": (
            "Generates camera stream URLs by loading the local iSpy camera database "
            "and substituting credential/address tokens in URL templates."
        ),
        "authors": (
            "iSpy/ispyconnect.com (database)",
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://www.ispyconnect.com/",
        ),
        "devices": (
            "Any camera in the iSpy database",
        ),
    }

    target = OptIP("", "Camera IPv4 address")
    vendor = OptString("", "Camera vendor (e.g. hikvision, dahua, axis)")
    model = OptString("", "Model name substring filter (empty = all models)")
    username = OptString("admin", "Camera username")
    password = OptString("", "Camera password")
    channel = OptInteger(1, "Channel number")

    def run(self) -> None:
        """Generate and display stream URLs for the target camera."""
        if not self.target or not self.vendor:
            print_error("Set both target (IP) and vendor options")
            return

        try:
            gen = CameraURLGenerator()
        except FileNotFoundError as exc:
            print_error(str(exc))
            return

        urls = gen.generate(
            ip=str(self.target),
            vendor=str(self.vendor),
            model=str(self.model) if self.model else "",
            username=str(self.username),
            password=str(self.password),
            channel=int(self.channel),
        )

        if urls:
            print_success(f"Generated {len(urls)} URL(s) for {self.vendor}")
            rows = [(u.model, u.url_type, u.url) for u in urls[:20]]
            print_table(("Model", "Type", "URL"), *rows)
        else:
            print_info(f"No URLs found for vendor '{self.vendor}' in the database")
            print_status("Available vendors: " + ", ".join(gen.list_vendors()[:20]))

    def check(self) -> bool:
        """Check if the database exists and the vendor is known."""
        if not _DB_PATH.exists():
            return False
        if not self.vendor:
            return False
        try:
            gen = CameraURLGenerator()
            return str(self.vendor).lower() in gen.list_vendors()
        except Exception:
            return False
