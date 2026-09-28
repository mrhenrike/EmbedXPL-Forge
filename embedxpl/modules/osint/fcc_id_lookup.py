"""FCC-ID lookup with multi-source fallback.

Retrieves device information from the FCC database using a multi-source
approach: fccid.io (primary), fcc.report (fallback 1), and FCC OpenData
API (fallback 2).

CLI: embedxpl fcc-id XXXXXX
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests
from embedxpl.core.exploit import *


@dataclass
class FCCDeviceProfile:
    """FCC device registration information."""

    fcc_id: str
    product_name: str = ""
    manufacturer: str = ""
    frequencies: list[str] = field(default_factory=list)
    documents: list[str] = field(default_factory=list)
    filing_date: str = ""
    applicant: str = ""
    equipment_class: str = ""
    source: str = ""


_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class Exploit(Exploit):
    """FCC-ID Multi-Source Device Lookup.

    Retrieves device information by FCC ID using a cascade of sources:
    1. fccid.io (HTML parsing)
    2. fcc.report (HTML parsing)
    3. FCC OpenData API (data.fcc.gov)

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    """

    __info__ = {
        "name": "FCC-ID Multi-Source Device Lookup",
        "description": (
            "Retrieves manufacturer, product name, frequencies, documents, and "
            "filing date for a device from the FCC ID database using multiple "
            "sources with automatic fallback."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
        ),
        "references": (
            "https://fccid.io/",
            "https://fcc.report/",
            "https://data.fcc.gov/api/",
        ),
        "devices": (
            "Any FCC-certified wireless device",
        ),
    }

    fcc_id = OptString("", "FCC ID to look up (e.g. PD9HG8245H)")

    def run(self) -> None:
        """Look up the FCC ID and display device information."""
        fcc_id = (self.fcc_id or "").strip().upper()
        if not fcc_id:
            print_error("Set fcc_id to the FCC ID to look up (e.g. PD9HG8245H)")
            return

        profile = self._lookup(fcc_id)
        if profile:
            print_success(f"FCC ID found: {fcc_id} (via {profile.source})")
            rows = [
                ("FCC ID", profile.fcc_id),
                ("Product Name", profile.product_name or "(unknown)"),
                ("Manufacturer", profile.manufacturer or "(unknown)"),
                ("Applicant", profile.applicant or "(unknown)"),
                ("Equipment Class", profile.equipment_class or "(unknown)"),
                ("Filing Date", profile.filing_date or "(unknown)"),
                ("Frequencies", ", ".join(profile.frequencies) or "(none)"),
            ]
            print_table(("Field", "Value"), *rows)
            if profile.documents:
                print_status(f"Documents ({len(profile.documents)}):")
                for doc in profile.documents[:10]:
                    print_info(f"  {doc}")
        else:
            print_error(f"FCC ID not found: {fcc_id}")

    def check(self) -> bool:
        """Validate that the fcc_id option is set and non-empty."""
        fcc_id = (self.fcc_id or "").strip()
        return bool(fcc_id) and len(fcc_id) >= 3

    def _lookup(self, fcc_id: str) -> FCCDeviceProfile | None:
        """Perform multi-source FCC ID lookup with automatic fallback.

        Args:
            fcc_id: Uppercase FCC ID string.

        Returns:
            FCCDeviceProfile if found in any source, else None.
        """
        for method in (self._lookup_fccid_io, self._lookup_fcc_report, self._lookup_opendata_api):
            try:
                result = method(fcc_id)
                if result:
                    return result
            except Exception:
                pass
            time.sleep(0.3)
        return None

    def _lookup_fccid_io(self, fcc_id: str) -> FCCDeviceProfile | None:
        """Query fccid.io for device information.

        Args:
            fcc_id: FCC ID string.

        Returns:
            FCCDeviceProfile or None.
        """
        url = f"https://fccid.io/{fcc_id}"
        resp = requests.get(url, headers=_HEADERS, timeout=10)
        if resp.status_code != 200:
            return None

        html = resp.text
        profile = FCCDeviceProfile(fcc_id=fcc_id, source="fccid.io")

        name_m = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
        if name_m:
            profile.product_name = name_m.group(1).strip()

        mfr_m = re.search(
            r'(?:manufacturer|company)\s*:?\s*</[^>]+>\s*<[^>]+>([^<]+)',
            html, re.IGNORECASE,
        )
        if mfr_m:
            profile.manufacturer = mfr_m.group(1).strip()

        freq_matches = re.findall(r'(\d+\.?\d*\s*MHz|\d+\.?\d*\s*GHz)', html)
        profile.frequencies = list(dict.fromkeys(freq_matches))[:10]

        doc_urls = re.findall(
            r'href="(/[^"]+\.pdf)"', html, re.IGNORECASE
        )
        profile.documents = [f"https://fccid.io{u}" for u in doc_urls[:20]]

        date_m = re.search(
            r'(?:filing|approval|date)[^:]*:\s*([A-Z][a-z]+ \d{1,2},? \d{4}|\d{4}-\d{2}-\d{2})',
            html, re.IGNORECASE,
        )
        if date_m:
            profile.filing_date = date_m.group(1)

        return profile if profile.product_name or profile.manufacturer else None

    def _lookup_fcc_report(self, fcc_id: str) -> FCCDeviceProfile | None:
        """Query fcc.report for device information.

        Args:
            fcc_id: FCC ID string.

        Returns:
            FCCDeviceProfile or None.
        """
        url = f"https://fcc.report/FCC-ID/{fcc_id}"
        resp = requests.get(url, headers=_HEADERS, timeout=10)
        if resp.status_code != 200:
            return None

        html = resp.text
        if "not found" in html.lower() or "no results" in html.lower():
            return None

        profile = FCCDeviceProfile(fcc_id=fcc_id, source="fcc.report")

        name_m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        if name_m:
            title = name_m.group(1).strip()
            if fcc_id.lower() not in title.lower() and "fcc" not in title.lower():
                profile.product_name = title

        doc_urls = re.findall(r'href="(/FCC-ID/[^"]+\.pdf)"', html, re.IGNORECASE)
        profile.documents = [f"https://fcc.report{u}" for u in doc_urls[:20]]

        return profile if profile.documents or profile.product_name else None

    def _lookup_opendata_api(self, fcc_id: str) -> FCCDeviceProfile | None:
        """Query FCC OpenData API for device information.

        Args:
            fcc_id: FCC ID string.

        Returns:
            FCCDeviceProfile or None.
        """
        url = (
            f"https://data.fcc.gov/api/license-view/basicSearch/getLicenses"
            f"?searchValue={fcc_id}&format=json&limit=5"
        )
        resp = requests.get(url, headers=_HEADERS, timeout=10)
        if resp.status_code != 200:
            return None

        try:
            data: Any = resp.json()
        except ValueError:
            return None

        licenses = data.get("Licenses", {}).get("License", [])
        if not licenses:
            return None

        if isinstance(licenses, dict):
            licenses = [licenses]

        lic = licenses[0]
        profile = FCCDeviceProfile(
            fcc_id=fcc_id,
            product_name=lic.get("licenseName", ""),
            manufacturer=lic.get("licenseeName", ""),
            applicant=lic.get("licenseeName", ""),
            filing_date=lic.get("lastActionDate", ""),
            source="FCC OpenData API",
        )
        return profile if (profile.product_name or profile.manufacturer) else None
