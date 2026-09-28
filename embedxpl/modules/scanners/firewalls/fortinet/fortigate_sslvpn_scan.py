"""Banner and CVE correlation scan for FortiGate SSL-VPN / management web UI."""

from __future__ import annotations

import re
from typing import List

from embedxpl.core.cve.cve_db import CVEDatabase
from embedxpl.core.exploit.option import OptBool, OptIP, OptPort
from embedxpl.core.exploit.printer import print_error, print_status, print_success
from embedxpl.core.http.http_client import HTTPClient

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek


class Exploit(HTTPClient):
    """Probe FortiGate-style SSL-VPN pages and correlate with local CVE catalog."""

    __info__ = {
        "name": "FortiGate SSL-VPN / Web CVE Correlation Scan",
        "description": (
            "Fetches common FortiOS SSL-VPN paths (/remote/login, etc.), extracts "
            "version hints when present, and lists matching CVEs from the embedded + "
            "extended FirewallXPL-Forge catalog (CVE-2018-13379, CVE-2022-40684, "
            "CVE-2023-27997, CVE-2024-21762, CVE-2025-59718, ...). "
            "Does not exploit — recon only."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "references": (
            "https://www.fortiguard.com/psirt",
            "https://nvd.nist.gov/ — Fortinet vendor search",
        ),
        "devices": (
            "Fortinet FortiGate / FortiOS SSL-VPN",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "HTTPS port (default 443)")
    ssl = OptBool(True, "Use HTTPS/TLS (FortiGate SSL-VPN default)")

    _PATHS = ("/remote/login", "/remote/error", "/")

    def run(self) -> None:
        """Execute HTTP probes and print CVE matches."""
        db = CVEDatabase()
        combined: str = ""
        for path in self._PATHS:
            response = self.http_request("GET", path)
            if response is None:
                continue
            snippet = (response.text or "")[:12000]
            combined += "\n" + snippet
            if response.status_code:
                print_status("{} -> HTTP {}".format(path, response.status_code))

        if not combined.strip():
            print_error("No HTTP response from target (check ssl/port/firewall).")
            return

        lower = combined.lower()
        if "forti" not in lower and "fortigate" not in lower:
            print_status("No obvious Fortinet/FortiOS banner in first responses (may still be FortiGate).")

        version_guess = self._extract_fortios_version(combined)
        if version_guess:
            print_success("Possible FortiOS build string: {}".format(version_guess))

        cves = db.lookup(vendor="fortinet", product="fortigate", version=version_guess or "", banner=combined)
        if not cves:
            cves = db.lookup_by_banner(combined, remote_only=False)

        fortinets: List = [e for e in cves if e.vendor.lower() == "fortinet"]
        if fortinets:
            cves = fortinets

        print_success("CVE matches (Fortinet-focused, sorted by CVSS): {}".format(len(cves)))
        for entry in cves[:40]:
            mod = entry.rxf_module or "—"
            print_status(
                "{} | {} | {} | {} | rxf: {}".format(
                    entry.cve_id,
                    entry.cvss_score,
                    entry.access_vector,
                    entry.status_label,
                    mod,
                )
            )
        if len(cves) > 40:
            print_status("... {} more (use generic/cve/cve_lookup)".format(len(cves) - 40))

    @staticmethod
    def _extract_fortios_version(text: str) -> str:
        """Best-effort FortiOS version from HTML/JS banners."""
        patterns = (
            r"FortiOS\s*v?([0-9]+\.[0-9]+\.[0-9]+(?:\s*build\s*[0-9]+)?)",
            r"fortios\s*=\s*[\"'\s]*([0-9]+\.[0-9]+\.[0-9]+)",
            r"\"version\"\s*:\s*\"([0-9]+\.[0-9]+\.[0-9]+)\"",
        )
        for pat in patterns:
            match = re.search(pat, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""
