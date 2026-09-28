"""CVE2PoC — GitHub PoC Lookup for CVEs.

Queries multiple public CVE-to-PoC index APIs (nomi-sec, trickest/cve,
CVE2PoC, BugBountyHunt, Vulhub) to find public exploit/PoC GitHub repositories
for a given CVE ID.

Original tool references
------------------------
nomi-sec/PoC-in-GitHub : https://github.com/nomi-sec/PoC-in-GitHub
trickest/cve           : https://github.com/trickest/cve
0liverFlow/CVE2PoC     : https://github.com/0liverFlow/CVE2PoC
ljmane/cvescope        : https://github.com/ljmane/cvescope
BugBountyHunt API      : https://www.bugbountyhunt.com/cve
labs.jamessawyer CVE API: https://labs.jamessawyer.co.uk/cves/

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.request
import urllib.error
from typing import Any, Optional

from embedxpl.core.exploit import *


_USER_AGENT = "EmbedXPL/3.9-intel"


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get_json(url: str, timeout: float = 15) -> Optional[Any]:
    """GET JSON from URL, returns parsed body or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            return json.loads(resp.read(32768))
    except Exception:
        return None


def lookup_nomi_sec(cve_id: str) -> list[dict]:
    """Query nomi-sec/PoC-in-GitHub raw index JSON."""
    year = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not year:
        return []
    y = year.group(1)
    num = cve_id.upper().split("-")[2]
    url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{y}/{cve_id.upper()}.json"
    data = _get_json(url)
    if isinstance(data, list):
        return data
    return []


def lookup_trickest(cve_id: str) -> list[str]:
    """Search trickest/cve index for PoC file links."""
    year = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not year:
        return []
    y = year.group(1)
    url = f"https://raw.githubusercontent.com/trickest/cve/main/{y}/{cve_id.upper()}.md"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as resp:
            text = resp.read(16384).decode("utf-8", errors="replace")
            links = re.findall(r"https://github\.com/[^\s\)\"]+", text)
            return links[:10]
    except Exception:
        return []


def lookup_bugbountyhunt(cve_id: str) -> list[str]:
    """Query BugBountyHunt CVE tracker API."""
    url = f"https://www.bugbountyhunt.com/cve/{cve_id.upper()}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=15) as resp:
            text = resp.read(16384).decode("utf-8", errors="replace")
            links = re.findall(r"https://github\.com/[^\s\"<>]+", text)
            return list(set(links))[:10]
    except Exception:
        return []


class Exploit(Exploit):
    """CVE2PoC — multi-source PoC/exploit repository lookup for a CVE ID."""

    __info__ = {
        "name": "CVE2PoC — GitHub PoC Lookup (nomi-sec + trickest + BugBountyHunt)",
        "description": (
            "Queries nomi-sec/PoC-in-GitHub, trickest/cve, and BugBountyHunt API "
            "to find public exploit/PoC GitHub repos for a CVE. "
            "Useful for intelligence gathering before EmbedXPL module development."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # Inspired by: nomi-sec, trickest, 0liverFlow, ljmane, BugBountyHunt
        ),
        "references": (
            "https://github.com/nomi-sec/PoC-in-GitHub",
            "https://github.com/trickest/cve",
            "https://www.bugbountyhunt.com/cve",
        ),
        "devices": ("Intelligence gathering — any CVE",),
    }

    cve_id = OptString("CVE-2024-12345", "CVE ID to look up")
    timeout = OptInteger(15, "HTTP timeout in seconds")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        cve = str(self.cve_id).upper().strip()
        timeout = float(self.timeout)

        print_status(f"CVE2PoC lookup — {cve}")

        # nomi-sec
        print_status("Querying nomi-sec/PoC-in-GitHub…")
        nomi = lookup_nomi_sec(cve)
        if nomi:
            for entry in nomi[:5]:
                html_url = entry.get("html_url", "")
                desc = entry.get("description", "")[:80]
                stars = entry.get("stargazers_count", 0)
                print_success(f"  [nomi-sec] ★{stars:>4} {html_url}  {desc}")
        else:
            print_info("  nomi-sec: no results")

        # trickest
        print_status("Querying trickest/cve…")
        tc = lookup_trickest(cve)
        if tc:
            for link in tc[:5]:
                print_success(f"  [trickest] {link}")
        else:
            print_info("  trickest: no results")

        # BugBountyHunt
        print_status("Querying BugBountyHunt…")
        bb = lookup_bugbountyhunt(cve)
        if bb:
            for link in bb[:5]:
                print_success(f"  [BugBountyHunt] {link}")
        else:
            print_info("  BugBountyHunt: no results")
