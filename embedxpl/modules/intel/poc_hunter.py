"""POC-Hunter / PoC Finder — Multi-Source Public PoC Discovery.

Searches multiple sources for public PoC exploits related to a CVE or keyword:
  - GitHub Search API (via unauthenticated public search)
  - pocfinder.io (unofficial API wrapper)
  - Exploit-DB search
  - Fakechippies/POC-Hunter index
  - l0n3m4n/pocfinder
  - 4m3rr0r/poc-finder

Original tool references
------------------------
Fakechippies/POC-Hunter  : https://github.com/Fakechippies/POC-Hunter
l0n3m4n/pocfinder        : https://github.com/l0n3m4n/pocfinder
4m3rr0r/poc-finder       : https://github.com/4m3rr0r/poc-finder
ljmane/cvescope          : https://github.com/ljmane/cvescope
eavil666/cve-poc-mapper  : https://github.com/eavil666/cve-poc-mapper

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

from embedxpl.core.exploit import *


_USER_AGENT = "EmbedXPL/3.9-intel"


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get_text(url: str, timeout: float = 15) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            return resp.read(32768).decode("utf-8", errors="replace")
    except Exception:
        return ""


def search_github_api(query: str, timeout: float = 15) -> list[dict[str, Any]]:
    """Unauthenticated GitHub repository search (rate-limited to 10 req/min)."""
    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/repositories?q={encoded}&sort=stars&order=desc&per_page=10"
    text = _get_text(url, timeout)
    if not text:
        return []
    try:
        data = json.loads(text)
        return data.get("items", [])[:10]
    except Exception:
        return []


def search_exploitdb(keyword: str, timeout: float = 15) -> list[dict[str, Any]]:
    """Scrape Exploit-DB search results for keyword."""
    encoded = urllib.parse.quote(keyword)
    url = f"https://www.exploit-db.com/search?q={encoded}"
    text = _get_text(url, timeout)
    results = []
    # Find EDB IDs in the page (table rows with /exploits/<id>)
    for match in re.finditer(r"/exploits/(\d+)", text):
        edb_id = match.group(1)
        if not any(r.get("id") == edb_id for r in results):
            results.append({"id": edb_id, "url": f"https://www.exploit-db.com/exploits/{edb_id}"})
    return results[:10]


class Exploit(Exploit):
    """POC-Hunter — Multi-source public PoC discovery (GitHub + EDB + nomi-sec)."""

    __info__ = {
        "name": "POC-Hunter — Multi-Source Public PoC Discovery",
        "description": (
            "Searches GitHub, Exploit-DB, and nomi-sec for public PoC exploits "
            "matching a CVE ID or keyword. Aggregates results from multiple indices. "
            "Inspired by: Fakechippies/POC-Hunter, l0n3m4n/pocfinder, 4m3rr0r/poc-finder."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # Inspired by: Fakechippies, l0n3m4n, 4m3rr0r, eavil666, ljmane
        ),
        "references": (
            "https://github.com/Fakechippies/POC-Hunter",
            "https://github.com/l0n3m4n/pocfinder",
            "https://github.com/4m3rr0r/poc-finder",
        ),
        "devices": ("Intelligence gathering — any vulnerability keyword",),
    }

    query = OptString("CVE-2024-12345", "CVE ID or keyword to search")
    timeout = OptInteger(15, "HTTP timeout in seconds")

    @mute
    def check(self) -> bool:
        return True

    def run(self) -> None:
        query = str(self.query).strip()
        timeout = float(self.timeout)

        print_status(f"POC-Hunter lookup — {query}")

        # GitHub
        print_status("Searching GitHub API…")
        gh_results = search_github_api(query, timeout)
        if gh_results:
            for r in gh_results[:5]:
                print_success(f"  [GitHub ★{r.get('stargazers_count',0):>4}] {r.get('html_url','')} — {r.get('description','')[:60]}")
        else:
            print_info("  GitHub: no results (may be rate-limited)")

        # Exploit-DB
        print_status("Searching Exploit-DB…")
        edb_results = search_exploitdb(query, timeout)
        if edb_results:
            for r in edb_results[:5]:
                print_success(f"  [EDB-{r.get('id','')}] {r.get('url','')}")
        else:
            print_info("  Exploit-DB: no results")
