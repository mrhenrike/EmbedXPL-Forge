"""Trickest CVE Repository Reference Module.

Pointer to the trickest/cve submodule (github.com/trickest/cve).
Does not embed exploit code — provides lookups and integration hooks.

Original repository
-------------------
trickest/cve : https://github.com/trickest/cve
License      : CC0 1.0 Universal (Public Domain)
Description  : Automatically generated, daily-updated repository of CVE
               PoC files aggregated from hundreds of GitHub repositories.

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from embedxpl.core.exploit import *


_TRICKEST_ENV = "TRICKEST_CVE_PATH"
_DEFAULT_PATHS = (
    Path("d:/Projetos-SafeLabs/submodules/labs/trickest-cve"),
    Path("d:/Projetos-SafeLabs/submodules/trickest-cve"),
    Path.home() / "trickest-cve",
)


def _find_trickest() -> Optional[Path]:
    env = os.environ.get(_TRICKEST_ENV)
    if env:
        p = Path(env)
        if p.exists():
            return p
    for p in _DEFAULT_PATHS:
        if p.exists():
            return p
    return None


def search_trickest(cve_id: str, base: Optional[Path] = None) -> Optional[Path]:
    """Return path to trickest/cve markdown file for a CVE ID."""
    root = base or _find_trickest()
    if not root:
        return None
    import re
    year_match = re.match(r"CVE-(\d{4})-", cve_id.upper())
    if not year_match:
        return None
    year = year_match.group(1)
    candidate = root / year / f"{cve_id.upper()}.md"
    return candidate if candidate.exists() else None


class Exploit(Exploit):
    """Trickest CVE Repository Reference (pointer + CVE markdown lookup)."""

    __info__ = {
        "name": "Trickest CVE Reference (trickest/cve submodule pointer)",
        "description": (
            "Lookup CVE markdown files in a locally cloned trickest/cve repository. "
            "trickest/cve contains daily-updated aggregated PoC links for thousands of CVEs. "
            "Clone: git clone https://github.com/trickest/cve.git"
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # Data source: trickest/cve (CC0 1.0)
        ),
        "references": ("https://github.com/trickest/cve",),
        "devices": ("Intelligence gathering — any CVE",),
    }

    cve_id = OptString("CVE-2024-12345", "CVE ID to look up in trickest/cve")

    @mute
    def check(self) -> bool:
        return _find_trickest() is not None

    def run(self) -> None:
        cve = str(self.cve_id).upper().strip()
        root = _find_trickest()

        print_status(f"Trickest CVE lookup — {cve}")
        if not root:
            print_error("trickest/cve not found locally")
            print_info("Clone: git clone https://github.com/trickest/cve.git")
            print_info(f"Then set env: {_TRICKEST_ENV}=<path>")
            return

        print_info(f"trickest/cve path: {root}")
        md_path = search_trickest(cve, root)
        if md_path:
            print_success(f"Found: {md_path}")
            print_info(md_path.read_text(encoding="utf-8", errors="replace")[:1024])
        else:
            print_info(f"No trickest entry for {cve}")
