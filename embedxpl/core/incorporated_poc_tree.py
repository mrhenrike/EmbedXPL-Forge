# Author: André Henrique (@mrhenrike) | União Geek
"""Resolve paths into the mirrored ``incorporated_third_party`` PoC tree."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_ROUTERXPL_PKG = Path(__file__).resolve().parent.parent
_DEFAULT_ROOT = (
    _ROUTERXPL_PKG / "resources" / "arsenal" / "pocs" / "incorporated_third_party"
)


def incorporated_poc_root(*, must_exist: bool = False) -> Path:
    """Root directory containing one subfolder per upstream slug (see incorporated_third_party_index.json)."""

    env = os.environ.get("ROUTERXPL_INCORPORATED_POC_ROOT", "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if p.is_dir():
            return p
    root = _DEFAULT_ROOT.resolve()
    if must_exist and not root.is_dir():
        raise FileNotFoundError("incorporated_third_party tree missing: %s" % root)
    return root


def path_for_slug(slug: str) -> Optional[Path]:
    """Return ``<root>/<slug>`` if present."""

    root = incorporated_poc_root()
    cand = (root / slug.strip()).resolve()
    if not cand.is_dir():
        return None
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand
