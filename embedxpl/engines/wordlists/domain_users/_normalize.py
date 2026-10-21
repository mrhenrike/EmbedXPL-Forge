"""Accent normalization and name parsing utilities."""
from __future__ import annotations

import re
import unicodedata as _ud


def _norm(text: str) -> str:
    """
    Normalize: strip accents via NFD decomposition, lowercase, strip whitespace.

    Correctly handles all Portuguese/Spanish accented characters including
    ç → c, ã → a, õ → o, é → e, ó → o, ú → u, etc.
    """
    nfd = _ud.normalize("NFD", text)
    stripped = "".join(c for c in nfd if _ud.category(c) != "Mn")
    return stripped.lower().strip()


def _clean(text: str) -> str:
    """Normalize and strip non-alphanumeric characters."""
    return re.sub(r"[^a-z0-9]", "", _norm(text))

# ── Name parsing ───────────────────────────────────────────────────────────────

def parse_full_name(full_name: str) -> dict:
    """
    Parse a full name string into structured components.

    Handles compound last names (da PessoaY, de CorpX, etc.) and
    Brazilian naming conventions.

    Args:
        full_name: Full name string (e.g., "PessoaX da PessoaY").

    Returns:
        Dict with keys:
          - first: First name
          - middle: List of middle names (may be empty)
          - last: Last name (last token, may include particles)
          - all_parts: All name parts as list
          - initials: String of first letters of each part
          - fi: First letter of first name
          - li: First letter of last name
    """
    # Portuguese/Brazilian name particles (prepositions) - not counted as names
    particles = {"da", "de", "do", "das", "dos", "di", "du", "van", "von", "del", "el", "la", "le"}

    raw_parts = [p.strip() for p in full_name.split() if p.strip()]
    if not raw_parts:
        return {
            "first": "", "middle": [], "last": "",
            "all_parts": [], "initials": "", "fi": "", "li": "",
        }

    # Filter out pure particles for building name parts
    name_parts = [p for p in raw_parts if p.lower() not in particles]

    if not name_parts:
        name_parts = raw_parts

    first = name_parts[0]
    last = name_parts[-1] if len(name_parts) > 1 else ""
    middle = name_parts[1:-1] if len(name_parts) > 2 else []

    # Build initials from all parts (including particles skipped)
    initials = "".join(p[0] for p in raw_parts if p)

    # Particle-inclusive last name: e.g. "da PessoaY" → "dapessoay", "de CorpX" → "decorpx"
    # Detected when particle(s) immediately precede the last name_part in raw_parts.
    last_idx_in_raw = None
    for i in range(len(raw_parts) - 1, -1, -1):
        if raw_parts[i].lower() not in particles:
            last_idx_in_raw = i
            break
    last_full = last  # default: same as last
    if last_idx_in_raw is not None and last_idx_in_raw > 0:
        preceding = raw_parts[last_idx_in_raw - 1]
        if preceding.lower() in particles:
            # Collect consecutive particles before last
            parts_before = []
            j = last_idx_in_raw - 1
            while j >= 0 and raw_parts[j].lower() in particles:
                parts_before.insert(0, raw_parts[j])
                j -= 1
            last_full = "".join(parts_before) + last

    return {
        "first": first,
        "middle": middle,
        "last": last,
        "last_full": last_full,        # particle-inclusive (e.g. "dasilva")
        "all_parts": name_parts,
        "raw_parts": raw_parts,
        "initials": initials,
        "fi": first[0] if first else "",
        "li": last[0] if last else "",
        "mi": middle[0][0] if middle else "",
    }

