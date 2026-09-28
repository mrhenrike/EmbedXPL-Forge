"""
embedxpl.engines.wordlists/pattern_ranker.py - Password Pattern Ranker and Hashcat Mask Builder.

Analyzes a wordlist and ranks passwords by:
  1. Keyboard walk score (QWERTY / ABNT2 layout adjacency patterns)
  2. Hashcat mask frequency analysis (?l?u?d?s pattern distribution)
  3. PTBR month/day name detection

Native Python reimplementation from:
  - submodules/Wordlists/pipal/passpat.rb (keyboard walk scoring)
  - submodules/Wordlists/pipal/checkers_available/hashcat_mask_generator.rb
  - submodules/Wordlists/pipal/layouts/ptbr.rb (ABNT2 keyboard layout)
  - submodules/Wordlists/pipal/checkers_available/PTBR_date_checker.rb

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import collections
import re
from pathlib import Path
from typing import Dict, Generator, List, Optional, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Keyboard layout adjacency maps
# ---------------------------------------------------------------------------

# QWERTY US layout (row-based adjacency)
_QWERTY_ADJ: Dict[str, str] = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd", "g": "tyhbvf",
    "h": "yugnbg", "j": "uikmnh", "k": "iolmj", "l": "opk",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
    "1": "2q", "2": "13qw", "3": "24we", "4": "35er", "5": "46rt",
    "6": "57ty", "7": "68yu", "8": "79ui", "9": "80io", "0": "9p",
}

# ABNT2 Brazilian Portuguese keyboard (additional accented positions)
_ABNT2_ADJ: Dict[str, str] = dict(_QWERTY_ADJ)
_ABNT2_ADJ.update({
    "p": "ol;", ";": "lp/", "~": "`1", "cedilla": "l;",
    "/": ";.", ".": ",/", ",": "m.", "m": "nj,",
})

# PTBR month names (for detection)
_PTBR_MONTHS = [
    "janeiro", "fevereiro", "marco", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    "jan", "fev", "mar", "abr", "mai", "jun",
    "jul", "ago", "set", "out", "nov", "dez",
]

# Hashcat char-class codes
_MASK_MAP = {
    "?l": re.compile(r"^[a-z]$"),
    "?u": re.compile(r"^[A-Z]$"),
    "?d": re.compile(r"^[0-9]$"),
    "?s": re.compile(r"^[^a-zA-Z0-9]$"),
}


def _char_to_mask(c: str) -> str:
    """Return the Hashcat char class code for a single character."""
    for code, pattern in _MASK_MAP.items():
        if pattern.match(c):
            return code
    return "?a"


def build_hashcat_mask(password: str) -> str:
    """Convert a password to a Hashcat mask string.

    Example: "P@ssw0rd!" -> "?u?s?l?l?l?d?l?l?s"

    Args:
        password: Input password string.

    Returns:
        Hashcat mask string.
    """
    return "".join(_char_to_mask(c) for c in password)


def score_keyboard_walk(
    password: str,
    layout: str = "qwerty",
) -> float:
    """Score how much a password resembles a keyboard walk pattern.

    Lower score = more keyboard-like (easier to crack).
    1.0 = fully random, ~0.0 = pure keyboard walk.

    Args:
        password: Password to analyze.
        layout: "qwerty" or "abnt2".

    Returns:
        Float in [0.0, 1.0] where 0 = keyboard walk, 1 = random.
    """
    adj = _ABNT2_ADJ if layout == "abnt2" else _QWERTY_ADJ
    if len(password) < 2:
        return 1.0

    walk_pairs = 0
    total_pairs = len(password) - 1

    for i in range(total_pairs):
        a, b = password[i].lower(), password[i + 1].lower()
        if b in adj.get(a, ""):
            walk_pairs += 1

    walk_ratio = walk_pairs / total_pairs
    return 1.0 - walk_ratio  # invert: 0 = all walk, 1 = no walk


def detect_ptbr_month(password: str) -> Optional[str]:
    """Detect if password contains a PTBR month name.

    Returns the detected month name or None.
    """
    pwd_lower = password.lower()
    for month in _PTBR_MONTHS:
        if month in pwd_lower:
            return month
    return None


def analyze_wordlist(
    wordlist_path: str,
    max_lines: int = 500_000,
    layout: str = "qwerty",
) -> Dict:
    """Analyze a wordlist file and produce statistics.

    Args:
        wordlist_path: Path to wordlist file (one password per line).
        max_lines: Maximum lines to analyze.
        layout: Keyboard layout for walk scoring.

    Returns:
        Analysis dict with mask_counts, walk_scores, top_masks, ptbr_months.
    """
    mask_counts: Dict[str, int] = collections.Counter()
    walk_scores: List[float] = []
    ptbr_count = 0
    total = 0

    with open(wordlist_path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            pwd = line.rstrip("\n\r")
            if not pwd:
                continue
            total += 1
            mask = build_hashcat_mask(pwd)
            mask_counts[mask] += 1
            walk_scores.append(score_keyboard_walk(pwd, layout))
            if detect_ptbr_month(pwd):
                ptbr_count += 1

    top_masks = mask_counts.most_common(20)
    avg_walk = sum(walk_scores) / len(walk_scores) if walk_scores else 0.5

    return {
        "total_analyzed": total,
        "unique_masks": len(mask_counts),
        "top_masks": [(mask, count, round(count / total * 100, 1)) for mask, count in top_masks],
        "keyboard_walk_avg": round(avg_walk, 4),
        "keyboard_walk_pct": round((1 - avg_walk) * 100, 1),
        "ptbr_month_count": ptbr_count,
        "ptbr_month_pct": round(ptbr_count / total * 100, 1) if total else 0,
    }


def prioritize_by_walk(
    passwords: List[str],
    layout: str = "qwerty",
    threshold: float = 0.3,
) -> List[Tuple[str, float]]:
    """Return passwords sorted by keyboard-walk score (most walk-like first).

    Args:
        passwords: List of passwords to rank.
        layout: Keyboard layout.
        threshold: Only return passwords with walk_score <= threshold.

    Returns:
        List of (password, walk_score) tuples, most walk-like first.
    """
    scored = [(pwd, score_keyboard_walk(pwd, layout)) for pwd in passwords]
    # Filter to walk-like only and sort ascending (lower = more walk-like)
    walks = [(pwd, sc) for pwd, sc in scored if sc <= threshold]
    walks.sort(key=lambda t: t[1])
    return walks
