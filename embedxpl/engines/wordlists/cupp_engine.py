"""
embedxpl.engines.wordlists/cupp_engine.py - CUPP/BEWGor Profile-Based Password Generator.

Generates password candidates from a structured user profile using the
CUPP (Common User Passwords Profiler) algorithm.

Native Python reimplementation of:
  - submodules/Wordlists/cupp/cupp.py (komb, make_leet, concats)
  - submodules/Wordlists/BEWGor/BEWGor.py (extended rules)

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

__version__ = "1.0.0"

# Default leet map (configurable via CuppProfile.leet_map)
_DEFAULT_LEET: Dict[str, str] = {
    "a": "4", "i": "1", "e": "3", "t": "7",
    "o": "0", "s": "5", "g": "9", "z": "2",
}

# Default special chars appended in combinations
_DEFAULT_SPECIALS = ["", "!", "@", "#", ".", "*", "_", "-", "?"]

# Number suffixes for concats
_DEFAULT_NUMS_START = 0
_DEFAULT_NUMS_STOP = 100


def make_leet(word: str, leet_map: Optional[Dict[str, str]] = None) -> str:
    """Apply leet substitutions to a word.

    Args:
        word: Input string.
        leet_map: Substitution dict. Defaults to _DEFAULT_LEET.

    Returns:
        Word with leet characters substituted.
    """
    lm = leet_map or _DEFAULT_LEET
    result = word.lower()
    for orig, repl in lm.items():
        result = result.replace(orig, repl)
    return result


def concats(seq: List[str], start: int, stop: int) -> Generator[str, None, None]:
    """Append numbers in range [start, stop) to each word.

    Args:
        seq: Input word list.
        start: Range start (inclusive).
        stop: Range stop (exclusive).

    Yields:
        word + str(num) for each word and num.
    """
    for word in seq:
        for num in range(start, stop):
            yield word + str(num)


def komb(
    seq: List[str],
    start: List[str],
    special: str = "",
) -> Generator[str, None, None]:
    """Generate cartesian product combinations: seq x start with optional separator.

    Args:
        seq: Primary word list.
        start: Secondary word list.
        special: Separator between words (default empty string).

    Yields:
        word1 + special + word2 for all pairs.
    """
    for w1 in seq:
        for w2 in start:
            yield w1 + special + w2


@dataclass
class CuppProfile:
    """User profile for CUPP-style password generation."""
    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    birth_date: str = ""        # DDMMYYYY format (no separators)
    partner_first: str = ""
    partner_last: str = ""
    partner_nick: str = ""
    partner_birth: str = ""
    child_name: str = ""
    child_birth: str = ""
    pet_name: str = ""
    company: str = ""
    extra_words: List[str] = field(default_factory=list)
    leet_map: Dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_LEET))
    specials: List[str] = field(default_factory=lambda: list(_DEFAULT_SPECIALS))
    num_start: int = _DEFAULT_NUMS_START
    num_stop: int = _DEFAULT_NUMS_STOP


class CuppEngine:
    """CUPP/BEWGor password generator.

    Generates target-specific password candidates from a structured profile.
    All algorithm logic is native Python - no cupp/BEWGor runtime dependency.

    Usage:
        engine = CuppEngine()
        profile = CuppProfile(first_name="Andre", birth_date="01011990")
        passwords = engine.generate(profile, max_output=50000)
    """

    def generate(
        self,
        profile: CuppProfile,
        max_output: int = 0,
        leet: bool = True,
    ) -> List[str]:
        """Generate password candidates from profile.

        Args:
            profile: User profile data.
            max_output: Maximum candidates to return (0 = all).
            leet: Include leet variants.

        Returns:
            Deduplicated list of password candidates.
        """
        # Collect base words
        base = []
        for val in [
            profile.first_name, profile.last_name, profile.nickname,
            profile.partner_first, profile.partner_last, profile.partner_nick,
            profile.child_name, profile.pet_name, profile.company,
        ]:
            if val.strip():
                v = val.strip()
                base.extend([v.lower(), v.capitalize(), v.upper()])

        base.extend(w.strip() for w in profile.extra_words if w.strip())

        # Birth dates
        dates = []
        for d in [profile.birth_date, profile.partner_birth, profile.child_birth]:
            if d and len(d) >= 4:
                dates.append(d)
                dates.append(d[:4])   # year only
                if len(d) >= 6:
                    dates.append(d[-4:])  # year as last 4 chars
                    dates.append(d[-2:])  # 2-digit year

        combined = base + dates
        seen = set()
        results = []

        def _add(val: str) -> None:
            v = val.strip()
            if 4 <= len(v) <= 32 and v not in seen:
                seen.add(v)
                results.append(v)

        # Standalone base words
        for w in combined:
            _add(w)

        # Base + specials
        for w in base:
            for s in profile.specials:
                _add(w + s)

        # Base + numbers (concats)
        for c in concats(base, profile.num_start, min(profile.num_stop, profile.num_start + 100)):
            _add(c)

        # komb: base x dates
        for combo in komb(base, dates):
            _add(combo)

        # komb: base x base (pairs with separator)
        for combo in komb(base[:8], base[:8]):
            _add(combo)

        # komb: base x special chars
        for combo in komb(base, profile.specials):
            _add(combo)

        # Leet variants
        if leet:
            for w in list(results[:200]):
                leet_w = make_leet(w, profile.leet_map)
                if leet_w != w:
                    _add(leet_w)

        if max_output > 0:
            return results[:max_output]
        return results
