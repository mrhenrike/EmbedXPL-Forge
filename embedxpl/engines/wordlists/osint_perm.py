"""
embedxpl.engines.wordlists/osint_perm.py - OSINT Permutation Engine.

Generates target-aware password candidates from OSINT profile data:
  - Name, nickname, pet name permutations (lowercase, capitalized, reversed)
  - Dates: birth, anniversary, important events (dd-mm-yyyy, ddmmyyyy, etc.)
  - Phone numbers: extracted pattern from BR DDD prefix
  - Old passwords: leet transform variants
  - Combinations at multiple complexity levels

Native Python reimplementation of:
  - submodules/Wordlists/elpscrk/perm_classes.py (names_perm, dates_perm)
  - submodules/Wordlists/elpscrk/elpscrk.py (main_ganerator logic)

No external dependencies beyond Python stdlib.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, Generator, List, Optional

__version__ = "1.0.0"

# Leet substitution map
_LEET: Dict[str, str] = {
    "a": "4", "i": "1", "e": "3", "t": "7",
    "o": "0", "s": "5", "g": "9", "z": "2", "l": "1",
}

# Common password suffixes (preserved for backward compatibility)
_COMMON_SUFFIXES = [
    "", "1", "12", "123", "1234", "12345",
    "!", "@", "#", "01", "02",
    "2020", "2021", "2022", "2023", "2024", "2025",
]

# Special chars appended to indicate common patterns
_SPECIAL_CHARS = ["!", "@", "#", "$", "*", ".", "_", "-"]

_OWASP_CHARS: List[str] = [
    "!", "@", "#", "$", "%", "^", "&", "*",
    "(", ")", "-", "_", "+", "=", ".", ",", "?",
]

_BASIC_SPECIAL: List[str] = ["!", "@", "#", "$"]

_COMMON_YEARS: List[str] = ["2020", "2021", "2022", "2023", "2024", "2025"]


def _make_leet(word: str) -> List[str]:
    """Generate leet variations of a word (single-substitution only for speed)."""
    variants = [word]
    for orig, replacement in _LEET.items():
        if orig in word.lower():
            variants.append(word.lower().replace(orig, replacement))
    return variants


def _word_variants(word: str, level: int = 1) -> List[str]:
    """Generate case/leet variants of a word.

    Level 1: lower + capitalized
    Level 2: + upper + reversed + leet
    """
    variants = [word.lower(), word.capitalize()]
    if level >= 2:
        variants += [word.upper(), word[::-1].lower()]
        variants += _make_leet(word)
    return list(dict.fromkeys(variants))  # preserve order, deduplicate


def _date_variants(date_str: str) -> List[str]:
    """Generate common date format permutations from 'dd-mm-yyyy'."""
    try:
        parts = date_str.strip().split("-")
        if len(parts) != 3:
            return []
        day, month, year = parts[0], parts[1], parts[2]
        year2 = year[-2:]
        month2 = month.zfill(2)
        day2 = day.zfill(2)
    except Exception:
        return []

    return [
        f"{day}{month}{year}",
        f"{day2}{month2}{year}",
        f"{year}{month2}{day2}",
        f"{day2}{month2}{year2}",
        f"{year2}{month2}{day2}",
        day, month, year, year2,
        f"{month}{year}",
        f"{year}{month}",
    ]


@dataclass
class OsintProfile:
    """Target profile for OSINT-based password generation."""
    first_name: str = ""
    last_name: str = ""
    nickname: str = ""
    pet_name: str = ""
    partner_name: str = ""
    birth_date: str = ""          # Format: dd-mm-yyyy
    anniversary_date: str = ""    # Format: dd-mm-yyyy
    phone: str = ""               # Digits only
    old_passwords: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    level: int = 1
    complexity: int = field(default=0, repr=False)   # alias for level; 0 = unset
    years: List[str] = field(default_factory=list)
    nums_range: tuple = (0, 99)
    special_chars: List[str] = field(default_factory=list)
    apply_post_leet: bool = False

    def __post_init__(self) -> None:
        if self.complexity != 0 and self.level == 1:
            self.level = self.complexity
        self.complexity = self.level


def _recipes(
    level: int,
    years: List[str],
    nums_range: tuple,
    special_chars: List[str],
) -> List[str]:
    """Return suffix/append recipes based on generation level.

    Args:
        level: Generation level (0-5).
        years: Custom years to append at level >= 4.
        nums_range: (start, end) inclusive numeric range appended at level >= 2.
        special_chars: Extra special characters appended at level >= 2.

    Returns:
        Ordered, deduplicated list of suffix strings to append to candidates.
    """
    if level == 0:
        return []

    recipes: List[str] = ["", "1", "12", "123"] + _COMMON_YEARS

    if level >= 2:
        num_start, num_end = nums_range
        recipes += [str(n) for n in range(num_start, min(num_end + 1, num_start + 200))]
        for c in _BASIC_SPECIAL + special_chars:
            if c not in recipes:
                recipes.append(c)

    if level >= 3:
        for c in _OWASP_CHARS:
            if c not in recipes:
                recipes.append(c)

    if level >= 4:
        for y in years:
            if y not in recipes:
                recipes.append(y)

    return list(dict.fromkeys(recipes))


def post_leet_perm(candidates: List[str], max_per_word: int = 256) -> List[str]:
    """Apply global cartesian leet permutation over a candidate list.

    Calls leet_perm_wordlist from leet_permuter for a full elpscrk-style pass.

    Args:
        candidates: List of password candidates post-generation.
        max_per_word: Maximum product iterations per candidate word.

    Returns:
        Deduplicated list of all leet variants.
    """
    from embedxpl.engines.wordlists.leet_permuter import leet_perm_wordlist
    return list(leet_perm_wordlist(candidates, max_per_word=max_per_word))


class OsintPermGenerator:
    """Generate password candidates from OSINT profile data.

    Usage:
        profile = OsintProfile(first_name="Andre", birth_date="01-01-1990")
        gen = OsintPermGenerator()
        passwords = gen.generate(profile)
    """

    def generate(self, profile: OsintProfile) -> List[str]:
        """Generate all password candidates from profile.

        Args:
            profile: OSINT profile data.

        Returns:
            Deduplicated list of password candidates.
        """
        candidates = []
        level = profile.level

        suffixes = _recipes(level, profile.years, profile.nums_range, profile.special_chars)

        base_words = []
        for field_val in [
            profile.first_name, profile.last_name,
            profile.nickname, profile.pet_name, profile.partner_name,
        ]:
            if field_val.strip():
                base_words.append(field_val.strip())

        base_words.extend(k.strip() for k in profile.keywords if k.strip())

        all_word_variants: List[str] = []
        for word in base_words:
            all_word_variants.extend(_word_variants(word, level))

        candidates.extend(all_word_variants)

        for word in all_word_variants:
            for suf in suffixes:
                candidates.append(word + suf)

        for date_str in [profile.birth_date, profile.anniversary_date]:
            if date_str.strip():
                date_vars = _date_variants(date_str)
                candidates.extend(date_vars)
                for word in all_word_variants:
                    for dv in date_vars:
                        candidates.append(word + dv)
                        if level >= 2:
                            candidates.append(dv + word)

        if profile.phone:
            phone_digits = "".join(c for c in profile.phone if c.isdigit())
            if phone_digits:
                candidates.extend([
                    phone_digits,
                    phone_digits[-8:],
                    phone_digits[-9:],
                    phone_digits[:4],
                ])
                for word in all_word_variants[:5]:
                    candidates.append(word + phone_digits[-4:])

        for old_pwd in profile.old_passwords:
            if old_pwd.strip():
                candidates.extend(_make_leet(old_pwd))
                for suf in ["1", "2", "!", "2024", "2025"]:
                    candidates.append(old_pwd + suf)
                if level >= 2:
                    candidates += [old_pwd.upper(), old_pwd.lower(), old_pwd[::-1]]

        if level >= 2 and len(all_word_variants) > 1:
            for w1, w2 in itertools.combinations(all_word_variants[:6], 2):
                candidates.append(w1 + w2)
                candidates.append(w1 + "_" + w2)

        result: List[str] = []
        seen: set = set()
        for c in candidates:
            c = c.strip()
            if 4 <= len(c) <= 32 and c not in seen:
                seen.add(c)
                result.append(c)

        if profile.apply_post_leet:
            result = post_leet_perm(result, max_per_word=256)

        return result

    def generate_lazy(self, profile: OsintProfile) -> Generator[str, None, None]:
        """Lazy generator version for large profiles."""
        for pwd in self.generate(profile):
            yield pwd
