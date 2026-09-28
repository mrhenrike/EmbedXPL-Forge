"""iwlgen.py - Intelligence Wordlist Generator engine for WFH.

Native Python 3 port of the intelligence-wordlist-generator permutation
logic (original: Python 2 / ConfigParser / itertools). No dependency on
the source repository at runtime.

Supports:
    - Full keyword permutations with configurable connectors
    - Abbreviation variants (forward, backward, accumulative)
    - Reverse variants (per-element and accumulative)
    - Leet-speak substitution (single and multi-pass)
    - Numeric tail appending (ranges and explicit values)
    - Case folding (to_lower)
    - Length filtering

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 1.0.0
"""
from __future__ import annotations

import itertools
import logging
import re
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default leet substitution table
# ---------------------------------------------------------------------------

_DEFAULT_REPLACEMENTS: List[tuple[str, str]] = [
    ("a", "@"),
    ("a", "4"),
    ("e", "3"),
    ("i", "1"),
    ("i", "!"),
    ("o", "0"),
    ("s", "5"),
    ("s", "$"),
    ("t", "7"),
    ("l", "1"),
    ("b", "8"),
    ("g", "9"),
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class IwlgenEngine:
    """Intelligence Wordlist Generator engine.

    Wraps all permutation, abbreviation, reversal, and leet operations
    with a single high-level generate() entry point.

    Example::

        engine = IwlgenEngine()
        words = engine.generate(
            keywords=["admin", "router", "2024"],
            config={
                "connectors": ["", "@", ".", "_", "-"],
                "leet": True,
                "num_tails": ["1", "2", "01-05"],
                "min_length": 4,
                "max_length": 20,
                "abbreviation": True,
                "reverse": False,
                "to_lower": True,
            },
        )
    """

    def generate(
        self,
        keywords: List[str],
        config: Optional[Dict] = None,
    ) -> List[str]:
        """Generate a deduplicated wordlist from keywords and config.

        Args:
            keywords: Seed keyword list.
            config: Generation options dict (see class docstring for keys).

        Returns:
            Sorted, deduplicated list of generated strings.
        """
        cfg = config or {}
        connectors: List[str] = cfg.get("connectors", ["", ".", "_", "-", "@"])
        do_leet: bool = bool(cfg.get("leet", False))
        do_abbr: bool = bool(cfg.get("abbreviation", False))
        do_reverse: bool = bool(cfg.get("reverse", False))
        do_lower: bool = bool(cfg.get("to_lower", True))
        num_tails: List[str] = cfg.get("num_tails", [])
        tails: List[str] = cfg.get("tails", [""])
        min_len: int = int(cfg.get("min_length", 1))
        max_len: int = int(cfg.get("max_length", 64))
        replacements: List[tuple[str, str]] = cfg.get("replacements", _DEFAULT_REPLACEMENTS)

        result: list[str] = list(all_perms(keywords, connectors))

        if do_abbr:
            result.extend(_abbreviation_variants(keywords, connectors))

        if do_reverse:
            result.extend(_reverse_variants(keywords, connectors))

        result = _unique(result)

        if do_leet:
            result.extend(leetify(result, replacements))
            result = _unique(result)

        if num_tails:
            result.extend(list(_append_tails(result, num_tails, tails)))
            result = _unique(result)

        if do_lower:
            lc = [w.lower() for w in result]
            result = _unique(result + lc)

        # Length filter
        result = [w for w in result if min_len < len(w) < max_len]

        return sorted(_unique(result))


# ---------------------------------------------------------------------------
# Core permutation functions
# ---------------------------------------------------------------------------


def all_perms(
    keywords: Sequence[str],
    connectors: Sequence[str],
    leet: bool = False,
    num_tails: Optional[Sequence[str]] = None,
    abbreviation: bool = False,
) -> Iterator[str]:
    """Yield all permutations of keywords joined by each connector.

    For each permutation length from 1 to len(keywords), yields
    every ordering joined by each connector value.

    Args:
        keywords: Input keyword list.
        connectors: Connector strings to place between keywords.
        leet: If True, also yield leet variants of each permutation.
        num_tails: Optional list of numeric tails to append.
        abbreviation: If True, also yield single-char abbreviation variants.

    Yields:
        Generated strings.
    """
    items = list(keywords)
    n = len(items)

    for length in range(1, n + 1):
        for perm in itertools.permutations(items, length):
            for connector in connectors:
                word = connector.join(perm)
                yield word
                if leet:
                    yield from leetify([word])
                if num_tails:
                    yield from _append_tails([word], list(num_tails), [""])

    if abbreviation:
        yield from _abbreviation_variants(items, list(connectors))


def leetify(
    words: Sequence[str],
    replacements: Optional[List[tuple[str, str]]] = None,
) -> List[str]:
    """Apply leet substitutions to a list of words.

    For each (original, replacement) pair, applies the substitution to
    every word and accumulates results. Also applies all replacements
    simultaneously to produce a fully-leeted variant.

    Args:
        words: Input strings.
        replacements: List of (char, leet_char) pairs.
                      Uses _DEFAULT_REPLACEMENTS if None.

    Returns:
        New list with all leet variants (may contain duplicates - caller
        should deduplicate).
    """
    subs = replacements or _DEFAULT_REPLACEMENTS
    leeted: List[str] = []
    words_list = list(words)

    # Single-substitution variants: one replacement at a time
    for original, replacement in subs:
        for word in words_list:
            if original in word.lower():
                variant = re.sub(re.escape(original), replacement, word, flags=re.IGNORECASE)
                leeted.append(variant)

    # Fully-leeted: all replacements applied in sequence
    for word in words_list:
        fully = word
        for original, replacement in subs:
            fully = re.sub(re.escape(original), replacement, fully, flags=re.IGNORECASE)
        leeted.append(fully)

    return leeted


# ---------------------------------------------------------------------------
# Abbreviation and reverse helpers
# ---------------------------------------------------------------------------


def _abbreviation_variants(
    keywords: List[str],
    connectors: List[str],
) -> Iterator[str]:
    """Yield abbreviation permutations.

    Three abbreviation strategies from the original iwlgen:
    1. Abbreviate by single element at a time.
    2. Accumulative forward abbreviation.
    3. Accumulative backward abbreviation.
    """
    m = len(keywords)

    # Strategy 1: one element abbreviated at a time
    for i in range(m):
        abbr = list(keywords)
        abbr[i] = abbr[i][0] if abbr[i] else abbr[i]
        yield from all_perms(abbr, connectors)

    # Strategy 2: accumulative forward
    abbr = list(keywords)
    for i in range(m):
        abbr[i] = abbr[i][0] if abbr[i] else abbr[i]
        yield from all_perms(list(abbr), connectors)

    # Strategy 3: accumulative backward
    abbr = list(keywords)
    for i in range(m):
        k = m - i - 1
        abbr[k] = abbr[k][0] if abbr[k] else abbr[k]
        yield from all_perms(list(abbr), connectors)


def _reverse_variants(
    keywords: List[str],
    connectors: List[str],
) -> Iterator[str]:
    """Yield element-reversal permutations.

    Three reversal strategies from the original iwlgen:
    1. Reverse one element at a time.
    2. Accumulative forward reversal.
    3. Accumulative backward reversal.
    """
    m = len(keywords)

    # Strategy 1: one element reversed at a time
    for i in range(m):
        inv = list(keywords)
        inv[i] = inv[i][::-1]
        yield from all_perms(inv, connectors)

    # Strategy 2: accumulative forward
    inv = list(keywords)
    for i in range(m):
        inv[i] = inv[i][::-1]
        yield from all_perms(list(inv), connectors)

    # Strategy 3: accumulative backward
    inv = list(keywords)
    for i in range(m):
        k = m - i - 1
        inv[k] = inv[k][::-1]
        yield from all_perms(list(inv), connectors)


# ---------------------------------------------------------------------------
# Tail helpers
# ---------------------------------------------------------------------------


def _expand_tail(spec: str) -> Iterator[str]:
    """Expand a tail specification to individual strings.

    A spec may be:
    - A plain string: yielded as-is.
    - A range 'START-END': yields str(n) for n in range(START, END+1).
    - An empty string: yields ''.
    """
    if not spec:
        yield ""
        return
    # Range pattern: digits-digits
    range_m = re.fullmatch(r"(\d+)-(\d+)", spec)
    if range_m:
        start, end = int(range_m.group(1)), int(range_m.group(2))
        for n in range(start, end + 1):
            yield str(n)
    else:
        yield spec


def _append_tails(
    words: Iterable[str],
    num_tails: List[str],
    tails: List[str],
) -> Iterator[str]:
    """Append tail combinations to each word."""
    effective_tails = tails if tails else [""]
    for word in words:
        for tail in effective_tails:
            for num_spec in num_tails:
                for n in _expand_tail(num_spec):
                    yield f"{word}{n}{tail}"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _unique(items: List[str]) -> List[str]:
    """Return deduplicated list preserving insertion order."""
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
