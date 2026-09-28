"""
prince_engine.py - PRINCE (PRobability INfinite Chained Elements) attack mode.

Generates password candidates by combining elements from a single wordlist
through chained concatenation, ordered by element probability. Discovers
multi-word passwords like "correcthorsebatterystaple".

Inspired by hashcat's princeprocessor (pp64).

Key features:
  - Probability-ordered element selection
  - Configurable element count (min/max chain length)
  - Password length constraints
  - Case permutation mode
  - Separator support (none, common, custom)
  - Duplicate elimination

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import heapq
import logging
from collections import Counter
from itertools import product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


def _load_wordlist(filepath: str, max_words: int = 0) -> list[tuple[str, int]]:
    """Load wordlist with frequency tracking.

    If the file contains `count word` format (withcount), uses counts.
    Otherwise, all words get count=1.

    Args:
        filepath: Path to wordlist file.
        max_words: Max words to load (0 = all).

    Returns:
        List of (word, count) tuples sorted by frequency descending.
    """
    freq: Counter = Counter()
    path = Path(filepath)

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n\r")
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                freq[parts[1]] += int(parts[0])
            else:
                freq[line] += 1

            if max_words and len(freq) >= max_words:
                break

    return freq.most_common()


def _case_permute(word: str) -> list[str]:
    """Generate case permutations of a word."""
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    if len(word) > 1:
        variants.add(word[0].upper() + word[1:].lower())
        variants.add(word.swapcase())
    return sorted(variants)


def prince_generate(
    wordlist_path: str,
    min_pw_len: int = 1,
    max_pw_len: int = 32,
    min_elem: int = 1,
    max_elem: int = 4,
    separator: str = "",
    case_permute: bool = False,
    max_candidates: int = 0,
    max_words: int = 0,
    min_word_len: int = 0,
    max_word_len: int = 0,
    superchop: int = 0,
) -> Generator[str, None, None]:
    """Generate PRINCE-mode candidates from a wordlist.

    Chains elements from the wordlist in all combinations of [min_elem, max_elem]
    elements, filtered by password length constraints. Elements are selected
    based on frequency (most common first).

    Args:
        wordlist_path: Path to the input wordlist.
        min_pw_len: Minimum output password length.
        max_pw_len: Maximum output password length.
        min_elem: Minimum elements per chain.
        max_elem: Maximum elements per chain.
        separator: String to join elements with.
        case_permute: Generate case variants.
        max_candidates: Maximum candidates (0 = unlimited).
        max_words: Maximum words to load from file (0 = all).

    Yields:
        Password candidates.
    """
    raw_words = _load_wordlist(wordlist_path, max_words)
    if not raw_words:
        return

    words: list[str] = []
    for w, _ in raw_words:
        if superchop > 0:
            w = w[:superchop]
        wlen = len(w)
        if min_word_len and wlen < min_word_len:
            continue
        if max_word_len and wlen > max_word_len:
            continue
        if w:
            words.append(w)
    if not words:
        return

    by_length: dict[int, list[str]] = {}
    for w in words:
        wlen = len(w)
        if wlen not in by_length:
            by_length[wlen] = []
        by_length[wlen].append(w)

    seen: set[str] = set()
    count = 0

    for num_elements in range(min_elem, max_elem + 1):
        if num_elements == 1:
            for w in words:
                candidates = _case_permute(w) if case_permute else [w]
                for c in candidates:
                    if min_pw_len <= len(c) <= max_pw_len and c not in seen:
                        seen.add(c)
                        yield c
                        count += 1
                        if max_candidates and count >= max_candidates:
                            return
            continue

        sep_overhead = len(separator) * (num_elements - 1)
        usable_len = max_pw_len - sep_overhead

        if usable_len < num_elements:
            continue

        length_combos: list[tuple[int, ...]] = []
        _find_length_combos(
            num_elements, min_pw_len - sep_overhead, usable_len,
            list(sorted(by_length.keys())), [], length_combos,
            max_combos=500,
        )

        for lc in length_combos:
            word_pools = []
            skip = False
            for elem_len in lc:
                pool = by_length.get(elem_len, [])
                if not pool:
                    skip = True
                    break
                word_pools.append(pool[:50])
            if skip:
                continue

            for combo in product(*word_pools):
                candidate = separator.join(combo)
                if min_pw_len <= len(candidate) <= max_pw_len:
                    if case_permute:
                        base_variants = [candidate]
                        base_variants.append(candidate.capitalize())
                        base_variants.append(candidate.upper())
                        for v in base_variants:
                            if v not in seen:
                                seen.add(v)
                                yield v
                                count += 1
                                if max_candidates and count >= max_candidates:
                                    return
                    else:
                        if candidate not in seen:
                            seen.add(candidate)
                            yield candidate
                            count += 1
                            if max_candidates and count >= max_candidates:
                                return


def _find_length_combos(
    slots: int,
    min_total: int,
    max_total: int,
    available_lengths: list[int],
    current: list[int],
    results: list[tuple[int, ...]],
    max_combos: int = 500,
) -> None:
    """Find valid combinations of word lengths that sum within bounds.

    Recursive with pruning for efficiency.
    """
    if len(results) >= max_combos:
        return

    if slots == 0:
        total = sum(current)
        if min_total <= total <= max_total:
            results.append(tuple(current))
        return

    for length in available_lengths:
        partial = sum(current) + length
        remaining_min = length * (slots - 1)
        remaining_max = (available_lengths[-1] if available_lengths else length) * (slots - 1)

        if partial + remaining_min > max_total:
            continue
        if partial + remaining_max < min_total:
            continue

        current.append(length)
        _find_length_combos(
            slots - 1, min_total, max_total,
            available_lengths, current, results,
            max_combos,
        )
        current.pop()


def handle_prince(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for PRINCE attack mode.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator yielding password candidates, or None.
    """
    wordlist = getattr(args, "wordlist", None)
    if not wordlist:
        logger.error("No wordlist provided")
        return None

    p = Path(wordlist)
    if not p.exists():
        logger.error("Wordlist not found: %s", wordlist)
        return None

    separator = getattr(args, "separator", "") or ""
    if separator.upper() == "EMPTY":
        separator = ""

    return prince_generate(
        str(p),
        min_pw_len=getattr(args, "min_len", 1),
        max_pw_len=getattr(args, "max_len", 32),
        min_elem=getattr(args, "min_elem", 1),
        max_elem=getattr(args, "max_elem", 4),
        separator=separator,
        case_permute=getattr(args, "case_permute", False),
        max_candidates=getattr(args, "limit", 0) or 0,
        max_words=getattr(args, "max_words", 0) or 0,
        min_word_len=getattr(args, "wordlen_min", 0) or 0,
        max_word_len=getattr(args, "wordlen_max", 0) or 0,
        superchop=getattr(args, "superchop", 0) or 0,
    )
