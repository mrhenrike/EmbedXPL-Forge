"""
combiner.py - Keyword combiner for intelligent wordlist generation.

Generates permutations of keywords joined by connectors, with optional
abbreviation, reversal, leet, and numeric tail variations.

Inspired by intelligence-wordlist-generator (iwlgen).

Author: André Henrique (@mrhenrike)
Version: 1.1.0
"""
from __future__ import annotations

import logging
import sys
from itertools import permutations
from typing import Generator, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONNECTORS = ["", "-", "_", ".", "@", "#"]

DEFAULT_NUM_TAILS = [
    "", "1", "2", "3", "12", "123", "1234",
    "01", "00", "69", "99", "007",
    "!", "@", "#", "!!", "!@#",
    "2024", "2025", "2026",
]

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def combine_keywords(
    keywords: list[str],
    connectors: Optional[list[str]] = None,
    num_tails: Optional[list[str]] = None,
    max_depth: int = 0,
    use_abbreviation: bool = False,
    use_reverse: bool = False,
    use_leet: bool = False,
    use_lowercase: bool = False,
    use_titlecase: bool = False,
    affix_specials: Optional[list[str]] = None,
    min_length: int = 1,
    max_length: int = 64,
) -> Generator[str, None, None]:
    """Generate keyword combination wordlist.

    Args:
        keywords: List of base keywords.
        connectors: Separator strings between keywords.
        num_tails: Numeric/special suffixes to append.
        max_depth: Max permutation depth (0 = all up to len(keywords)).
        use_abbreviation: Generate abbreviation variants.
        use_reverse: Generate reversed variants.
        use_leet: Generate leet speak variants.
        use_lowercase: Add lowercase duplicates.
        use_titlecase: Capitalize each component before joining, producing
            CamelCase-style compounds (for example "NerdTrilha").
        affix_specials: Special characters used to wrap numeric tails, enabling
            composite affixes such as "@0724", "0724!" and "@0724!". Applied
            only to purely numeric tails to keep the keyspace bounded.
        min_length: Minimum output length.
        max_length: Maximum output length.

    Yields:
        Combined keyword strings.
    """
    conns = connectors if connectors is not None else DEFAULT_CONNECTORS
    tails = num_tails if num_tails is not None else DEFAULT_NUM_TAILS
    specials = [s for s in (affix_specials or []) if s]
    seen: set[str] = set()
    n = len(keywords)
    depth = max_depth if max_depth > 0 else n

    def emit(s: str) -> Optional[str]:
        # Case-sensitive dedup: "Admin" and "admin" are distinct password
        # candidates, and case variants (titlecase/lowercase) must survive.
        if s and s not in seen and min_length <= len(s) <= max_length:
            seen.add(s)
            return s
        return None

    base_combos: list[str] = []

    for size in range(1, min(depth, n) + 1):
        for perm in permutations(keywords, size):
            for conn in conns:
                combo = conn.join(perm)
                base_combos.append(combo)
                r = emit(combo)
                if r:
                    yield r
                if use_titlecase:
                    tcombo = conn.join(w.capitalize() for w in perm)
                    if tcombo != combo:
                        base_combos.append(tcombo)
                        r = emit(tcombo)
                        if r:
                            yield r

    for combo in list(base_combos):
        for tail in tails:
            if not tail:
                continue
            if specials and tail.isdigit():
                # Composite affixes: [lead special] + numeric tail + [trail special]
                for lead in [""] + specials:
                    for trail in [""] + specials:
                        r = emit(combo + lead + tail + trail)
                        if r:
                            yield r
            else:
                r = emit(combo + tail)
                if r:
                    yield r

    if use_abbreviation:
        for abbr in _abbreviation_variants(keywords):
            r = emit(abbr)
            if r:
                yield r
            for tail in tails:
                if tail:
                    r = emit(abbr + tail)
                    if r:
                        yield r

    if use_reverse:
        for combo in list(base_combos)[:500]:
            rev = combo[::-1]
            r = emit(rev)
            if r:
                yield r

    if use_leet:
        for combo in list(base_combos)[:500]:
            leet = _leetify(combo)
            if leet != combo:
                r = emit(leet)
                if r:
                    yield r

    if use_lowercase:
        for combo in list(base_combos)[:500]:
            low = combo.lower()
            r = emit(low)
            if r:
                yield r


def _abbreviation_variants(keywords: list[str]) -> list[str]:
    """Generate abbreviation variants from keywords.

    Three families:
    1. Single position abbreviated (only i-th word as first letter)
    2. Cumulative forward (first N words as first letters)
    3. Cumulative backward (last N words as first letters)
    """
    abbrs: list[str] = []
    n = len(keywords)

    for i in range(n):
        parts = list(keywords)
        if parts[i]:
            parts[i] = parts[i][0]
        abbrs.append("".join(parts))

    for cutoff in range(1, n):
        parts = [kw[0] if j < cutoff and kw else kw for j, kw in enumerate(keywords)]
        abbrs.append("".join(parts))

    for cutoff in range(1, n):
        parts = [kw[0] if j >= n - cutoff and kw else kw for j, kw in enumerate(keywords)]
        abbrs.append("".join(parts))

    return list(dict.fromkeys(abbrs))


def _leetify(text: str) -> str:
    """Apply leet substitutions."""
    return "".join(LEET_MAP.get(c.lower(), c) if c.isalpha() else c for c in text)


def handle_combiner(args, ctx: dict) -> None:
    """CLI handler for the combiner subcommand."""
    keywords = list(args.keywords) if args.keywords else []

    if getattr(args, "keywords_file", None):
        try:
            with open(args.keywords_file, encoding="utf-8") as f:
                for line in f:
                    kw = line.strip()
                    if kw and not kw.startswith("#"):
                        keywords.append(kw)
        except FileNotFoundError:
            logger.error("Keywords file not found: %s", args.keywords_file)
            return

    if not keywords:
        logger.error("No keywords provided. Use positional args or --keywords-file.")
        return

    connectors = None
    if getattr(args, "connectors", None):
        connectors = [c if c != "EMPTY" else "" for c in args.connectors.split(",")]

    # Optional linguistic linking words (articles/prepositions/conjunctions).
    # These are only added as extra connectors when the user explicitly asks for
    # a language, and only after an interactive confirmation, so they are not
    # applied blindly to every generation.
    link_list = _resolve_link_words(args)
    if link_list:
        if connectors is None:
            connectors = list(DEFAULT_CONNECTORS)
        for w in link_list:
            if w not in connectors:
                connectors.append(w)

    num_tails = None
    if getattr(args, "tails", None):
        num_tails = [""] + [t.strip() for t in args.tails.split(",")]

    affix_specials = None
    if getattr(args, "affix_specials", None):
        affix_specials = [s.strip() for s in args.affix_specials.split(",") if s.strip()]

    gen = combine_keywords(
        keywords,
        connectors=connectors,
        num_tails=num_tails,
        max_depth=getattr(args, "depth", 0),
        use_abbreviation=getattr(args, "abbreviation", False),
        use_reverse=getattr(args, "reverse", False),
        use_leet=getattr(args, "leet", False),
        use_lowercase=getattr(args, "lowercase", False),
        use_titlecase=getattr(args, "titlecase", False),
        affix_specials=affix_specials,
        min_length=getattr(args, "min_len", 1),
        max_length=getattr(args, "max_len", 64),
    )

    return gen


def _resolve_link_words(args) -> list[str]:
    """Resolve linguistic linking words from CLI args, with user confirmation.

    Reads ``--link-lang`` (language codes/aliases or ``all``) and ``--link-words``
    (explicit comma-separated linkers). When linkers are requested and the session
    is interactive, asks the user whether to include them, unless ``--assume-yes``
    (or ``--no-prompt``) is set. Returns an ordered, deduplicated list, or an empty
    list when nothing is requested or the user declines.

    Args:
        args: Parsed CLI namespace.

    Returns:
        List of linking words to add as connectors.
    """
    from embedxpl.engines.wordlists.linkwords import get_link_words

    link_list: list[str] = []
    if getattr(args, "link_lang", None):
        link_list.extend(get_link_words(args.link_lang))
    if getattr(args, "link_words", None):
        for w in args.link_words.replace(";", ",").split(","):
            w = w.strip()
            if w and w not in link_list:
                link_list.append(w)

    if not link_list:
        return []

    assume_yes = getattr(args, "assume_yes", False) or getattr(args, "no_prompt", False)
    if not assume_yes and sys.stdin.isatty():
        preview = ", ".join(link_list[:10]) + ("..." if len(link_list) > 10 else "")
        try:
            resp = input(
                f"  Include {len(link_list)} linguistic linking words "
                f"({preview}) as connectors? [Y/n]: "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            resp = "n"
        if resp in ("n", "no"):
            logger.info("Linking words skipped by user choice.")
            return []

    logger.info("Using %d linguistic linking words as connectors.", len(link_list))
    return link_list
