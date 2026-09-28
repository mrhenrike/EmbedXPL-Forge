"""
affix_engine.py - Composite affix mutation layer and CamelCase sourcing.

Provides a reusable layer that takes a stream of base words (for example the
output of the combiner) and appends composite affixes in a single pass:
the numeric core alone, a leading special plus core, core plus trailing
special, and leading plus core plus trailing special (for example ``0724``,
``@0724``, ``0724!`` and ``@0724!``). This guarantees the two-affix chaining
that a single ``combiner --tails`` or a plain ``mutate --suffixes`` pass does
not produce automatically.

The same affix specification can be exported as a hashcat rule set (append
rules) so it can be fed to ``rules apply`` or to hashcat/John directly.

It also exposes CamelCase-per-component helpers (title-case each token before
or after joining), a common human pattern that the combiner and mutate engines
do not cover on concatenated tokens.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
from typing import Generator, Iterable, Optional

logger = logging.getLogger(__name__)

DEFAULT_SPECIALS: tuple[str, ...] = ("!", "@", "#")

# Split a token run from its trailing separator, keeping the separator so a
# word can be rebuilt after per-token casing changes.
_TOKEN_SPLIT_RE = re.compile(r"([^A-Za-z0-9]+)")
# Camel boundary: a lowercase letter immediately followed by an uppercase one.
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z])(?=[A-Z])")


def expand_affixes(
    cores: Iterable[str],
    specials: Optional[Iterable[str]] = None,
    positions: str = "both",
    include_bare_core: bool = True,
    include_bare_specials: bool = False,
) -> list[str]:
    """Build composite suffix strings from numeric cores and special chars.

    For each core, generates the core alone and every requested wrapping with a
    leading and/or trailing special. Order is stable and deduplicated.

    Args:
        cores: Numeric cores such as dates or years (for example ``0724``,
            ``1988``). Empty tokens are ignored.
        specials: Special characters to wrap around cores. Defaults to
            :data:`DEFAULT_SPECIALS`.
        positions: Where specials may appear: ``"suffix"`` (core + trailing),
            ``"prefix"`` (leading + core), or ``"both"`` (all combinations).
        include_bare_core: When True, emit the core without any special.
        include_bare_specials: When True, also emit each special on its own
            (for example ``!``), independent of any core.

    Returns:
        Ordered, deduplicated list of suffix strings to append to base words.
    """
    spec = [s for s in (list(specials) if specials is not None else list(DEFAULT_SPECIALS)) if s]
    core_list = [c for c in (str(c).strip() for c in cores) if c]

    leads = [""] + spec if positions in ("prefix", "both") else [""]
    trails = [""] + spec if positions in ("suffix", "both") else [""]

    out: list[str] = []
    seen: set[str] = set()

    def _add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    for core in core_list:
        for lead in leads:
            for trail in trails:
                if not include_bare_core and not lead and not trail:
                    continue
                _add(lead + core + trail)

    if include_bare_specials:
        for s in spec:
            _add(s)

    return out


def titlecase_word(word: str) -> str:
    """Capitalize each alphanumeric token of a word, preserving separators.

    Splits on non-alphanumeric separators and on camelCase boundaries, then
    capitalizes the first letter of each token. On a fully concatenated token
    with no separators (for example ``nerdtrilha``) only the first letter can
    be raised, since word boundaries are unknown. Use the combiner ``--titlecase``
    option when the individual components are available.

    Args:
        word: Input word.

    Returns:
        The word with each detected token capitalized.

    Examples:
        >>> titlecase_word("nerd_trilha")
        'Nerd_Trilha'
        >>> titlecase_word("nerdTrilha")
        'NerdTrilha'
    """
    if not word:
        return word
    # Insert a null marker at camel boundaries so they survive the split.
    marked = _CAMEL_BOUNDARY_RE.sub("\x00", word)
    parts = _TOKEN_SPLIT_RE.split(marked)
    rebuilt: list[str] = []
    for idx, part in enumerate(parts):
        if idx % 2 == 1:  # separator run
            rebuilt.append(part)
            continue
        segments = part.split("\x00")
        rebuilt.append("".join(seg[:1].upper() + seg[1:] if seg else seg for seg in segments))
    return "".join(rebuilt)


def case_variants(word: str, include_upper: bool = True) -> list[str]:
    """Return common human case variants of a word, deduplicated.

    Args:
        word: Input word.
        include_upper: When True, include the fully uppercase variant.

    Returns:
        Ordered list of variants: original, lowercase, capitalized first letter,
        per-token title case, and optionally uppercase.
    """
    variants = [word, word.lower(), word[:1].upper() + word[1:], titlecase_word(word)]
    if include_upper:
        variants.append(word.upper())
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def apply_affix_layer(
    words: Iterable[str],
    cores: Iterable[str],
    specials: Optional[Iterable[str]] = None,
    positions: str = "both",
    include_base: bool = True,
    titlecase: bool = False,
    case: bool = False,
    include_bare_specials: bool = False,
    dedupe: bool = True,
) -> Generator[str, None, None]:
    """Append composite affixes to a stream of base words.

    For every base word (optionally expanded into case/CamelCase variants),
    yields the base plus each composite affix produced by :func:`expand_affixes`.

    Args:
        words: Iterable of base words (for example combiner output).
        cores: Numeric cores such as dates/years.
        specials: Special characters to wrap around cores.
        positions: Special placement (``"suffix"``, ``"prefix"`` or ``"both"``).
        include_base: When True, also emit each base word unchanged.
        titlecase: When True, add a per-token CamelCase variant of each base.
        case: When True, add lower/UPPER/Title case variants of each base.
        include_bare_specials: When True, also append lone specials.
        dedupe: When True, suppress duplicate outputs (uses memory).

    Yields:
        Base words and their composite-affix expansions.
    """
    suffixes = expand_affixes(
        cores,
        specials=specials,
        positions=positions,
        include_bare_core=True,
        include_bare_specials=include_bare_specials,
    )
    seen: Optional[set[str]] = set() if dedupe else None

    def _emit(s: str) -> Optional[str]:
        if not s:
            return None
        if seen is not None:
            if s in seen:
                return None
            seen.add(s)
        return s

    for raw in words:
        base = raw.rstrip("\n\r")
        if not base:
            continue

        bases: list[str] = [base]
        if case:
            for v in case_variants(base):
                if v not in bases:
                    bases.append(v)
        elif titlecase:
            tc = titlecase_word(base)
            if tc not in bases:
                bases.append(tc)

        for b in bases:
            if include_base:
                r = _emit(b)
                if r is not None:
                    yield r
            for suf in suffixes:
                r = _emit(b + suf)
                if r is not None:
                    yield r


def build_ruleset(
    cores: Iterable[str],
    specials: Optional[Iterable[str]] = None,
    positions: str = "both",
    include_titlecase: bool = False,
    include_case: bool = False,
) -> list[str]:
    """Build hashcat append rules for the composite affix specification.

    Each composite affix becomes a chain of ``$x`` append functions so the rule
    set can be used with ``rules apply``, hashcat ``-r`` or John. Optional case
    rules (``l``, ``u``, ``c``) can be prepended so casing and affixing combine.

    Args:
        cores: Numeric cores such as dates/years.
        specials: Special characters to wrap around cores.
        positions: Special placement (``"suffix"``, ``"prefix"`` or ``"both"``).
        include_titlecase: When True, also add a capitalize rule (``c``).
        include_case: When True, add lowercase/uppercase/capitalize rules for
            each affix, multiplying the rule set.

    Returns:
        Ordered, deduplicated rule lines.
    """
    suffixes = expand_affixes(cores, specials=specials, positions=positions,
                              include_bare_core=True)
    case_prefixes: list[str] = [""]
    if include_case:
        case_prefixes = ["", "l ", "u ", "c "]
    elif include_titlecase:
        case_prefixes = ["", "c "]

    out: list[str] = []
    seen: set[str] = set()
    for cp in case_prefixes:
        for suf in suffixes:
            append_ops = " ".join(f"${ch}" for ch in suf)
            rule = (cp + append_ops).strip()
            if rule and rule not in seen:
                seen.add(rule)
                out.append(rule)
    return out


def _iter_words(wordlist: Optional[str], keywords: Optional[list[str]]) -> Generator[str, None, None]:
    """Yield base words from a wordlist file, stdin, or inline keywords.

    Args:
        wordlist: Path to a wordlist file, ``"-"`` for stdin, or None.
        keywords: Inline base words when no file is given.

    Yields:
        Stripped base words.
    """
    import sys
    from pathlib import Path

    if wordlist == "-":
        for line in sys.stdin:
            yield line.rstrip("\n\r")
        return
    if wordlist:
        p = Path(wordlist)
        if not p.exists():
            raise FileNotFoundError(f"wordlist not found: {wordlist}")
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line.rstrip("\n\r")
        return
    for kw in keywords or []:
        yield kw


def handle_affix(args, ctx: dict) -> Optional[Generator[str, None, None]]:
    """CLI handler for the ``affix`` composite-affix mutation layer.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        Generator of output lines, or None on error or after writing a ruleset.
    """
    raw_dates = getattr(args, "dates", None)
    cores = [d.strip() for d in raw_dates.split(",")] if raw_dates else []
    if not cores:
        logger.error("affix requires --dates LIST (e.g. --dates '0724,1988')")
        return None

    raw_specials = getattr(args, "specials", None)
    specials = ([s.strip() for s in raw_specials.split(",") if s.strip()]
                if raw_specials is not None else list(DEFAULT_SPECIALS))

    positions = getattr(args, "positions", "both") or "both"
    titlecase = bool(getattr(args, "titlecase", False))
    case = bool(getattr(args, "case", False))
    bare_specials = bool(getattr(args, "bare_specials", False))

    emit_ruleset = getattr(args, "emit_ruleset", None)
    if emit_ruleset:
        rules = build_ruleset(
            cores,
            specials=specials,
            positions=positions,
            include_titlecase=titlecase,
            include_case=case,
        )
        try:
            with open(emit_ruleset, "w", encoding="utf-8") as fh:
                fh.write("# Composite affix rules generated by WordlistXPL-Forge\n")
                fh.write(f"# cores={','.join(cores)} specials={','.join(specials)} positions={positions}\n")
                for r in rules:
                    fh.write(r + "\n")
        except OSError as exc:
            logger.error("could not write ruleset: %s", exc)
            return None
        logger.info("Wrote %d composite affix rules to %s", len(rules), emit_ruleset)
        return None

    wordlist = getattr(args, "wordlist", None)
    keywords = list(getattr(args, "keywords", None) or [])

    # Reconcile positional argument: a single token that is '-' (stdin) or an
    # existing file is treated as the wordlist source; otherwise positionals are
    # inline base words.
    if not wordlist and keywords:
        from pathlib import Path
        if keywords[0] == "-":
            wordlist, keywords = "-", []
        elif len(keywords) == 1 and Path(keywords[0]).is_file():
            wordlist, keywords = keywords[0], []

    if not wordlist and not keywords:
        logger.error("affix requires a WORDLIST, --wordlist FILE, '-' for stdin, or inline keywords")
        return None

    try:
        words = _iter_words(wordlist, keywords)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        return None

    return apply_affix_layer(
        words,
        cores,
        specials=specials,
        positions=positions,
        include_base=not getattr(args, "no_base", False),
        titlecase=titlecase,
        case=case,
        include_bare_specials=bare_specials,
        dedupe=not getattr(args, "no_dedupe", False),
    )
