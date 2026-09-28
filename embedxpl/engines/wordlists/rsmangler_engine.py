from __future__ import annotations

"""
rsmangler_engine.py - Port Python do RSMangler v1.5 (Robin Wood / digininja).

Porta as regras de mangling do RSMangler original (Ruby) para Python nativo,
sem dependência do interpretador Ruby. Inspirado em: https://github.com/digininja/RSMangler

Regras implementadas (todas ON por default, desativar via ManglerOptions):
  perms         Permutações ordenadas de todas as palavras (aviso se >5 palavras)
  acronym       Acrônimo das palavras de entrada
  double        Palavra duplicada (passpass)
  reverse       Inverter a palavra
  capital       Capitalizar primeira letra
  upper         Uppercase completo
  lower         Lowercase completo
  swap          Swap case (togglecase)
  ed            Adicionar sufixo "ed"
  ing           Adicionar sufixo "ing"
  leet          Leet speak simples (um char de cada vez)
  full_leet     Todas combinações de leet (produto cartesiano)
  punctuation   Sufixos de pontuação: !@$%^&*()
  years         Anos 1990..ano_atual prefixo/sufixo
  common        Prepend/append: admin, sys, pw, pwd
  pna           Sufixo 01-09
  pnb           Prefixo 01-09
  na            Sufixo 1-123
  nb            Prefixo 1-123
  space         Espaço entre palavras permutadas

Author: André Henrique (@mrhenrike) - baseado em RSMangler 1.5 por Robin Wood
"""

import datetime
import itertools
import logging
import zlib
from dataclasses import dataclass, field
from typing import Generator, Optional

logger = logging.getLogger(__name__)

LEET_SIMPLE: dict[str, str] = {
    "s": "$", "e": "3", "a": "@", "o": "0",
    "i": "1", "l": "1", "t": "7", "b": "8", "z": "2",
}

LEET_FULL: dict[str, list[str]] = {
    "s": ["$", "z"], "e": ["3"], "a": ["4", "@"], "o": ["0"],
    "i": ["1", "!"], "l": ["1", "!"], "t": ["7"], "b": ["8"], "z": ["2"],
}

COMMON_WORDS = ["pw", "pwd", "admin", "sys"]
PUNCTUATION_CHARS = list("!@$%^&*()")


@dataclass
class ManglerOptions:
    """Configuration flags controlling which mangling rules are applied."""

    perms: bool = True
    acronym: bool = True
    double: bool = True
    reverse: bool = True
    capital: bool = True
    upper: bool = True
    lower: bool = True
    swap: bool = True
    ed: bool = True
    ing: bool = True
    leet: bool = True
    full_leet: bool = True
    punctuation: bool = True
    years: bool = True
    common: bool = True
    pna: bool = True
    pnb: bool = True
    na: bool = True
    nb: bool = True
    space: bool = False
    deduplicate: bool = True
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    force_perms: bool = False


def _leet_simple_variations(word: str) -> list[str]:
    """Generate leet-speak variants by substituting one character at a time.

    Args:
        word: Input word to transform.

    Returns:
        List of variants where each substitutable character is replaced once.
    """
    results: list[str] = []
    chars = list(word.lower())
    for idx, ch in enumerate(chars):
        if ch in LEET_SIMPLE:
            variant = chars[:]
            variant[idx] = LEET_SIMPLE[ch]
            results.append("".join(variant))
    return results


_LEET_FULL_MAX: int = 512


def _leet_full_variations(word: str) -> list[str]:
    """Generate cartesian-product leet-speak combinations for a word.

    Capped at _LEET_FULL_MAX to prevent memory explosion on long words.
    Words longer than 12 characters use single-position substitution only.

    Args:
        word: Input word to transform.

    Returns:
        Bounded list of leet variants.
    """
    chars = list(word.lower())

    # For long words, fall back to single-position substitution to stay bounded.
    if len(chars) > 12:
        results: list[str] = []
        for idx, ch in enumerate(chars):
            if ch in LEET_FULL:
                for sub in LEET_FULL[ch]:
                    variant = chars[:]
                    variant[idx] = sub
                    candidate = "".join(variant)
                    if candidate != word:
                        results.append(candidate)
        return results[:_LEET_FULL_MAX]

    options_per_position: list[list[str]] = []
    for ch in chars:
        if ch in LEET_FULL:
            options_per_position.append([ch] + LEET_FULL[ch])
        else:
            options_per_position.append([ch])

    results = []
    for combo in itertools.product(*options_per_position):
        candidate = "".join(combo)
        if candidate != word:
            results.append(candidate)
            if len(results) >= _LEET_FULL_MAX:
                break
    return results


def _permutations_of(words: list[str], separator: str = "") -> Generator[str, None, None]:
    """Yield all ordered permutations of subsets of words, joined by separator.

    Args:
        words: Source word list.
        separator: String placed between words in each permutation.

    Yields:
        Concatenated permutation strings.
    """
    for length in range(1, len(words) + 1):
        for perm in itertools.permutations(words, length):
            yield separator.join(perm)


def _apply_rules(word: str, options: ManglerOptions) -> Generator[str, None, None]:
    """Apply all single-word transformation rules to one word.

    Args:
        word: The candidate word to transform.
        options: Active rule flags.

    Yields:
        Transformed string variants.
    """
    yield word

    if options.double:
        yield word + word

    if options.reverse:
        yield word[::-1]

    if options.capital:
        yield word.capitalize()

    if options.upper:
        yield word.upper()

    if options.lower:
        yield word.lower()

    if options.swap:
        yield word.swapcase()

    if options.ed:
        yield word + "ed"

    if options.ing:
        yield word + "ing"

    if options.leet:
        yield from _leet_simple_variations(word)

    if options.full_leet:
        yield from _leet_full_variations(word)

    if options.punctuation:
        for ch in PUNCTUATION_CHARS:
            yield word + ch

    current_year = datetime.date.today().year
    if options.years:
        for yr in range(1990, current_year + 1):
            yield word + str(yr)
            yield str(yr) + word

    if options.common:
        for cw in COMMON_WORDS:
            yield word + cw
            yield cw + word

    if options.pna:
        for n in range(1, 10):
            yield word + f"{n:02d}"

    if options.pnb:
        for n in range(1, 10):
            yield f"{n:02d}" + word

    if options.na:
        for n in range(1, 124):
            yield word + str(n)

    if options.nb:
        for n in range(1, 124):
            yield str(n) + word


def mangle(
    words: list[str],
    options: ManglerOptions = ManglerOptions(),
) -> Generator[str, None, None]:
    """Generate RSMangler-style password variations from a list of words.

    Uses CRC32 checksums for streaming deduplication without loading all
    candidates into memory at once. Emits a warning when permutation mode
    is active with more than five words unless force_perms is set.

    Args:
        words: Source words to mangle.
        options: Rule configuration object.

    Yields:
        Deduplicated, length-filtered candidate strings.
    """
    if not words:
        return

    if options.perms and len(words) > 5 and not options.force_perms:
        logger.warning(
            "perms=True with %d words will generate a very large output. "
            "Set force_perms=True to suppress this warning.",
            len(words),
        )

    seen_crcs: set[int] = set()
    separator = " " if options.space else ""

    def _emit(candidate: str) -> Generator[str, None, None]:
        if options.min_length is not None and len(candidate) < options.min_length:
            return
        if options.max_length is not None and len(candidate) > options.max_length:
            return
        if options.deduplicate:
            crc = zlib.crc32(candidate.encode("utf-8", errors="replace")) & 0xFFFFFFFF
            if crc in seen_crcs:
                return
            seen_crcs.add(crc)
        yield candidate

    base_candidates: list[str]
    if options.perms:
        base_candidates = list(_permutations_of(words, separator))
    else:
        base_candidates = list(words)

    if options.acronym and len(words) > 1:
        acro = "".join(w[0] for w in words if w)
        base_candidates.append(acro)

    for base in base_candidates:
        for variant in _apply_rules(base, options):
            yield from _emit(variant)


def mangle_to_file(
    words: list[str],
    output_path: str,
    options: ManglerOptions = ManglerOptions(),
) -> dict:
    """Write mangle output to a file, one candidate per line.

    Args:
        words: Source words to mangle.
        output_path: Filesystem path for the output file.
        options: Rule configuration object.

    Returns:
        Dictionary with keys: lines_written (int), source_words (int),
        output_path (str).
    """
    lines_written = 0
    with open(output_path, "w", encoding="utf-8") as fh:
        for candidate in mangle(words, options):
            fh.write(candidate + "\n")
            lines_written += 1
    logger.info(
        "mangle_to_file: %d lines written to %s from %d source words",
        lines_written,
        output_path,
        len(words),
    )
    return {
        "lines_written": lines_written,
        "source_words": len(words),
        "output_path": output_path,
    }
