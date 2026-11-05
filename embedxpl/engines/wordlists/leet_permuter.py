"""
leet_permuter.py - Leet speak permutation and writing variation generation.

Available modes:
  basic      - Most common substitutions (a->@, e->3, i->1, o->0, s->$)
  medium     - Extended substitutions (t->7, l->1, b->6, etc.)
  aggressive - All possible substitutions + combinations
  custom     - User-defined mapping (e.g. a=@,4;t=7;s=$)

Reference: C code permutation engine (GeekUniao), CUPP 1337 mode.
Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import zlib
from itertools import product
from typing import Generator, Iterable

logger = logging.getLogger(__name__)

# ── Leet substitution mappings ───────────────────────────────────────────────

LEET_BASIC: dict[str, list[str]] = {
    "a": ["a", "@"],
    "A": ["A", "@", "4"],
    "e": ["e", "3"],
    "E": ["E", "3"],
    "i": ["i", "1"],
    "I": ["I", "1", "!"],
    "o": ["o", "0"],
    "O": ["O", "0"],
    "s": ["s", "$"],
    "S": ["S", "$"],
}

LEET_MEDIUM: dict[str, list[str]] = {
    **LEET_BASIC,
    "a": ["a", "@", "4"],
    "A": ["A", "@", "4"],
    "b": ["b", "6", "8"],
    "B": ["B", "6", "8"],
    "c": ["c", "(", "ç"],
    "C": ["C", "(", "Ç"],
    "g": ["g", "9"],
    "G": ["G", "9"],
    "h": ["h", "#"],
    "H": ["H", "#"],
    "i": ["i", "1", "!", "|"],
    "I": ["I", "1", "!", "|", "l"],
    "l": ["l", "1", "|", "!"],
    "L": ["L", "1", "|"],
    "n": ["n"],
    "N": ["N"],
    "q": ["q", "9"],
    "t": ["t", "7"],
    "T": ["T", "7"],
    "u": ["u", "v"],
    "U": ["U", "V"],
    "z": ["z", "2"],
    "Z": ["Z", "2"],
}

LEET_AGGRESSIVE: dict[str, list[str]] = {
    **LEET_MEDIUM,
    "a": ["a", "@", "4", "^", "∂"],
    "A": ["A", "@", "4", "^"],
    "b": ["b", "6", "8", "|3", "|}"],
    "B": ["B", "6", "8", "|3"],
    "c": ["c", "(", "ç", "<", "{"],
    "C": ["C", "(", "Ç", "<", "{"],
    "d": ["d", "|>", "cl"],
    "D": ["D", "|>"],
    "e": ["e", "3", "€", "&"],
    "E": ["E", "3", "€"],
    "f": ["f", "|=", "ph"],
    "F": ["F", "|="],
    "g": ["g", "9", "6", "&"],
    "G": ["G", "9", "6"],
    "h": ["h", "#", "|-|", "4"],
    "H": ["H", "#", "|-|"],
    "i": ["i", "1", "!", "|", "l", "eye"],
    "I": ["I", "1", "!", "|", "l"],
    "j": ["j", "_|"],
    "J": ["J", "_|"],
    "k": ["k", "|<", "|("],
    "K": ["K", "|<", "|("],
    "l": ["l", "1", "|", "!", "i"],
    "L": ["L", "1", "|", "!"],
    "m": ["m", "/\\/\\", "|v|"],
    "M": ["M", "/\\/\\"],
    "n": ["n", "|\\|"],
    "N": ["N", "|\\|"],
    "o": ["o", "0", "()", "[]"],
    "O": ["O", "0", "()", "[]"],
    "p": ["p", "|°", "ph"],
    "P": ["P", "|°"],
    "q": ["q", "9", "(,)", "0_"],
    "Q": ["Q", "9"],
    "r": ["r", "|2", "/2"],
    "R": ["R", "|2"],
    "s": ["s", "$", "5", "z"],
    "S": ["S", "$", "5"],
    "t": ["t", "7", "+", "†"],
    "T": ["T", "7", "+"],
    "u": ["u", "v", "|_|"],
    "U": ["U", "V", "|_|"],
    "v": ["v", "\\/"],
    "V": ["V", "\\/"],
    "w": ["w", "\\/\\/", "vv"],
    "W": ["W", "\\/\\/"],
    "x": ["x", "><", "*"],
    "X": ["X", "><"],
    "y": ["y", "¥", "j"],
    "Y": ["Y", "¥"],
    "z": ["z", "2", "7_"],
    "Z": ["Z", "2"],
}


ELPSCRK_LEVELS: dict[int, str] = {
    0: "basic (name+date only)",
    1: "standard (combos + suffixes)",
    2: "extended (leet + reversed + upper)",
    3: "full (OWASP chars appended)",
    4: "intensive (perm depth + custom years)",
    5: "max (unconstrained perm)",
}


def leet_perm_wordlist(
    words: Iterable[str],
    leet_map: dict[str, str] | None = None,
    max_per_word: int = 512,
) -> Generator[str, None, None]:
    """Apply cartesian leet permutation across an entire wordlist.

    Ports elpscrk's leet_perm: for each word, generates the full cartesian
    product of {original_char, leet_sub(char)} for every character position.
    Unlike token-level leet applied during generation, this is a global pass
    over the completed wordlist.

    Args:
        words: Input wordlist (list or any iterable of strings).
        leet_map: Simple char-to-char substitution map. Defaults to LEET_MEDIUM
                  (first non-original substitution per character).
        max_per_word: Maximum product iterations per word to prevent combinatorial
                      explosion.

    Yields:
        Unique word variants (including originals) deduplicated via CRC32.
    """
    if leet_map is None:
        leet_map = {
            k: (v[1] if len(v) > 1 else k)
            for k, v in LEET_MEDIUM.items()
        }

    seen_crc: set[int] = set()

    for word in words:
        char_sets = [{c, leet_map.get(c, c)} for c in word]
        count = 0
        for combo in product(*char_sets):
            if count >= max_per_word:
                break
            count += 1
            variant = "".join(combo)
            crc = zlib.crc32(variant.encode())
            if crc not in seen_crc:
                seen_crc.add(crc)
                yield variant


def parse_custom_mapping(mapping_str: str) -> dict[str, list[str]]:
    """
    Convert a custom mapping string into a substitution dict.

    Format: 'a=@,4;t=7;s=$;l=1,|'
    Each char=subs pair separated by ';', subs separated by ','

    Args:
        mapping_str: Mapping string in the described format.

    Returns:
        Dict mapping each char to a list of substitutions.
    """
    mapping: dict[str, list[str]] = {}
    if not mapping_str:
        return mapping
    for pair in mapping_str.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        char, subs_raw = pair.split("=", 1)
        char = char.strip()
        subs = [s.strip() for s in subs_raw.split(",") if s.strip()]
        if char and subs:
            if char not in mapping:
                mapping[char] = [char]
            mapping[char].extend([s for s in subs if s not in mapping[char]])
    return mapping


def _get_table(mode: str, custom_mapping: str = "") -> dict[str, list[str]]:
    """
    Return the substitution table for the specified mode.

    Args:
        mode: 'basic', 'medium', 'aggressive', or 'custom'.
        custom_mapping: Mapping string (only for 'custom' mode).

    Returns:
        Leet substitution dict for the chosen mode.
    """
    if mode == "basic":
        return LEET_BASIC
    elif mode == "medium":
        return LEET_MEDIUM
    elif mode == "aggressive":
        return LEET_AGGRESSIVE
    elif mode == "custom":
        return parse_custom_mapping(custom_mapping)
    else:
        raise ValueError(f"Invalid leet mode: {mode}. Use basic|medium|aggressive|custom")


def generate_leet(
    word: str,
    mode: str = "basic",
    custom_mapping: str = "",
    max_results: int = 10000,
) -> Generator[str, None, None]:
    """
    Generate all leet permutations for a word in the specified mode.

    In 'aggressive' mode, the number of combinations can be very high.
    Use max_results to cap the output.

    Args:
        word: Input word.
        mode: Substitution mode ('basic', 'medium', 'aggressive', 'custom').
        custom_mapping: Custom mapping string (only for mode='custom').
        max_results: Maximum number of results to generate.

    Yields:
        Strings with leet variations of the word.
    """
    table = _get_table(mode, custom_mapping)

    # For each character, get the list of possible substitutions
    char_options: list[list[str]] = []
    for ch in word:
        opts = table.get(ch, [ch])
        if not opts:
            opts = [ch]
        char_options.append(opts)

    count = 0
    for combination in product(*char_options):
        if count >= max_results:
            logger.debug("Result limit of %d reached for '%s'", max_results, word)
            break
        yield "".join(combination)
        count += 1


def generate_case_variations(word: str) -> Generator[str, None, None]:
    """
    Generate case variations (uppercase, lowercase, title, toggle).

    Args:
        word: Input word.

    Yields:
        Writing variations: original, upper, lower, title, swapcase.
    """
    seen: set[str] = set()
    for variant in [word, word.upper(), word.lower(), word.title(), word.swapcase()]:
        if variant not in seen:
            seen.add(variant)
            yield variant


def generate_all_variations(
    word: str,
    leet_mode: str = "basic",
    custom_mapping: str = "",
    include_case: bool = True,
    max_leet: int = 5000,
) -> Generator[str, None, None]:
    """
    Generate full variations: case + leet for a word.

    Args:
        word: Base word.
        leet_mode: Leet mode to apply.
        custom_mapping: Custom mapping string.
        include_case: If True, apply case variations before leet.
        max_leet: Maximum leet permutations per case variation.

    Yields:
        All unique generated variations.
    """
    seen: set[str] = set()

    base_words = list(generate_case_variations(word)) if include_case else [word]

    for base in base_words:
        for leet in generate_leet(base, leet_mode, custom_mapping, max_leet):
            if leet not in seen:
                seen.add(leet)
                yield leet


def permute_geek_uniao(password: str) -> Generator[str, None, None]:
    """
    Python port of the GeekUniao C permutation algorithm.

    Generates all character-by-character combinations for a password
    using the aggressive substitution mapping.

    Equivalent to the C code with strU, strN, strI, strA, strO,
    strG, strE, strK and strNumEsp combined in nested loops.

    Args:
        password: Base password to permute.

    Yields:
        All permutations of the password.
    """
    yield from generate_leet(password, mode="aggressive", max_results=100000)
