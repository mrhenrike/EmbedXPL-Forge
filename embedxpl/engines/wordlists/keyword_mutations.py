"""
keyword_mutations.py - Variações opcionais de keywords por inversão de letras e sílabas.

Modos:
  letter_reverse   : xpto → otpx
  syllable_reverse : xpto → otpx  (inverte ordem das sílabas)
  syllable_rotate  : xpto → otpx (rotação cíclica)

Heurística de sílabas: vogais como núcleo, grupos PT (nh, lh, ch, rr, ss) como unidade.
Funciona bem para nomes próprios e keywords pessoais (2-4 sílabas).

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import re
import zlib
from enum import Enum
from typing import Optional, Union

logger = logging.getLogger(__name__)

_MIN_MUTATION_LEN = 3

_VOWELS: frozenset[str] = frozenset("aeiouáéíóúàèìòùâêîôûãõäëïöüAEIOUÁÉÍÓÚÀÈÌÒÙÂÊÎÔÛÃÕÄËÏÖÜ")

_PT_DIGRAPHS: tuple[str, ...] = ("nh", "lh", "ch", "rr", "ss", "qu", "gu")

_DIGRAPH_RE = re.compile(
    "|".join(re.escape(d) for d in _PT_DIGRAPHS),
    re.IGNORECASE,
)


class MutationMode(str, Enum):
    """Available keyword mutation strategies."""

    LETTER_REVERSE = "letter_reverse"
    SYLLABLE_REVERSE = "syllable_reverse"
    SYLLABLE_ROTATE = "syllable_rotate"


def letter_reverse(word: str) -> str:
    """Reverse the characters of a word.

    Preserves capitalisation pattern: if the original word is capitalised
    (first letter upper, rest lower), the reversed result is also capitalised.

    Args:
        word: Input word.

    Returns:
        Character-reversed word with case normalised to match the input style.

    Examples:
        >>> letter_reverse("xpto")
        'otpx'
        >>> letter_reverse("Xpto")
        'Otpx'
    """
    if not word:
        return word
    reversed_chars = word[::-1]
    if word[0].isupper() and word[1:].islower():
        return reversed_chars[0].upper() + reversed_chars[1:].lower()
    return reversed_chars


def _tokenise_with_digraphs(word: str) -> list[str]:
    """Break a word into individual characters, treating PT digraphs as single units.

    Args:
        word: Input word.

    Returns:
        List of character tokens where each PT digraph occupies one slot.
    """
    tokens: list[str] = []
    i = 0
    lower = word.lower()
    while i < len(word):
        matched = False
        for dg in _PT_DIGRAPHS:
            if lower[i:i + len(dg)] == dg:
                tokens.append(word[i:i + len(dg)])
                i += len(dg)
                matched = True
                break
        if not matched:
            tokens.append(word[i])
            i += 1
    return tokens


def _split_syllables(word: str) -> list[str]:
    """Divide a word into syllables using a CV/CVC heuristic.

    Treats Portuguese digraphs (nh, lh, ch, rr, ss, qu, gu) as single
    consonant units. Falls back to returning [word] on words shorter than 2
    characters or when no vowel nucleus is found.

    Args:
        word: Input word.

    Returns:
        List of syllable strings. Returns [word] when segmentation is not
        possible or would yield a single-element list identical to input.
    """
    if len(word) < 2:
        return [word]

    tokens = _tokenise_with_digraphs(word)

    syllables: list[str] = []
    current: list[str] = []
    found_vowel_in_current = False

    for idx, tok in enumerate(tokens):
        is_vowel = tok[0] in _VOWELS
        current.append(tok)
        if is_vowel:
            found_vowel_in_current = True
            remaining = tokens[idx + 1:]
            next_is_consonant = bool(remaining) and remaining[0][0] not in _VOWELS
            next_next_is_vowel = (
                len(remaining) > 1 and remaining[1][0] in _VOWELS
            )
            if next_is_consonant and next_next_is_vowel:
                syllables.append("".join(current))
                current = []
                found_vowel_in_current = False
            elif not remaining:
                syllables.append("".join(current))
                current = []
                found_vowel_in_current = False

    if current:
        if syllables and found_vowel_in_current is False:
            syllables[-1] += "".join(current)
        else:
            syllables.append("".join(current))

    if len(syllables) <= 1:
        return [word]

    return syllables


def syllable_reverse(word: str) -> str:
    """Reverse the syllable order of a word.

    Args:
        word: Input word.

    Returns:
        Word with syllables in reverse order. Capitalisation of the first
        character is preserved when the input starts with an uppercase letter.

    Examples:
        >>> syllable_reverse("xpto")
        'xpto'
        >>> syllable_reverse("pessoax")
        'ssoaxpe'
    """
    if not word:
        return word
    syllables = _split_syllables(word)
    reversed_word = "".join(reversed(syllables))
    if word[0].isupper():
        return reversed_word[0].upper() + reversed_word[1:].lower()
    return reversed_word


def syllable_rotate(word: str, n: int = 1) -> str:
    """Cyclically rotate syllables of a word by n positions.

    A rotation of 1 moves the first syllable to the end:
    "per-so-nay" → "so-nay-per".

    Args:
        word: Input word.
        n: Number of rotation steps (positive = left rotation).

    Returns:
        Word with syllables rotated. Capitalisation is preserved as in
        syllable_reverse.

    Examples:
        >>> syllable_rotate("personay", n=1)
        'nayperso'
    """
    if not word:
        return word
    syllables = _split_syllables(word)
    if len(syllables) <= 1:
        return word
    n = n % len(syllables)
    rotated = syllables[n:] + syllables[:n]
    result = "".join(rotated)
    if word[0].isupper():
        return result[0].upper() + result[1:].lower()
    return result


def _crc32(s: str) -> int:
    return zlib.crc32(s.encode("utf-8", errors="replace")) & 0xFFFFFFFF


def mutate(
    words: Union[list[str], str],
    modes: list[MutationMode],
    include_original: bool = True,
) -> list[str]:
    """Apply mutation modes to each word in the input.

    Words shorter than 3 characters are skipped (originals kept if
    include_original=True). Results are deduplicated using CRC32 hashing.

    Args:
        words: Single word or list of words to mutate.
        modes: List of MutationMode values to apply.
        include_original: When True, each original word is included in output.

    Returns:
        Deduplicated list of original words (optional) and their mutations.
    """
    if isinstance(words, str):
        words = [words]

    seen: set[int] = set()
    result: list[str] = []

    def _add(w: str) -> None:
        key = _crc32(w)
        if key not in seen:
            seen.add(key)
            result.append(w)

    for word in words:
        if include_original:
            _add(word)
        else:
            seen.add(_crc32(word))

        if len(word) < _MIN_MUTATION_LEN:
            continue

        for mode in modes:
            if mode == MutationMode.LETTER_REVERSE:
                _add(letter_reverse(word))
            elif mode == MutationMode.SYLLABLE_REVERSE:
                _add(syllable_reverse(word))
            elif mode == MutationMode.SYLLABLE_ROTATE:
                _add(syllable_rotate(word, n=1))

    return result


def mutate_tokens(
    token_dict: dict,
    modes: list[MutationMode],
    scope_keys: Optional[list[str]] = None,
) -> dict:
    """Apply mutations to string/list values in a profile dictionary.

    For each targeted key, a new key ``<original_key>_mutations`` is added to
    the returned dictionary containing the mutated variants (originals excluded
    from the mutation list to avoid redundancy with the source key).

    Args:
        token_dict: Profile dictionary whose values are strings or lists of
            strings.
        modes: Mutation modes to apply.
        scope_keys: Restrict mutation to these specific keys. When None, all
            keys whose value is a str or list[str] are mutated.

    Returns:
        New dictionary that includes all original keys plus the added
        ``<key>_mutations`` entries.
    """
    result = dict(token_dict)

    keys_to_process: list[str] = list(scope_keys) if scope_keys else list(token_dict.keys())

    for key in keys_to_process:
        value = token_dict.get(key)
        if value is None:
            continue

        if isinstance(value, str):
            raw_words: list[str] = [value]
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            raw_words = list(value)
        else:
            continue

        mutations = mutate(raw_words, modes, include_original=False)
        if mutations:
            result[f"{key}_mutations"] = mutations
            logger.debug(
                "mutate_tokens: key=%s produced %d mutations", key, len(mutations)
            )

    return result


def ask_mutation_options(t_func=None) -> tuple[list[MutationMode], bool]:
    """Prompt the user interactively for mutation options.

    Args:
        t_func: Optional i18n function t(key) → str. When None, English
            strings are used.

    Returns:
        Tuple of (selected_modes, enabled). When the user declines, returns
        ([], False).
    """

    def _t(key: str, fallback: str) -> str:
        return t_func(key) if t_func else fallback

    enable_ans = input(
        _t("ask_mutations_enable", "Generate keyword mutations? [y/N]: ")
    ).strip().lower()

    if enable_ans not in ("y", "yes"):
        return [], False

    print(
        _t(
            "ask_mutations_choices",
            "  1  letter_reverse     xpto → otpx\n"
            "  2  syllable_reverse   xpto → otpx\n"
            "  3  syllable_rotate    xpto → otpx (cyclic)\n",
        )
    )

    raw = input(
        _t("ask_mutations_select", "Select modes (comma-separated, e.g. 1,2): ")
    ).strip()

    choice_map: dict[str, MutationMode] = {
        "1": MutationMode.LETTER_REVERSE,
        "2": MutationMode.SYLLABLE_REVERSE,
        "3": MutationMode.SYLLABLE_ROTATE,
    }

    selected: list[MutationMode] = []
    seen_modes: set[MutationMode] = set()
    for token in raw.split(","):
        token = token.strip()
        mode = choice_map.get(token)
        if mode and mode not in seen_modes:
            selected.append(mode)
            seen_modes.add(mode)

    if not selected:
        selected = [MutationMode.LETTER_REVERSE]

    return selected, True
