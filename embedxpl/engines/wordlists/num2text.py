"""
num2text.py - Digit-to-text wordlist generator (multi-language).

Converts a number (up to 12 digits) into its digit-by-digit text representation
and produces case/leet/separator variations for password wordlist generation.

Supported languages:
  en   - English (US/GB identical digits)   one, two, three, ...
  pt   - European Portuguese                um, dois, três, ...
  br   - Brazilian Portuguese               um/uma, dois/duas, três, ... (+ informal)
  es   - Spanish (ES/MX/LA neutral)         uno, dos, tres, ...

Examples:
  123   (en) → onetwothree, ONETWOTHREE, OneTwoThree, on37w07hr33, one-two-three, ...
  123   (pt) → umdoistres, UMDOISTRES, UmDoisTrês, um-dois-três, ...
  123   (br) → umdoistres + umadoisduas variants
  123   (es) → unodostres, UNODOSTRES, UnoDostres, uno-dos-tres, ...

Usage:
  wlf num2text --number 123
  wlf num2text --number 123 --lang pt
  wlf num2text --number 123456 --lang es --separators -,_,@
  wlf num2text --range 0-9999 -o labs/labs_number2text.lst

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import unicodedata
from typing import Generator

MAX_DIGITS = 12

# ---------------------------------------------------------------------------
# Digit name tables
# ---------------------------------------------------------------------------

# English (US / GB - identical for single digits)
DIGIT_EN: dict[str, str] = {
    "0": "zero",
    "1": "one",
    "2": "two",
    "3": "three",
    "4": "four",
    "5": "five",
    "6": "six",
    "7": "seven",
    "8": "eight",
    "9": "nine",
}

# British alternative: "nought" for zero
DIGIT_EN_GB_ALT: dict[str, str] = {**DIGIT_EN, "0": "nought"}

# European Portuguese (accent-free base for ASCII-safe variants)
DIGIT_PT: dict[str, str] = {
    "0": "zero",
    "1": "um",
    "2": "dois",
    "3": "tres",
    "4": "quatro",
    "5": "cinco",
    "6": "seis",
    "7": "sete",
    "8": "oito",
    "9": "nove",
}

# PT with native accents
DIGIT_PT_ACC: dict[str, str] = {**DIGIT_PT, "3": "três"}

# Brazilian Portuguese - masculine base same as PT;
# feminine variants for 1 and 2 are extras (uma, duas)
DIGIT_BR_FEM: dict[str, str] = {**DIGIT_PT, "1": "uma", "2": "duas"}
DIGIT_BR_FEM_ACC: dict[str, str] = {**DIGIT_BR_FEM, "3": "três"}

# Spanish neutral (ES / MX / LA - digit names are identical across variants)
DIGIT_ES: dict[str, str] = {
    "0": "cero",
    "1": "uno",
    "2": "dos",
    "3": "tres",
    "4": "cuatro",
    "5": "cinco",
    "6": "seis",
    "7": "siete",
    "8": "ocho",
    "9": "nueve",
}

# Spanish feminine variants for 1 (una) and 2 is invariant
DIGIT_ES_FEM: dict[str, str] = {**DIGIT_ES, "1": "una"}

# Aliases normalised from user input
LANG_ALIASES: dict[str, str] = {
    "en": "en", "en-us": "en", "en-gb": "en",
    "us": "en", "gb": "en",
    "pt": "pt", "pt-pt": "pt",
    "br": "br", "pt-br": "br",
    "es": "es", "es-es": "es", "es-mx": "es", "es-la": "es",
    "sp": "es", "spanish": "es",
}

LEET_MAP: dict[str, str] = {
    "a": "4", "e": "3", "i": "1", "o": "0",
    "s": "$", "t": "7", "z": "2", "g": "9",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_accents(s: str) -> str:
    return unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()


def _normalise_lang(lang: str) -> str:
    return LANG_ALIASES.get(lang.lower().strip(), "en")


def _digits(number: str | int) -> list[str]:
    """Validates and returns individual digit characters."""
    s = str(number)
    if not s.isdigit():
        raise ValueError(f"Not a valid number: {number!r}")
    if len(s) > MAX_DIGITS:
        raise ValueError(f"Number exceeds {MAX_DIGITS} digits: {s!r}")
    return list(s)


def _word_tables(lang: str) -> list[dict[str, str]]:
    """
    Returns a list of digit tables to use for a given language.
    Multiple tables = multiple gender/accent variants to iterate over.
    """
    lang = _normalise_lang(lang)
    if lang == "en":
        return [DIGIT_EN, DIGIT_EN_GB_ALT]
    if lang == "pt":
        return [DIGIT_PT, DIGIT_PT_ACC]
    if lang == "br":
        return [DIGIT_PT, DIGIT_PT_ACC, DIGIT_BR_FEM, DIGIT_BR_FEM_ACC]
    if lang == "es":
        return [DIGIT_ES, DIGIT_ES_FEM]
    return [DIGIT_EN]  # fallback


def _word_list(number: str | int, table: dict[str, str]) -> list[str]:
    return [table[d] for d in _digits(number)]


# ---------------------------------------------------------------------------
# Case variants
# ---------------------------------------------------------------------------

def _case_variants(words: list[str]) -> list[str]:
    """
    Returns multiple case styles for a list of words.

    Styles produced (concatenated):
      all_lower         umdoistres
      ALL_UPPER         UMDOISTRES
      title             UmDoisTres  (each word capitalised)
      camel             umDoisTres  (first lowercase, rest capitalised)
      alternating_char  uMdOiStReS  (char-level alternating)
      alternating_word  umDOIStres  (word-level alternating upper/lower)
      block2            UMdoiSTres  (alternating blocks of 2 chars)
    """
    joined  = "".join(words)
    titled  = "".join(w.capitalize() for w in words)
    camel   = words[0].lower() + "".join(w.capitalize() for w in words[1:]) if len(words) > 1 else words[0].lower()

    # char-level alternating
    alt_chars = "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(joined))

    # word-level alternating
    alt_words = "".join(w.upper() if i % 2 else w.lower() for i, w in enumerate(words))

    # block-of-2 chars alternating upper/lower
    block2_chars = []
    for i, c in enumerate(joined):
        block2_chars.append(c.upper() if (i // 2) % 2 == 0 else c.lower())
    block2 = "".join(block2_chars)

    seen: set[str] = set()
    result: list[str] = []
    for v in [joined.lower(), joined.upper(), titled, camel, alt_chars, alt_words, block2]:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


# ---------------------------------------------------------------------------
# Separator variants
# ---------------------------------------------------------------------------

def _sep_variants(words: list[str], separators: list[str]) -> list[str]:
    """Joins words with each separator in both lower and upper."""
    result: list[str] = []
    seen: set[str] = set()
    for sep in separators:
        if sep == "":
            continue  # handled by case_variants
        for variant in [sep.join(w.lower() for w in words),
                        sep.join(w.upper() for w in words),
                        sep.join(w.capitalize() for w in words)]:
            if variant not in seen:
                seen.add(variant)
                result.append(variant)
    return result


# ---------------------------------------------------------------------------
# Leet variant
# ---------------------------------------------------------------------------

def _leet(s: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in s)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def num2text_variants(
    number: str | int,
    lang: str = "en",
    separators: list[str] | None = None,
    with_leet: bool = True,
    min_len: int = 0,
    max_len: int = 0,
) -> Generator[str, None, None]:
    """
    Generates all text variants for a number.

    Args:
        number:     The number to convert (up to 12 digits).
        lang:       Language code - en (default), pt, br, es.
                    Aliases accepted: en-us, en-gb, pt-br, es-mx, es-la, etc.
        separators: Separators between digit words (default: \"\", -, _, ., @, #, !).
        with_leet:  Include leet substitutions.
        min_len:    Minimum length filter (0 = no filter).
        max_len:    Maximum length filter (0 = no filter).

    Yields:
        Password variant strings (deduped across all table/gender variants).
    """
    seps    = separators if separators is not None else ["", "-", "_", ".", "@", "#", "!"]
    tables  = _word_tables(lang)
    num_str = str(number)

    seen: set[str] = set()

    def emit(s: str) -> bool:
        if s in seen:
            return False
        seen.add(s)
        if min_len and len(s) < min_len:
            return False
        if max_len and len(s) > max_len:
            return False
        return True

    for table in tables:
        words = _word_list(number, table)

        # Case variants (concatenated, no separator)
        for v in _case_variants(words):
            if emit(v):
                yield v
            # leet on each case variant
            if with_leet:
                lv = _leet(v)
                if emit(lv):
                    yield lv
            # also yield ascii-stripped version if different (handles accents)
            ascii_v = _strip_accents(v)
            if emit(ascii_v):
                yield ascii_v

        # Separator variants
        for v in _sep_variants(words, seps):
            if emit(v):
                yield v
            ascii_v = _strip_accents(v)
            if emit(ascii_v):
                yield ascii_v

    # Original digits appended to text base (e.g. onetwothree123)
    primary_words = _word_list(number, tables[0])
    base = "".join(primary_words)
    for suffix in [num_str, num_str[::-1]]:
        for case_base in [base.lower(), base.upper(), "".join(w.capitalize() for w in primary_words)]:
            for sep in ["", "_", "@", "#"]:
                v = f"{case_base}{sep}{suffix}"
                if emit(v):
                    yield v


def num2text_range(
    start: int,
    end: int,
    lang: str = "en",
    separators: list[str] | None = None,
    with_leet: bool = True,
    min_len: int = 0,
    max_len: int = 0,
) -> Generator[str, None, None]:
    """Generates variants for every number in [start, end] (deduped globally)."""
    seen: set[str] = set()
    for n in range(start, end + 1):
        for v in num2text_variants(n, lang, separators, with_leet, min_len, max_len):
            if v not in seen:
                seen.add(v)
                yield v
