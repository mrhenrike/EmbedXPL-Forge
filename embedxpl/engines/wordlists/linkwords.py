"""
linkwords.py - Linguistic linking words (articles, prepositions, conjunctions).

Provides per-language sets of short function words that people naturally use to
glue tokens into compound expressions or phrases (for example the Portuguese
"nerd na trilha" -> "nerdnatrilha"). These are meant to be used as optional
connectors in the combiner, only when compound words or phrases are plausible,
never applied blindly to every single guess.

Words are curated and deduplicated per language, ordered from most to least
common, and kept lowercase. Callers decide casing and joining strategy.

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

from typing import Iterable

# Supported languages mapped to their common linking words. Kept intentionally
# small: only high-frequency articles, prepositions and conjunctions that show
# up in real compound expressions, so the keyspace does not explode.
LINK_WORDS: dict[str, list[str]] = {
    "pt": [
        "de", "da", "do", "das", "dos", "na", "no", "nas", "nos",
        "e", "em", "com", "a", "o", "as", "os", "ao", "aos", "sem", "por",
    ],
    "en": [
        "the", "of", "and", "in", "on", "at", "to", "for", "a", "an",
        "with", "by", "my", "is",
    ],
    "es": [
        "el", "la", "los", "las", "de", "del", "y", "en", "con", "a",
        "un", "una", "por", "para",
    ],
    "fr": [
        "le", "la", "les", "de", "du", "des", "et", "en", "au", "aux",
        "un", "une", "dans", "sur",
    ],
    "it": [
        "il", "lo", "la", "i", "gli", "le", "di", "del", "della", "e",
        "in", "con", "un", "una",
    ],
    "de": [
        "der", "die", "das", "und", "von", "im", "in", "mit", "ein",
        "eine", "zum", "zur", "am",
    ],
}

# Convenience alias groups so callers can request families.
LANGUAGE_ALIASES: dict[str, str] = {
    "portuguese": "pt",
    "pt-br": "pt",
    "ptbr": "pt",
    "brazil": "pt",
    "english": "en",
    "spanish": "es",
    "espanol": "es",
    "castellano": "es",
    "french": "fr",
    "francais": "fr",
    "italian": "it",
    "italiano": "it",
    "german": "de",
    "deutsch": "de",
}


def supported_languages() -> list[str]:
    """Return the list of supported language codes.

    Returns:
        Sorted list of ISO-like language codes (for example ``["de", "en", ...]``).
    """
    return sorted(LINK_WORDS.keys())


def normalize_lang(code: str) -> str:
    """Normalize a language token to a supported code.

    Args:
        code: Raw language token (code, alias or name), case-insensitive.

    Returns:
        The canonical language code, or an empty string when unsupported.
    """
    key = (code or "").strip().lower()
    if not key:
        return ""
    if key in LINK_WORDS:
        return key
    return LANGUAGE_ALIASES.get(key, "")


def get_link_words(langs: Iterable[str] | str | None) -> list[str]:
    """Collect deduplicated linking words for the requested languages.

    Args:
        langs: A single language token, an iterable of tokens, a comma
            separated string, or the special value ``"all"`` for every
            supported language. ``None`` yields an empty list.

    Returns:
        Ordered, deduplicated, lowercase linking words. Unsupported tokens are
        ignored silently so the caller can pass user input directly.
    """
    if langs is None:
        return []

    if isinstance(langs, str):
        tokens = [t for t in langs.replace(";", ",").split(",")]
    else:
        tokens = list(langs)

    requested: list[str] = []
    for token in tokens:
        token = (token or "").strip().lower()
        if not token:
            continue
        if token == "all":
            requested.extend(supported_languages())
            continue
        code = normalize_lang(token)
        if code:
            requested.append(code)

    words: list[str] = []
    seen: set[str] = set()
    for code in requested:
        for word in LINK_WORDS.get(code, []):
            if word not in seen:
                seen.add(word)
                words.append(word)
    return words
