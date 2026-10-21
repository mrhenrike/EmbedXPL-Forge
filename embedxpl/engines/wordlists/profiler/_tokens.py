"""_tokens submodule of profiler."""
from __future__ import annotations

import json
import logging
import re
import uuid
import zlib
from datetime import date, datetime
from itertools import permutations as _permutations
from itertools import product as _product
from pathlib import Path
from typing import Generator, Optional

def _keyword_abbreviations(text: str) -> list[str]:
    """
    Build acronym tokens from keywords (e.g. cyber security → CS).

    Also handles camelCase (CyberSecurity → CS) and explicit short acronyms.
    """
    if not text or not text.strip():
        return []
    raw = strip_accents(text.strip())
    compact = re.sub(r"[\s\-_/]+", "", raw)
    found: list[str] = []

    if 2 <= len(compact) <= 8 and compact.isalpha() and raw.upper() == raw:
        found.append(compact.upper())

    words = [w for w in re.split(r"[\s\-_/]+", raw) if w]
    if len(words) >= 2:
        initials = "".join(w[0] for w in words if w and w[0].isalpha())
        if len(initials) >= 2:
            found.append(initials.upper())

    camel_parts = re.findall(r"[A-Z]?[a-z]+", raw)
    if len(camel_parts) >= 2:
        initials = "".join(p[0] for p in camel_parts if p)
        if len(initials) >= 2:
            found.append(initials.upper())

    # Single compound: cybersecurity → cyber + security
    lower = compact.lower()
    for prefix, suffix in (
        ("cyber", "security"), ("info", "sec"), ("net", "work"),
        ("soft", "ware"), ("dev", "ops"), ("cyber", "sec"),
    ):
        if lower.startswith(prefix) and lower.endswith(suffix):
            ab = (prefix[0] + suffix[0]).upper()
            found.append(ab)
            break

    result: list[str] = []
    seen: _SeenSet = _SeenSet()
    for a in found:
        for v in (a.upper(), a.lower(), a.capitalize()):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result


def _word_variants(word: str, leet: bool = True, leet_mode: str = "basic") -> list[str]:
    """
    Generate case and leet variants of a single word.

    Each variant is a clean single-word token (no spaces).

    Args:
        word: Single word to vary.
        leet: Include leet substitutions.

    Returns:
        Ordered unique list of variants.
    """
    clean = normalize(word)
    if not clean:
        return []

    base = list(dict.fromkeys([
        clean,
        clean.lower(),
        clean.upper(),
        clean.capitalize(),
        clean[0].upper() + clean[1:].lower() if len(clean) > 1 else clean.upper(),
        *_extended_case_variants(clean),
    ]))

    if leet:
        mode = leet_mode if leet_mode not in ("none", "") else "basic"
        for w in list(base):
            for table in _leet_tables_for_mode(mode):
                leet_w = _apply_leet(w, table)
                if leet_w not in base and leet_w != w:
                    base.append(leet_w)
            # lowercase selective substitutions
            low = w.lower()
            sel = _apply_leet(low, _SELECTIVE_LEET_LOWER)
            if sel not in base and sel != low:
                base.append(sel)
            # uppercase numeric leet (medium/aggressive)
            if mode in ("medium", "aggressive"):
                up = w.upper()
                v2 = _apply_leet(up, _LEET_V2)
                if v2 not in base and v2 != up:
                    base.append(v2)
                # @-style on uppercase base: D@RYU$ etc.
                v3 = _apply_leet(up, _LEET_V3)
                if v3 not in base and v3 != up:
                    base.append(v3)

    return base


def _date_tokens(day: int, month: int, year: int) -> list[str]:
    """
    Generate date string tokens from date components.

    Produces: ddmmyyyy, dd/mm/yyyy, dd-mm-yyyy, yyyy, ddmm, mmyyyy,
    and reversed variants (yyyymmdd).

    Args:
        day: Day (0 = unknown).
        month: Month (0 = unknown).
        year: Year (0 = unknown).

    Returns:
        List of date token strings.
    """
    tokens: list[str] = []
    if year:
        tokens.append(str(year))
        tokens.append(str(year)[-2:])  # 2-digit year
    if day and month:
        dd = str(day).zfill(2)
        mm = str(month).zfill(2)
        tokens.extend([
            f"{dd}{mm}",
            f"{mm}{dd}",
        ])
        if year:
            yy = str(year)
            y2 = yy[-2:]
            tokens.extend([
                f"{dd}{mm}{yy}",
                f"{dd}{mm}{y2}",
                f"{yy}{mm}{dd}",
                f"{y2}{mm}{dd}",
                f"{dd}/{mm}/{yy}",
                f"{dd}-{mm}-{yy}",
                f"{dd}.{mm}.{yy}",
                f"{dd}/{mm}/{y2}",
                f"{dd}-{mm}-{y2}",
            ])
    elif month and year:
        mm = str(month).zfill(2)
        tokens.extend([f"{mm}{year}", f"{year}{mm}"])
    return list(dict.fromkeys(tokens))


def _clean_phone(phone: str) -> list[str]:
    """
    Return phone number in multiple formats: E.164, local (no +), bare digits.

    Args:
        phone: Raw phone string (e.g., '+5511912345678', '11912345678').

    Returns:
        List of phone string variants.
    """
    digits = re.sub(r"\D", "", phone)
    variants = [digits]
    if phone.startswith("+"):
        variants.append("+" + digits)
    return list(dict.fromkeys(v for v in variants if len(v) >= 7))


def _social_handle_variants(handle: str) -> list[str]:
    """
    Return social media handle with and without @ prefix.

    Args:
        handle: Handle string, optionally prefixed with @.

    Returns:
        List with/without @ variant.
    """
    clean = handle.lstrip("@").strip()
    if not clean:
        return []
    return list(dict.fromkeys([clean, f"@{clean}"]))


# ── CUPP/elpscrk/BEWGor enhancements ─────────────────────────────────────────

def _reversed_tokens(tokens: list[str]) -> list[str]:
    """Generate reversed versions of all tokens (CUPP/elpscrk/BEWGor parity)."""
    reversed_list: list[str] = []
    for tok in tokens:
        rev = tok[::-1]
        if rev != tok and len(rev) >= 3:
            reversed_list.append(rev)
    return reversed_list


def _name_initials(full_name: str) -> list[str]:
    """Extract name fragments: initials, first letter, first 2 letters (BEWGor/elpscrk parity)."""
    parts = _split_words(full_name)
    if not parts:
        return []

    fragments: list[str] = []
    initials = "".join(p[0] for p in parts if p).upper()
    if len(initials) >= 2:
        fragments.append(initials)
        fragments.append(initials.lower())

    for part in parts:
        clean = normalize(part)
        if not clean:
            continue
        fragments.append(clean[0].lower())
        fragments.append(clean[0].upper())
        if len(clean) >= 2:
            fragments.append(clean[:2].lower())
            fragments.append(clean[:2].upper())
            fragments.append(clean[:2].capitalize())

    return list(dict.fromkeys(fragments))


def _extra_date_fragments(day: int, month: int, year: int) -> list[str]:
    """Generate granular date fragments (CUPP-style: isolated day, month, year digits)."""
    frags: list[str] = []
    if day:
        frags.append(str(day))
        frags.append(str(day).zfill(2))
        if day >= 10:
            frags.append(str(day % 10))
    if month:
        frags.append(str(month))
        frags.append(str(month).zfill(2))
        if month >= 10:
            frags.append(str(month % 10))
    if year:
        ys = str(year)
        frags.append(ys)
        frags.append(ys[-2:])
        if len(ys) >= 3:
            frags.append(ys[-3:])
    return list(dict.fromkeys(frags))


def _date_fragment_combos(date_tokens: list[str], max_combos: int = 200) -> list[str]:
    """Generate CUPP-style bdss cartesian products from numeric date fragments.

    Filters numeric-only tokens of 2-4 chars, then yields all pairwise
    concatenations (f1+f2) and separator-joined forms (f1+sep+f2).
    Equivalent to CUPP's ``bdss`` / ``kbdss`` logic.

    Args:
        date_tokens: List of raw date token strings (may include non-numeric).
        max_combos: Upper limit on total combos returned (avoids explosion).

    Returns:
        Deduplicated list of combined date fragment strings.
    """
    candidates = [
        t for t in date_tokens
        if t.isdigit() and 2 <= len(t) <= 4
    ]
    candidates = list(dict.fromkeys(candidates))

    seps = ["", "-", "/"]
    seen: set[str] = set()
    combos: list[str] = []

    for f1, f2 in _product(candidates, candidates):
        if f1 == f2:
            continue
        for sep in seps:
            combo = f"{f1}{sep}{f2}"
            if combo not in seen:
                seen.add(combo)
                combos.append(combo)
                if len(combos) >= max_combos:
                    return combos

    return combos


def _phone_fragments(phone: str) -> list[str]:
    """Decompose phone into fragments: last 4, first 4, national format (elpscrk parity)."""
    digits = re.sub(r"\D", "", phone)
    frags: list[str] = []
    if len(digits) >= 4:
        frags.append(digits[-4:])
        frags.append(digits[:4])
    if len(digits) >= 7:
        frags.append(digits[-7:])
    if digits.startswith("55") and len(digits) > 4:
        frags.append("0" + digits[2:])
    return list(dict.fromkeys(f for f in frags if f))


MULTI_CHAR_SPECIALS = [
    "!!", "!@", "!#", "@!", "@#", "#!", "#@",
    "123", "1!", "!1", "12", "01", "!@#", "@!#",
    "$$", "**", "##", "!", "@", "#", "$", "*",
]

# Hacker-culture suffixes (0x90 = NOP in x86 shellcode)
HACKER_SUFFIXES: list[str] = [
    "@0x90", "#0x90", "_0x90", "!0x90",
    "@0x41", "#0x41", "@0x00", "_0x00",
]

_BIRTHSTONES: dict[int, list[str]] = {
    1: ["garnet"],
    2: ["amethyst"],
    3: ["aquamarine", "bloodstone"],
    4: ["diamond"],
    5: ["emerald"],
    6: ["pearl", "moonstone"],
    7: ["ruby"],
    8: ["peridot", "spinel"],
    9: ["sapphire"],
    10: ["opal", "tourmaline"],
    11: ["topaz", "citrine"],
    12: ["tanzanite", "zircon", "turquoise"],
}


def get_birthstone_tokens(month: int) -> list[str]:
    """Return birthstone names for a given birth month as profile tokens.

    Returns list with each stone name in lowercase and capitalized form.
    """
    stones = _BIRTHSTONES.get(month, [])
    tokens: list[str] = []
    for stone in stones:
        low = stone.lower()
        cap = stone.capitalize()
        if low not in tokens:
            tokens.append(low)
        if cap not in tokens:
            tokens.append(cap)
    return tokens


# PT-BR informal shorthands used in phrase-initial extraction
_BR_INITIALS_MAP: dict[str, str] = {
    "mais": "+",   # "mais" (more) written as + in BR text messages
}


def _phrase_initials_suffixes(
    extra_suffixes: list[str] | None = None,
    *,
    include_recent_years: bool = True,
    recent_years_lookback: int = 1,
) -> list[str]:
    """Build prefix/suffix list for phrase-initial combos (incl. rolling years)."""
    suffixes: list[str] = [
        "",
        "@0x90", "#0x90", "_0x90", "!0x90",
        "@0x41", "#0x41",
        "@123", "#123", "_123", "!123",
        "@!", "#!", "_!",
    ]
    if include_recent_years:
        for y in rolling_recent_year_tokens(recent_years_lookback):
            for pref in ("@", "#", "_", "!", "$"):
                suffixes.append(f"{pref}{y}")
    for s in extra_suffixes or []:
        if s not in suffixes:
            suffixes.append(s)
    return list(dict.fromkeys(suffixes))


def phrase_initials_variants(
    phrase: str,
    extra_prefixes: list[str] | None = None,
    extra_suffixes: list[str] | None = None,
    *,
    include_recent_years: bool = True,
    recent_years_lookback: int = 1,
) -> list[str]:
    """
    Generate password variants from phrase initials (first letter of each word).

    PT-BR informal shorthand: "mais" → "+" (common in text/SMS messages).
    Applies case mutations, leet substitutions, and prefix/suffix combinations
    including hacker-culture patterns like @0x90, #0x90.

    Args:
        phrase: Input phrase (e.g. "é mais fácil pedir do que tentar quebrar").
        extra_prefixes: Additional prefixes to combine (added on top of defaults).
        extra_suffixes: Additional suffixes to combine (added on top of defaults).

    Returns:
        Ordered unique list of password candidates.

    Example::

        phrase_initials_variants("é mais fácil pedir do que tentar quebrar")
        # initials → "e+fpdqtq"
        # variants → "E+FPDQTQ", "_E+FPDQTQ@0x90", "e+fpdqtq@123", ...
    """
    words = _split_words(phrase)
    if not words:
        return []

    # Build initials with PT-BR informal shorthands
    initials_chars: list[str] = []
    for word in words:
        clean = strip_accents(word.strip().lower())
        if not clean:
            continue
        shorthand = _BR_INITIALS_MAP.get(clean)
        if shorthand:
            initials_chars.append(shorthand)
        else:
            initials_chars.append(clean[0])

    if not initials_chars:
        return []

    raw = "".join(initials_chars)  # e.g. "e+fpdqtq"
    n = len(raw)

    # Case variants
    base_variants: list[str] = list(dict.fromkeys([
        raw,                                                   # e+fpdqtq
        raw.upper(),                                           # E+FPDQTQ
        raw.capitalize(),                                      # E+fpdqtq
        # alternating upper/lower starting with upper (pos 0 → upper)
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(raw)),
        # alternating lower/upper starting with lower (pos 0 → lower)
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(raw)),
        # first half upper, second half lower
        raw[:n // 2].upper() + raw[n // 2:].lower(),
        # first half lower, second half upper
        raw[:n // 2].lower() + raw[n // 2:].upper(),
        # thirds: upper / lower / upper
        raw[:n // 3].upper() + raw[n // 3: 2 * n // 3].lower() + raw[2 * n // 3:].upper()
        if n >= 3 else raw.upper(),
        # blocks of 2: UUllUUll... (generates E+FpdQTq style)
        _block_case(raw, 2, True),
        # blocks of 2: llUUllUU...
        _block_case(raw, 2, False),
        # blocks of 3: UUUlllUUU...
        _block_case(raw, 3, True),
    ]))

    # Leet substitution variants
    leet_variants: list[str] = []
    for b in base_variants:
        leet_v = "".join(LEET_BASIC.get(ch, ch) for ch in b)
        if leet_v not in base_variants and leet_v != b:
            leet_variants.append(leet_v)

    all_bases = list(dict.fromkeys(base_variants + leet_variants))

    prefixes: list[str] = ["", "_", "__", "@", "#", "!"] + (extra_prefixes or [])
    suffixes = _phrase_initials_suffixes(
        extra_suffixes,
        include_recent_years=include_recent_years,
        recent_years_lookback=recent_years_lookback,
    )

    results: list[str] = []
    seen: _SeenSet = _SeenSet()

    for base in all_bases:
        for pref in prefixes:
            for suf in suffixes:
                candidate = pref + base + suf
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    results.append(candidate)

    return results


def _emit_phrase_initials_combos(
    profile: dict,
    min_len: int,
    max_len: int,
    seen: "_SeenSet | set[str]",
) -> Generator[str, None, None]:
    """
    Yield acrostic passwords from personal phrases/jargon in the profile.

    Example phrase → ``_E+FpQTq@2026`` (prefix + initials + year suffix).
    """
    phrases = list(profile.get("phrases") or []) + list(profile.get("jargon_phrases") or [])
    if not phrases:
        return

    lookback = int(profile.get("recent_years_lookback", 1))
    include_years = profile.get("include_recent_years", True)

    for phrase in phrases:
        if not phrase or not str(phrase).strip():
            continue
        for variant in phrase_initials_variants(
            str(phrase),
            include_recent_years=include_years,
            recent_years_lookback=lookback,
        ):
            if variant and variant not in seen and min_len <= len(variant) <= max_len:
                seen.add(variant)
                yield variant


def _emit_phrase_full_combos(
    profile: dict,
    min_len: int,
    max_len: int,
    seen: "_SeenSet | set[str]",
    *,
    do_leet: bool = False,
    leet_mode: str = "basic",
) -> Generator[str, None, None]:
    """Yield full-phrase password variants (motor 6 / phrase_mode full)."""
    phrases = list(profile.get("phrases") or []) + list(profile.get("jargon_phrases") or [])
    if not phrases:
        return

    phrase_opts = profile.get("phrase_options") or {}
    use_prefixes = profile.get("phrase_prefixes", phrase_opts.get("prefixes", True))
    use_year_suffix = profile.get(
        "phrase_suffix_years",
        phrase_opts.get("suffix_years", True),
    )
    lookback = int(profile.get("recent_years_lookback", 1))

    prefixes = ["", "_", "@", "#"] if use_prefixes else [""]
    suffixes: list[str] = [""]
    if use_year_suffix and profile.get("include_recent_years", True):
        suffixes.extend(
            _phrase_initials_suffixes(
                None,
                include_recent_years=True,
                recent_years_lookback=lookback,
            )
        )

    for phrase in phrases:
        if not phrase or not str(phrase).strip():
            continue
        words = _split_words(str(phrase))
        if not words:
            continue

        bases: list[str] = []
        joined = "".join(words)
        underscored = "_".join(words)
        dotted = ".".join(words)
        for base in (joined, underscored, dotted, strip_accents(joined)):
            if base:
                bases.append(base)

        expanded: list[str] = []
        for base in bases:
            expanded.append(base)
            expanded.append(base.lower())
            expanded.append(base.upper())
            expanded.append(base.capitalize())
            if do_leet:
                for variant in _word_variants(base, leet=True, leet_mode=leet_mode):
                    expanded.append(variant)

        for base in dict.fromkeys(expanded):
            for pref in prefixes:
                for suff in suffixes:
                    candidate = f"{pref}{base}{suff}"
                    if (
                        candidate
                        and candidate not in seen
                        and min_len <= len(candidate) <= max_len
                    ):
                        seen.add(candidate)
                        yield candidate


# Leet tables alias - defined above near LEET_BASIC
_VOWELS = set("aeiouAEIOU")


