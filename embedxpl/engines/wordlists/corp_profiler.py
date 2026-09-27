"""
corp_profiler.py - Interactive corporate target profiling for wordlist generation.

Generates wordlist entries from company data: names, brands, domains, slogans,
partner names, CNPJs, keywords, dates, leet variants, and more.

Each variation is emitted as a separate line (one entry per line).

Usage:
  wlf.py corp                         # full interactive wizard
  wlf.py corp --name "BrandX" --domain "acme.example" --year 2008

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
from typing import Generator, Optional

from embedxpl.engines.wordlists.profiler import (
    ACCENT_MAP,
    COMMON_SUFFIXES,
    WORD_SEPARATORS,
    LEET_BASIC,
    _split_words,
    _word_variants,
    _date_tokens,
    _emit_all,
    _ask,
    _ask_multi,
    normalize,
    parse_date_input,
)

logger = logging.getLogger(__name__)

# ── Extra corporate separators ────────────────────────────────────────────────

CORP_SEPARATORS = list(WORD_SEPARATORS) + ["/", "+", "~", "^", "%", "&"]

COMMON_CORP_SUFFIXES = [
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "!", "@", "#", "$", "%", ".", "_", "-",
    "123", "1234", "admin", "root", "local", "vpn", "lab", "corp",
]

CNPJ_PATTERN = re.compile(r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def clean_cnpj(raw: str) -> list[str]:
    """
    Return CNPJ in multiple formats: bare digits, and formatted.

    Args:
        raw: Raw CNPJ string.

    Returns:
        List with bare-digits and formatted variants.
    """
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 14:
        return [digits] if digits else []
    formatted = f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:]}"
    return [digits, formatted]


def _slogan_tokens(text: str, do_leet: bool) -> list[str]:
    """
    Generate tokens from a multi-word slogan/phrase.

    Produces: each word variant + joined-no-space + joined-underscore variants.

    Args:
        text: Multi-word slogan.
        do_leet: Apply leet substitutions.

    Returns:
        List of token strings.
    """
    tokens: list[str] = []
    words = _split_words(text)
    if not words:
        return tokens

    for w in words:
        tokens.extend(_word_variants(w, leet=do_leet))

    # Full slogan joined
    joined = "".join(normalize(w) for w in words)
    tokens.extend(_word_variants(joined, leet=do_leet))

    # Underscore-joined
    us_joined = "_".join(normalize(w) for w in words)
    tokens.extend(_word_variants(us_joined, leet=do_leet))

    return list(dict.fromkeys(tokens))


# ── Interactive wizard ────────────────────────────────────────────────────────

def interactive_corp_profile() -> dict:
    """
    Full interactive corporate profiling wizard.

    Returns:
        Dict with all collected corporate profile data.
    """
    print("\n" + "=" * 58)
    print("  Corporate Target Profiler - Wordlist Generator")
    print("=" * 58)
    print("  Press Enter to skip any field.\n")

    profile: dict = {}

    # ── Identity ──────────────────────────────────────────────
    print("[ COMPANY IDENTITY ]")
    profile["trade_name"] = _ask("Trade name / DBA (nome fantasia)")
    profile["legal_name"] = _ask("Legal / full company name (razão social)")
    profile["brands"] = _ask("Brands (semicolon-separated, e.g. Brand A;Brand B)")
    profile["abbreviation"] = _ask("Common abbreviation or acronym (e.g. BrandX, CORP)")
    profile["cnpj"] = _ask("CNPJ or national tax ID (leave blank if unknown)")
    profile["domain"] = _ask("Primary domain (e.g. acme.example)")
    profile["email_pattern"] = _ask("Email pattern (e.g. name.surname@acme.example)")
    profile["website"] = _ask("Website URL")
    profile["sector"] = _ask("Business sector / industry (e.g. healthcare, fintech)")

    # ── Founding ──────────────────────────────────────────────
    print("\n[ FOUNDING ]")
    profile["founded_year"] = _ask("Year of foundation (yyyy)")
    profile["founded_date"] = _ask("Full founding date if known (dd/mm/yyyy)")
    profile["headquarters"] = _ask("Headquarters city / country")

    # ── Culture & identity ────────────────────────────────────
    print("\n[ CULTURE & IDENTITY ]")
    print("  (Enter multi-line text; leave blank to skip)")
    profile["slogan"] = _ask("Slogan / tagline")
    profile["mission"] = _ask("Mission statement (single paragraph, no line breaks)")
    profile["vision"] = _ask("Vision statement (single paragraph, no line breaks)")
    profile["values"] = _ask("Values (single paragraph, no line breaks)")
    profile["keywords"] = _ask_multi("Keywords / jargon / terms associated with the company")

    # ── Partners / Founders ───────────────────────────────────
    print("\n[ PARTNERS / FOUNDERS ]")
    profile["partners"] = []
    while True:
        name = _ask("Partner/founder full name (or Enter to stop)")
        if not name:
            break
        nick = _ask(f"  {name} short name or nickname")
        profile["partners"].append({"name": name, "nick": nick})

    # ── Phones & contact ─────────────────────────────────────
    print("\n[ CONTACT ]")
    profile["phones"] = _ask_multi("Company phone numbers (with or without DDI/DDD)")

    # ── Generation options ────────────────────────────────────
    print("\n[ GENERATION OPTIONS ]")
    profile["leet_mode"] = _ask("Leet mode [none/basic/medium/aggressive] (default: basic)") or "basic"
    profile["with_spaces"] = _ask("Include spaces between words? [y/N]").lower() in ("y", "yes")
    profile["reverse_mode"] = _ask("Include reversed strings? [y/N]").lower() in ("y", "yes")
    profile["camel_case"] = _ask("Include CamelCase variants? [y/N]").lower() in ("y", "yes")

    specials_raw = _ask("Special characters to include (e.g. @#!$, or 'all', or Enter to skip)")
    if specials_raw.lower() == "all":
        profile["special_chars"] = list("@#!$%^&*()-_+=~`")
    else:
        profile["special_chars"] = list(specials_raw) if specials_raw else []

    min_raw = _ask("Minimum password length (default: 6)")
    max_raw = _ask("Maximum password length (default: 32, 0 = unlimited)")
    profile["min_len"] = int(min_raw) if min_raw.isdigit() else 6
    profile["max_len"] = int(max_raw) if max_raw.isdigit() and int(max_raw) > 0 else 32

    return profile


# ── Generation ────────────────────────────────────────────────────────────────

def generate_from_corp_profile(
    profile: dict,
    leet_mode: Optional[str] = None,
    min_len: int = 6,
    max_len: int = 32,
    with_spaces: bool = False,
) -> Generator[str, None, None]:
    """
    Generate wordlist from corporate profile data.

    Each variation is yielded as a single separate string (one per line).

    Args:
        profile: Dict returned by interactive_corp_profile() or manually built.
        leet_mode: Override leet mode.
        min_len: Minimum entry length.
        max_len: Maximum entry length (0 = unlimited).
        with_spaces: Include space as separator.

    Yields:
        Individual wordlist entries, one per yield.
    """
    use_leet = leet_mode or profile.get("leet_mode", "basic")
    do_leet = use_leet not in ("none", "")
    do_reverse = profile.get("reverse_mode", False)
    do_camel = profile.get("camel_case", False)
    effective_max = max_len if max_len > 0 else 9999
    if profile.get("min_len"):
        min_len = profile["min_len"]
    if profile.get("max_len"):
        effective_max = profile["max_len"]
    if profile.get("with_spaces"):
        with_spaces = profile["with_spaces"]

    seen: set[str] = set()
    word_tokens: list[str] = []
    all_date_tokens: list[str] = []

    def add_words(text: str) -> None:
        for word in _split_words(text):
            for v in _word_variants(word, leet=do_leet):
                if v and v not in word_tokens:
                    word_tokens.append(v)

    def add_phrase(text: str) -> None:
        for t in _slogan_tokens(text, do_leet):
            if t and t not in word_tokens:
                word_tokens.append(t)
        add_words(text)

    # ── Trade name & legal name ───────────────────────────────
    add_phrase(profile.get("trade_name", ""))
    add_phrase(profile.get("legal_name", ""))

    # ── Abbreviation ──────────────────────────────────────────
    abbr = profile.get("abbreviation", "")
    if abbr:
        add_words(abbr)

    # ── Brands ───────────────────────────────────────────────
    for brand in profile.get("brands", "").split(";"):
        add_phrase(brand.strip())

    # ── CNPJ / Tax ID ─────────────────────────────────────────
    cnpj_raw = profile.get("cnpj", "")
    if cnpj_raw:
        for cv in clean_cnpj(cnpj_raw):
            if cv and cv not in word_tokens:
                word_tokens.append(cv)

    # ── Domain / email ────────────────────────────────────────
    domain = profile.get("domain", "").replace("https://", "").replace("http://", "").strip()
    if domain:
        add_words(domain.split(".")[0])
        word_tokens.append(domain)

    email_pat = profile.get("email_pattern", "").strip()
    if email_pat:
        word_tokens.append(email_pat)

    # ── Sector ───────────────────────────────────────────────
    add_words(profile.get("sector", ""))

    # ── Headquarters ─────────────────────────────────────────
    add_words(profile.get("headquarters", ""))

    # ── Founding dates ────────────────────────────────────────
    fy_raw = profile.get("founded_year", "").strip()
    if fy_raw.isdigit():
        add_date = _date_tokens(0, 0, int(fy_raw))
        for dt in add_date:
            if dt not in all_date_tokens:
                all_date_tokens.append(dt)

    fd_raw = profile.get("founded_date", "")
    if fd_raw:
        parsed = parse_date_input(fd_raw)
        if parsed:
            for dt in _date_tokens(*parsed):
                if dt not in all_date_tokens:
                    all_date_tokens.append(dt)

    # ── Culture ──────────────────────────────────────────────
    add_phrase(profile.get("slogan", ""))
    add_phrase(profile.get("mission", ""))
    add_phrase(profile.get("vision", ""))
    add_phrase(profile.get("values", ""))

    for kw in profile.get("keywords", []):
        add_phrase(kw)

    # ── Partners / Founders ───────────────────────────────────
    for partner in profile.get("partners", []):
        add_words(partner.get("name", ""))
        add_words(partner.get("nick", ""))

    # ── Phones ───────────────────────────────────────────────
    for phone in profile.get("phones", []):
        digits = re.sub(r"\D", "", phone)
        if digits and digits not in word_tokens:
            word_tokens.append(digits)

    # ── CamelCase variants ────────────────────────────────────
    if do_camel:
        camel_extras: list[str] = []
        for i in range(min(len(word_tokens), 15)):
            for j in range(min(len(word_tokens), 15)):
                if i != j:
                    a = normalize(word_tokens[i]).capitalize()
                    b = normalize(word_tokens[j]).capitalize()
                    camel = a + b
                    if camel not in camel_extras and camel not in word_tokens:
                        camel_extras.append(camel)
        word_tokens.extend(camel_extras)

    # ── Special chars ─────────────────────────────────────────
    seps = list(CORP_SEPARATORS)
    for sc in profile.get("special_chars", []):
        if sc not in seps:
            seps.append(sc)

    # ── Emit combinations ─────────────────────────────────────
    base_gen = _emit_all(
        word_tokens, all_date_tokens,
        seps, min_len, effective_max,
        with_spaces, seen,
    )

    for entry in base_gen:
        yield entry
        if do_reverse:
            rev = entry[::-1]
            if rev and rev not in seen and min_len <= len(rev) <= effective_max:
                seen.add(rev)
                yield rev

    # ── Token + COMMON_CORP_SUFFIXES ─────────────────────────
    for tok in word_tokens[:30]:
        for suf in COMMON_CORP_SUFFIXES:
            combo = tok + suf
            if combo not in seen and min_len <= len(combo) <= effective_max:
                seen.add(combo)
                yield combo
                if do_reverse:
                    rev = combo[::-1]
                    if rev not in seen and min_len <= len(rev) <= effective_max:
                        seen.add(rev)
                        yield rev
