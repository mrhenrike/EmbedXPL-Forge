"""_combos submodule of profiler."""
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

def password_variants(
    password: str,
    extra_prefixes: list[str] | None = None,
    extra_suffixes: list[str] | None = None,
    leet_mode: str = "all",
    min_len: int = 1,
    max_len: int = 128,
) -> list[str]:
    """
    Generate an exhaustive set of mutations from an existing password.

    Mutations applied:
    - Original as-is
    - Case variants: lower, UPPER, Capitalize, alternating char, block-2, half/half
    - Reversed string
    - Duplicated (password+password)
    - Vowels stripped
    - Leet substitutions (basic, v2/v3 tables) on every case variant
    - All bases × prefixes × suffixes (cartesian product)

    Args:
        password: Existing password to mutate.
        extra_prefixes: Additional prefixes (adds to defaults). Use ``[""]`` to keep
            only the empty prefix.
        extra_suffixes: Additional suffixes (adds to defaults). Use ``[""]`` to keep
            only the empty suffix.
        leet_mode: ``"basic"``, ``"v2"``, ``"v3"``, ``"all"`` or ``"none"``.
        min_len: Discard results shorter than this.
        max_len: Discard results longer than this.

    Returns:
        Ordered unique list of password mutation candidates.

    Example::

        password_variants("1q2w3e4r")
        # → "1q2w3e4r", "1Q2W3E4R", "_1q2w3e4r@0x90", "1q2w3e4r@123", ...
    """
    if not password:
        return []

    pw = password

    # ── Base forms (case) ─────────────────────────────────────────────────────
    n = len(pw)

    def _block2_upper(s: str) -> str:
        res, upper, cnt = [], True, 0
        for c in s:
            res.append(c.upper() if upper else c.lower())
            if c.isalpha():
                cnt += 1
                if cnt % 2 == 0:
                    upper = not upper
        return "".join(res)

    bases: list[str] = list(dict.fromkeys([
        pw,
        pw.lower(),
        pw.upper(),
        pw.capitalize(),
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(pw)),
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(pw)),
        pw[:n // 2].upper() + pw[n // 2:].lower(),
        pw[:n // 2].lower() + pw[n // 2:].upper(),
        _block2_upper(pw),
        pw[::-1],                                    # reversed
        pw + pw,                                     # duplicated
        "".join(c for c in pw if c not in _VOWELS), # vowels stripped
    ]))

    # ── Leet variants ─────────────────────────────────────────────────────────
    def _apply(s: str, table: dict[str, str]) -> str:
        return "".join(table.get(c, c) for c in s)

    leet_tables: list[dict[str, str]] = []
    if leet_mode in ("basic", "all"):
        leet_tables.append(LEET_BASIC)
    if leet_mode in ("v2", "all"):
        leet_tables.append(_LEET_V2)
    if leet_mode in ("v3", "all"):
        leet_tables.append(_LEET_V3)

    leet_extra: list[str] = []
    for b in bases:
        for table in leet_tables:
            lv = _apply(b, table)
            if lv not in bases and lv != b and lv not in leet_extra:
                leet_extra.append(lv)

    all_bases = list(dict.fromkeys(bases + leet_extra))

    # ── Prefixes / suffixes ───────────────────────────────────────────────────
    default_prefixes: list[str] = ["", "_", "__", "!", "@", "#", "0", "1", "my", "the"]
    default_suffixes: list[str] = [
        "",
        "!", "@", "#", "$", "*", "?",
        "1", "01", "12", "123", "1234", "12345",
        "@123", "#123", "_123", "!123",
        "@0x90", "#0x90", "_0x90", "!0x90",
        "@0x41", "#0x41",
        "@2020", "@2021", "@2022", "@2023", "@2024", "@2025", "@2026",
        "#2024", "#2025", "_2024", "_2025",
        "2024", "2025", "2026",
        "@!", "#!", "_!",
        "br", "@br", "_br",
    ]

    prefixes = list(dict.fromkeys(default_prefixes + (extra_prefixes or [])))
    suffixes = list(dict.fromkeys(default_suffixes + (extra_suffixes or [])))

    results: list[str] = []
    seen: _SeenSet = _SeenSet()

    for base in all_bases:
        for pref in prefixes:
            for suf in suffixes:
                candidate = pref + base + suf
                if (
                    candidate
                    and candidate not in seen
                    and min_len <= len(candidate) <= max_len
                ):
                    seen.add(candidate)
                    results.append(candidate)

    return results


# ── Main generator ────────────────────────────────────────────────────────────

def _prioritize_tokens_for_pairing(tokens: list[str]) -> list[str]:
    """Names/words first, then year-suffix combos - keeps BrandX#Pet25 reachable."""
    names: list[str] = []
    year_suffix: list[str] = []
    other: list[str] = []
    seen: _SeenSet = _SeenSet()
    for t in tokens:
        if t in seen:
            continue
        seen.add(t)
        if len(t) >= 4 and t[-2:].isdigit() and any(c.isalpha() for c in t[:-2]):
            year_suffix.append(t)
        elif len(t) >= 2 and not any(c.isdigit() for c in t):
            names.append(t)
        else:
            other.append(t)
    return names + year_suffix + other


def _append_year_suffix_tokens(tokens: list[str], date_tokens: list[str]) -> list[str]:
    """Build token+year combos (e.g. Pet + 25 → Pet25) for profile patterns."""
    years_2 = [dt for dt in date_tokens if len(dt) == 2 and dt.isdigit()]
    years_4 = [dt for dt in date_tokens if len(dt) == 4 and dt.isdigit()]
    extra: list[str] = []
    seen = set(tokens)
    for tok in tokens:
        if not tok or not tok[0].isalnum():
            continue
        for y in years_2:
            combo = tok + y
            if combo not in seen:
                seen.add(combo)
                extra.append(combo)
        for y in years_4:
            combo = tok + y[-2:]
            if combo not in seen:
                seen.add(combo)
                extra.append(combo)
            combo4 = tok + y
            if combo4 not in seen:
                seen.add(combo4)
                extra.append(combo4)
    return extra


def _profile_combo_separators(
    include_specials: bool,
    with_spaces: bool,
) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """Separators and prefixes based on interactive generation options."""
    single: list[str] = [""]
    if include_specials:
        single.extend(["@", "#", "_", "-", "!", ".", "$"])
        dual: list[tuple[str, str]] = [
            ("@", "#"), ("#", "@"), ("_", "@"), ("@", "@"),
            ("#", "#"), ("_", "#"), ("!", "#"), ("@", "_"),
        ]
        prefixes = list(SPECIAL_PREFIXES)
    else:
        single.extend(["_", "-"])
        dual = [("", ""), ("_", ""), ("", "_")]
        prefixes = ["", "_"]

    if with_spaces and " " not in single:
        single.append(" ")

    return single, dual, prefixes


def _build_token_pool(
    raw_values: list[str],
    leet_mode: str,
    *,
    max_per_source: int = 12,
) -> list[str]:
    """
    Plain + leet variants for each non-empty source string.

    When leet_mode is ``none``, only plain case variants are included.
    """
    pool: list[str] = []
    seen: _SeenSet = _SeenSet()
    do_leet = leet_mode not in ("none", "")

    for raw in raw_values:
        if not raw or not str(raw).strip():
            continue
        per_source = 0
        for word in _split_words(str(raw)):
            variants: list[str] = []
            variants.extend(_word_variants(word, leet=False, leet_mode="none"))
            if do_leet:
                for v in _word_variants(word, leet=True, leet_mode=leet_mode):
                    if v not in variants:
                        variants.append(v)
            for v in variants:
                if v and v not in seen:
                    seen.add(v)
                    pool.append(v)
                    per_source += 1
                    if per_source >= max_per_source:
                        break
    return pool


def _emit_pair_combos(
    pool_a: list[str],
    pool_b: list[str],
    seps: list[str],
    prefixes: list[str],
    try_emit,
) -> Generator[str, None, None]:
    """Emit a+sep+b and b+sep+a (optional leading prefix)."""
    if not pool_a or not pool_b:
        return
    for a in pool_a[:20]:
        for b in pool_b[:48]:
            if a.lower() == b.lower():
                continue
            for sep in seps:
                for combo in (a + sep + b, b + sep + a):
                    r = try_emit(combo)
                    if r:
                        yield r
            for pref in prefixes:
                if not pref:
                    continue
                for sep in seps:
                    for combo in (pref + a + sep + b, pref + b + sep + a):
                        r = try_emit(combo)
                        if r:
                            yield r


def _emit_entity_date_combos(
    entities: list[str],
    dates: list[str],
    seps: list[str],
    prefixes: list[str],
    try_emit,
) -> Generator[str, None, None]:
    """Entity + date and date + entity (Pet2026, 2026Pet, _Pet@26, …)."""
    if not entities or not dates:
        return
    for ent in entities[:18]:
        for dt in dates[:14]:
            for sep in seps:
                for combo in (ent + sep + dt, dt + sep + ent):
                    r = try_emit(combo)
                    if r:
                        yield r
            for pref in prefixes:
                if not pref:
                    continue
                for sep in seps:
                    for combo in (pref + ent + sep + dt, pref + dt + sep + ent):
                        r = try_emit(combo)
                        if r:
                            yield r
            # Concatenated suffix/prefix years (Pet26, Pet2026)
            for combo in (ent + dt, dt + ent):
                r = try_emit(combo)
                if r:
                    yield r


def _emit_triple_combos(
    pool_a: list[str],
    mids: list[str],
    pool_b: list[str],
    dual_seps: list[tuple[str, str]],
    prefixes: list[str],
    try_emit,
) -> Generator[str, None, None]:
    """pref + A + sep1 + mid + sep2 + B  (_NOME@2026#Pet, _CORP@2026#Dept)."""
    if not pool_a or not pool_b:
        return
    mid_list = [m for m in mids if m][:14]
    if not mid_list:
        return
    for a in pool_a[:22]:
        for mid in mid_list:
            for b in pool_b[:48]:
                if a.lower() == b.lower():
                    continue
                for pref in prefixes:
                    for s1, s2 in dual_seps:
                        combo = f"{pref}{a}{s1}{mid}{s2}{b}"
                        r = try_emit(combo)
                        if r:
                            yield r


def _emit_profile_relationship_combos(
    profile: dict,
    date_tokens: list[str],
    min_len: int,
    max_len: int,
    seen: "_SeenSet | set[str]",
    *,
    include_specials: bool = False,
    with_spaces: bool = False,
) -> Generator[str, None, None]:
    """
    Relationship-aware profile combos driven by filled wizard fields.

    Covers: name↔corp, name↔nick, name↔pet, pet↔dates, partner↔dates,
    children↔dates, _NOME@year#Pet, _CORP@year#Dept, _leet@year#SIGLA, etc.
    Respects ``include_specials``, ``with_spaces``, and ``leet_mode``.
    """
    def _try_emit(s: str) -> Optional[str]:
        if s and s not in seen and min_len <= len(s) <= max_len:
            seen.add(s)
            return s
        return None

    leet_mode = profile.get("leet_mode", "basic")
    single_seps, dual_seps, prefixes = _profile_combo_separators(include_specials, with_spaces)

    rolling = [
        y for y in rolling_recent_year_tokens(int(profile.get("recent_years_lookback", 1)))
        if y in date_tokens
    ] or rolling_recent_year_tokens(1)

    personal_dates = _date_tokens(
        profile.get("birth_day", 0) or 0,
        profile.get("birth_month", 0) or 0,
        profile.get("birth_year", 0) or 0,
    )
    partner_dates = _date_tokens(
        profile.get("partner_birth_day", 0) or 0,
        profile.get("partner_birth_month", 0) or 0,
        profile.get("partner_birth_year", 0) or 0,
    )

    # ── Token pools (only from filled profile sections) ───────
    names = _build_token_pool([
        profile.get("full_name", ""),
        profile.get("short_name", ""),
        profile.get("surname", ""),
    ], leet_mode)

    nicks = _build_token_pool(profile.get("nicknames", []), leet_mode)

    domain = (profile.get("company_domain", "") or "").replace("https://", "").replace("http://", "")
    domain_prefix = domain.split(".")[0] if domain else ""
    corps = _build_corp_relationship_pool(profile, leet_mode)

    depts = _build_token_pool([profile.get("company_department", "") or ""], leet_mode)

    year_mids = list(dict.fromkeys(
        [y for y in rolling if len(y) in (2, 4)]
        + [y for y in personal_dates if len(y) in (2, 4)]
        + [y for y in date_tokens if len(y) in (2, 4)][:10]
    ))

    pets = _build_pets_relationship_pool(profile, leet_mode, year_mids)
    pets_plain = _build_token_pool(
        _normalize_pet_entries(profile.get("pets") or [])[0], leet_mode,
    )
    leet_corps = _leet_token_filter(corps)

    partners = _build_token_pool([
        profile.get("partner_name", ""),
        profile.get("partner_nick", ""),
    ], leet_mode)

    children: list[str] = []
    child_date_map: list[tuple[list[str], list[str]]] = []
    for child in profile.get("children", []):
        cname = child.get("name", "")
        if not cname:
            continue
        cpool = _build_token_pool([cname], leet_mode)
        children.extend(cpool)
        cdts = _date_tokens(
            child.get("birth_day", 0) or 0,
            child.get("birth_month", 0) or 0,
            child.get("birth_year", 0) or 0,
        )
        child_date_map.append((cpool, cdts + rolling))

    children = list(dict.fromkeys(children))

    countries: list[str] = []
    country_raw = (profile.get("location_country", "") or "").strip()
    if country_raw and profile.get("include_country_variations", True):
        from embedxpl.engines.wordlists.country_tokens import country_word_tokens
        countries = country_word_tokens(country_raw)
        if leet_mode not in ("none", ""):
            leet_extra: list[str] = []
            for ct in countries[:18]:
                if len(ct) <= 8:
                    leet_extra.extend(
                        v for v in _word_variants(ct, leet=True, leet_mode=leet_mode)
                        if len(v) <= 14
                    )
            countries = list(dict.fromkeys(countries + leet_extra))

    abbrs: list[str] = []
    for src in (
        *profile.get("keywords", []),
        profile.get("company_department", "") or "",
        profile.get("company_name", "") or "",
        profile.get("company_legal", "") or "",
    ):
        abbrs.extend(_keyword_abbreviations(src))
    abbrs = list(dict.fromkeys(abbrs))
    if leet_mode not in ("none", ""):
        abbrs_leet: list[str] = []
        for ab in list(abbrs):
            abbrs_leet.extend(_word_variants(ab, leet=True, leet_mode=leet_mode))
        abbrs = list(dict.fromkeys(abbrs + abbrs_leet))

    leet_names = _leet_token_filter(names)

    all_dates = list(dict.fromkeys(rolling + personal_dates + partner_dates + [
        d for d in date_tokens if d.isdigit() or "/" in d or "-" in d
    ]))

    # ── Pairwise relationships ────────────────────────────────
    if names and corps:
        yield from _emit_pair_combos(names, corps, single_seps, prefixes, _try_emit)

    if names and nicks:
        yield from _emit_pair_combos(names, nicks, single_seps, prefixes, _try_emit)

    if names and pets:
        yield from _emit_pair_combos(names, pets, single_seps, prefixes, _try_emit)

    if names and abbrs:
        yield from _emit_pair_combos(names, abbrs, single_seps, prefixes, _try_emit)

    if corps and pets:
        yield from _emit_pair_combos(corps, pets, single_seps, prefixes, _try_emit)

    if corps and depts:
        yield from _emit_pair_combos(corps, depts, single_seps, prefixes, _try_emit)

    if corps and abbrs:
        yield from _emit_pair_combos(corps, abbrs, single_seps, prefixes, _try_emit)

    if leet_corps and abbrs:
        yield from _emit_pair_combos(leet_corps, abbrs, single_seps, prefixes, _try_emit)

    if names and countries:
        yield from _emit_pair_combos(names, countries, single_seps, prefixes, _try_emit)

    if countries and pets:
        yield from _emit_pair_combos(countries, pets, single_seps, prefixes, _try_emit)

    if countries and corps:
        yield from _emit_pair_combos(countries, corps, single_seps, prefixes, _try_emit)

    # ── Entity + date ─────────────────────────────────────────
    if names:
        yield from _emit_entity_date_combos(names, personal_dates + rolling, single_seps, prefixes, _try_emit)

    if pets_plain:
        yield from _emit_entity_date_combos(pets_plain, all_dates, single_seps, prefixes, _try_emit)

    if partners:
        yield from _emit_entity_date_combos(partners, partner_dates + rolling, single_seps, prefixes, _try_emit)

    for cpool, cdts in child_date_map:
        yield from _emit_entity_date_combos(cpool, cdts, single_seps, prefixes, _try_emit)

    if children:
        yield from _emit_entity_date_combos(children, all_dates, single_seps, prefixes, _try_emit)

    if countries:
        yield from _emit_entity_date_combos(countries, rolling + all_dates, single_seps, prefixes, _try_emit)

    # ── Triple: _A@year#B ─────────────────────────────────────
    if names and pets:
        yield from _emit_triple_combos(names, year_mids, pets, dual_seps, prefixes, _try_emit)

    if corps and pets:
        yield from _emit_triple_combos(corps, year_mids, pets, dual_seps, prefixes, _try_emit)

    if leet_corps and pets:
        yield from _emit_triple_combos(leet_corps, year_mids, pets, dual_seps, prefixes, _try_emit)

    if corps and depts:
        yield from _emit_triple_combos(corps, year_mids, depts, dual_seps, prefixes, _try_emit)

    if names and abbrs:
        yield from _emit_triple_combos(names, year_mids, abbrs, dual_seps, prefixes, _try_emit)

    if leet_names and abbrs:
        yield from _emit_triple_combos(leet_names, year_mids, abbrs, dual_seps, prefixes, _try_emit)

    if leet_names and pets:
        yield from _emit_triple_combos(leet_names, year_mids, pets, dual_seps, prefixes, _try_emit)

    if corps and abbrs:
        yield from _emit_triple_combos(corps, year_mids, abbrs, dual_seps, prefixes, _try_emit)

    if leet_corps and abbrs:
        yield from _emit_triple_combos(leet_corps, year_mids, abbrs, dual_seps, prefixes, _try_emit)

    if names and countries:
        yield from _emit_triple_combos(names, year_mids, countries, dual_seps, prefixes, _try_emit)

    if countries and pets:
        yield from _emit_triple_combos(countries, year_mids, pets, dual_seps, prefixes, _try_emit)

    # Name/corp + year suffix concat (BrandX25)
    for name in (names + leet_names + corps + leet_corps)[:36]:
        for y in year_mids:
            r = _try_emit(name + y)
            if r:
                yield r


# Backward-compatible alias
_emit_profile_signature_combos = _emit_profile_relationship_combos


