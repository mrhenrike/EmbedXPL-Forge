"""_generators submodule of profiler."""
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

def _emit_all(
    tokens: list[str],
    date_tokens: list[str],
    separators: list[str],
    min_len: int,
    max_len: int,
    with_spaces: bool,
    seen: "_SeenSet | set[str]",
    depth: int = 3,
) -> Generator[str, None, None]:
    """Yield all combinations of tokens, dates, separators.

    Args:
        tokens: Base word tokens.
        date_tokens: Date-derived tokens.
        separators: Separators to use between tokens.
        min_len: Minimum entry length.
        max_len: Maximum entry length.
        with_spaces: Include space as a separator option.
        seen: Mutable set of already-emitted entries.
        depth: Max permutation depth (3=default, 4=enhanced, 5=max BEWGor).
    """
    seps = list(separators)
    if with_spaces and " " not in seps:
        seps.append(" ")

    def _try_emit(s: str) -> Optional[str]:
        if s and s not in seen and min_len <= len(s) <= max_len:
            seen.add(s)
            return s
        return None

    # Single tokens
    for tok in tokens:
        r = _try_emit(tok)
        if r:
            yield r

    # Token + suffix
    for tok in tokens:
        for suf in COMMON_SUFFIXES:
            r = _try_emit(tok + suf)
            if r:
                yield r

    # Token + date token
    for tok in tokens:
        for dt in date_tokens:
            for sep in seps:
                for combo in [tok + sep + dt, dt + sep + tok]:
                    r = _try_emit(combo)
                    if r:
                        yield r

    # Name/word + separator + token-with-year (BrandX#Pet25)
    name_like = [t for t in tokens if len(t) >= 3 and not any(c.isdigit() for c in t)][:20]
    year_like_raw = [t for t in tokens if len(t) >= 4 and t[-2:].isdigit()]
    # Prefer mixed-case year suffixes before plain
    year_like = sorted(
        year_like_raw,
        key=lambda t: (
            0 if any(c.isupper() for c in t[:-2]) and any(c.islower() for c in t[:-2]) else 1,
            len(t),
        ),
    )[:50]
    for t1 in name_like:
        for t2 in year_like:
            if t1 == t2 or t2.startswith(t1):
                continue
            for sep in seps:
                r = _try_emit(t1 + sep + t2)
                if r:
                    yield r

    # Token pair combinations (2-token permutations)
    tokens = _prioritize_tokens_for_pairing(tokens)
    limit = min(len(tokens), 40)  # Cap to avoid combinatorial explosion
    token_subset = tokens[:limit]
    for t1, t2 in _permutations(token_subset, 2):
        for sep in seps:
            r = _try_emit(t1 + sep + t2)
            if r:
                yield r

    # Multi-separator 3-part: Name@2026#Pet (word + date + word)
    multi_seps = ["@", "#", "_", "-", "!", "$", "."]
    date_subset = date_tokens[:12]
    word_subset = tokens[:30]
    for t1 in word_subset:
        for mid in date_subset:
            for t2 in word_subset:
                if t1 == t2:
                    continue
                for sep1 in multi_seps:
                    for sep2 in multi_seps:
                        for combo in (
                            t1 + sep1 + mid + sep2 + t2,
                            t1 + sep1 + t2 + sep2 + mid,
                        ):
                            r = _try_emit(combo)
                            if r:
                                yield r

    # Leading special prefix + multi-sep (e.g. _BRANDX@2026#Pet)
    for pref in SPECIAL_PREFIXES:
        if not pref:
            continue
        for t1 in word_subset:
            for mid in date_subset:
                for t2 in word_subset:
                    if t1 == t2:
                        continue
                    for sep1 in multi_seps:
                        for sep2 in multi_seps:
                            r = _try_emit(pref + t1 + sep1 + mid + sep2 + t2)
                            if r:
                                yield r

    # 3-token combinations - use first 8 tokens only to limit volume
    limit3 = min(len(tokens), 8)
    token3_subset = tokens[:limit3]
    for t1, t2, t3 in _permutations(token3_subset, 3):
        r = _try_emit(t1 + t2 + t3)
        if r:
            yield r
        non_empty_seps = [s for s in seps if s]
        if non_empty_seps:
            sep = non_empty_seps[0]
            r = _try_emit(t1 + sep + t2 + sep + t3)
            if r:
                yield r

    # 4-token combinations (depth 4, BEWGor parity) - first 6 tokens
    if depth >= 4:
        limit4 = min(len(tokens), 6)
        for t1, t2, t3, t4 in _permutations(tokens[:limit4], 4):
            r = _try_emit(t1 + t2 + t3 + t4)
            if r:
                yield r

    # 5-token combinations (depth 5, BEWGor max parity) - first 5 tokens
    if depth >= 5:
        limit5 = min(len(tokens), 5)
        for combo in _permutations(tokens[:limit5], 5):
            r = _try_emit("".join(combo))
            if r:
                yield r

    # Prefix + token
    for pref in COMMON_PREFIXES:
        if not pref:
            continue
        for tok in tokens[:10]:
            r = _try_emit(pref + tok)
            if r:
                yield r

    # Reversed tokens (CUPP/elpscrk/BEWGor parity)
    rev_tokens = _reversed_tokens(tokens[:15])
    for rev in rev_tokens:
        r = _try_emit(rev)
        if r:
            yield r
        for dt in date_tokens[:10]:
            r = _try_emit(rev + dt)
            if r:
                yield r
            r = _try_emit(dt + rev)
            if r:
                yield r

    # Multi-char special suffixes (CUPP parity)
    for tok in tokens[:12]:
        for spec in MULTI_CHAR_SPECIALS:
            r = _try_emit(tok + spec)
            if r:
                yield r


# ── Interactive wizard ────────────────────────────────────────────────────────

def _generate_from_behavior(
    profile: dict,
    seen: "_SeenSet | set[str]",
    min_len: int,
    max_len: int,
) -> Generator[str, None, None]:
    """
    Yield wordlist entries derived from religion and behavioral patterns in the JSON DB.

    Uses data/behavior_patterns.json loaded offline.

    Args:
        profile: Profiler dict with religion_key, keywords, location_city, etc.
        seen: Mutable dedup set.
        min_len: Minimum entry length.
        max_len: Maximum entry length.

    Yields:
        Individual wordlist entries.
    """
    db = _load_behavior_db()
    if not db:
        return

    def _try(s: str) -> Optional[str]:
        s = s.strip()
        if s and s not in seen and min_len <= len(s) <= max_len:
            seen.add(s)
            return s
        return None

    anos = [str(y) for y in range(2016, 2027)]
    seps = ["@", "#", "_", "-", "!", ".", ""]

    # ── Religion patterns ──────────────────────────────────────
    rel_key = profile.get("religion_key")
    rel_custom = profile.get("religion_custom", "")
    church = (profile.get("church_name") or "").strip()
    group = (profile.get("church_group") or "").strip()

    rel_data: dict = {}
    if rel_key:
        rel_data = db.get("religions", {}).get(rel_key, {})

    # Keywords from religion
    for kw in rel_data.get("keywords", []):
        kw_clean = normalize(kw)
        if not kw_clean:
            continue
        r = _try(kw_clean)
        if r:
            yield r
        r = _try(kw_clean.capitalize())
        if r:
            yield r
        # kw + year
        for ano in anos:
            for sep in ["@", "#", "_", ""]:
                r = _try(f"{kw_clean}{sep}{ano}")
                if r:
                    yield r
                r = _try(f"{kw_clean.capitalize()}{sep}{ano}")
                if r:
                    yield r

    # Common phrases from religion
    for phrase in rel_data.get("phrases", []):
        p = phrase.strip()
        if not p:
            continue
        r = _try(p)
        if r:
            yield r
        r = _try(p.lower())
        if r:
            yield r
        for ano in anos:
            for sep in ["@", "#", ""]:
                r = _try(f"{p}{sep}{ano}")
                if r:
                    yield r

    # Verse references
    for ref in rel_data.get("verse_refs", []):
        r = _try(ref)
        if r:
            yield r
        for ano in anos:
            r = _try(f"{ref}{ano}")
            if r:
                yield r

    # Holy names
    for name in rel_data.get("holy_names", []):
        n = normalize(name)
        if not n:
            continue
        r = _try(n)
        if r:
            yield r
        for ano in anos:
            for sep in ["@", "#", ""]:
                r = _try(f"{n}{sep}{ano}")
                if r:
                    yield r
                r = _try(f"{n.lower()}{sep}{ano}")
                if r:
                    yield r

    # Common titles from religion
    for title in rel_data.get("common_titles", []):
        t = normalize(title).replace(" ", "")
        if not t:
            continue
        r = _try(t)
        if r:
            yield r

    # Prebuilt common passwords
    for pw in rel_data.get("common_passwords", []):
        r = _try(pw)
        if r:
            yield r

    # Church name patterns
    if church:
        ch_clean = normalize(church).replace(" ", "")
        for sep in seps:
            for ano in anos:
                r = _try(f"{ch_clean}{sep}{ano}")
                if r:
                    yield r
        r = _try(ch_clean)
        if r:
            yield r
        r = _try(ch_clean.lower())
        if r:
            yield r
        r = _try(ch_clean.upper())
        if r:
            yield r

    # Church + group
    if group:
        gr_clean = normalize(group).replace(" ", "")
        r = _try(gr_clean)
        if r:
            yield r
        if ch_clean if church else "":
            r = _try(f"{ch_clean}{gr_clean}")
            if r:
                yield r
            for sep in ["@", "#", "_", ""]:
                for ano in anos:
                    r = _try(f"{gr_clean}{sep}{ano}")
                    if r:
                        yield r

    # Custom religion name
    if rel_custom:
        rc = normalize(rel_custom).replace(" ", "")
        for sep in seps:
            for ano in anos:
                r = _try(f"{rc}{sep}{ano}")
                if r:
                    yield r
        r = _try(rc)
        if r:
            yield r

    # ── BR cultural phrases ────────────────────────────────────
    for phrase in db.get("cultural_phrases_br", {}).get("popular", []):
        r = _try(phrase)
        if r:
            yield r
    for phrase in db.get("cultural_phrases_br", {}).get("religious_phrases_br", []):
        r = _try(phrase)
        if r:
            yield r

    # ── Keyword-based behavioral patterns ─────────────────────
    profile_keywords = [normalize(kw).replace(" ", "") for kw in profile.get("keywords", [])]
    for kw in profile_keywords:
        if not kw:
            continue
        for bp_key, bp_data in db.get("behavioral_patterns", {}).items():
            # Check if keyword matches sports/music/gaming
            bp_kws = [k.lower() for k in bp_data.get("keywords", [])]
            if any(kw.lower() in bk or bk in kw.lower() for bk in bp_kws):
                for pat in bp_data.get("patterns", [])[:5]:
                    candidate = pat.replace("{clube}", kw).replace("{artista}", kw).replace("{game}", kw).replace("{nick}", kw).replace("{ano}", anos[-1])
                    r = _try(candidate)
                    if r:
                        yield r

    # ── Sports fan: city/club combos ─────────────────────────
    city = normalize(profile.get("location_city", "")).replace(" ", "")
    if city:
        for club in db.get("behavioral_patterns", {}).get("sports_fan", {}).get("br_clubs", []):
            cl = normalize(club)
            for ano in anos[-3:]:  # last 3 years only to limit volume
                r = _try(f"{cl}@{ano}")
                if r:
                    yield r



# ── Generation ────────────────────────────────────────────────────────────────

def generate_from_profile(
    profile: dict,
    leet_mode: Optional[str] = None,
    min_len: int = 6,
    max_len: int = 32,
    with_spaces: bool = False,
    include_specials: bool = False,
) -> Generator[str, None, None]:
    """
    Generate wordlist from personal profile data.

    Each variation is yielded as a single separate string (one per line).

    Args:
        profile: Dict returned by interactive_profile() or manually built.
        leet_mode: Override leet mode ('none', 'basic', 'medium', 'aggressive').
        min_len: Minimum entry length.
        max_len: Maximum entry length (0 = unlimited).
        with_spaces: Include space as separator in combinations.
        include_specials: Include special char variants.

    Yields:
        Individual wordlist entries, one per yield.
    """
    profile = _normalize_profile_pets(dict(profile))
    use_leet = leet_mode or profile.get("leet_mode", "basic")
    do_leet = use_leet not in ("none", "")
    effective_max = max_len if max_len > 0 else 9999
    effective_min = min_len

    _active_raw = profile.get("_active_engines")
    _active: set[int] | None = None
    if _active_raw is not None:
        _active = {int(x) for x in _active_raw}

    def _eng(engine_id: int) -> bool:
        return _active is None or engine_id in _active

    # Override from profile if present
    if profile.get("min_len"):
        effective_min = profile["min_len"]
    if profile.get("max_len"):
        effective_max = profile["max_len"]
    for kt in profile.get("known_targets") or []:
        if isinstance(kt, str) and kt:
            effective_max = max(effective_max, len(kt))
            effective_min = min(effective_min, len(kt))
    if profile.get("with_spaces"):
        with_spaces = profile["with_spaces"]
    if profile.get("include_specials"):
        include_specials = profile["include_specials"]

    seen: _SeenSet = _SeenSet()
    word_tokens: list[str] = []
    all_date_tokens: list[str] = []

    def add_words(text: str) -> None:
        """Add all word variants from a text string."""
        for word in _split_words(text):
            for variant in _word_variants(word, leet=do_leet, leet_mode=use_leet):
                if variant and variant not in word_tokens:
                    word_tokens.append(variant)

    def add_abbreviations(text: str) -> None:
        """Add acronym tokens from multi-word keywords (cyber security → CS)."""
        for ab in _keyword_abbreviations(text):
            for variant in _word_variants(ab, leet=do_leet, leet_mode=use_leet):
                if variant and variant not in word_tokens:
                    word_tokens.append(variant)

    def add_dates(day: int, month: int, year: int) -> None:
        """Add date tokens from date components."""
        for dt in _date_tokens(day, month, year):
            if dt not in all_date_tokens:
                all_date_tokens.append(dt)

    depth = profile.get("depth", 3) or 3

    # ── Collect tokens ────────────────────────────────────────

    # Full name words
    add_words(profile.get("full_name", ""))
    add_words(profile.get("short_name", ""))

    # Name initials and fragments (BEWGor/elpscrk parity)
    for name_field in ("full_name", "short_name"):
        for frag in _name_initials(profile.get(name_field, "")):
            if frag and frag not in word_tokens:
                word_tokens.append(frag)

    # Surname as separate field (CUPP parity)
    surname = profile.get("surname", "")
    if surname:
        add_words(surname)

    # Maiden name (CUPP parity)
    add_words(profile.get("maiden_name", ""))

    # Nicknames
    for nick in profile.get("nicknames", []):
        add_words(nick)

    # Birth date
    if _eng(2):
        day = profile.get("birth_day", 0) or 0
        month = profile.get("birth_month", 0) or 0
        year = profile.get("birth_year", 0) or 0
        add_dates(day, month, year)

        # Zodiac
        if day and month:
            zodiac = get_zodiac(day, month)
            add_words(zodiac)
            if year:
                add_words(get_chinese_zodiac(year))

        # Birthstone tokens (month-based, CUPP parity extension)
        if month:
            for stone in get_birthstone_tokens(month):
                add_words(stone)
    else:
        day = profile.get("birth_day", 0) or 0
        month = profile.get("birth_month", 0) or 0
        year = profile.get("birth_year", 0) or 0

    # National ID as token
    nid = profile.get("national_id", "").strip()
    if nid:
        clean_nid = re.sub(r"\D", "", nid)
        for v in [nid, clean_nid]:
            if v and v not in word_tokens:
                word_tokens.append(v)

    # Old passwords (elpscrk parity)
    if _eng(1) or _eng(9):
        for oldpwd in profile.get("old_passwords", []):
            if oldpwd and oldpwd not in word_tokens:
                word_tokens.append(oldpwd)
            if _eng(9):
                rev = oldpwd[::-1]
                if rev and rev != oldpwd and rev not in word_tokens:
                    word_tokens.append(rev)

    # Phones + fragments (elpscrk parity)
    for phone in profile.get("phones", []):
        for pv in _clean_phone(phone):
            if pv not in word_tokens:
                word_tokens.append(pv)
        for frag in _phone_fragments(phone):
            if frag not in word_tokens:
                word_tokens.append(frag)

    # T9 phone spelling from names (BEWGor parity)
    try:
        from embedxpl.engines.wordlists.phone_gen import t9_wordlist_tokens
        t9_names: list[str] = []
        for field in ("full_name", "short_name", "partner_name", "company_name"):
            for w in _split_words(profile.get(field, "")):
                if w:
                    t9_names.append(w)
        for nick in profile.get("nicknames", []):
            if nick:
                t9_names.append(str(nick))
        for tok in t9_wordlist_tokens(
            t9_names[:12], include_encoded=True, include_decoded=False,
        ):
            if tok and tok not in word_tokens:
                word_tokens.append(tok)
    except ImportError:
        pass

    # Location
    add_words(profile.get("location_city", ""))
    add_words(profile.get("location_state", ""))
    country_raw = (profile.get("location_country", "") or "").strip()
    if country_raw and _eng(24):
        from embedxpl.engines.wordlists.country_tokens import (
            country_minimal_tokens,
            country_word_tokens,
            resolve_country,
        )
        ckey = resolve_country(country_raw)
        if ckey:
            profile["location_country_key"] = ckey
        if profile.get("include_country_variations", True):
            for ctok in country_word_tokens(country_raw):
                add_words(ctok)
        else:
            for ctok in country_minimal_tokens(country_raw):
                if ctok and ctok not in word_tokens:
                    word_tokens.append(ctok)

    # Partner
    add_words(profile.get("partner_name", ""))
    add_words(profile.get("partner_nick", ""))
    if _eng(2):
        add_dates(
            profile.get("partner_birth_day", 0) or 0,
            profile.get("partner_birth_month", 0) or 0,
            profile.get("partner_birth_year", 0) or 0,
        )

    # Children
    for child in profile.get("children", []):
        add_words(child.get("name", ""))
        if _eng(2):
            add_dates(
                child.get("birth_day", 0) or 0,
                child.get("birth_month", 0) or 0,
                child.get("birth_year", 0) or 0,
            )

    # Pets
    pet_names, _ = _normalize_pet_entries(profile.get("pets") or [])
    for pet in pet_names:
        add_words(pet)

    # Corporate
    if _eng(25):
        add_words(profile.get("company_name", ""))
        add_words(profile.get("company_legal", ""))
        dept = profile.get("company_department", "") or ""
        if dept:
            add_words(dept)
            add_abbreviations(dept)
        email = profile.get("company_email", "")
        if email:
            word_tokens.append(email)
            local = email.split("@")[0]
            if local:
                add_words(local)
        domain = profile.get("company_domain", "").replace("https://", "").replace("http://", "")
        if domain:
            add_words(domain.split(".")[0])

    # Social handles
    for handle in profile.get("social_handles", []):
        for hv in _social_handle_variants(handle):
            if hv not in word_tokens:
                word_tokens.append(hv)

    # Keywords + acronyms (cyber security → CS)
    for kw in profile.get("keywords", []):
        add_words(kw)
        add_abbreviations(kw)

    # Corporate acronyms from company name
    if _eng(25):
        for corp_field in ("company_name", "company_legal", "company_department"):
            corp_val = profile.get(corp_field, "")
            if corp_val:
                add_abbreviations(corp_val)

    # Religion tokens (church/group names as word tokens)
    church = (profile.get("church_name") or "").strip()
    if church:
        add_words(church)
    church_group = (profile.get("church_group") or "").strip()
    if church_group:
        add_words(church_group)
    rel_custom = (profile.get("religion_custom") or "").strip()
    if rel_custom:
        add_words(rel_custom)

    # Special dates
    if _eng(2):
        for sd in profile.get("special_dates", []):
            parsed = parse_date_input(sd)
            if parsed:
                add_dates(*parsed)
            else:
                clean_sd = re.sub(r"\D", "", sd)
                if clean_sd and clean_sd not in all_date_tokens:
                    all_date_tokens.append(clean_sd)

        # ── Rolling recent years (current + previous): 25, 2025, 26, 2026 ──
        if profile.get("include_recent_years", True):
            lookback = int(profile.get("recent_years_lookback", 1))
            for yt in rolling_recent_year_tokens(lookback):
                if yt not in all_date_tokens:
                    all_date_tokens.append(yt)

        # ── Year range tokens (--year-start / --year-end) ─────────
        y_start = profile.get("year_start")
        y_end = profile.get("year_end")
        if y_start and y_end:
            for yt in generate_year_range_tokens(int(y_start), int(y_end)):
                if yt not in all_date_tokens:
                    all_date_tokens.append(yt)

        # ── Suffix range tokens (--suffix-range) ──────────────────
        sr_start = profile.get("suffix_range_start")
        sr_end = profile.get("suffix_range_end")
        if sr_start is not None and sr_end is not None:
            zero_pad = int(profile.get("suffix_range_zero_pad", 0))
            for st in generate_suffix_range_tokens(int(sr_start), int(sr_end), zero_pad):
                if st not in all_date_tokens:
                    all_date_tokens.append(st)

        # Extra date fragments (CUPP-style granular: isolated day, month, year digits)
        for date_src in [
            (day, month, year),
            (profile.get("partner_birth_day", 0) or 0,
             profile.get("partner_birth_month", 0) or 0,
             profile.get("partner_birth_year", 0) or 0),
        ]:
            for frag in _extra_date_fragments(*date_src):
                if frag not in all_date_tokens:
                    all_date_tokens.append(frag)

    # Parents and siblings (BEWGor parity)
    for parent in profile.get("parents", []):
        if isinstance(parent, dict):
            add_words(parent.get("name", ""))
        elif isinstance(parent, str):
            add_words(parent)
    for sibling in profile.get("siblings", []):
        if isinstance(sibling, dict):
            add_words(sibling.get("name", ""))
        elif isinstance(sibling, str):
            add_words(sibling)

    # Special characters override
    seps = list(WORD_SEPARATORS)
    if include_specials:
        seps.extend(["&", "*", "(", ")", "+", "=", "~"])

    # Token + year suffixes (Pet25, Name2026, ...)
    if _eng(2):
        word_tokens = list(dict.fromkeys(
            word_tokens + _append_year_suffix_tokens(word_tokens, all_date_tokens)
        ))

    # ── CUPP bdss: cartesian date fragment combos ─────────────
    if _eng(8):
        for _combo in _date_fragment_combos(all_date_tokens):
            if _combo not in seen:
                seen.add(_combo)
                if effective_min <= len(_combo) <= effective_max:
                    yield _combo

    # ── Emit all token combinations ───────────────────────────
    if _eng(3):
        yield from _emit_all(
            word_tokens, all_date_tokens,
            seps, effective_min, effective_max,
            with_spaces, seen, depth=depth,
        )

    # ── Relationship combos (_NOME@2026#Pet, name↔corp, pet↔dates, …) ──
    if _eng(4):
        yield from _emit_profile_relationship_combos(
            profile, all_date_tokens, effective_min, effective_max, seen,
            include_specials=include_specials,
            with_spaces=with_spaces,
        )

    # ── Phrase/jargon acrostics (_E+FpQTq@2026, …) ────────────
    phrase_opts = profile.get("phrase_options") or {}
    phrase_mode = profile.get("phrase_mode") or phrase_opts.get("mode", "both")
    if _eng(5) and phrase_mode in ("acrostic", "both"):
        yield from _emit_phrase_initials_combos(
            profile, effective_min, effective_max, seen,
        )

    # ── Full phrase combos (no acrostic) ───────────────────────
    if _eng(6) and phrase_mode in ("full", "both"):
        yield from _emit_phrase_full_combos(
            profile, effective_min, effective_max, seen,
            do_leet=do_leet,
            leet_mode=use_leet,
        )

    # ── Behavioral/religious patterns from JSON DB ────────────
    if _eng(7) and profile.get("use_behavior_patterns", True):
        yield from _generate_from_behavior(
            profile, seen, effective_min, effective_max,
        )


def improve_wordlist(
    source_path: str,
    output_path: str,
    leet_mode: str = "basic",
    append_years: bool = True,
    append_specials: bool = True,
    year_start: int = 2020,
    year_end: int = 2027,
    special_chars: list[str] | None = None,
    min_len: int = 6,
    max_len: int = 32,
) -> int:
    """Enrich an existing wordlist with mutations (CUPP -w parity).

    Reads each word from *source_path* and generates:

    - leet variants (via :func:`_word_variants` with leet=True)
    - word + year combos (year_start..year_end)
    - word + special char combos
    - 1-3 char special suffix combos

    Writes deduplicated output to *output_path*.

    Args:
        source_path: Path to input wordlist (one entry per line).
        output_path: Path to write enriched output.
        leet_mode: Leet substitution intensity ('basic', 'medium', 'aggressive').
        append_years: Append year suffixes to each base word.
        append_specials: Append special char suffixes to each base word.
        year_start: First year for year suffix range.
        year_end: Last year for year suffix range (inclusive).
        special_chars: Override special char list. Defaults to COMMON_SUFFIXES.
        min_len: Minimum entry length to include in output.
        max_len: Maximum entry length to include in output.

    Returns:
        Count of entries written to *output_path*.
    """
    if special_chars is None:
        special_chars = list(COMMON_SUFFIXES)

    years = [str(y) for y in range(year_start, year_end + 1)]
    two_digit_years = [y[-2:] for y in years]
    all_years = list(dict.fromkeys(years + two_digit_years))

    seen: _SeenSet = _SeenSet()
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with open(source_path, "r", encoding="utf-8", errors="ignore") as src, \
            open(out_path, "w", encoding="utf-8") as dst:

        for raw_line in src:
            base = raw_line.rstrip("\n\r")
            if not base:
                continue

            candidates: list[str] = []

            # Base word + leet variants
            for variant in _word_variants(base, leet=True, leet_mode=leet_mode):
                candidates.append(variant)

            # Word + year combos
            if append_years:
                for word in list(candidates):
                    for yr in all_years:
                        candidates.append(f"{word}{yr}")
                        candidates.append(f"{yr}{word}")

            # Word + special char combos (1-char suffix)
            if append_specials:
                for word in list(candidates):
                    for sp in special_chars:
                        candidates.append(f"{word}{sp}")

            # 1-3 char special suffix combos
            if append_specials:
                for word in list(candidates):
                    for sp1 in ["!", "@", "#", "$", "_", "."]:
                        for sp2 in ["", "1", "12", "123"]:
                            combo = f"{word}{sp1}{sp2}"
                            if combo not in candidates:
                                candidates.append(combo)

            for entry in candidates:
                if not entry:
                    continue
                if not (min_len <= len(entry) <= max_len):
                    continue
                if entry in seen:
                    continue
                seen.add(entry)
                dst.write(entry + "\n")
                written += 1

    return written

