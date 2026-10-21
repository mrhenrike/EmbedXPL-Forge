"""_interactive submodule of profiler."""
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

def _ask(prompt: str, required: bool = False, default_hint: str = "") -> str:
    """Prompt user for input, repeating if required and empty."""
    suffix = f" [{default_hint}]" if default_hint else ""
    while True:
        val = input(f"  {prompt}{suffix}: ").strip()
        if val or not required:
            return val


def _ask_multi(prompt: str, hint: str = "(one per line, empty to stop)") -> list[str]:
    """Collect multiple values, stopping on empty input."""
    print(f"  {prompt} {hint}:")
    values: list[str] = []
    while True:
        val = input("    > ").strip()
        if not val:
            break
        values.append(val)
    return values


def _ask_aliases(t_func, multi_hint: str) -> tuple[str, list[str]]:
    """Single prompt for short name + nicknames (deduplicated)."""
    aliases = _ask_multi(t_func("field.aliases"), multi_hint)
    seen: set[str] = set()
    unique: list[str] = []
    for a in aliases:
        key = a.casefold()
        if key not in seen:
            seen.add(key)
            unique.append(a)
    short_name = unique[0] if unique else ""
    return short_name, unique


_LEET_MODES = ("none", "basic", "medium", "aggressive")
_LEET_BY_NUM = {"1": "none", "2": "basic", "3": "medium", "4": "aggressive"}


def _ask_leet_mode(t_func, default: str = "basic") -> str:
    """Prompt leet mode via number (1-4) or slug."""
    print(f"  {t_func('gen.leet_menu')}")
    raw = input(f"  {t_func('engines.prompt')} [{default}]: ").strip().lower()
    if not raw:
        return default
    if raw in _LEET_BY_NUM:
        return _LEET_BY_NUM[raw]
    if raw in _LEET_MODES:
        return raw
    return default


def _yes(raw: str) -> bool:
    """True if the user answered affirmatively."""
    return raw.lower() in ("y", "yes", "s", "si", "sim", "oui")


def _no(raw: str) -> bool:
    """True if the user answered negatively."""
    return raw.lower() in ("n", "no", "nao", "não", "non")


def interactive_profile(
    preset_leet: str | None = None,
    preset_output: str | None = None,
) -> dict:
    """
    Full interactive personal profiling wizard with i18n support.

    The first prompt selects the session language; all subsequent prompts
    are shown in the chosen locale. Default locale is 'en'.

    Args:
        preset_leet: Leet mode from CLI/menu; skips duplicate prompt.
        preset_output: Output path from CLI/menu; skips duplicate path prompt.

    Returns:
        Dict with all collected profile data.
    """
    from embedxpl.engines.wordlists.date_profile import ask_date_profile, build_date_tokens
    from embedxpl.engines.wordlists.i18n import ask_language_selection, t

    # ── Language selection (first screen) ─────────────────────
    locale = ask_language_selection()
    profile: dict = {"locale": locale}

    print("\n" + "=" * 58)
    print(f"  {t('wizard.header')}")
    print("=" * 58 + "\n")

    # ── Personal ─────────────────────────────────────────────
    print(t("section.personal"))
    profile["full_name"] = _ask(t("field.full_name"))
    multi_hint = t("field.multi_hint")
    profile["short_name"], profile["nicknames"] = _ask_aliases(t, multi_hint)

    dp = ask_date_profile(t("date.label_birth"), locale)
    dp_dict = dp.to_dict()
    profile.update({
        "birth_day":        dp_dict["birth_day"],
        "birth_month":      dp_dict["birth_month"],
        "birth_year":       dp_dict["birth_year"],
        "birth_mode":       dp_dict["birth_mode"],
        "birth_age":        dp_dict["birth_age"],
        "birth_sign_index": dp_dict["birth_sign_index"],
        "birth_year_min":   dp_dict["birth_year_min"],
        "birth_year_max":   dp_dict["birth_year_max"],
        "birth_locale":     dp_dict["birth_locale"],
        "_date_tokens":     build_date_tokens(dp, locale),
    })

    profile["national_id"] = _ask(t("field.national_id"))
    profile["phones"] = _ask_multi(t("field.phones"), multi_hint)
    profile["location_city"] = _ask(t("field.city"))
    profile["location_state"] = _ask(t("field.state"))
    profile["location_country"] = _ask(t("field.country"))
    if profile.get("location_country"):
        try:
            from embedxpl.engines.wordlists.country_tokens import country_display_name, resolve_country
            _country_key = resolve_country(profile["location_country"])
            if _country_key:
                profile["location_country_key"] = _country_key
                print(f"  → Country resolved: {country_display_name(_country_key)} ({_country_key})")
        except ImportError:
            pass
        profile["include_country_variations"] = not _no(_ask(t("country.full_variations")))
    else:
        profile["include_country_variations"] = False

    # ── Partner ───────────────────────────────────────────────
    print(f"\n{t('section.partner')}")
    if _yes(_ask(t("partner.add"))):
        profile["partner_name"] = _ask(t("partner.full_name"))
        profile["partner_nick"] = _ask(t("partner.nick"))
        pdp = ask_date_profile(t("partner.full_name"), locale)
        pdp_dict = pdp.to_dict()
        profile["partner_birth_day"]   = pdp_dict["birth_day"]
        profile["partner_birth_month"] = pdp_dict["birth_month"]
        profile["partner_birth_year"]  = pdp_dict["birth_year"]
        profile["_partner_date_tokens"] = build_date_tokens(pdp, locale)

    # ── Children ──────────────────────────────────────────────
    print(f"\n{t('section.children')}")
    if _yes(_ask(t("children.add"))):
        profile["children"] = []
        while True:
            child_name = _ask(t("children.name"))
            if not child_name:
                break
            cdp = ask_date_profile(child_name, locale)
            cdp_dict = cdp.to_dict()
            profile["children"].append({
                "name":         child_name,
                "birth_day":    cdp_dict["birth_day"],
                "birth_month":  cdp_dict["birth_month"],
                "birth_year":   cdp_dict["birth_year"],
                "_date_tokens": build_date_tokens(cdp, locale),
            })

    # ── Pets ──────────────────────────────────────────────────
    print(f"\n{t('section.pets')}")
    if _yes(_ask(t("pets.add"))):
        profile["pets"] = []
        while True:
            pet_name = _ask(t("pets.name"))
            if not pet_name:
                break
            pet_year_raw = _ask(t("pets.year", name=pet_name))
            if pet_year_raw.strip().isdigit() and len(pet_year_raw.strip()) == 4:
                profile["pets"].append({"name": pet_name, "year": int(pet_year_raw.strip())})
            else:
                profile["pets"].append(pet_name)

    # ── Corporate ─────────────────────────────────────────────
    print(f"\n{t('section.corporate')}")
    if _yes(_ask(t("corp.add"))):
        profile["company_name"]       = _ask(t("corp.name"))
        profile["company_legal"]      = _ask(t("corp.legal"))
        profile["company_department"] = _ask(t("corp.department"))
        profile["company_email"]      = _ask(t("corp.email"))
        profile["company_domain"]     = _ask(t("corp.domain"))
        hdp = ask_date_profile(t("corp.hire_date"), locale)
        hdict = hdp.to_dict()
        profile["hire_day"]          = hdict["birth_day"]
        profile["hire_month"]        = hdict["birth_month"]
        profile["hire_year"]         = hdict["birth_year"]
        profile["hire_mode"]         = hdict["birth_mode"]
        profile["_hire_date_tokens"] = build_date_tokens(hdp, locale)

    # ── Social media ──────────────────────────────────────────
    profile["social_handles"] = _ask_multi(t("social.handles"), multi_hint)

    # ── Religion ──────────────────────────────────────────────
    print(f"\n{t('section.religion')}")
    profile["religion_key"] = None
    profile["religion_custom"] = None
    profile["church_name"] = None
    profile["church_group"] = None

    if _yes(_ask(t("religion.add"))):
        religions = list_religions()
        print("\n  Available religions (enter number or press Enter to type custom):")
        for idx, (key, display) in enumerate(religions, 1):
            print(f"    {idx:>2}. {display}")
        print(f"    {len(religions)+1:>2}. Other / not listed")

        choice_raw = _ask(t("religion.select", range=f"1-{len(religions)+1}")).strip()
        if choice_raw.isdigit():
            choice = int(choice_raw)
            if 1 <= choice <= len(religions):
                profile["religion_key"] = religions[choice - 1][0]
                print(f"  Selected: {religions[choice - 1][1]}")
            else:
                profile["religion_custom"] = _ask(t("religion.custom"))
        else:
            profile["religion_custom"] = choice_raw if choice_raw else None

        if profile["religion_key"] or profile["religion_custom"]:
            print()
            if _yes(_ask(t("church.add"))):
                profile["church_name"]  = _ask(t("church.name"))
                profile["church_group"] = _ask(t("church.group"))

    # ── Keywords & special dates ──────────────────────────────
    print(f"\n{t('section.keywords')}")
    profile["keywords"] = _ask_multi(t("keywords.list"), multi_hint)
    profile["special_dates"] = _ask_multi(t("keywords.special_dates"), multi_hint)

    # ── Phrases & jargon ─────────────────────────────────────
    print(f"\n{t('section.phrases')}")
    print(f"  {t('phrases.hint')}")
    profile["phrases"] = _ask_multi(t("phrases.enter"), multi_hint)
    if profile["phrases"]:
        phrase_mode_raw = _ask(t("phrases.mode")).strip()
        profile["phrase_mode"] = {"1": "acrostic", "2": "full", "3": "both"}.get(phrase_mode_raw, "both")
        profile["phrase_prefixes"] = not _no(_ask(t("phrases.prefixes")))
        profile["phrase_suffix_years"] = not _no(_ask(t("phrases.suffix_years")))
    else:
        profile["phrase_mode"] = "both"
        profile["phrase_prefixes"] = True
        profile["phrase_suffix_years"] = True

    # ── Keyword mutations (optional) ──────────────────────────
    print(f"\n{t('section.keyword_mutations')}")
    print(t("mutations.hint"))
    mutation_raw = _ask(t("mutations.ask"))
    if _yes(mutation_raw):
        sel = _ask(t("mutations.select")).strip()
        modes = []
        for part in sel.replace(",", " ").split():
            if part == "1":
                modes.append("letter_reverse")
            elif part == "2":
                modes.append("syllable_reverse")
            elif part == "3":
                modes.append("syllable_rotate")
        profile["keyword_mutations"] = {
            "enabled": True,
            "modes": modes or ["letter_reverse", "syllable_reverse"],
        }
    else:
        profile["keyword_mutations"] = {"enabled": False, "modes": []}

    # ── Engine selection ──────────────────────────────────────
    print(f"\n{t('section.engines')}")
    try:
        from embedxpl.engines.wordlists.generation_engines import ask_engine_selection
        engine_ids = ask_engine_selection(t_func=t)
        if engine_ids:
            profile["_engine_ids"] = sorted(engine_ids)
    except ImportError:
        pass

    # ── Generation options ────────────────────────────────────
    print(f"\n{t('section.generation')}")
    if preset_leet is not None:
        profile["leet_mode"] = preset_leet
    elif not profile.get("leet_mode"):
        profile["leet_mode"] = _ask_leet_mode(t)
    profile["with_spaces"] = _yes(_ask(t("gen.with_spaces")))
    profile["use_behavior_patterns"] = not _no(_ask(t("gen.behavior_patterns")))
    min_raw = _ask(t("gen.min_len"))
    max_raw = _ask(t("gen.max_len"))
    profile["min_len"] = int(min_raw) if min_raw.isdigit() else 6
    profile["max_len"] = int(max_raw) if max_raw.isdigit() and int(max_raw) > 0 else 32
    profile["include_specials"] = _yes(_ask(t("gen.include_specials")))
    profile["include_recent_years"] = not _no(_ask(t("gen.include_recent_years")))
    if profile.get("include_recent_years", True):
        lb_raw = _ask(t("gen.recent_years_lookback"))
        profile["recent_years_lookback"] = int(lb_raw) if lb_raw.isdigit() else 1
    else:
        profile["recent_years_lookback"] = 0

    # ── Output finalization ────────────────────────────────────
    print(f"\n{t('section.output')}")
    preset_out = (preset_output or "").strip()
    try:
        from embedxpl.engines.wordlists.archive_export import ask_export_options
        export_opts, _ = ask_export_options(t_func=t, ask_path=False)
        export_fmt = export_opts.format.value
        profile["output"] = {
            "sanitize": export_opts.sanitize,
            "dedupe":   export_opts.dedupe,
            "sort":     export_opts.sort,
            "format":   export_fmt,
        }
        print(t(
            "output.summary",
            sanitize=t("output.val_yes") if export_opts.sanitize else t("output.val_no"),
            sort=export_opts.sort or "none",
            format=export_fmt,
        ))
    except ImportError:
        export_fmt = "lst"
        profile["output"] = {}

    if preset_out:
        out_raw = preset_out
        print(t("output.using_path", path=preset_out))
    else:
        default_out = suggested_profile_output_path(profile, export_fmt)
        out_raw = _ask(t("output.path"), default_hint=default_out)
        if not out_raw:
            out_raw = default_out

    profile["output_path"] = normalize_profile_output_path(out_raw, profile, export_fmt)
    print(t("output.will_save", path=profile["output_path"]))

    profile["interactive_mode"] = True

    return profile


# ── Behavioral pattern generator ──────────────────────────────────────────────

