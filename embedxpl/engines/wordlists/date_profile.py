"""
date_profile.py - Flexible date profile for wordlist generation.

Replaces the limited date handling in profiler.py, supporting:
  - Full date (dd/mm/yyyy)
  - Month and year (mm/yyyy)
  - Year only (yyyy)
  - Approximate age (derives a window of possible birth years)
  - Age + zodiac sign (without needing the exact date)

Integrates with i18n for multilingual tokens: months, signs, elements, and rulers.

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from embedxpl.engines.wordlists.i18n import (
    get_element_for_sign,
    get_months,
    get_months_abbr,
    get_planet_for_sign,
    get_session_locale,
    get_zodiac_alts,
    get_zodiac_names,
    sign_index_from_day_month,
    sign_index_from_name,
    t,
)

logger = logging.getLogger(__name__)

_CURRENT_YEAR = datetime.now().year


# ── Enums ─────────────────────────────────────────────────────────────────────

class DateMode(str, Enum):
    """User date input mode."""
    FULL = "full"            # dd/mm/yyyy
    MONTH_YEAR = "month_year"  # mm/yyyy
    YEAR = "year"            # yyyy
    AGE = "age"              # age → year window
    AGE_SIGN = "age_sign"    # age + zodiac sign
    SKIP = "skip"            # no date


# ── Dataclass principal ───────────────────────────────────────────────────────

@dataclass
class DateProfile:
    """
    Date profile for an entity (person, partner, company, etc.).

    Date fields are optional; 0 means unknown.
    sign_index points to ZODIAC_KEYS[sign_index].
    """
    mode: DateMode = DateMode.SKIP
    day: int = 0
    month: int = 0
    year: int = 0
    age: Optional[int] = None
    sign_index: Optional[int] = None  # 0-11, mapped in i18n/locale.py

    # year window derived from age (for AGE/AGE_SIGN modes)
    year_min: int = 0
    year_max: int = 0

    # locale used when this profile was created (for correct tokens)
    locale: str = "en"

    def __post_init__(self) -> None:
        if self.mode in (DateMode.AGE, DateMode.AGE_SIGN) and self.age:
            self._resolve_age_window()
        elif self.mode == DateMode.FULL and self.year and self.day and self.month:
            self._resolve_sign_from_full()

    def _resolve_age_window(self) -> None:
        """Derive birth-year window from age."""
        base = _CURRENT_YEAR - self.age
        # a person aged X may have been born in base or base-1
        self.year_min = base - 1
        self.year_max = base
        if not self.year:
            self.year = base  # central estimate

    def _resolve_sign_from_full(self) -> None:
        """If full date is known and sign is still unknown, derive the sign."""
        if self.sign_index is None:
            self.sign_index = sign_index_from_day_month(self.day, self.month)

    def has_sign(self) -> bool:
        return self.sign_index is not None

    def has_year(self) -> bool:
        return self.year > 0

    def has_month(self) -> bool:
        return self.month > 0

    def has_day(self) -> bool:
        return self.day > 0

    def year_range(self) -> range:
        """Return the range of possible years for this entity."""
        if self.mode in (DateMode.AGE, DateMode.AGE_SIGN) and self.year_min and self.year_max:
            return range(self.year_min, self.year_max + 1)
        if self.has_year():
            return range(self.year, self.year + 1)
        return range(0)

    def to_dict(self) -> dict:
        """Convert to a dict compatible with the profiler's legacy format."""
        return {
            "birth_day":   self.day,
            "birth_month": self.month,
            "birth_year":  self.year,
            "birth_mode":  self.mode.value,
            "birth_age":   self.age,
            "birth_sign_index": self.sign_index,
            "birth_year_min": self.year_min,
            "birth_year_max": self.year_max,
            "birth_locale": self.locale,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DateProfile":
        """Reconstruct a DateProfile from a profile dictionary."""
        return cls(
            mode=DateMode(d.get("birth_mode", "skip")),
            day=d.get("birth_day", 0),
            month=d.get("birth_month", 0),
            year=d.get("birth_year", 0),
            age=d.get("birth_age"),
            sign_index=d.get("birth_sign_index"),
            year_min=d.get("birth_year_min", 0),
            year_max=d.get("birth_year_max", 0),
            locale=d.get("birth_locale", "en"),
        )


# ── Parsers ────────────────────────────────────────────────────────────────────

def parse_full_date(raw: str) -> Optional[tuple[int, int, int]]:
    """
    Parse a full date in multiple formats.

    Accepted formats: dd/mm/yyyy, dd-mm-yyyy, dd.mm.yyyy, ddmmyyyy.

    Returns:
        Tuple (day, month, year) or None.
    """
    raw = raw.strip()
    if not raw:
        return None

    if re.fullmatch(r"\d{8}", raw):
        d, m, y = int(raw[:2]), int(raw[2:4]), int(raw[4:])
        return (d, m, y) if 1 <= d <= 31 and 1 <= m <= 12 else None

    match = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})", raw)
    if match:
        d, m, y = int(match.group(1)), int(match.group(2)), int(match.group(3))
        return (d, m, y) if 1 <= d <= 31 and 1 <= m <= 12 else None

    return None


def parse_month_year(raw: str) -> Optional[tuple[int, int]]:
    """
    Parse a month/year entry.

    Accepted formats: mm/yyyy, mm-yyyy, mm.yyyy.

    Returns:
        Tuple (month, year) or None.
    """
    raw = raw.strip()
    match = re.fullmatch(r"(\d{1,2})[/\-.](\d{4})", raw)
    if match:
        m, y = int(match.group(1)), int(match.group(2))
        return (m, y) if 1 <= m <= 12 else None
    return None


def parse_year_only(raw: str) -> Optional[int]:
    """
    Parse a year only (4 digits).

    Returns:
        Integer year or None.
    """
    raw = raw.strip()
    if re.fullmatch(r"\d{4}", raw):
        y = int(raw)
        return y if 1900 <= y <= _CURRENT_YEAR + 1 else None
    return None


def parse_age(raw: str) -> Optional[int]:
    """
    Parse an approximate age (positive integer).

    Returns:
        Integer age or None.
    """
    raw = raw.strip()
    if re.fullmatch(r"\d{1,3}", raw):
        age = int(raw)
        return age if 0 < age < 130 else None
    return None


# ── Construção de DateProfile a partir de raw input ───────────────────────────

def date_profile_from_full(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Create a DateProfile in FULL mode from a date string."""
    parsed = parse_full_date(raw)
    if not parsed:
        return None
    d, m, y = parsed
    return DateProfile(mode=DateMode.FULL, day=d, month=m, year=y, locale=locale)


def date_profile_from_month_year(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Create a DateProfile in MONTH_YEAR mode."""
    parsed = parse_month_year(raw)
    if not parsed:
        return None
    m, y = parsed
    return DateProfile(mode=DateMode.MONTH_YEAR, month=m, year=y, locale=locale)


def date_profile_from_year(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Create a DateProfile in YEAR mode."""
    y = parse_year_only(raw)
    if y is None:
        return None
    return DateProfile(mode=DateMode.YEAR, year=y, locale=locale)


def date_profile_from_age(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Create a DateProfile in AGE mode."""
    age = parse_age(raw)
    if age is None:
        return None
    return DateProfile(mode=DateMode.AGE, age=age, locale=locale)


def date_profile_from_age_sign(age_raw: str, sign_raw: str, locale: str = "en") -> Optional[DateProfile]:
    """
    Create a DateProfile in AGE_SIGN mode from an age and a sign name.

    Args:
        age_raw: Age string (e.g. '26').
        sign_raw: Sign name in the active locale (e.g. 'touro', 'taurus').
        locale: Locale for sign lookup.

    Returns:
        DateProfile with age + sign_index, or None if parsing fails.
    """
    age = parse_age(age_raw)
    if age is None:
        return None
    sign_idx = sign_index_from_name(sign_raw, locale)
    if sign_idx is None:
        logger.warning("Unrecognized sign: '%s' (locale: %s)", sign_raw, locale)
        return None
    return DateProfile(mode=DateMode.AGE_SIGN, age=age, sign_index=sign_idx, locale=locale)


def date_profile_from_yaml(entry: dict | str, locale: str = "en") -> Optional[DateProfile]:
    """
    Create a DateProfile from a YAML entry.

    Supports both formats:
      - Legacy (string): birth: "dd/mm/yyyy" or yyyy
      - Structured (dict): {mode: age_sign, age: 26, sign: touro}

    Args:
        entry: Value of the birth/hire YAML field.
        locale: Active session locale.

    Returns:
        DateProfile or None.
    """
    if entry is None:
        return DateProfile(mode=DateMode.SKIP, locale=locale)

    if isinstance(entry, str):
        # Legacy format: try to parse as full date, month/year, or year only
        dp = date_profile_from_full(entry, locale)
        if dp:
            return dp
        dp = date_profile_from_month_year(entry, locale)
        if dp:
            return dp
        # May be just an age
        if re.fullmatch(r"\d{1,3}", entry.strip()) and int(entry.strip()) < 120:
            return date_profile_from_age(entry, locale)
        dp = date_profile_from_year(entry, locale)
        return dp

    if isinstance(entry, dict):
        mode_str = entry.get("mode", "skip")
        try:
            mode = DateMode(mode_str)
        except ValueError:
            logger.warning("Unknown date mode: '%s'", mode_str)
            mode = DateMode.SKIP

        if mode == DateMode.FULL:
            return date_profile_from_full(str(entry.get("value", "")), locale)

        if mode == DateMode.MONTH_YEAR:
            return date_profile_from_month_year(str(entry.get("value", "")), locale)

        if mode == DateMode.YEAR:
            raw_year = str(entry.get("value", entry.get("year", "")))
            return date_profile_from_year(raw_year, locale)

        if mode == DateMode.AGE:
            return date_profile_from_age(str(entry.get("age", "")), locale)

        if mode == DateMode.AGE_SIGN:
            age_raw = str(entry.get("age", ""))
            sign_raw = str(entry.get("sign", ""))
            return date_profile_from_age_sign(age_raw, sign_raw, locale)

        return DateProfile(mode=DateMode.SKIP, locale=locale)

    return None


# ── Geração de tokens a partir de DateProfile ────────────────────────────────

def build_date_tokens(dp: DateProfile, locale: Optional[str] = None) -> list[str]:
    """
    Build a wordlist token list from a DateProfile.

    Tokens included (depending on mode):
      - Numeric fragments: day, month, year, yy, ddmm, mmyyyy, etc.
      - Month names in the active locale
      - Sign names + variations + element + ruler
      - Years in the age window (AGE/AGE_SIGN modes)

    Args:
        dp: DateProfile for the entity.
        locale: Locale override (uses dp.locale by default).

    Returns:
        List of token strings (no duplicates, lowercase).
    """
    active_locale = locale or dp.locale or get_session_locale()
    tokens: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        sv = s.strip()
        if sv and sv not in seen:
            seen.add(sv)
            tokens.append(sv)

    # ── Tokens numéricos ──────────────────────────────────────────────────────
    if dp.has_day():
        add(f"{dp.day:02d}")
        add(str(dp.day))

    if dp.has_month():
        add(f"{dp.month:02d}")
        add(str(dp.month))
        months = get_months(active_locale)
        abbr = get_months_abbr(active_locale)
        if 1 <= dp.month <= 12:
            add(months[dp.month - 1])
            add(abbr[dp.month - 1])

    if dp.has_day() and dp.has_month():
        add(f"{dp.day:02d}{dp.month:02d}")
        add(f"{dp.month:02d}{dp.day:02d}")

    if dp.has_year():
        yy = str(dp.year)
        add(yy)
        add(yy[2:])  # short year (26, 99, etc.)
        if dp.has_month():
            add(f"{dp.month:02d}{yy}")
            add(f"{yy}{dp.month:02d}")
        if dp.has_day():
            add(f"{dp.day:02d}{dp.month:02d}{yy}" if dp.has_month() else f"{dp.day:02d}{yy}")

    # ── Age window tokens ─────────────────────────────────────────────────────
    for yr in dp.year_range():
        if yr > 0:
            add(str(yr))
            add(str(yr)[2:])

    if dp.age is not None:
        add(str(dp.age))

    # ── Sign tokens ───────────────────────────────────────────────────────────
    if dp.has_sign():
        idx = dp.sign_index
        # primary name in the active locale
        names = get_zodiac_names(active_locale)
        if 0 <= idx < len(names):
            add(names[idx])
        # variações/aliases no locale ativo
        for alt in get_zodiac_alts(active_locale, idx):
            add(alt)
        # elemento e regente
        el = get_element_for_sign(idx, active_locale)
        if el:
            add(el)
        pl = get_planet_for_sign(idx, active_locale)
        if pl:
            add(pl)

    return tokens


# ── Wizard interativo ─────────────────────────────────────────────────────────

def ask_date_profile(label: str, locale: Optional[str] = None) -> DateProfile:
    """
    Interactive wizard to collect a date for an entity.

    Args:
        label: Entity name (e.g. 'target', 'partner').
        locale: Locale override (uses session locale if None).

    Returns:
        Populated DateProfile.
    """
    active_locale = locale or get_session_locale()

    print(f"\n  {label} - {t('date.menu_header', active_locale)}")
    print(f"    {t('date.mode_full',       active_locale)}")
    print(f"    {t('date.mode_month_year', active_locale)}")
    print(f"    {t('date.mode_year',       active_locale)}")
    print(f"    {t('date.mode_age',        active_locale)}")
    print(f"    {t('date.mode_age_sign',   active_locale)}")
    print(f"    {t('date.mode_skip',       active_locale)}")
    print()

    while True:
        raw = input(f"    {t('date.mode_select', active_locale)}: ").strip()
        if raw in ("", "6"):
            return DateProfile(mode=DateMode.SKIP, locale=active_locale)
        if raw == "1":
            v = input(f"    {t('date.prompt_full', active_locale)}: ").strip()
            dp = date_profile_from_full(v, active_locale)
            if dp:
                return dp
        elif raw == "2":
            v = input(f"    {t('date.prompt_month_year', active_locale)}: ").strip()
            dp = date_profile_from_month_year(v, active_locale)
            if dp:
                return dp
        elif raw == "3":
            v = input(f"    {t('date.prompt_year', active_locale)}: ").strip()
            dp = date_profile_from_year(v, active_locale)
            if dp:
                return dp
        elif raw == "4":
            v = input(f"    {t('date.prompt_age', active_locale)}: ").strip()
            dp = date_profile_from_age(v, active_locale)
            if dp:
                return dp
        elif raw == "5":
            age_v = input(f"    {t('date.prompt_age', active_locale)}: ").strip()
            sign_v = input(f"    {t('date.prompt_sign', active_locale)}: ").strip()
            dp = date_profile_from_age_sign(age_v, sign_v, active_locale)
            if dp:
                return dp
            print(f"    {t('msg.invalid_choice', active_locale)}")
            continue
        else:
            print(f"    {t('msg.invalid_choice', active_locale)}")
            continue
        print(f"    {t('msg.invalid_choice', active_locale)}")
