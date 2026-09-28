"""
date_profile.py - Perfil de data flexível para geração de wordlists.

Substitui o tratamento limitado de datas em profiler.py, suportando:
  - Data completa (dd/mm/yyyy)
  - Mês e ano (mm/yyyy)
  - Apenas ano (yyyy)
  - Idade aproximada (deriva janela de anos possíveis)
  - Idade + signo do zodíaco (sem precisar da data exata)

Integra com i18n para tokens multilíngues de meses, signos, elementos e regentes.

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Optional

from embedxpl.engines.wordlists.i18n import (
    get_months,
    get_months_abbr,
    get_zodiac_names,
    get_zodiac_alts,
    get_element_for_sign,
    get_planet_for_sign,
    sign_index_from_day_month,
    sign_index_from_name,
    t,
    get_session_locale,
)

logger = logging.getLogger(__name__)

_CURRENT_YEAR = datetime.now().year


# ── Enums ─────────────────────────────────────────────────────────────────────

class DateMode(str, Enum):
    """Modo de entrada de data do usuário."""
    FULL = "full"            # dd/mm/yyyy
    MONTH_YEAR = "month_year"  # mm/yyyy
    YEAR = "year"            # yyyy
    AGE = "age"              # idade → janela de anos
    AGE_SIGN = "age_sign"    # idade + signo
    SKIP = "skip"            # sem data


# ── Dataclass principal ───────────────────────────────────────────────────────

@dataclass
class DateProfile:
    """
    Perfil de data para uma entidade (pessoa, parceiro, empresa, etc.).

    Campos de data são opcionais; 0 indica desconhecido.
    O campo sign_index aponta para ZODIAC_KEYS[sign_index].
    """
    mode: DateMode = DateMode.SKIP
    day: int = 0
    month: int = 0
    year: int = 0
    age: Optional[int] = None
    sign_index: Optional[int] = None  # 0-11, mapeado em i18n/locale.py

    # janela de anos derivada da idade (para modo AGE/AGE_SIGN)
    year_min: int = 0
    year_max: int = 0

    # locale que foi usado ao criar este perfil (para tokens corretos)
    locale: str = "en"

    def __post_init__(self) -> None:
        if self.mode in (DateMode.AGE, DateMode.AGE_SIGN) and self.age:
            self._resolve_age_window()
        elif self.mode == DateMode.FULL and self.year and self.day and self.month:
            self._resolve_sign_from_full()

    def _resolve_age_window(self) -> None:
        """Deriva janela de ano de nascimento a partir da idade."""
        base = _CURRENT_YEAR - self.age
        # pessoa com X anos pode ter nascido em base ou base-1
        self.year_min = base - 1
        self.year_max = base
        if not self.year:
            self.year = base  # estimativa central

    def _resolve_sign_from_full(self) -> None:
        """Se data completa e signo ainda desconhecido, derivar signo."""
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
        """Retorna range de anos possíveis para esta entidade."""
        if self.mode in (DateMode.AGE, DateMode.AGE_SIGN) and self.year_min and self.year_max:
            return range(self.year_min, self.year_max + 1)
        if self.has_year():
            return range(self.year, self.year + 1)
        return range(0)

    def to_dict(self) -> dict:
        """Converte para dicionário compatível com o formato legado do profiler."""
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
        """Reconstrói DateProfile a partir de dicionário do perfil."""
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
    Parseia data completa em múltiplos formatos.

    Formatos aceitos: dd/mm/yyyy, dd-mm-yyyy, dd.mm.yyyy, ddmmyyyy.

    Returns:
        Tupla (day, month, year) ou None.
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
    Parseia entrada de mês/ano.

    Formatos aceitos: mm/yyyy, mm-yyyy, mm.yyyy.

    Returns:
        Tupla (month, year) ou None.
    """
    raw = raw.strip()
    match = re.fullmatch(r"(\d{1,2})[/\-.](\d{4})", raw)
    if match:
        m, y = int(match.group(1)), int(match.group(2))
        return (m, y) if 1 <= m <= 12 else None
    return None


def parse_year_only(raw: str) -> Optional[int]:
    """
    Parseia apenas o ano (4 dígitos).

    Returns:
        Ano inteiro ou None.
    """
    raw = raw.strip()
    if re.fullmatch(r"\d{4}", raw):
        y = int(raw)
        return y if 1900 <= y <= _CURRENT_YEAR + 1 else None
    return None


def parse_age(raw: str) -> Optional[int]:
    """
    Parseia idade aproximada (número inteiro positivo).

    Returns:
        Idade inteira ou None.
    """
    raw = raw.strip()
    if re.fullmatch(r"\d{1,3}", raw):
        age = int(raw)
        return age if 0 < age < 130 else None
    return None


# ── Construção de DateProfile a partir de raw input ───────────────────────────

def date_profile_from_full(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Cria DateProfile no modo FULL a partir de string de data."""
    parsed = parse_full_date(raw)
    if not parsed:
        return None
    d, m, y = parsed
    return DateProfile(mode=DateMode.FULL, day=d, month=m, year=y, locale=locale)


def date_profile_from_month_year(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Cria DateProfile no modo MONTH_YEAR."""
    parsed = parse_month_year(raw)
    if not parsed:
        return None
    m, y = parsed
    return DateProfile(mode=DateMode.MONTH_YEAR, month=m, year=y, locale=locale)


def date_profile_from_year(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Cria DateProfile no modo YEAR."""
    y = parse_year_only(raw)
    if y is None:
        return None
    return DateProfile(mode=DateMode.YEAR, year=y, locale=locale)


def date_profile_from_age(raw: str, locale: str = "en") -> Optional[DateProfile]:
    """Cria DateProfile no modo AGE."""
    age = parse_age(raw)
    if age is None:
        return None
    return DateProfile(mode=DateMode.AGE, age=age, locale=locale)


def date_profile_from_age_sign(age_raw: str, sign_raw: str, locale: str = "en") -> Optional[DateProfile]:
    """
    Cria DateProfile no modo AGE_SIGN a partir de idade e nome do signo.

    Args:
        age_raw: string com a idade (ex: '26').
        sign_raw: nome do signo no locale ativo (ex: 'touro', 'taurus').
        locale: locale para lookup do signo.

    Returns:
        DateProfile com age + sign_index, ou None se parsing falhar.
    """
    age = parse_age(age_raw)
    if age is None:
        return None
    sign_idx = sign_index_from_name(sign_raw, locale)
    if sign_idx is None:
        logger.warning("Signo não reconhecido: '%s' (locale: %s)", sign_raw, locale)
        return None
    return DateProfile(mode=DateMode.AGE_SIGN, age=age, sign_index=sign_idx, locale=locale)


def date_profile_from_yaml(entry: dict | str, locale: str = "en") -> Optional[DateProfile]:
    """
    Cria DateProfile a partir de entrada YAML.

    Suporta ambos os formatos:
      - Legado (string): birth: "dd/mm/yyyy" ou yyyy
      - Estruturado (dict): {mode: age_sign, age: 26, sign: touro}

    Args:
        entry: valor do campo birth/hire do YAML.
        locale: locale ativo da sessão.

    Returns:
        DateProfile ou None.
    """
    if entry is None:
        return DateProfile(mode=DateMode.SKIP, locale=locale)

    if isinstance(entry, str):
        # formato legado: tenta parsear como data completa, mês/ano ou apenas ano
        dp = date_profile_from_full(entry, locale)
        if dp:
            return dp
        dp = date_profile_from_month_year(entry, locale)
        if dp:
            return dp
        # Pode ser apenas idade
        if re.fullmatch(r"\d{1,3}", entry.strip()) and int(entry.strip()) < 120:
            return date_profile_from_age(entry, locale)
        dp = date_profile_from_year(entry, locale)
        return dp

    if isinstance(entry, dict):
        mode_str = entry.get("mode", "skip")
        try:
            mode = DateMode(mode_str)
        except ValueError:
            logger.warning("Modo de data desconhecido: '%s'", mode_str)
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
    Gera lista de tokens de wordlist a partir de um DateProfile.

    Tokens incluídos (dependendo do modo):
      - Fragmentos numéricos: dia, mês, ano, yy, ddmm, mmyyyy, etc.
      - Nomes de meses no locale ativo
      - Nomes de signo + variações + elemento + regente
      - Anos da janela de idade (modo AGE/AGE_SIGN)

    Args:
        dp: DateProfile da entidade.
        locale: override de locale (usa dp.locale por padrão).

    Returns:
        Lista de strings de token (sem duplicatas, lowercase).
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

    # ── Tokens da janela de idade ─────────────────────────────────────────────
    for yr in dp.year_range():
        if yr > 0:
            add(str(yr))
            add(str(yr)[2:])

    if dp.age is not None:
        add(str(dp.age))

    # ── Tokens de signo ───────────────────────────────────────────────────────
    if dp.has_sign():
        idx = dp.sign_index
        # nome principal no locale ativo
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
    Wizard interativo para coleta de data de uma entidade.

    Args:
        label: nome da entidade (ex: 'target', 'partner').
        locale: override de locale (usa sessão se None).

    Returns:
        DateProfile preenchido.
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
