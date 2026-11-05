"""
embedxpl.engines.wordlists.i18n - Localisation registry and translation helpers.

Basic usage:
    from embedxpl.engines.wordlists.i18n import t, set_session_locale, get_session_locale

    set_session_locale("pt-br")
    print(t("wizard.header"))
    print(t("children.birth", name="Pedro"))

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

from embedxpl.engines.wordlists.i18n.locale import (
    DEFAULT_LOCALE,
    SUPPORTED_LOCALES,
    detect_locale_from_text,
    get_element_for_sign,
    get_months,
    get_months_abbr,
    get_planet_for_sign,
    get_zodiac_alts,
    get_zodiac_names,
    normalise_locale,
    sign_index_from_day_month,
    sign_index_from_name,
)
from embedxpl.engines.wordlists.i18n.prompts import get_catalog

logger = logging.getLogger(__name__)

# ── Session state (thread-local) ──────────────────────────────────────────────

_session = threading.local()
_CATALOG: dict[str, dict[str, str]] = get_catalog()


def set_session_locale(locale: str) -> str:
    """Set the session locale (thread-safe via threading.local).

    Args:
        locale: locale string (e.g. 'pt-br', 'en', 'es').

    Returns:
        Normalised locale that was saved.
    """
    normalised = normalise_locale(locale)
    if normalised not in SUPPORTED_LOCALES:
        logger.warning("Locale '%s' not supported, falling back to '%s'.", locale, DEFAULT_LOCALE)
        normalised = DEFAULT_LOCALE
    _session.locale = normalised
    return normalised


def get_session_locale() -> str:
    """Return the active session locale, or DEFAULT_LOCALE if not set."""
    return getattr(_session, "locale", DEFAULT_LOCALE)


def t(key: str, locale: Optional[str] = None, **kwargs) -> str:
    """Translate a catalog key to the active locale (or the one provided).

    Args:
        key: dot-separated hierarchical key (e.g. 'wizard.header').
        locale: locale override — uses session locale when None.
        **kwargs: interpolation variables (e.g. name='Pedro').

    Returns:
        Translated string; falls back to the key itself if missing.
    """
    active_locale = locale or get_session_locale()
    entry = _CATALOG.get(key)
    if entry is None:
        logger.debug("i18n key missing: '%s'", key)
        return key

    text = entry.get(active_locale) or entry.get(DEFAULT_LOCALE) or key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError as exc:
            logger.debug("i18n interpolation failed for '%s': %s", key, exc)
    return text


def ask_language_selection() -> str:
    """Display language selection menu and read choice from stdin.

    Returns the normalised locale (defaults to 'en' on blank Enter).
    """
    print()
    print(t("lang.select_header", locale="en"))
    print(f"  {t('lang.option_en',    locale='en')}")
    print(f"  {t('lang.option_ptbr',  locale='en')}")
    print(f"  {t('lang.option_ptpt',  locale='en')}")
    print(f"  {t('lang.option_es',    locale='en')}")
    print()

    _map = {"1": "en", "2": "pt-br", "3": "pt-pt", "4": "es"}
    raw = input(f"  {t('lang.prompt', locale='en')}: ").strip()
    locale = _map.get(raw, DEFAULT_LOCALE)
    set_session_locale(locale)
    return locale


def register_extra_strings(extra: dict[str, dict[str, str]]) -> None:
    """Register additional strings into the catalog (useful for plugins/extensions).

    Args:
        extra: dict in the same format as _CATALOG.
    """
    _CATALOG.update(extra)


# ── Convenience re-exports ────────────────────────────────────────────────────

__all__ = [
    "DEFAULT_LOCALE",
    "SUPPORTED_LOCALES",
    "ask_language_selection",
    "detect_locale_from_text",
    "get_element_for_sign",
    "get_months",
    "get_months_abbr",
    "get_planet_for_sign",
    "get_session_locale",
    "get_zodiac_alts",
    "get_zodiac_names",
    "normalise_locale",
    "register_extra_strings",
    "set_session_locale",
    "sign_index_from_day_month",
    "sign_index_from_name",
    "t",
]
