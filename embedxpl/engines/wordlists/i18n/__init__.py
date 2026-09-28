"""
embedxpl.engines.wordlists.i18n - Registry de localização e funções de tradução.

Uso básico:
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
    SUPPORTED_LOCALES,
    DEFAULT_LOCALE,
    normalise_locale,
    detect_locale_from_text,
    get_months,
    get_months_abbr,
    get_zodiac_names,
    get_zodiac_alts,
    sign_index_from_day_month,
    sign_index_from_name,
    get_element_for_sign,
    get_planet_for_sign,
)
from embedxpl.engines.wordlists.i18n.prompts import get_catalog

logger = logging.getLogger(__name__)

# ── Estado de sessão (thread-local) ───────────────────────────────────────────

_session = threading.local()
_CATALOG: dict[str, dict[str, str]] = get_catalog()


def set_session_locale(locale: str) -> str:
    """
    Define o locale da sessão atual (thread-safe via threading.local).

    Args:
        locale: string de locale (ex: 'pt-br', 'en', 'es').

    Returns:
        Locale normalizado que foi salvo.
    """
    normalised = normalise_locale(locale)
    if normalised not in SUPPORTED_LOCALES:
        logger.warning("Locale '%s' não suportado, usando '%s'.", locale, DEFAULT_LOCALE)
        normalised = DEFAULT_LOCALE
    _session.locale = normalised
    return normalised


def get_session_locale() -> str:
    """Retorna o locale da sessão atual, ou DEFAULT_LOCALE se não definido."""
    return getattr(_session, "locale", DEFAULT_LOCALE)


def t(key: str, locale: Optional[str] = None, **kwargs) -> str:
    """
    Traduz uma chave do catálogo para o locale ativo (ou o fornecido).

    Args:
        key: chave hierárquica com ponto (ex: 'wizard.header').
        locale: override de locale (usa sessão se None).
        **kwargs: variáveis de interpolação (ex: name='Pedro').

    Returns:
        String traduzida; se chave ausente, retorna a própria chave como fallback.
    """
    active_locale = locale or get_session_locale()
    entry = _CATALOG.get(key)
    if entry is None:
        logger.debug("Chave i18n ausente: '%s'", key)
        return key

    text = entry.get(active_locale) or entry.get(DEFAULT_LOCALE) or key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError as exc:
            logger.debug("Interpolação i18n falhou em '%s': %s", key, exc)
    return text


def ask_language_selection() -> str:
    """
    Exibe menu de seleção de idioma e lê escolha via stdin.
    Retorna locale normalizado (default 'en' se Enter em branco).
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
    """
    Registra strings adicionais no catálogo (útil para plugins/extensões).

    Args:
        extra: dicionário no mesmo formato do _CATALOG.
    """
    _CATALOG.update(extra)


# ── Re-exports convenientes ────────────────────────────────────────────────────

__all__ = [
    "t",
    "set_session_locale",
    "get_session_locale",
    "ask_language_selection",
    "register_extra_strings",
    "SUPPORTED_LOCALES",
    "DEFAULT_LOCALE",
    "normalise_locale",
    "detect_locale_from_text",
    "get_months",
    "get_months_abbr",
    "get_zodiac_names",
    "get_zodiac_alts",
    "sign_index_from_day_month",
    "sign_index_from_name",
    "get_element_for_sign",
    "get_planet_for_sign",
]
