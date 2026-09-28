"""
locale.py - Dados de localização para geração de wordlists.

Contém meses, signos do zodíaco, elementos e regentes planetários
nos quatro locales suportados: en, pt-br, pt-pt, es.

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

from typing import Optional

# ── Locales suportados ────────────────────────────────────────────────────────

SUPPORTED_LOCALES: tuple[str, ...] = ("en", "pt-br", "pt-pt", "es")
DEFAULT_LOCALE = "en"


# ── Meses ─────────────────────────────────────────────────────────────────────

MONTHS: dict[str, list[str]] = {
    "en": [
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
    ],
    "pt-br": [
        "janeiro", "fevereiro", "março", "abril", "maio", "junho",
        "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    ],
    "pt-pt": [
        "janeiro", "fevereiro", "março", "abril", "maio", "junho",
        "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
    ],
    "es": [
        "enero", "febrero", "marzo", "abril", "mayo", "junio",
        "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
    ],
}

MONTHS_ABBR: dict[str, list[str]] = {
    "en":    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"],
    "pt-br": ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"],
    "pt-pt": ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"],
    "es":    ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"],
}


# ── Signos do zodíaco ─────────────────────────────────────────────────────────
# (mm_start, dd_start, mm_end, dd_end)
ZODIAC_RANGES: list[tuple[int, int, int, int]] = [
    (3, 21, 4, 19),   # aries
    (4, 20, 5, 20),   # taurus
    (5, 21, 6, 20),   # gemini
    (6, 21, 7, 22),   # cancer
    (7, 23, 8, 22),   # leo
    (8, 23, 9, 22),   # virgo
    (9, 23, 10, 22),  # libra
    (10, 23, 11, 21), # scorpio
    (11, 22, 12, 21), # sagittarius
    (12, 22, 1, 19),  # capricorn
    (1, 20, 2, 18),   # aquarius
    (2, 19, 3, 20),   # pisces
]

ZODIAC_KEYS: tuple[str, ...] = (
    "aries", "taurus", "gemini", "cancer", "leo", "virgo",
    "libra", "scorpio", "sagittarius", "capricorn", "aquarius", "pisces",
)

ZODIAC_NAMES: dict[str, list[str]] = {
    "en": [
        "aries", "taurus", "gemini", "cancer", "leo", "virgo",
        "libra", "scorpio", "sagittarius", "capricorn", "aquarius", "pisces",
    ],
    "pt-br": [
        "aries", "touro", "gemeos", "cancer", "leao", "virgem",
        "libra", "escorpiao", "sagitario", "capricornio", "aquario", "peixes",
    ],
    "pt-pt": [
        "aries", "touro", "gemeos", "cancer", "leao", "virgem",
        "libra", "escorpiao", "sagitario", "capricornio", "aquario", "peixes",
    ],
    "es": [
        "aries", "tauro", "geminis", "cancer", "leo", "virgo",
        "libra", "escorpio", "sagitario", "capricornio", "acuario", "piscis",
    ],
}

ZODIAC_NAMES_ALT: dict[str, list[list[str]]] = {
    "en": [
        ["aries", "ram"],
        ["taurus", "bull"],
        ["gemini", "twins"],
        ["cancer", "crab"],
        ["leo", "lion"],
        ["virgo", "maiden"],
        ["libra", "scales"],
        ["scorpio", "scorpion", "scorpius"],
        ["sagittarius", "archer"],
        ["capricorn", "capricornus", "goat"],
        ["aquarius", "waterbearer"],
        ["pisces", "fish"],
    ],
    "pt-br": [
        ["aries", "carneiro"],
        ["touro", "taurus"],
        ["gemeos", "gemini"],
        ["cancer", "caranguejo"],
        ["leao", "leo"],
        ["virgem", "virgo"],
        ["libra", "balanca"],
        ["escorpiao", "scorpio"],
        ["sagitario", "sagittarius"],
        ["capricornio", "capricorn"],
        ["aquario", "aquarius"],
        ["peixes", "pisces"],
    ],
    "pt-pt": [
        ["aries", "carneiro"],
        ["touro", "taurus"],
        ["gemeos", "gemini"],
        ["cancer", "caranguejo"],
        ["leao", "leo"],
        ["virgem", "virgo"],
        ["libra", "balanca"],
        ["escorpiao", "scorpio"],
        ["sagitario", "sagittarius"],
        ["capricornio", "capricorn"],
        ["aquario", "aquarius"],
        ["peixes", "pisces"],
    ],
    "es": [
        ["aries", "carnero"],
        ["tauro", "toro"],
        ["geminis", "gemelos"],
        ["cancer", "cangrejo"],
        ["leo", "leon"],
        ["virgo", "doncella"],
        ["libra", "balanza"],
        ["escorpio", "escorpion"],
        ["sagitario", "arquero"],
        ["capricornio", "cabra"],
        ["acuario", "aguador"],
        ["piscis", "pez"],
    ],
}


# ── Elementos ─────────────────────────────────────────────────────────────────

# Mapeamento signo_index → elemento_index (0=fire,1=earth,2=air,3=water)
ZODIAC_ELEMENT_IDX: tuple[int, ...] = (0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3)

ELEMENTS: dict[str, list[str]] = {
    "en":    ["fire", "earth", "air", "water"],
    "pt-br": ["fogo", "terra", "ar", "agua"],
    "pt-pt": ["fogo", "terra", "ar", "agua"],
    "es":    ["fuego", "tierra", "aire", "agua"],
}


# ── Regentes planetários ──────────────────────────────────────────────────────

# Mapeamento signo_index → planeta_index (ordem: mars, venus, mercury, moon, sun, mercury2, venus2, pluto/mars, jupiter, saturn, uranus, neptune)
ZODIAC_PLANET_IDX: tuple[int, ...] = (0, 1, 2, 3, 4, 2, 1, 5, 6, 7, 8, 9)

PLANETS: dict[str, list[str]] = {
    "en":    ["mars", "venus", "mercury", "moon", "sun", "pluto", "jupiter", "saturn", "uranus", "neptune"],
    "pt-br": ["marte", "venus", "mercurio", "lua", "sol", "plutao", "jupiter", "saturno", "urano", "netuno"],
    "pt-pt": ["marte", "venus", "mercurio", "lua", "sol", "plutao", "jupiter", "saturno", "urano", "netuno"],
    "es":    ["marte", "venus", "mercurio", "luna", "sol", "pluton", "jupiter", "saturno", "urano", "neptuno"],
}


# ── Funções de consulta ───────────────────────────────────────────────────────

def get_months(locale: str) -> list[str]:
    """Retorna lista de meses no locale dado."""
    return MONTHS.get(locale, MONTHS[DEFAULT_LOCALE])


def get_months_abbr(locale: str) -> list[str]:
    """Retorna abreviações dos meses no locale dado."""
    return MONTHS_ABBR.get(locale, MONTHS_ABBR[DEFAULT_LOCALE])


def get_zodiac_names(locale: str) -> list[str]:
    """Retorna nomes dos signos no locale dado (índice = signo_index 0-11)."""
    return ZODIAC_NAMES.get(locale, ZODIAC_NAMES[DEFAULT_LOCALE])


def get_zodiac_alts(locale: str, sign_index: int) -> list[str]:
    """Retorna lista de variações de nome para o signo no locale dado."""
    alts = ZODIAC_NAMES_ALT.get(locale, ZODIAC_NAMES_ALT[DEFAULT_LOCALE])
    if 0 <= sign_index < len(alts):
        return alts[sign_index]
    return []


def sign_index_from_day_month(day: int, month: int) -> Optional[int]:
    """
    Retorna índice do signo (0-11) dado dia e mês.
    Retorna None se inválido.
    """
    for idx, (ms, ds, me, de) in enumerate(ZODIAC_RANGES):
        if ms <= me:
            if (month == ms and day >= ds) or (month == me and day <= de):
                return idx
            if ms < month < me:
                return idx
        else:
            # capricórnio cruza virada de ano
            if (month == ms and day >= ds) or (month == me and day <= de):
                return idx
            if month > ms or month < me:
                return idx
    return None


def sign_index_from_name(name: str, locale: str = DEFAULT_LOCALE) -> Optional[int]:
    """
    Retorna índice do signo a partir do nome no locale dado.
    Busca case-insensitive, também nos aliases.
    """
    name_lower = name.lower().strip()
    names = get_zodiac_names(locale)
    for i, n in enumerate(names):
        if n == name_lower:
            return i
    # buscar em alternativas do locale
    alts = ZODIAC_NAMES_ALT.get(locale, ZODIAC_NAMES_ALT[DEFAULT_LOCALE])
    for i, alt_list in enumerate(alts):
        if name_lower in [a.lower() for a in alt_list]:
            return i
    # fallback: buscar em en
    if locale != "en":
        return sign_index_from_name(name, "en")
    return None


def get_element_for_sign(sign_index: int, locale: str = DEFAULT_LOCALE) -> Optional[str]:
    """Retorna nome do elemento para o signo no locale dado."""
    if not 0 <= sign_index < 12:
        return None
    el_idx = ZODIAC_ELEMENT_IDX[sign_index]
    elements = ELEMENTS.get(locale, ELEMENTS[DEFAULT_LOCALE])
    return elements[el_idx]


def get_planet_for_sign(sign_index: int, locale: str = DEFAULT_LOCALE) -> Optional[str]:
    """Retorna nome do regente planetário para o signo no locale dado."""
    if not 0 <= sign_index < 12:
        return None
    pl_idx = ZODIAC_PLANET_IDX[sign_index]
    planets = PLANETS.get(locale, PLANETS[DEFAULT_LOCALE])
    if pl_idx < len(planets):
        return planets[pl_idx]
    return None


def detect_locale_from_text(text: str) -> Optional[str]:
    """
    Tenta detectar o locale a partir de palavras-chave no texto.
    Heurística leve: verifica presença de meses/signos em cada locale.
    Retorna o locale com maior número de matches, ou None.
    """
    text_lower = text.lower()
    scores: dict[str, int] = {loc: 0 for loc in SUPPORTED_LOCALES}

    for locale in SUPPORTED_LOCALES:
        for m in MONTHS[locale]:
            if m in text_lower:
                scores[locale] += 1
        for z in ZODIAC_NAMES[locale]:
            if z in text_lower:
                scores[locale] += 2

    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else None


def normalise_locale(raw: str) -> str:
    """
    Normaliza string de locale para um dos SUPPORTED_LOCALES.
    Aceita 'br', 'pt', 'pt_BR', 'es-ES', etc.
    Fallback: DEFAULT_LOCALE.
    """
    raw = raw.lower().strip().replace("_", "-")
    if raw in SUPPORTED_LOCALES:
        return raw
    if raw in ("br", "pt-br", "ptbr", "portuguese-br", "pt_br"):
        return "pt-br"
    if raw in ("pt", "pt-pt", "ptpt", "portuguese", "portuguese-pt", "pt_pt"):
        return "pt-pt"
    if raw in ("es", "es-es", "español", "spanish"):
        return "es"
    if raw in ("en", "en-us", "en-gb", "english"):
        return "en"
    return DEFAULT_LOCALE
