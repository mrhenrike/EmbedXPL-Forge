"""
country_tokens.py - Resolve country input and emit password token variants.

Accepts ISO codes, English/local names, and common aliases in any casing
(e.g. BR, br, Brasil, brazil, BRAZIL → Brazil tokens + BR + BRA + 55).

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import re
from typing import Optional

# canonical_key → metadata
# aliases: extra spellings; local_name: native endonym when useful for passwords
COUNTRY_REGISTRY: dict[str, dict] = {
    "brazil": {
        "iso2": "BR",
        "iso3": "BRA",
        "name": "Brazil",
        "local_name": "Brasil",
        "ddi": "55",
        "aliases": ["brasil", "brazil", "br", "bra", "braz", "brasilian", "brazilian"],
    },
    "usa": {
        "iso2": "US",
        "iso3": "USA",
        "name": "United States",
        "local_name": "America",
        "ddi": "1",
        "aliases": ["usa", "us", "america", "american", "united states", "unitedstates", "estados unidos", "eua"],
    },
    "uk": {
        "iso2": "GB",
        "iso3": "GBR",
        "name": "United Kingdom",
        "local_name": "Britain",
        "ddi": "44",
        "aliases": ["uk", "gb", "gbr", "england", "britain", "great britain", "united kingdom", "reino unido"],
    },
    "portugal": {
        "iso2": "PT",
        "iso3": "PRT",
        "name": "Portugal",
        "ddi": "351",
        "aliases": ["pt", "prt", "portuguese"],
    },
    "spain": {
        "iso2": "ES",
        "iso3": "ESP",
        "name": "Spain",
        "local_name": "Espana",
        "ddi": "34",
        "aliases": ["es", "esp", "espana", "españa", "spanish", "espanha"],
    },
    "france": {
        "iso2": "FR",
        "iso3": "FRA",
        "name": "France",
        "ddi": "33",
        "aliases": ["fr", "fra", "french", "franca", "frança"],
    },
    "germany": {
        "iso2": "DE",
        "iso3": "DEU",
        "name": "Germany",
        "local_name": "Deutschland",
        "ddi": "49",
        "aliases": ["de", "deu", "german", "alemanha", "alemania"],
    },
    "italy": {
        "iso2": "IT",
        "iso3": "ITA",
        "name": "Italy",
        "local_name": "Italia",
        "ddi": "39",
        "aliases": ["it", "ita", "italian", "italia", "italie"],
    },
    "argentina": {
        "iso2": "AR",
        "iso3": "ARG",
        "name": "Argentina",
        "ddi": "54",
        "aliases": ["ar", "arg", "argentinian", "argentino"],
    },
    "mexico": {
        "iso2": "MX",
        "iso3": "MEX",
        "name": "Mexico",
        "local_name": "Mexico",
        "ddi": "52",
        "aliases": ["mx", "mex", "mexican", "méxico", "mexico"],
    },
    "chile": {
        "iso2": "CL",
        "iso3": "CHL",
        "name": "Chile",
        "ddi": "56",
        "aliases": ["cl", "chl", "chilean"],
    },
    "colombia": {
        "iso2": "CO",
        "iso3": "COL",
        "name": "Colombia",
        "ddi": "57",
        "aliases": ["co", "col", "colombian"],
    },
    "peru": {
        "iso2": "PE",
        "iso3": "PER",
        "name": "Peru",
        "local_name": "Peru",
        "ddi": "51",
        "aliases": ["pe", "per", "peruvian", "peru"],
    },
    "uruguay": {
        "iso2": "UY",
        "iso3": "URY",
        "name": "Uruguay",
        "ddi": "598",
        "aliases": ["uy", "ury", "uruguayan"],
    },
    "paraguay": {
        "iso2": "PY",
        "iso3": "PRY",
        "name": "Paraguay",
        "ddi": "595",
        "aliases": ["py", "pry", "paraguayan"],
    },
    "bolivia": {
        "iso2": "BO",
        "iso3": "BOL",
        "name": "Bolivia",
        "ddi": "591",
        "aliases": ["bo", "bol", "bolivian"],
    },
    "venezuela": {
        "iso2": "VE",
        "iso3": "VEN",
        "name": "Venezuela",
        "ddi": "58",
        "aliases": ["ve", "ven", "venezuelan"],
    },
    "canada": {
        "iso2": "CA",
        "iso3": "CAN",
        "name": "Canada",
        "ddi": "1",
        "aliases": ["ca", "can", "canadian"],
    },
    "australia": {
        "iso2": "AU",
        "iso3": "AUS",
        "name": "Australia",
        "ddi": "61",
        "aliases": ["au", "aus", "australian"],
    },
    "japan": {
        "iso2": "JP",
        "iso3": "JPN",
        "name": "Japan",
        "local_name": "Nippon",
        "ddi": "81",
        "aliases": ["jp", "jpn", "japanese", "nippon"],
    },
    "china": {
        "iso2": "CN",
        "iso3": "CHN",
        "name": "China",
        "ddi": "86",
        "aliases": ["cn", "chn", "chinese"],
    },
    "india": {
        "iso2": "IN",
        "iso3": "IND",
        "name": "India",
        "ddi": "91",
        "aliases": ["in", "ind", "indian", "bharat"],
    },
    "russia": {
        "iso2": "RU",
        "iso3": "RUS",
        "name": "Russia",
        "ddi": "7",
        "aliases": ["ru", "rus", "russian"],
    },
    "netherlands": {
        "iso2": "NL",
        "iso3": "NLD",
        "name": "Netherlands",
        "ddi": "31",
        "aliases": ["nl", "nld", "holland", "dutch"],
    },
    "switzerland": {
        "iso2": "CH",
        "iso3": "CHE",
        "name": "Switzerland",
        "ddi": "41",
        "aliases": ["ch", "che", "swiss", "suica", "suíça"],
    },
    "ireland": {
        "iso2": "IE",
        "iso3": "IRL",
        "name": "Ireland",
        "ddi": "353",
        "aliases": ["ie", "irl", "irish", "irlanda"],
    },
    "south_africa": {
        "iso2": "ZA",
        "iso3": "ZAF",
        "name": "South Africa",
        "ddi": "27",
        "aliases": ["za", "zaf", "southafrica", "south africa", "africa do sul"],
    },
    "israel": {
        "iso2": "IL",
        "iso3": "ISR",
        "name": "Israel",
        "ddi": "972",
        "aliases": ["il", "isr", "israeli"],
    },
    "south_korea": {
        "iso2": "KR",
        "iso3": "KOR",
        "name": "South Korea",
        "local_name": "Korea",
        "ddi": "82",
        "aliases": ["kr", "kor", "korea", "korean", "coreia", "corea"],
    },
}

# Merge DDI from phone_gen when available (keeps single source for phone countries)
try:
    from embedxpl.engines.wordlists.phone_gen import COUNTRIES as _PHONE_COUNTRIES

    for _key, _pdata in _PHONE_COUNTRIES.items():
        if _key in COUNTRY_REGISTRY:
            COUNTRY_REGISTRY[_key]["ddi"] = _pdata.get("ddi", COUNTRY_REGISTRY[_key].get("ddi", ""))
        else:
            COUNTRY_REGISTRY[_key] = {
                "iso2": "",
                "iso3": "",
                "name": _pdata.get("name", _key.title()),
                "ddi": _pdata.get("ddi", ""),
                "aliases": [_key, _pdata.get("name", "").lower()],
            }
except ImportError:
    pass

_ACCENTS = str.maketrans(
    "áàâãäåéèêëíìîïóòôõöúùûüçñÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇÑ",
    "aaaaaaeeeeiiiiooooouuuucnAAAAAEEEEIIIIOOOOOUUUUCN",
)


def _norm(text: str) -> str:
    """Lowercase, strip accents, collapse whitespace/punctuation."""
    t = text.translate(_ACCENTS).strip().lower()
    t = re.sub(r"[\s._\-/]+", " ", t)
    return t.strip()


def _case_variants(word: str) -> list[str]:
    if not word:
        return []
    w = word.strip()
    if not w:
        return []
    out = [w, w.lower(), w.upper(), w.capitalize()]
    if len(w) >= 2:
        out.append(w[0].upper() + w[1:].lower())
    return list(dict.fromkeys(x for x in out if x))


def _build_alias_index() -> dict[str, str]:
    idx: dict[str, str] = {}
    for key, data in COUNTRY_REGISTRY.items():
        candidates = {key, data.get("name", ""), data.get("local_name", "")}
        candidates.update(data.get("aliases", []))
        for field in ("iso2", "iso3"):
            v = data.get(field, "")
            if v:
                candidates.add(v)
        for c in candidates:
            if not c:
                continue
            n = _norm(c)
            if n:
                idx[n] = key
            # ISO codes also match without normalization lower (BR stays BR conceptually)
            raw = c.strip()
            if raw:
                idx[raw.lower()] = key
                idx[raw.upper()] = key
    return idx


_ALIAS_INDEX = _build_alias_index()


def resolve_country(raw: str) -> Optional[str]:
    """
    Resolve free-text country input to a canonical registry key.

    Examples: ``BR`` → ``brazil``, ``Brasil`` → ``brazil``, ``brazil`` → ``brazil``.
    """
    if not raw or not raw.strip():
        return None
    text = raw.strip()
    n = _norm(text)
    if n in _ALIAS_INDEX:
        return _ALIAS_INDEX[n]
    # compact: "unitedstates"
    compact = n.replace(" ", "")
    if compact in _ALIAS_INDEX:
        return _ALIAS_INDEX[compact]
    # exact ISO2/ISO3 uppercase
    up = text.upper()
    if up in _ALIAS_INDEX:
        return _ALIAS_INDEX[up]
    low = text.lower()
    if low in _ALIAS_INDEX:
        return _ALIAS_INDEX[low]
    return None


def country_display_name(key: str) -> str:
    """Human-readable label for a canonical country key."""
    data = COUNTRY_REGISTRY.get(key, {})
    return data.get("name") or key.replace("_", " ").title()


def country_base_forms(key: str) -> list[str]:
    """Core token bases for a resolved country (no case expansion)."""
    data = COUNTRY_REGISTRY.get(key, {})
    bases: set[str] = set()
    ordered: list[str] = []
    for field in ("iso2", "iso3", "ddi", "local_name", "name"):
        v = data.get(field, "")
        if v and v not in bases:
            bases.add(str(v))
            ordered.append(str(v))
    if key not in bases:
        ordered.append(key)
        bases.add(key)
    for alias in data.get("aliases", []):
        if alias and len(alias) <= 12 and alias not in bases:
            bases.add(alias)
            ordered.append(alias)
    return ordered


def country_word_tokens(raw: str) -> list[str]:
    """
    Full country token set: ISO codes, names, DDI, aliases, case variants.

    Use when ``include_country_variations`` is enabled in profile mode.
    """
    if not raw or not raw.strip():
        return []

    key = resolve_country(raw)
    if key:
        bases = country_base_forms(key)
    else:
        bases = [raw.strip()]

    result: list[str] = []
    seen: set[str] = set()
    for base in bases:
        for v in _case_variants(base):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result


def country_minimal_tokens(raw: str) -> list[str]:
    """
    Minimal country tokens: ISO2 + local/English name only (no DDI, no alias flood).

    Use when the user declines full country variations in profile mode.
    """
    if not raw or not raw.strip():
        return []

    key = resolve_country(raw)
    if not key:
        return _case_variants(raw.strip())

    data = COUNTRY_REGISTRY[key]
    bases: list[str] = []
    for field in ("iso2", "local_name", "name"):
        v = data.get(field, "")
        if v:
            bases.append(str(v))

    result: list[str] = []
    seen: set[str] = set()
    for base in bases:
        for v in _case_variants(base):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result
