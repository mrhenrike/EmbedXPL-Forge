"""
phone_gen.py - Phone number wordlist generation.

Supports:
  - Country selection with automatic DDI prefix
  - State/region selection with automatic DDD/area code
  - Custom prefix and digit patterns (X = any digit 0-9)
  - Mobile and landline generation
  - Output: E.164 format, local format, or both

Usage (CLI):
  wlf.py phone --country brazil --state SP
  wlf.py phone --country brazil --ddd 11 --type mobile
  wlf.py phone --ddi +1 --prefix "212" --pattern "XXXXXXX"
  wlf.py phone --country usa --area 212

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
from itertools import product
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Country/DDI/State/DDD data ────────────────────────────────────────────────

COUNTRIES: dict[str, dict] = {
    "brazil": {
        "ddi": "55",
        "name": "Brazil",
        "mobile_digits": 9,       # 9 digits after DDD (9XXXXXXXX)
        "landline_digits": 8,     # 8 digits after DDD
        "mobile_prefix": "9",     # Brazilian mobiles start with 9
        "states": {
            "AC": ["68"],
            "AL": ["82"],
            "AM": ["92", "97"],
            "AP": ["96"],
            "BA": ["71", "73", "74", "75", "77"],
            "CE": ["85", "88"],
            "DF": ["61"],
            "ES": ["27", "28"],
            "GO": ["62", "64"],
            "MA": ["98", "99"],
            "MG": ["31", "32", "33", "34", "35", "37", "38"],
            "MS": ["67"],
            "MT": ["65", "66"],
            "PA": ["91", "93", "94"],
            "PB": ["83"],
            "PE": ["81", "87"],
            "PI": ["86", "89"],
            "PR": ["41", "42", "43", "44", "45", "46"],
            "RJ": ["21", "22", "24"],
            "RN": ["84"],
            "RO": ["69"],
            "RR": ["95"],
            "RS": ["51", "53", "54", "55"],
            "SC": ["47", "48", "49"],
            "SE": ["79"],
            "SP": ["11", "12", "13", "14", "15", "16", "17", "18", "19"],
            "TO": ["63"],
        },
    },
    "usa": {
        "ddi": "1",
        "name": "United States",
        "mobile_digits": 7,
        "landline_digits": 7,
        "mobile_prefix": "",
        "states": {
            "NY": ["212", "646", "332", "718", "917", "347", "929"],
            "CA": ["213", "310", "323", "424", "562", "619", "626", "650", "714", "760", "818", "858", "909", "916", "949"],
            "TX": ["210", "214", "254", "281", "325", "361", "409", "430", "432", "469", "512", "682", "713", "726", "806", "817", "830", "903", "936", "940", "956", "972", "979"],
            "FL": ["239", "305", "321", "352", "386", "407", "561", "727", "754", "772", "786", "813", "850", "863", "904", "941", "954"],
            "IL": ["217", "224", "309", "312", "331", "447", "464", "618", "630", "708", "773", "779", "815", "847", "872"],
        },
    },
    "uk": {
        "ddi": "44",
        "name": "United Kingdom",
        "mobile_digits": 10,
        "landline_digits": 10,
        "mobile_prefix": "7",
        "states": {
            "London": ["20"],
            "Manchester": ["161"],
            "Birmingham": ["121"],
            "Glasgow": ["141"],
            "Leeds": ["113"],
            "Edinburgh": ["131"],
        },
    },
    "germany": {
        "ddi": "49",
        "name": "Germany",
        "mobile_digits": 11,
        "landline_digits": 11,
        "mobile_prefix": "15",
        "states": {
            "Berlin": ["30"],
            "Munich": ["89"],
            "Hamburg": ["40"],
            "Frankfurt": ["69"],
            "Cologne": ["221"],
        },
    },
    "argentina": {
        "ddi": "54",
        "name": "Argentina",
        "mobile_digits": 8,
        "landline_digits": 8,
        "mobile_prefix": "9",
        "states": {
            "Buenos Aires": ["11"],
            "Córdoba": ["351"],
            "Rosario": ["341"],
            "Mendoza": ["261"],
        },
    },
    "portugal": {
        "ddi": "351",
        "name": "Portugal",
        "mobile_digits": 9,
        "landline_digits": 9,
        "mobile_prefix": "9",
        "states": {
            "Lisboa": ["21"],
            "Porto": ["22"],
            "Braga": ["253"],
            "Faro": ["289"],
        },
    },
    "spain": {
        "ddi": "34",
        "name": "Spain",
        "mobile_digits": 9,
        "landline_digits": 9,
        "mobile_prefix": "6",
        "states": {
            "Madrid": ["91"],
            "Barcelona": ["93"],
            "Valencia": ["96"],
            "Seville": ["954"],
        },
    },
    "france": {
        "ddi": "33",
        "name": "France",
        "mobile_digits": 9,
        "landline_digits": 9,
        "mobile_prefix": "6",
        "states": {
            "Paris": ["1"],
            "Lyon": ["4"],
            "Marseille": ["4"],
            "Toulouse": ["5"],
        },
    },
    "mexico": {
        "ddi": "52",
        "name": "Mexico",
        "mobile_digits": 10,
        "landline_digits": 10,
        "mobile_prefix": "",
        "states": {
            "Mexico City": ["55"],
            "Guadalajara": ["33"],
            "Monterrey": ["81"],
            "Puebla": ["222"],
        },
    },
}


def list_countries() -> list[str]:
    """Return sorted list of supported country names."""
    return sorted(COUNTRIES.keys())


def list_states(country: str) -> list[str]:
    """Return sorted list of states/regions for a country."""
    c = COUNTRIES.get(country.lower(), {})
    return sorted(c.get("states", {}).keys())


def get_ddds(country: str, state: str) -> list[str]:
    """Return DDD/area codes for a state."""
    c = COUNTRIES.get(country.lower(), {})
    return c.get("states", {}).get(state.upper(), [])


def _expand_pattern(pattern: str) -> Generator[str, None, None]:
    """
    Expand a pattern where 'X' is any digit 0-9, literal chars are kept.

    Example: "9XXXX" with N=4 generates "90000".."99999".

    Args:
        pattern: Pattern string with X as wildcard digit.

    Yields:
        All expanded strings.
    """
    slots: list[list[str]] = []
    for ch in pattern:
        if ch == "X":
            slots.append(list("0123456789"))
        else:
            slots.append([ch])

    for combo in product(*slots):
        yield "".join(combo)


def estimate_count(pattern: str) -> int:
    """Return the number of combinations for a pattern."""
    return 10 ** pattern.count("X")


def generate_phones(
    country: Optional[str] = None,
    state: Optional[str] = None,
    ddi: Optional[str] = None,
    ddd: Optional[str] = None,
    phone_type: str = "both",
    custom_pattern: Optional[str] = None,
    output_formats: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Generate phone number wordlist.

    Args:
        country: Country name (e.g., 'brazil', 'usa'). Used to get DDI and DDDs.
        state: State/region code (e.g., 'SP', 'NY'). Filters DDDs.
        ddi: Manual DDI override (e.g., '55'). Used if country not set.
        ddd: Manual DDD/area code override. Used if state not set.
        phone_type: 'mobile', 'landline', or 'both'.
        custom_pattern: Custom digit pattern ('X' = any digit). Overrides type patterns.
        output_formats: List of formats to output. Options:
            'e164'    -> +55119XXXXXXXX
            'local'   -> 119XXXXXXXX
            'ddd'     -> 119XXXXXXXX (no DDI)
            'bare'    -> 9XXXXXXXX (no DDI, no DDD)
          Default: ['e164', 'local']

    Yields:
        Phone number strings in requested formats.
    """
    formats = output_formats or ["e164", "local"]
    seen: set[str] = set()

    # Resolve country data
    country_data = COUNTRIES.get((country or "").lower(), {})
    resolved_ddi = ddi or country_data.get("ddi", "")

    # Resolve DDDs to iterate
    if ddd:
        ddds = [ddd]
    elif state and country_data:
        ddds = get_ddds(country or "", state)
        if not ddds:
            logger.warning("State '%s' not found for country '%s'", state, country)
            ddds = [""]
    else:
        ddds = [""]  # No DDD prefix

    mobile_prefix = country_data.get("mobile_prefix", "")
    mobile_digits = country_data.get("mobile_digits", 8)
    landline_digits = country_data.get("landline_digits", 8)

    for area_code in ddds:
        if custom_pattern:
            patterns = [custom_pattern]
        else:
            patterns = []
            if phone_type in ("mobile", "both"):
                remaining = mobile_digits - len(mobile_prefix)
                patterns.append(mobile_prefix + "X" * remaining)
            if phone_type in ("landline", "both"):
                # Landline: avoid mobile prefix range
                landline_first = [d for d in "234568" if d != mobile_prefix]
                for first in landline_first[:2]:  # Limit to 2 first-digit classes
                    remaining = landline_digits - 1
                    patterns.append(first + "X" * remaining)

        for pattern in patterns:
            for number in _expand_pattern(pattern):
                results: list[str] = []
                if "e164" in formats:
                    results.append(f"+{resolved_ddi}{area_code}{number}")
                if "local" in formats or "ddd" in formats:
                    results.append(f"{area_code}{number}")
                if "bare" in formats:
                    results.append(number)

                for r in results:
                    if r and r not in seen:
                        seen.add(r)
                        yield r


def interactive_phone_wizard() -> dict:
    """
    Interactive wizard to configure phone number generation.

    Returns:
        Dict with generation parameters.
    """
    print("\n=== Phone Number Generator ===\n")
    print(f"Supported countries: {', '.join(list_countries())}\n")

    country = input("  Country (or Enter to skip): ").strip().lower() or None

    state = None
    if country and country in COUNTRIES:
        states = list_states(country)
        if states:
            print(f"  States/regions: {', '.join(states)}")
            state = input("  State/region (or Enter for all): ").strip().upper() or None

    ddi_manual = None
    ddd_manual = None
    if not country:
        ddi_manual = input("  DDI (e.g., 55 for Brazil, 1 for USA): ").strip() or None
        ddd_manual = input("  DDD/area code (or Enter to skip): ").strip() or None

    phone_type = input("  Type [mobile/landline/both]: ").strip().lower() or "both"
    if phone_type not in ("mobile", "landline", "both"):
        phone_type = "both"

    custom_pat = input("  Custom pattern (X=any digit, e.g. '9XXXX-XXXX', or Enter to skip): ").strip() or None

    formats_raw = input("  Output formats [e164/local/bare, comma-sep, default e164,local]: ").strip()
    formats = [f.strip() for f in formats_raw.split(",")] if formats_raw else ["e164", "local"]

    # Estimate size
    from embedxpl.engines.wordlists.phone_gen import estimate_count
    if custom_pat:
        count = estimate_count(custom_pat)
    elif country in COUNTRIES:
        cdata = COUNTRIES[country]
        count = 10 ** (cdata.get("mobile_digits", 8) - len(cdata.get("mobile_prefix", "")))
    else:
        count = 10 ** 8

    ddds_used = get_ddds(country or "", state or "") if country and state else ["(all)"]
    count_total = count * len(ddds_used) * len(formats)

    print(f"\n  Estimated: ~{count_total:,} entries")

    return {
        "country": country,
        "state": state,
        "ddi": ddi_manual,
        "ddd": ddd_manual,
        "phone_type": phone_type,
        "custom_pattern": custom_pat,
        "output_formats": formats,
    }


# ── BEWGor T9 spelling (native port) ──────────────────────────────────────────

# Standard T9/ITU-T E.161 keypad layout
_T9_MAP: dict[str, str] = {
    "a": "2", "b": "2", "c": "2",
    "d": "3", "e": "3", "f": "3",
    "g": "4", "h": "4", "i": "4",
    "j": "5", "k": "5", "l": "5",
    "m": "6", "n": "6", "o": "6",
    "p": "7", "q": "7", "r": "7", "s": "7",
    "t": "8", "u": "8", "v": "8",
    "w": "9", "x": "9", "y": "9", "z": "9",
    " ": "0",
}

# Reverse map: digit -> list of letters (first letter of each trio/quad)
_T9_REVERSE: dict[str, list[str]] = {
    "2": ["a", "b", "c"],
    "3": ["d", "e", "f"],
    "4": ["g", "h", "i"],
    "5": ["j", "k", "l"],
    "6": ["m", "n", "o"],
    "7": ["p", "q", "r", "s"],
    "8": ["t", "u", "v"],
    "9": ["w", "x", "y", "z"],
    "0": [" "],
}


def t9_encode(word: str) -> str:
    """Encode a word to its T9 digit representation (BEWGor parity).

    Maps each letter to the corresponding phone keypad digit.
    Non-alpha characters are preserved as-is.

    Args:
        word: Input word (name, keyword, etc.).

    Returns:
        T9 digit string (e.g. "xpto" -> "9786").
    """
    return "".join(_T9_MAP.get(ch.lower(), ch) for ch in word)


def t9_decode_variants(t9_digits: str, max_variants: int = 256) -> list[str]:
    """Decode T9 digit string to possible words (all combinations).

    Uses cartesian product of each digit's letter alternatives. Caps the
    number of generated variants to ``max_variants`` to avoid combinatorial
    explosion.

    Args:
        t9_digits: Digit sequence (e.g. "26337").
        max_variants: Maximum number of word candidates to return.

    Returns:
        List of possible word spellings.
    """
    import itertools

    pools: list[list[str]] = []
    for ch in t9_digits:
        candidates = _T9_REVERSE.get(ch)
        if candidates:
            pools.append(candidates)
        elif ch.isdigit():
            pools.append([ch])
        else:
            pools.append([ch])

    if not pools:
        return []

    results: list[str] = []
    for combo in itertools.product(*pools):
        results.append("".join(combo))
        if len(results) >= max_variants:
            break
    return results


def t9_wordlist_tokens(
    words: list[str],
    include_encoded: bool = True,
    include_decoded: bool = False,
    max_decode_variants: int = 64,
) -> list[str]:
    """Generate T9-based wordlist tokens from a list of base words (BEWGor parity).

    For each word:
    - Optionally adds its T9 encoding (digits)
    - Optionally adds reverse-decoded variants from the encoding

    Typical usage: feed name tokens for phone-number-as-password patterns.

    Args:
        words: Base word list (names, keywords, etc.).
        include_encoded: Add the T9 digit encoding of each word.
        include_decoded: Add reverse-decoded word variants.
        max_decode_variants: Cap per-word decode variants.

    Returns:
        Deduplicated list of T9-related tokens.
    """
    seen: set[str] = set()
    results: list[str] = []

    for word in words:
        if not word.strip():
            continue
        encoded = t9_encode(word.strip())
        if include_encoded and encoded not in seen:
            seen.add(encoded)
            results.append(encoded)
        if include_decoded:
            for variant in t9_decode_variants(encoded, max_decode_variants):
                if variant not in seen:
                    seen.add(variant)
                    results.append(variant)

    return results
