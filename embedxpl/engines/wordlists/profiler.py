"""
profiler.py - Interactive personal target profiling for wordlist generation.

Each variation is emitted as a separate line (one entry per line).
Generates: case variants, leet variants, reversed strings, name initials/fragments,
token combinations (up to depth 5), date fragment tokens, old password mutations,
social handles, location patterns, corporate keywords, religious patterns,
behavioral patterns from data/behavior_patterns.json, and multi-char special suffixes.

Inspired by CUPP, elpscrk, and BEWGor - absorbs their best mutation strategies.

Author: André Henrique (@mrhenrike)
Version: 2.4.0
"""
from __future__ import annotations

import json
import logging
import re
import uuid
import zlib
from datetime import datetime, date
from itertools import permutations as _permutations, product as _product
from pathlib import Path
from typing import Generator, Optional

_MODULE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _MODULE_DIR.parent
_BEHAVIOR_DB: Optional[dict] = None


class _SeenSet:
    """CRC32-based deduplication set.

    Stores 32-bit hashes instead of full strings, reducing memory usage by ~10x
    compared to a plain set[str] when handling large wordlists.

    Supports the same ``in`` / ``add`` / ``discard`` interface as ``set`` for
    drop-in compatibility with callers that treat it as a set of strings.
    """

    __slots__ = ("_hashes",)

    def __init__(self) -> None:
        self._hashes: set[int] = set()

    @staticmethod
    def _h(s: str) -> int:
        return zlib.crc32(s.encode("utf-8", errors="replace")) & 0xFFFFFFFF

    def __contains__(self, s: object) -> bool:
        if not isinstance(s, str):
            return False
        return self._h(s) in self._hashes

    def add(self, s: str) -> None:
        self._hashes.add(self._h(s))

    def discard(self, s: str) -> None:
        self._hashes.discard(self._h(s))


def _find_data_file(filename: str) -> Path:
    """Resolve data file path, checking embedxpl.engines.wordlists/data/ first then repo root data/."""
    pkg_path = _MODULE_DIR / "data" / filename
    if pkg_path.exists():
        return pkg_path
    return _REPO_ROOT / "data" / filename

logger = logging.getLogger(__name__)


def _load_behavior_db() -> dict:
    """Load behavior_patterns.json once and cache it in memory."""
    global _BEHAVIOR_DB
    if _BEHAVIOR_DB is None:
        path = _find_data_file("behavior_patterns.json")
        try:
            with open(path, encoding="utf-8") as f:
                _BEHAVIOR_DB = json.load(f)
        except FileNotFoundError:
            logger.warning("behavior_patterns.json not found at %s", path)
            _BEHAVIOR_DB = {}
    return _BEHAVIOR_DB


def load_profile_yaml(filepath: str) -> dict:
    """
    Load a personal profile from a YAML file.

    This allows non-interactive, scripted use of the profiler.
    The YAML structure mirrors the keys returned by interactive_profile().

    Example YAML::

        full_name: "PessoaX"
        short_name: "PessoaX"
        nicknames:
          - "robotx"
          - "pxcorpx"
        birth_day: 15
        birth_month: 3
        birth_year: 1990
        pets:
          - "petx"
          - name: "robotx"
            year: 2025
        pet_adoptions:
          - name: "petx"
            year: 2026
        keywords:
          - "soccer"
          - "hacker"
        leet_mode: "basic"
        min_len: 6
        max_len: 32
        year_start: 2000
        year_end: 2026
        suffix_range_start: 0
        suffix_range_end: 99
        suffix_range_zero_pad: 2

    Args:
        filepath: Path to the YAML profile file.

    Returns:
        Profile dict, same structure as interactive_profile() output.

    Raises:
        FileNotFoundError: If the YAML file does not exist.
        ImportError: If PyYAML is not installed.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError(
            "PyYAML is required for --profile-file. Install: pip install pyyaml"
        ) from exc

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Profile file not found: {filepath}")

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Normalize list fields that might be given as strings
    for list_field in ("nicknames", "phones", "social_handles", "keywords",
                       "special_dates", "pets", "children", "phrases"):
        val = data.get(list_field)
        if isinstance(val, str):
            data[list_field] = [v.strip() for v in val.split(",") if v.strip()]
        elif val is None:
            data[list_field] = []

    data = _normalize_profile_pets(data)
    data = _normalize_date_fields(data)
    return data


def _normalize_date_fields(data: dict) -> dict:
    """
    Normaliza campos de data do perfil YAML para o formato legado esperado pelo profiler.

    Suporta dois formatos:
      - Legado: birth_day, birth_month, birth_year como inteiros separados.
      - Estruturado: birth: {mode: age_sign, age: 26, sign: touro} ou birth: "dd/mm/yyyy".

    Também processa ``hire`` para entidades corporativas (mesma lógica).
    """
    try:
        from embedxpl.engines.wordlists.date_profile import date_profile_from_yaml, build_date_tokens
        from embedxpl.engines.wordlists.i18n import get_session_locale
    except ImportError:
        return data

    locale = data.get("locale") or get_session_locale()

    # ── Campo birth ────────────────────────────────────────────────────────────
    birth_raw = data.get("birth")
    if birth_raw is not None and not isinstance(birth_raw, int):
        dp = date_profile_from_yaml(birth_raw, locale)
        if dp:
            dp_dict = dp.to_dict()
            # Preservar campos legados: só sobrescrever se ainda em zero (não definidos)
            if not data.get("birth_day"):
                data["birth_day"] = dp_dict["birth_day"]
            if not data.get("birth_month"):
                data["birth_month"] = dp_dict["birth_month"]
            if not data.get("birth_year"):
                data["birth_year"] = dp_dict["birth_year"]
            # Campos novos (sem conflito com legado)
            data["birth_mode"] = dp_dict["birth_mode"]
            data["birth_age"] = dp_dict["birth_age"]
            data["birth_sign_index"] = dp_dict["birth_sign_index"]
            data["birth_year_min"] = dp_dict["birth_year_min"]
            data["birth_year_max"] = dp_dict["birth_year_max"]
            data["birth_locale"] = dp_dict["birth_locale"]
            # Pré-calcular tokens de data para uso posterior
            data.setdefault("_date_tokens", [])
            data["_date_tokens"] = build_date_tokens(dp, locale)

    # ── Campo hire (empresa) ───────────────────────────────────────────────────
    hire_raw = data.get("hire")
    if hire_raw is not None and not isinstance(hire_raw, int):
        dp = date_profile_from_yaml(hire_raw, locale)
        if dp:
            dp_dict = dp.to_dict()
            data["hire_day"] = dp_dict["birth_day"]
            data["hire_month"] = dp_dict["birth_month"]
            data["hire_year"] = dp_dict["birth_year"]
            data["hire_mode"] = dp_dict["birth_mode"]
            data["hire_age"] = dp_dict["birth_age"]
            data["hire_sign_index"] = dp_dict["birth_sign_index"]
            data["hire_year_min"] = dp_dict["birth_year_min"]
            data["hire_year_max"] = dp_dict["birth_year_max"]
            data.setdefault("_hire_date_tokens", [])
            data["_hire_date_tokens"] = build_date_tokens(dp, locale)

    # ── Normalizar partner birth estruturado ──────────────────────────────────
    if isinstance(data.get("partner"), dict):
        partner = data["partner"]
        pb_raw = partner.get("birth")
        if pb_raw is not None and not isinstance(pb_raw, int):
            dp = date_profile_from_yaml(pb_raw, locale)
            if dp:
                dp_dict = dp.to_dict()
                partner.setdefault("birth_day", dp_dict["birth_day"])
                partner.setdefault("birth_month", dp_dict["birth_month"])
                partner.setdefault("birth_year", dp_dict["birth_year"])
                partner["_date_tokens"] = build_date_tokens(dp, locale)

    return data


def _normalize_pet_entries(
    pets_raw: list,
) -> tuple[list[str], dict[str, list[str]]]:
    """
    Parse pet list entries (plain strings or dicts with adoption year).

    Returns:
        (pet names, map of lower(name) → year token strings e.g. ["2025", "25"])
    """
    names: list[str] = []
    year_map: dict[str, list[str]] = {}

    for item in pets_raw or []:
        if isinstance(item, dict):
            name = (item.get("name") or item.get("pet") or "").strip()
            if not name:
                continue
            names.append(name)
            yr_raw = item.get("year") or item.get("since") or item.get("adoption_year")
            if yr_raw is not None and str(yr_raw).strip().isdigit():
                ys = str(int(str(yr_raw).strip()))
                if len(ys) == 4:
                    year_map[name.lower()] = list(dict.fromkeys([ys, ys[-2:]]))
        elif isinstance(item, str) and item.strip():
            names.append(item.strip())

    return names, year_map


def _normalize_profile_pets(data: dict) -> dict:
    """Merge ``pet_adoptions`` into ``pets`` and keep dict entries intact."""
    pets_raw = list(data.get("pets") or [])
    for adop in data.get("pet_adoptions") or []:
        if isinstance(adop, dict) and (adop.get("name") or adop.get("pet")):
            pets_raw.append(adop)
    data["pets"] = pets_raw
    return data


def _build_pets_relationship_pool(
    profile: dict,
    leet_mode: str,
    year_mids: list[str],
) -> list[str]:
    """
    Pet tokens for relationship combos, including rolling year suffixes
    (25, 2025, 26, 2026) and optional per-pet adoption years.

    Enables patterns like ``BrandX#Pet25`` (corp + pet + year suffix).
    """
    pets_raw = profile.get("pets") or []
    names, year_map = _normalize_pet_entries(pets_raw)

    for adop in profile.get("pet_adoptions") or []:
        if not isinstance(adop, dict):
            continue
        aname = (adop.get("name") or adop.get("pet") or "").strip()
        yr_raw = adop.get("year") or adop.get("since") or adop.get("adoption_year")
        if aname and yr_raw is not None and str(yr_raw).strip().isdigit():
            ys = str(int(str(yr_raw).strip()))
            if len(ys) == 4:
                year_map[aname.lower()] = list(dict.fromkeys([ys, ys[-2:]]))

    if not names:
        return []

    do_leet = leet_mode not in ("none", "")
    base: list[str] = []
    seen: _SeenSet = _SeenSet()
    for pet_name in names:
        for variant in _word_variants(pet_name, leet=do_leet, leet_mode=leet_mode):
            if variant and variant not in seen:
                seen.add(variant)
                base.append(variant)

    rolling_years = [y for y in year_mids if len(y) in (2, 4)]
    adoption_priority: list[str] = []

    for pet_name in names:
        pyears = year_map.get(pet_name.lower(), [])
        if not pyears:
            continue
        pet_tokens: list[str] = []
        for variant in _word_variants(pet_name, leet=do_leet, leet_mode=leet_mode):
            if variant and variant not in pet_tokens:
                pet_tokens.append(variant)
        for tok in _append_year_suffix_tokens(pet_tokens, pyears):
            if tok not in seen:
                seen.add(tok)
                adoption_priority.append(tok)

    extended = list(base)
    for tok in _append_year_suffix_tokens(base, rolling_years):
        if tok not in seen:
            seen.add(tok)
            extended.append(tok)

    plain_heads: list[str] = []
    for pet_name in names:
        for variant in dict.fromkeys([
            pet_name,
            pet_name.capitalize(),
            pet_name.lower(),
            pet_name.upper(),
        ]):
            if variant:
                plain_heads.append(variant)

    return list(dict.fromkeys(plain_heads + adoption_priority + base + extended))


def _build_corp_relationship_pool(profile: dict, leet_mode: str) -> list[str]:
    """Company tokens with full leet/case variants (not truncated per-source)."""
    domain = (profile.get("company_domain", "") or "").replace("https://", "").replace("http://", "")
    domain_prefix = domain.split(".")[0] if domain else ""
    sources = [
        profile.get("company_name", "") or "",
        profile.get("company_legal", "") or "",
        domain_prefix,
    ]
    pool = _build_token_pool([s for s in sources if s], leet_mode, max_per_source=24)
    seen = set(pool)
    do_leet = leet_mode not in ("none", "")
    for src in sources:
        if not src or not str(src).strip():
            continue
        for word in _split_words(str(src)):
            for variant in _word_variants(word, leet=do_leet, leet_mode=leet_mode):
                if variant and variant not in seen:
                    seen.add(variant)
                    pool.append(variant)
    return pool


def _leet_token_filter(pool: list[str]) -> list[str]:
    """Tokens containing leet substitutions (``@``, digits+letters, etc.)."""
    return [
        t for t in pool
        if any(c in t for c in "@$!|+")
        or (any(c.isdigit() for c in t) and any(c.isalpha() for c in t))
    ]


def generate_year_range_tokens(
    year_start: int,
    year_end: int,
) -> list[str]:
    """
    Generate year string tokens for a range of years.

    Produces 4-digit and 2-digit representations.

    Args:
        year_start: First year (inclusive).
        year_end: Last year (inclusive).

    Returns:
        List of year strings (e.g., ["2020", "20", "2021", "21", ...]).
    """
    tokens: list[str] = []
    for y in range(year_start, year_end + 1):
        ys = str(y)
        tokens.append(ys)
        tokens.append(ys[-2:])
    return list(dict.fromkeys(tokens))


def rolling_recent_year_tokens(lookback: int = 1) -> list[str]:
    """
    Current year and the previous ``lookback`` year(s), 4- and 2-digit forms.

    Example (today=2026, lookback=1): ``2025``, ``25``, ``2026``, ``26``.
    """
    lookback = max(0, lookback)
    current = date.today().year
    out: list[str] = []
    for y in range(current - lookback, current + 1):
        ys = str(y)
        out.append(ys)
        out.append(ys[-2:])
    return list(dict.fromkeys(out))


def generate_suffix_range_tokens(
    start: int,
    end: int,
    zero_pad: int = 0,
) -> list[str]:
    """
    Generate numeric suffix tokens for a number range.

    Args:
        start: First number (inclusive).
        end: Last number (inclusive).
        zero_pad: Minimum width for zero-padding (0 = no padding).

    Returns:
        List of formatted number strings.

    Examples:
        generate_suffix_range_tokens(0, 99, 2) → ["00", "01", ..., "99"]
        generate_suffix_range_tokens(1, 9, 0)  → ["1", "2", ..., "9"]
    """
    fmt = f"0{zero_pad}d" if zero_pad > 0 else "d"
    return [format(n, fmt) for n in range(start, end + 1)]


def list_religions() -> list[tuple[str, str]]:
    """
    Return sorted list of (key, display_name) for all religions in the DB.

    Returns:
        List of (key, display) tuples.
    """
    db = _load_behavior_db()
    religions = db.get("religions", {})
    return sorted(
        [(k, v.get("display", k)) for k, v in religions.items()],
        key=lambda x: x[1],
    )


# ── Constants ─────────────────────────────────────────────────────────────────

COMMON_SUFFIXES = [
    "1", "12", "123", "1234", "12345",
    "!", "@", "#", ".", "_", "-",
    "01", "007", "69", "99", "100", "00",
]

COMMON_PREFIXES = ["", "my", "the", "mr", "ms", "dr", "sr", "jr"]

SPECIAL_PREFIXES = ["_", "__", "@", "#", "!", "$"]

DEFAULT_OUTPUT_DIR = Path("/tmp")

WORD_SEPARATORS = ["", ".", "-", "_", "@", "#", "!", "$"]

LEET_BASIC: dict[str, str] = {
    "a": "@", "A": "4",
    "e": "3", "E": "3",
    "i": "1", "I": "!",
    "o": "0", "O": "0",
    "s": "$", "S": "$",
    "t": "7", "T": "7",
    "l": "1", "L": "1",
    "b": "6", "B": "8",
    "g": "9", "G": "9",
    "z": "2", "Z": "2",
}

# Richer tables (shared with password_variants / profile leet modes)
_LEET_V2: dict[str, str] = {
    "a": "4", "A": "4",
    "e": "3", "E": "3",
    "i": "!", "I": "!",
    "o": "0", "O": "0",
    "s": "5", "S": "5",
    "t": "+", "T": "+",
    "l": "1", "L": "1",
    "b": "6", "B": "6",
    "g": "9", "G": "9",
}

_LEET_V3: dict[str, str] = {
    "a": "@", "A": "@",
    "i": "|", "I": "|",
    "s": "$", "S": "$",
    "b": "8", "B": "8",
    "g": "9", "G": "9",
    "t": "+", "T": "+",
    "l": "|", "L": "|",
}

# Lowercase selective - patterns like brand@year
_SELECTIVE_LEET_LOWER: dict[str, str] = {
    "a": "@", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1",
}

ACCENT_MAP: dict[str, str] = {
    "á": "a", "à": "a", "â": "a", "ã": "a", "ä": "a",
    "é": "e", "ê": "e", "ë": "e",
    "í": "i", "î": "i", "ï": "i",
    "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ú": "u", "û": "u", "ü": "u",
    "ç": "c", "ñ": "n",
    "Á": "A", "À": "A", "Â": "A", "Ã": "A",
    "É": "E", "Ê": "E",
    "Í": "I",
    "Ó": "O", "Ô": "O", "Õ": "O",
    "Ú": "U",
    "Ç": "C", "Ñ": "N",
}

ZODIAC = [
    ((3, 21), (4, 19), "aries"),
    ((4, 20), (5, 20), "taurus"),
    ((5, 21), (6, 20), "gemini"),
    ((6, 21), (7, 22), "cancer"),
    ((7, 23), (8, 22), "leo"),
    ((8, 23), (9, 22), "virgo"),
    ((9, 23), (10, 22), "libra"),
    ((10, 23), (11, 21), "scorpio"),
    ((11, 22), (12, 21), "sagittarius"),
    ((12, 22), (1, 19), "capricorn"),
    ((1, 20), (2, 18), "aquarius"),
    ((2, 19), (3, 20), "pisces"),
]

CHINESE_ZODIAC = [
    "rat", "ox", "tiger", "rabbit", "dragon", "snake",
    "horse", "goat", "monkey", "rooster", "dog", "pig",
]


# ── Utilities ─────────────────────────────────────────────────────────────────

def strip_accents(text: str) -> str:
    """Remove accented characters using PT/ES/FR/DE map."""
    for accented, plain in ACCENT_MAP.items():
        text = text.replace(accented, plain)
    return text


def normalize(word: str) -> str:
    """Strip accents and remove non-alphanumeric chars except dashes/underscores."""
    return strip_accents(word.strip())


def _block_case(s: str, block: int, start_upper: bool) -> str:
    """Alternating blocks of `block` chars upper/lower (e.g. block=2 → UUllUUll...)."""
    result: list[str] = []
    upper = start_upper
    count = 0
    for ch in s:
        result.append(ch.upper() if upper else ch.lower())
        if ch.isalpha():
            count += 1
            if count % block == 0:
                upper = not upper
    return "".join(result)


def _extended_case_variants(word: str) -> list[str]:
    """Extra mixed-case styles beyond lower/upper/capitalize (e.g. PetY)."""
    if not word or not any(c.isalpha() for c in word):
        return []
    clean = word
    n = len(clean)
    out: list[str] = [
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(clean)),
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(clean)),
        _block_case(clean, 2, True),
        _block_case(clean, 2, False),
    ]
    if n >= 2:
        # Pet → PeT (last letter upper)
        out.append(clean[:-1].capitalize() + clean[-1].upper())
        out.append(clean[0].upper() + clean[1:-1].lower() + clean[-1].upper())
    if n >= 4:
        # Pet → PET style (last two letters upper - common pet-password style)
        out.append(clean[0].upper() + clean[1:-2].lower() + clean[-2].upper() + clean[-1].upper())
    if n >= 3:
        out.append(
            clean[: n // 3].upper()
            + clean[n // 3: 2 * n // 3].lower()
            + clean[2 * n // 3:].upper()
        )
    return list(dict.fromkeys(v for v in out if v and v != clean))


def _slug_from_name(name: str) -> str:
    """Build a filesystem-safe slug from a display name."""
    slug = re.sub(r"[^\w\-]+", "_", strip_accents(name.strip()).lower()).strip("_")
    return slug[:40] if slug else ""


def _format_extension(fmt: str) -> str:
    """Map export format to file extension."""
    return {
        "lst": ".lst",
        "txt": ".txt",
        "tar": ".tar",
        "tar.gz": ".tar.gz",
        "zip": ".zip",
    }.get(fmt, ".lst")


def suggested_profile_output_path(profile: dict, fmt: str = "lst") -> str:
    """Default output path in cwd: <name-slug>.<ext> from export format."""
    slug = _slug_from_name(profile.get("full_name", "") or "")
    if not slug:
        slug = f"profile_{uuid.uuid4().hex[:8]}"
    return str(Path.cwd() / f"{slug}{_format_extension(fmt)}")


def default_profile_output_path(profile: dict) -> str:
    """Legacy default (lst in /tmp) - prefer suggested_profile_output_path."""
    slug = _slug_from_name(profile.get("full_name", "") or "")
    if not slug:
        slug = f"profile_{uuid.uuid4().hex[:8]}"
    return str(DEFAULT_OUTPUT_DIR / f"{slug}.lst")


def normalize_profile_output_path(
    raw: str,
    profile: dict,
    fmt: str = "lst",
) -> str:
    """
    Resolve interactive output path.

    - Empty → suggested path in cwd using profile name + format extension
    - Absolute path or path with directory → use as-is (mkdir on write)
    - Bare filename → current working directory; adds extension if missing
    """
    raw = (raw or "").strip()
    if not raw:
        return suggested_profile_output_path(profile, fmt)
    p = Path(raw).expanduser()
    target = p if (p.is_absolute() or p.parent != Path(".")) else Path.cwd() / p.name
    if not target.suffix and fmt in ("lst", "txt", "zip", "tar"):
        ext = _format_extension(fmt)
        if ext == ".tar.gz":
            target = target.with_name(target.name + ext)
        else:
            target = target.with_suffix(ext)
    return str(target)


def resolve_profile_output(cli_output: Optional[str], profile: dict) -> Optional[str]:
    """CLI -o wins; else interactive output_path; else None (stdout)."""
    fmt = (profile.get("output") or {}).get("format", "lst")
    if cli_output:
        return normalize_profile_output_path(cli_output, profile, fmt)
    if profile.get("output_path"):
        return profile["output_path"]
    return None


def get_zodiac(day: int, month: int) -> str:
    """Return zodiac sign name for a given day and month."""
    for (sm, sd), (em, ed), name in ZODIAC:
        if sm <= em:
            if (month == sm and day >= sd) or (month == em and day <= ed):
                return name
            if sm < month < em:
                return name
        else:
            if (month == sm and day >= sd) or month > sm or (month == em and day <= ed) or month < em:
                return name
    return "unknown"


def get_chinese_zodiac(year: int) -> str:
    """Return Chinese zodiac animal for a given year."""
    return CHINESE_ZODIAC[(year - 4) % 12]


def estimate_birth_year(age: int) -> int:
    """Estimate birth year from approximate age."""
    return datetime.now().year - age


def parse_date_input(raw: str) -> Optional[tuple[int, int, int]]:
    """
    Parse a date from user input in multiple formats.

    Supports: dd/mm/yyyy, dd-mm-yyyy, ddmmyyyy, yyyy, dd/mm, dd-mm, mm/yyyy.

    Args:
        raw: Raw date string from user.

    Returns:
        Tuple (day, month, year) with 0 for unknown components, or None.
    """
    raw = raw.strip()
    if not raw:
        return None

    # yyyy only
    if re.fullmatch(r"\d{4}", raw):
        return (0, 0, int(raw))

    # ddmmyyyy
    if re.fullmatch(r"\d{8}", raw):
        return (int(raw[:2]), int(raw[2:4]), int(raw[4:]))

    # dd/mm/yyyy or dd-mm-yyyy or dd.mm.yyyy
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})", raw)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    # dd/mm or dd-mm
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})", raw)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)

    # mm/yyyy
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{4})", raw)
    if m:
        return (0, int(m.group(1)), int(m.group(2)))

    return None


def _split_words(text: str) -> list[str]:
    """Split text on whitespace, returning non-empty tokens."""
    return [t for t in text.replace(",", " ").split() if t]


def _leet_tables_for_mode(mode: str) -> list[dict[str, str]]:
    """Return leet substitution tables for profile leet mode."""
    mode = (mode or "basic").lower()
    if mode in ("none", ""):
        return []
    if mode == "basic":
        return [LEET_BASIC]
    if mode == "medium":
        return [LEET_BASIC, _LEET_V2]
    return [LEET_BASIC, _LEET_V2, _LEET_V3]


def _apply_leet(s: str, table: dict[str, str]) -> str:
    return "".join(table.get(c, c) for c in s)


def _keyword_abbreviations(text: str) -> list[str]:
    """
    Build acronym tokens from keywords (e.g. cyber security → CS).

    Also handles camelCase (CyberSecurity → CS) and explicit short acronyms.
    """
    if not text or not text.strip():
        return []
    raw = strip_accents(text.strip())
    compact = re.sub(r"[\s\-_/]+", "", raw)
    found: list[str] = []

    if 2 <= len(compact) <= 8 and compact.isalpha() and raw.upper() == raw:
        found.append(compact.upper())

    words = [w for w in re.split(r"[\s\-_/]+", raw) if w]
    if len(words) >= 2:
        initials = "".join(w[0] for w in words if w and w[0].isalpha())
        if len(initials) >= 2:
            found.append(initials.upper())

    camel_parts = re.findall(r"[A-Z]?[a-z]+", raw)
    if len(camel_parts) >= 2:
        initials = "".join(p[0] for p in camel_parts if p)
        if len(initials) >= 2:
            found.append(initials.upper())

    # Single compound: cybersecurity → cyber + security
    lower = compact.lower()
    for prefix, suffix in (
        ("cyber", "security"), ("info", "sec"), ("net", "work"),
        ("soft", "ware"), ("dev", "ops"), ("cyber", "sec"),
    ):
        if lower.startswith(prefix) and lower.endswith(suffix):
            ab = (prefix[0] + suffix[0]).upper()
            found.append(ab)
            break

    result: list[str] = []
    seen: _SeenSet = _SeenSet()
    for a in found:
        for v in (a.upper(), a.lower(), a.capitalize()):
            if v not in seen:
                seen.add(v)
                result.append(v)
    return result


def _word_variants(word: str, leet: bool = True, leet_mode: str = "basic") -> list[str]:
    """
    Generate case and leet variants of a single word.

    Each variant is a clean single-word token (no spaces).

    Args:
        word: Single word to vary.
        leet: Include leet substitutions.

    Returns:
        Ordered unique list of variants.
    """
    clean = normalize(word)
    if not clean:
        return []

    base = list(dict.fromkeys([
        clean,
        clean.lower(),
        clean.upper(),
        clean.capitalize(),
        clean[0].upper() + clean[1:].lower() if len(clean) > 1 else clean.upper(),
        *_extended_case_variants(clean),
    ]))

    if leet:
        mode = leet_mode if leet_mode not in ("none", "") else "basic"
        for w in list(base):
            for table in _leet_tables_for_mode(mode):
                leet_w = _apply_leet(w, table)
                if leet_w not in base and leet_w != w:
                    base.append(leet_w)
            # lowercase selective substitutions
            low = w.lower()
            sel = _apply_leet(low, _SELECTIVE_LEET_LOWER)
            if sel not in base and sel != low:
                base.append(sel)
            # uppercase numeric leet (medium/aggressive)
            if mode in ("medium", "aggressive"):
                up = w.upper()
                v2 = _apply_leet(up, _LEET_V2)
                if v2 not in base and v2 != up:
                    base.append(v2)
                # @-style on uppercase base: D@RYU$ etc.
                v3 = _apply_leet(up, _LEET_V3)
                if v3 not in base and v3 != up:
                    base.append(v3)

    return base


def _date_tokens(day: int, month: int, year: int) -> list[str]:
    """
    Generate date string tokens from date components.

    Produces: ddmmyyyy, dd/mm/yyyy, dd-mm-yyyy, yyyy, ddmm, mmyyyy,
    and reversed variants (yyyymmdd).

    Args:
        day: Day (0 = unknown).
        month: Month (0 = unknown).
        year: Year (0 = unknown).

    Returns:
        List of date token strings.
    """
    tokens: list[str] = []
    if year:
        tokens.append(str(year))
        tokens.append(str(year)[-2:])  # 2-digit year
    if day and month:
        dd = str(day).zfill(2)
        mm = str(month).zfill(2)
        tokens.extend([
            f"{dd}{mm}",
            f"{mm}{dd}",
        ])
        if year:
            yy = str(year)
            y2 = yy[-2:]
            tokens.extend([
                f"{dd}{mm}{yy}",
                f"{dd}{mm}{y2}",
                f"{yy}{mm}{dd}",
                f"{y2}{mm}{dd}",
                f"{dd}/{mm}/{yy}",
                f"{dd}-{mm}-{yy}",
                f"{dd}.{mm}.{yy}",
                f"{dd}/{mm}/{y2}",
                f"{dd}-{mm}-{y2}",
            ])
    elif month and year:
        mm = str(month).zfill(2)
        tokens.extend([f"{mm}{year}", f"{year}{mm}"])
    return list(dict.fromkeys(tokens))


def _clean_phone(phone: str) -> list[str]:
    """
    Return phone number in multiple formats: E.164, local (no +), bare digits.

    Args:
        phone: Raw phone string (e.g., '+5511912345678', '11912345678').

    Returns:
        List of phone string variants.
    """
    digits = re.sub(r"\D", "", phone)
    variants = [digits]
    if phone.startswith("+"):
        variants.append("+" + digits)
    return list(dict.fromkeys(v for v in variants if len(v) >= 7))


def _social_handle_variants(handle: str) -> list[str]:
    """
    Return social media handle with and without @ prefix.

    Args:
        handle: Handle string, optionally prefixed with @.

    Returns:
        List with/without @ variant.
    """
    clean = handle.lstrip("@").strip()
    if not clean:
        return []
    return list(dict.fromkeys([clean, f"@{clean}"]))


# ── CUPP/elpscrk/BEWGor enhancements ─────────────────────────────────────────

def _reversed_tokens(tokens: list[str]) -> list[str]:
    """Generate reversed versions of all tokens (CUPP/elpscrk/BEWGor parity)."""
    reversed_list: list[str] = []
    for tok in tokens:
        rev = tok[::-1]
        if rev != tok and len(rev) >= 3:
            reversed_list.append(rev)
    return reversed_list


def _name_initials(full_name: str) -> list[str]:
    """Extract name fragments: initials, first letter, first 2 letters (BEWGor/elpscrk parity)."""
    parts = _split_words(full_name)
    if not parts:
        return []

    fragments: list[str] = []
    initials = "".join(p[0] for p in parts if p).upper()
    if len(initials) >= 2:
        fragments.append(initials)
        fragments.append(initials.lower())

    for part in parts:
        clean = normalize(part)
        if not clean:
            continue
        fragments.append(clean[0].lower())
        fragments.append(clean[0].upper())
        if len(clean) >= 2:
            fragments.append(clean[:2].lower())
            fragments.append(clean[:2].upper())
            fragments.append(clean[:2].capitalize())

    return list(dict.fromkeys(fragments))


def _extra_date_fragments(day: int, month: int, year: int) -> list[str]:
    """Generate granular date fragments (CUPP-style: isolated day, month, year digits)."""
    frags: list[str] = []
    if day:
        frags.append(str(day))
        frags.append(str(day).zfill(2))
        if day >= 10:
            frags.append(str(day % 10))
    if month:
        frags.append(str(month))
        frags.append(str(month).zfill(2))
        if month >= 10:
            frags.append(str(month % 10))
    if year:
        ys = str(year)
        frags.append(ys)
        frags.append(ys[-2:])
        if len(ys) >= 3:
            frags.append(ys[-3:])
    return list(dict.fromkeys(frags))


def _date_fragment_combos(date_tokens: list[str], max_combos: int = 200) -> list[str]:
    """Generate CUPP-style bdss cartesian products from numeric date fragments.

    Filters numeric-only tokens of 2-4 chars, then yields all pairwise
    concatenations (f1+f2) and separator-joined forms (f1+sep+f2).
    Equivalent to CUPP's ``bdss`` / ``kbdss`` logic.

    Args:
        date_tokens: List of raw date token strings (may include non-numeric).
        max_combos: Upper limit on total combos returned (avoids explosion).

    Returns:
        Deduplicated list of combined date fragment strings.
    """
    candidates = [
        t for t in date_tokens
        if t.isdigit() and 2 <= len(t) <= 4
    ]
    candidates = list(dict.fromkeys(candidates))

    seps = ["", "-", "/"]
    seen: set[str] = set()
    combos: list[str] = []

    for f1, f2 in _product(candidates, candidates):
        if f1 == f2:
            continue
        for sep in seps:
            combo = f"{f1}{sep}{f2}"
            if combo not in seen:
                seen.add(combo)
                combos.append(combo)
                if len(combos) >= max_combos:
                    return combos

    return combos


def _phone_fragments(phone: str) -> list[str]:
    """Decompose phone into fragments: last 4, first 4, national format (elpscrk parity)."""
    digits = re.sub(r"\D", "", phone)
    frags: list[str] = []
    if len(digits) >= 4:
        frags.append(digits[-4:])
        frags.append(digits[:4])
    if len(digits) >= 7:
        frags.append(digits[-7:])
    if digits.startswith("55") and len(digits) > 4:
        frags.append("0" + digits[2:])
    return list(dict.fromkeys(f for f in frags if f))


MULTI_CHAR_SPECIALS = [
    "!!", "!@", "!#", "@!", "@#", "#!", "#@",
    "123", "1!", "!1", "12", "01", "!@#", "@!#",
    "$$", "**", "##", "!", "@", "#", "$", "*",
]

# Hacker-culture suffixes (0x90 = NOP in x86 shellcode)
HACKER_SUFFIXES: list[str] = [
    "@0x90", "#0x90", "_0x90", "!0x90",
    "@0x41", "#0x41", "@0x00", "_0x00",
]

_BIRTHSTONES: dict[int, list[str]] = {
    1: ["garnet"],
    2: ["amethyst"],
    3: ["aquamarine", "bloodstone"],
    4: ["diamond"],
    5: ["emerald"],
    6: ["pearl", "moonstone"],
    7: ["ruby"],
    8: ["peridot", "spinel"],
    9: ["sapphire"],
    10: ["opal", "tourmaline"],
    11: ["topaz", "citrine"],
    12: ["tanzanite", "zircon", "turquoise"],
}


def get_birthstone_tokens(month: int) -> list[str]:
    """Return birthstone names for a given birth month as profile tokens.

    Returns list with each stone name in lowercase and capitalized form.
    """
    stones = _BIRTHSTONES.get(month, [])
    tokens: list[str] = []
    for stone in stones:
        low = stone.lower()
        cap = stone.capitalize()
        if low not in tokens:
            tokens.append(low)
        if cap not in tokens:
            tokens.append(cap)
    return tokens


# PT-BR informal shorthands used in phrase-initial extraction
_BR_INITIALS_MAP: dict[str, str] = {
    "mais": "+",   # "mais" (more) written as + in BR text messages
}


def _phrase_initials_suffixes(
    extra_suffixes: list[str] | None = None,
    *,
    include_recent_years: bool = True,
    recent_years_lookback: int = 1,
) -> list[str]:
    """Build prefix/suffix list for phrase-initial combos (incl. rolling years)."""
    suffixes: list[str] = [
        "",
        "@0x90", "#0x90", "_0x90", "!0x90",
        "@0x41", "#0x41",
        "@123", "#123", "_123", "!123",
        "@!", "#!", "_!",
    ]
    if include_recent_years:
        for y in rolling_recent_year_tokens(recent_years_lookback):
            for pref in ("@", "#", "_", "!", "$"):
                suffixes.append(f"{pref}{y}")
    for s in extra_suffixes or []:
        if s not in suffixes:
            suffixes.append(s)
    return list(dict.fromkeys(suffixes))


def phrase_initials_variants(
    phrase: str,
    extra_prefixes: list[str] | None = None,
    extra_suffixes: list[str] | None = None,
    *,
    include_recent_years: bool = True,
    recent_years_lookback: int = 1,
) -> list[str]:
    """
    Generate password variants from phrase initials (first letter of each word).

    PT-BR informal shorthand: "mais" → "+" (common in text/SMS messages).
    Applies case mutations, leet substitutions, and prefix/suffix combinations
    including hacker-culture patterns like @0x90, #0x90.

    Args:
        phrase: Input phrase (e.g. "é mais fácil pedir do que tentar quebrar").
        extra_prefixes: Additional prefixes to combine (added on top of defaults).
        extra_suffixes: Additional suffixes to combine (added on top of defaults).

    Returns:
        Ordered unique list of password candidates.

    Example::

        phrase_initials_variants("é mais fácil pedir do que tentar quebrar")
        # initials → "e+fpdqtq"
        # variants → "E+FPDQTQ", "_E+FPDQTQ@0x90", "e+fpdqtq@123", ...
    """
    words = _split_words(phrase)
    if not words:
        return []

    # Build initials with PT-BR informal shorthands
    initials_chars: list[str] = []
    for word in words:
        clean = strip_accents(word.strip().lower())
        if not clean:
            continue
        shorthand = _BR_INITIALS_MAP.get(clean)
        if shorthand:
            initials_chars.append(shorthand)
        else:
            initials_chars.append(clean[0])

    if not initials_chars:
        return []

    raw = "".join(initials_chars)  # e.g. "e+fpdqtq"
    n = len(raw)

    # Case variants
    base_variants: list[str] = list(dict.fromkeys([
        raw,                                                   # e+fpdqtq
        raw.upper(),                                           # E+FPDQTQ
        raw.capitalize(),                                      # E+fpdqtq
        # alternating upper/lower starting with upper (pos 0 → upper)
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(raw)),
        # alternating lower/upper starting with lower (pos 0 → lower)
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(raw)),
        # first half upper, second half lower
        raw[:n // 2].upper() + raw[n // 2:].lower(),
        # first half lower, second half upper
        raw[:n // 2].lower() + raw[n // 2:].upper(),
        # thirds: upper / lower / upper
        raw[:n // 3].upper() + raw[n // 3: 2 * n // 3].lower() + raw[2 * n // 3:].upper()
        if n >= 3 else raw.upper(),
        # blocks of 2: UUllUUll... (generates E+FpdQTq style)
        _block_case(raw, 2, True),
        # blocks of 2: llUUllUU...
        _block_case(raw, 2, False),
        # blocks of 3: UUUlllUUU...
        _block_case(raw, 3, True),
    ]))

    # Leet substitution variants
    leet_variants: list[str] = []
    for b in base_variants:
        leet_v = "".join(LEET_BASIC.get(ch, ch) for ch in b)
        if leet_v not in base_variants and leet_v != b:
            leet_variants.append(leet_v)

    all_bases = list(dict.fromkeys(base_variants + leet_variants))

    prefixes: list[str] = ["", "_", "__", "@", "#", "!"] + (extra_prefixes or [])
    suffixes = _phrase_initials_suffixes(
        extra_suffixes,
        include_recent_years=include_recent_years,
        recent_years_lookback=recent_years_lookback,
    )

    results: list[str] = []
    seen: _SeenSet = _SeenSet()

    for base in all_bases:
        for pref in prefixes:
            for suf in suffixes:
                candidate = pref + base + suf
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    results.append(candidate)

    return results


def _emit_phrase_initials_combos(
    profile: dict,
    min_len: int,
    max_len: int,
    seen: "_SeenSet | set[str]",
) -> Generator[str, None, None]:
    """
    Yield acrostic passwords from personal phrases/jargon in the profile.

    Example phrase → ``_E+FpQTq@2026`` (prefix + initials + year suffix).
    """
    phrases = list(profile.get("phrases") or []) + list(profile.get("jargon_phrases") or [])
    if not phrases:
        return

    lookback = int(profile.get("recent_years_lookback", 1))
    include_years = profile.get("include_recent_years", True)

    for phrase in phrases:
        if not phrase or not str(phrase).strip():
            continue
        for variant in phrase_initials_variants(
            str(phrase),
            include_recent_years=include_years,
            recent_years_lookback=lookback,
        ):
            if variant and variant not in seen and min_len <= len(variant) <= max_len:
                seen.add(variant)
                yield variant


def _emit_phrase_full_combos(
    profile: dict,
    min_len: int,
    max_len: int,
    seen: "_SeenSet | set[str]",
    *,
    do_leet: bool = False,
    leet_mode: str = "basic",
) -> Generator[str, None, None]:
    """Yield full-phrase password variants (motor 6 / phrase_mode full)."""
    phrases = list(profile.get("phrases") or []) + list(profile.get("jargon_phrases") or [])
    if not phrases:
        return

    phrase_opts = profile.get("phrase_options") or {}
    use_prefixes = profile.get("phrase_prefixes", phrase_opts.get("prefixes", True))
    use_year_suffix = profile.get(
        "phrase_suffix_years",
        phrase_opts.get("suffix_years", True),
    )
    lookback = int(profile.get("recent_years_lookback", 1))

    prefixes = ["", "_", "@", "#"] if use_prefixes else [""]
    suffixes: list[str] = [""]
    if use_year_suffix and profile.get("include_recent_years", True):
        suffixes.extend(
            _phrase_initials_suffixes(
                None,
                include_recent_years=True,
                recent_years_lookback=lookback,
            )
        )

    for phrase in phrases:
        if not phrase or not str(phrase).strip():
            continue
        words = _split_words(str(phrase))
        if not words:
            continue

        bases: list[str] = []
        joined = "".join(words)
        underscored = "_".join(words)
        dotted = ".".join(words)
        for base in (joined, underscored, dotted, strip_accents(joined)):
            if base:
                bases.append(base)

        expanded: list[str] = []
        for base in bases:
            expanded.append(base)
            expanded.append(base.lower())
            expanded.append(base.upper())
            expanded.append(base.capitalize())
            if do_leet:
                for variant in _word_variants(base, leet=True, leet_mode=leet_mode):
                    expanded.append(variant)

        for base in dict.fromkeys(expanded):
            for pref in prefixes:
                for suff in suffixes:
                    candidate = f"{pref}{base}{suff}"
                    if (
                        candidate
                        and candidate not in seen
                        and min_len <= len(candidate) <= max_len
                    ):
                        seen.add(candidate)
                        yield candidate


# Leet tables alias - defined above near LEET_BASIC
_VOWELS = set("aeiouAEIOU")


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
    from embedxpl.engines.wordlists.i18n import t, ask_language_selection, get_session_locale
    from embedxpl.engines.wordlists.date_profile import ask_date_profile, build_date_tokens

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
            from embedxpl.engines.wordlists.country_tokens import resolve_country, country_display_name
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
            country_word_tokens,
            country_minimal_tokens,
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
