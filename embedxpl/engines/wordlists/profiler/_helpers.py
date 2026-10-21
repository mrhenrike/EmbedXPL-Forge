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
from datetime import date, datetime
from itertools import permutations as _permutations
from itertools import product as _product
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
        from embedxpl.engines.wordlists.date_profile import build_date_tokens, date_profile_from_yaml
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


