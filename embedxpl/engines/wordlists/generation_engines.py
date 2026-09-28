from __future__ import annotations

"""
generation_engines.py - Registry de motores de geração e presets do WFH.

Define os 28 motores disponíveis no comando profile, presets L/M/P/NUCLEAR,
e funções de seleção interativa via menu numerado.

Author: André Henrique (@mrhenrike)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

_ENGINE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "engines.token_variants":     ("token_variants",     "Name variants, leet on tokens"),
    "engines.date_tokens":        ("date_tokens",        "Dates, age, zodiac sign tokens"),
    "engines.depth_combos":       ("depth_combos",       "Depth-first token combinations"),
    "engines.relationship_combos":("relationship_combos","Partner, family, pet combos"),
    "engines.phrase_acrostic":    ("phrase_acrostic",    "Acrostic from phrase tokens"),
    "engines.phrase_full":        ("phrase_full",        "Full phrase wordlist injection"),
    "engines.behavior_patterns":  ("behavior_patterns",  "Keyboard walk & habit patterns"),
    "engines.cupp_concats":       ("cupp_concats",       "CUPP-style concatenations"),
    "engines.reversed_tokens":    ("reversed_tokens",    "Reversed token variants"),
    "engines.prince":             ("prince",             "PRINCE algorithm chains"),
    "engines.rsmangler":          ("rsmangler",          "RSMangler v1.5 rule engine"),
    "engines.builtin_mangle":     ("builtin_mangle",     "Built-in mangling rules"),
    "engines.osint_scrape":       ("osint_scrape",       "OSINT web scrape tokens"),
    "engines.password_dna":       ("password_dna",       "Password DNA structural analysis"),
    "engines.rank_likelihood":    ("rank_likelihood",    "Likelihood ranking by patterns"),
    "engines.maya_rank":          ("maya_rank",          "MAYA ML-based probability rank"),
    "engines.osint_perm":         ("osint_perm",         "OSINT token permutations"),
    "engines.pcfg_hybrid":        ("pcfg_hybrid",        "PCFG probabilistic hybrid"),
    "engines.markov_omen":        ("markov_omen",        "Markov/OMEN next-token model"),
    "engines.num2text_dates":     ("num2text_dates",     "Numeric date to text tokens"),
    "engines.pattern_templates":  ("pattern_templates",  "Structural pattern templates"),
    "engines.rulegen_oldpwd":     ("rulegen_oldpwd",     "Old-password rule derivation"),
    "engines.positional_leet":    ("positional_leet",    "Positional leet permutations"),
    "engines.country_locale":     ("country_locale",     "Country/locale term injection"),
    "engines.corp_cross":         ("corp_cross",         "Corporate cross-profile combos"),
    "engines.scrape_merge":       ("scrape_merge",       "Scraped data merge & dedup"),
    "engines.output_finalize":    ("output_finalize",    "Sanitize, sort, archive export"),
    "engines.keyword_mutations":  ("keyword_mutations",  "Letter/syllable reverse mutations"),
    "engines.cewl_mut":           ("cewl_mut",           "CeWL scrape + RSMangler + John rules"),
}


@dataclass
class EngineSpec:
    """Descriptor for a single generation engine registered in the WFH system."""

    id: int
    key: str
    module: str
    default_on: bool
    description_key: str
    wave: int
    nuclear_only: bool = False

    @property
    def display_name(self) -> str:
        """Return the human-readable engine name from the description registry."""
        entry = _ENGINE_DESCRIPTIONS.get(self.description_key)
        return entry[0] if entry else self.key

    @property
    def description(self) -> str:
        """Return the short engine description from the description registry."""
        entry = _ENGINE_DESCRIPTIONS.get(self.description_key)
        return entry[1] if entry else ""


ENGINE_REGISTRY: list[EngineSpec] = [
    EngineSpec(1,  "token_variants",     "profiler",           True,  "engines.token_variants",     1),
    EngineSpec(2,  "date_tokens",        "date_profile",       True,  "engines.date_tokens",        1),
    EngineSpec(3,  "depth_combos",       "profiler",           True,  "engines.depth_combos",       1),
    EngineSpec(4,  "relationship_combos","profiler",           True,  "engines.relationship_combos",1),
    EngineSpec(5,  "phrase_acrostic",    "profiler",           True,  "engines.phrase_acrostic",    1),
    EngineSpec(6,  "phrase_full",        "profiler",           True,  "engines.phrase_full",        1),
    EngineSpec(7,  "behavior_patterns",  "profiler",           True,  "engines.behavior_patterns",  1),
    EngineSpec(8,  "cupp_concats",       "cupp_engine",        True,  "engines.cupp_concats",       1),
    EngineSpec(9,  "reversed_tokens",    "profiler",           False, "engines.reversed_tokens",    1),
    EngineSpec(10, "prince",             "prince_engine",      False, "engines.prince",             2),
    EngineSpec(11, "rsmangler",          "rsmangler_engine",   False, "engines.rsmangler",          2),
    EngineSpec(12, "builtin_mangle",     "mangler",            True,  "engines.builtin_mangle",     1),
    EngineSpec(13, "osint_scrape",       "web_scraper",        False, "engines.osint_scrape",       2),
    EngineSpec(14, "password_dna",       "password_dna",       False, "engines.password_dna",       2),
    EngineSpec(15, "rank_likelihood",    "pattern_ranker",     False, "engines.rank_likelihood",    2),
    EngineSpec(16, "maya_rank",          "maya_ranker",        False, "engines.maya_rank",          3),
    EngineSpec(17, "osint_perm",         "osint_perm",         False, "engines.osint_perm",         2),
    EngineSpec(18, "pcfg_hybrid",        "pcfg_engine",        False, "engines.pcfg_hybrid",        2),
    EngineSpec(19, "markov_omen",        "markov_engine",      False, "engines.markov_omen",        3, nuclear_only=True),
    EngineSpec(20, "num2text_dates",     "num2text",           True,  "engines.num2text_dates",     1),
    EngineSpec(21, "pattern_templates",  "pattern_engine",     False, "engines.pattern_templates",  2),
    EngineSpec(22, "rulegen_oldpwd",     "rulegen_engine",     False, "engines.rulegen_oldpwd",     2),
    EngineSpec(23, "positional_leet",    "leet_permuter",      False, "engines.positional_leet",    2),
    EngineSpec(24, "country_locale",     "country_tokens",     True,  "engines.country_locale",     1),
    EngineSpec(25, "corp_cross",         "corp_profiler",      True,  "engines.corp_cross",         1),
    EngineSpec(26, "scrape_merge",       "web_scraper",        False, "engines.scrape_merge",       2),
    EngineSpec(27, "output_finalize",    "archive_export",     True,  "engines.output_finalize",    1),
    EngineSpec(28, "keyword_mutations",  "keyword_mutations",  False, "engines.keyword_mutations",  2),
    EngineSpec(29, "cewl_mut",           "pipeline_engine",    False, "engines.cewl_mut",           2),
]

_REGISTRY_INDEX: dict[int, EngineSpec] = {e.id: e for e in ENGINE_REGISTRY}
_VALID_IDS: set[int] = set(_REGISTRY_INDEX)

PRESETS: dict[str, set[int]] = {
    "light":   {1, 2, 3, 5, 20, 24, 27},
    "medium":  {1, 2, 3, 4, 5, 6, 7, 8, 12, 20, 24, 25, 27},
    "potent":  {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25, 27, 28},
    "nuclear": set(range(1, 30)),
}

PRESET_ALIASES: dict[str, str] = {
    "l": "light", "L": "light",
    "m": "medium", "M": "medium",
    "p": "potent", "P": "potent",
    "n": "nuclear", "N": "nuclear",
}

_NUCLEAR_RAM_THRESHOLD_GB: float = 4.0


def _check_ram_gb() -> float:
    """Return approximate available RAM in gigabytes.

    Returns:
        Available RAM in GB, or 99.0 when psutil is not installed.
    """
    try:
        import psutil
        return psutil.virtual_memory().available / 1024 ** 3
    except ImportError:
        return 99.0


def get_engine(engine_id: int) -> Optional[EngineSpec]:
    """Return an EngineSpec by numeric ID, or None if not found.

    Args:
        engine_id: Registry ID to look up.

    Returns:
        Matching EngineSpec, or None.
    """
    return _REGISTRY_INDEX.get(engine_id)


def default_engine_ids() -> set[int]:
    """Engine IDs enabled by default (default_on in registry)."""
    return {e.id for e in ENGINE_REGISTRY if e.default_on}


def parse_engine_selection(raw: str) -> set[int]:
    """Parse a user-supplied engine selection string into a set of IDs.

    Accepted formats:
      - "all", "y", "Y"         -> engines with default_on=True
      - "L", "M", "P", "N"      -> preset expansion
      - "1-3"                    -> {1, 2, 3}
      - "1,3,5"                  -> {1, 3, 5}
      - "1-3,8,10"               -> {1, 2, 3, 8, 10}

    Empty string is not valid here - use default_engine_ids() for Enter/default.

    Args:
        raw: Raw selection string from the user.

    Returns:
        Set of valid engine IDs.

    Raises:
        ValueError: If any requested ID is not in the registry.
    """
    stripped = raw.strip()

    if not stripped:
        raise ValueError("Empty selection - press Enter for defaults or choose L/M/P/N.")

    if stripped.lower() in {"all", "y"}:
        return default_engine_ids()

    if stripped in PRESET_ALIASES:
        preset_name = PRESET_ALIASES[stripped]
        return set(PRESETS[preset_name])

    if stripped.lower() in PRESETS:
        return set(PRESETS[stripped.lower()])

    selected: set[int] = set()
    for part in stripped.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0].strip()), int(bounds[1].strip())
            except ValueError:
                raise ValueError(f"Invalid range segment: {part!r}")
            selected.update(range(lo, hi + 1))
        else:
            try:
                selected.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid engine ID: {part!r}")

    invalid = selected - _VALID_IDS
    if invalid:
        raise ValueError(
            f"Unknown engine IDs: {sorted(invalid)}. Valid range is 1-{max(_VALID_IDS)}."
        )
    return selected


def resolve_engines(
    selection: str | set[int] | None,
    check_ram_gb: float = 0.0,
) -> set[int]:
    """Resolve a selection input to a concrete set of active engine IDs.

    Args:
        selection: A raw selection string, a pre-built set of IDs, or None to
            use all engines with default_on=True.
        check_ram_gb: Override available RAM in GB (0.0 triggers auto-detection
            only when NUCLEAR preset is active).

    Returns:
        Resolved set of engine IDs.

    Raises:
        ValueError: If the selection string is invalid.
        MemoryError: If NUCLEAR preset is selected but available RAM is below
            the threshold.
    """
    if selection is None or (isinstance(selection, str) and not str(selection).strip()):
        return default_engine_ids()

    if isinstance(selection, set):
        ids = selection
    else:
        ids = parse_engine_selection(str(selection))

    if ids == PRESETS["nuclear"] or ids == set(range(1, 30)):
        ram = check_ram_gb if check_ram_gb > 0.0 else _check_ram_gb()
        if ram < _NUCLEAR_RAM_THRESHOLD_GB:
            raise MemoryError(
                f"NUCLEAR preset requires at least {_NUCLEAR_RAM_THRESHOLD_GB:.1f} GB of free RAM. "
                f"Detected: {ram:.2f} GB available. Free memory or use the potent preset instead."
            )

    return ids


def print_engine_menu(
    active_ids: Optional[set[int]] = None,
    t_func=None,
) -> None:
    """Print the numbered engine selection menu to stdout.

    Args:
        active_ids: Pre-selected engine IDs shown with [x]. When None, engines
            with default_on=True are highlighted.
        t_func: Optional translation callable accepting a string key. When None,
            the built-in English descriptions are used.
    """
    if active_ids is None:
        active_ids = default_engine_ids()

    def _t(key: str, fallback: str) -> str:
        if t_func is not None:
            translated = t_func(key)
            if translated and translated != key:
                return translated
        return fallback

    print()
    header = _t("engines.header", "Select variation engines")
    for line in header.split("\n"):
        print(f"  {line}")
    print()
    print(f"  {'ID':>3}  {'Engine':<22} {'Description':<40} {'Status'}")
    print("  " + "\u2500" * 75)

    for spec in ENGINE_REGISTRY:
        name = _t(spec.description_key + ".name", spec.display_name)
        desc = _t(spec.description_key + ".desc", spec.description)
        status = "[x]" if spec.id in active_ids else "[ ]"
        nuclear_tag = " *" if spec.nuclear_only else "  "
        print(f"  {spec.id:>3}{nuclear_tag} {name:<22} {desc:<40} {status}")

    print()
    print(f"  {_t('engines.nuclear_mark', '(* NUCLEAR-only engines marked with *)')}")
    print()


def ask_engine_selection(t_func=None) -> set[int]:
    """Display the engine menu and collect a selection from the user via stdin.

    Args:
        t_func: Optional translation callable passed through to print_engine_menu.

    Returns:
        Resolved set of selected engine IDs.
    """
    default_ids = default_engine_ids()

    def _t(key: str, fallback: str) -> str:
        if t_func is not None:
            translated = t_func(key)
            if translated and translated != key:
                return translated
        return fallback

    print_engine_menu(active_ids=default_ids, t_func=t_func)

    while True:
        try:
            prompt = _t("engines.prompt", "Choice (Enter=defaults)")
            raw = input(f"  {prompt}: ").strip()
        except (EOFError, KeyboardInterrupt):
            logger.info("Engine selection interrupted; using defaults.")
            return default_ids

        if not raw:
            return default_ids

        try:
            ids = parse_engine_selection(raw)
        except ValueError as exc:
            print(f"  [!] {exc}")
            continue

        is_nuclear = ids == PRESETS["nuclear"] or ids == set(range(1, 30))
        if is_nuclear:
            ram = _check_ram_gb()
            if ram < _NUCLEAR_RAM_THRESHOLD_GB:
                msg = _t(
                    "engines.nuclear_ram_block",
                    "ERROR: NUCLEAR requires at least 4 GB free RAM. "
                    "Current free: {free:.1f} GB. Use P=potent instead.",
                )
                try:
                    print(f"  [!] {msg.format(free=ram)}")
                except (KeyError, IndexError):
                    print(f"  [!] {msg}")
                print(f"  [!] {_t('engines.nuclear_fallback', 'Try P=potent or M=medium, or press Enter for defaults.')}")
                continue
            print(
                f"  [!] {_t('engines.nuclear_warning', 'WARNING: NUCLEAR preset - very large wordlist.')}"
            )

        return ids
