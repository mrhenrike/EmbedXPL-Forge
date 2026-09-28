"""
corp_prefixes.py - Corporate username prefix generation from JSON-driven config.

Generates username variations combining department/role prefixes with name parts.
All patterns and prefixes are loaded from an external JSON file - nothing is
hardcoded in source, and no real company names are ever referenced.

Config file: data/corp_prefix_patterns.json (relative to wfh root)
Override via: CORP_PREFIX_CONFIG env var pointing to any JSON file.

Examples generated:
  ti.pessoax.corpx         (dept prefix + firstname.lastname)
  svc.pxcorpx            (service account + initial+last)
  ext.pessoax.corpx.01     (contractor + firstname.lastname + numeric)
  adm.js                (admin role + initials)
  pessoax.corpx.adm        (firstname.lastname + role suffix)

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import json
import logging
import os
import unicodedata
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config loading ─────────────────────────────────────────────────────────────

_MODULE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _MODULE_DIR.parent


def _resolve_config_path() -> Path:
    """Resolve corp_prefix_patterns.json checking package data first, then repo root."""
    pkg_path = _MODULE_DIR / "data" / "corp_prefix_patterns.json"
    if pkg_path.exists():
        return pkg_path
    return _REPO_ROOT / "data" / "corp_prefix_patterns.json"


_DEFAULT_CONFIG_PATH = _resolve_config_path()
_CONFIG_CACHE: Optional[dict] = None


def load_prefix_config(path: Optional[str] = None) -> dict:
    """
    Load prefix patterns config from JSON file.

    Args:
        path: Path to JSON file. Defaults to data/corp_prefix_patterns.json
              or CORP_PREFIX_CONFIG env var.

    Returns:
        Parsed config dict.

    Raises:
        FileNotFoundError: If config file does not exist.
        json.JSONDecodeError: If JSON is malformed.
    """
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and path is None:
        return _CONFIG_CACHE

    cfg_path = (
        Path(path)
        if path
        else Path(os.environ.get("CORP_PREFIX_CONFIG", str(_DEFAULT_CONFIG_PATH)))
    )

    if not cfg_path.exists():
        raise FileNotFoundError(
            f"Corp prefix config not found: {cfg_path}. "
            "Expected at data/corp_prefix_patterns.json relative to wfh root."
        )

    with open(cfg_path, encoding="utf-8") as f:
        config = json.load(f)

    if path is None:
        _CONFIG_CACHE = config

    logger.debug("Loaded prefix config: %s (v%s)", cfg_path, config.get("_meta", {}).get("version", "?"))
    return config


def reload_config() -> dict:
    """Force reload of the config cache from disk."""
    global _CONFIG_CACHE
    _CONFIG_CACHE = None
    return load_prefix_config()


# ── Name normalization ─────────────────────────────────────────────────────────

def _norm(s: str) -> str:
    """Strip accents and lowercase."""
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn").lower()


# ── Prefix resolution ──────────────────────────────────────────────────────────

def get_all_prefixes(
    config: dict,
    categories: Optional[list[str]] = None,
) -> list[str]:
    """
    Return all prefix aliases from selected categories.

    Args:
        config: Loaded prefix config dict.
        categories: List of category keys to include. If None, includes all.
                    Valid: 'department', 'role', 'contractor', 'temp', 'generic'

    Returns:
        Deduplicated list of prefix strings.
    """
    all_prefixes: list[str] = []
    seen: set[str] = set()

    def _add(aliases: list[str]) -> None:
        for a in aliases:
            a = _norm(a)
            if a not in seen:
                seen.add(a)
                all_prefixes.append(a)

    def _add_category(cat_data: dict) -> None:
        if isinstance(cat_data, dict):
            if "aliases" in cat_data:
                _add(cat_data["aliases"])
            else:
                # department_prefixes has nested depts
                for dept in cat_data.values():
                    if isinstance(dept, dict) and "aliases" in dept:
                        _add(dept["aliases"])

    include_all = not categories

    if include_all or "department" in (categories or []):
        _add_category(config.get("department_prefixes", {}))

    if include_all or "role" in (categories or []):
        _add_category(config.get("role_prefixes", {}))

    if include_all or "contractor" in (categories or []):
        _add(config.get("contractor_prefixes", {}).get("aliases", []))

    if include_all or "temp" in (categories or []):
        _add(config.get("temp_account_prefixes", {}).get("aliases", []))

    if include_all or "generic" in (categories or []):
        _add(config.get("generic_prefixes", {}).get("aliases", []))

    return all_prefixes


def get_prefixes_for_sector(
    sector: str,
    config: dict,
) -> list[str]:
    """
    Return department prefix aliases recommended for a given sector.

    Args:
        sector: Sector label (from ml_patterns.classify_domain_sector).
        config: Loaded prefix config dict.

    Returns:
        List of recommended prefix aliases for this sector.
    """
    sector_map = config.get("sector_department_map", {})
    dept_keys = sector_map.get(sector) or sector_map.get("generic", [])

    dept_data = config.get("department_prefixes", {})
    prefixes: list[str] = []
    seen: set[str] = set()

    for key in dept_keys:
        # key may be alias or dept name
        dept = dept_data.get(key)
        if dept and "aliases" in dept:
            for a in dept["aliases"]:
                a = _norm(a)
                if a not in seen:
                    seen.add(a)
                    prefixes.append(a)
        else:
            a = _norm(key)
            if a not in seen:
                seen.add(a)
                prefixes.append(a)

    return prefixes


# ── Username generation ────────────────────────────────────────────────────────

def generate_prefixed_usernames(
    fn:         str,
    ln:         str,
    fi:         str,
    li:         str,
    ini:        str,
    prefixes:   list[str],
    separators: list[str],
    config:     Optional[dict] = None,
    patterns:   Optional[list[str]] = None,
    max_per_prefix: int = 0,
) -> list[str]:
    """
    Generate username variations combining prefixes with name components.

    Args:
        fn:  First name (normalized, no accents).
        ln:  Last name (normalized).
        fi:  First initial (single char).
        li:  Last initial (single char).
        ini: All initials concatenated.
        prefixes: List of prefix strings to apply (e.g. ['ti', 'svc']).
        separators: List of separator chars (e.g. ['.', '_', '']).
        config: Loaded prefix config (loaded from disk if None).
        patterns: Explicit list of pattern fmt strings; uses config if None.
        max_per_prefix: Max candidates per (prefix, separator) combo (0 = all).

    Returns:
        Deduplicated list of username strings.
    """
    if config is None:
        config = load_prefix_config()

    if patterns is None:
        raw_patterns = config.get("username_patterns", {}).get("patterns", [])
        patterns = [p["fmt"] for p in sorted(raw_patterns, key=lambda x: x.get("priority", 99))]

    results: list[str] = []
    seen: set[str] = set()

    for prefix in prefixes:
        prefix = _norm(prefix)
        for sep in separators:
            count = 0
            for pat in patterns:
                try:
                    val = pat.format(
                        prefix=prefix,
                        fn=fn,
                        ln=ln,
                        fi=fi,
                        li=li,
                        ini=ini,
                        sep=sep,
                    )
                except KeyError:
                    continue

                val = val.strip().lower()
                # Skip degenerate outputs (too short, only separator, etc.)
                if len(val) < 3 or val.replace(sep, "").strip() == "":
                    continue
                # Skip if only prefix (no name component)
                if val == prefix:
                    continue

                if val not in seen:
                    seen.add(val)
                    results.append(val)
                    count += 1

                if max_per_prefix and count >= max_per_prefix:
                    break

    return results


def generate_from_name(
    full_name:  str,
    domain:     str = "",
    prefixes:   Optional[list[str]] = None,
    categories: Optional[list[str]] = None,
    separators: Optional[list[str]] = None,
    sector:     Optional[str] = None,
    with_numeric: bool = True,
    config:     Optional[dict] = None,
) -> list[str]:
    """
    Generate all prefixed username variations for a full name.

    High-level interface: parses name, applies selected prefixes and patterns.

    Args:
        full_name: Full person name (e.g. 'PessoaX da PessoaY').
        domain: Company domain (used for sector inference if sector is None).
        prefixes: Explicit list of prefix strings. If None, uses categories.
        categories: Prefix categories to include ('department', 'role', 'contractor', etc.).
        separators: Separators to use. Defaults to ['.'].
        sector: Force a sector label (overrides auto-classify from domain).
        with_numeric: Also generate numeric-suffix variations.
        config: Loaded config dict (loaded from disk if None).

    Returns:
        Deduplicated list of username strings (no @domain suffix).
    """
    if config is None:
        config = load_prefix_config()

    # Normalize name components
    parts = _norm(full_name).split()
    if not parts:
        return []

    fn  = parts[0]
    ln  = parts[-1] if len(parts) > 1 else ""
    fi  = fn[0] if fn else ""
    li  = ln[0] if ln else ""
    ini = "".join(p[0] for p in parts)

    # Resolve separators
    if separators is None:
        separators = config.get("separators", ["."])[:1]  # default: dot only

    # Resolve prefixes
    if prefixes is None:
        if sector:
            used_prefixes = get_prefixes_for_sector(sector, config)
        elif domain:
            try:
                from embedxpl.engines.wordlists.ml_patterns import classify_domain_sector
                inferred_sector = classify_domain_sector(domain)
                used_prefixes = get_prefixes_for_sector(inferred_sector, config)
            except Exception:
                used_prefixes = get_all_prefixes(config, categories)
        else:
            used_prefixes = get_all_prefixes(config, categories)
    else:
        used_prefixes = [_norm(p) for p in prefixes]

    usernames = generate_prefixed_usernames(
        fn=fn, ln=ln, fi=fi, li=li, ini=ini,
        prefixes=used_prefixes,
        separators=separators,
        config=config,
    )

    # Numeric suffix variants (disambiguation)
    if with_numeric:
        num_cfg   = config.get("numeric_suffix_patterns", {})
        num_fmts  = num_cfg.get("formats", ["{username}{n}"])
        num_range = num_cfg.get("ranges", {}).get("common", [1, 2])

        seen = set(usernames)
        extended: list[str] = []
        for base in list(usernames):
            for fmt in num_fmts[:1]:  # only primary format to avoid explosion
                for n in num_range[:4]:  # only first 4 numbers
                    val = fmt.format(username=base, n=n).lower()
                    if val not in seen:
                        seen.add(val)
                        extended.append(val)
        usernames = usernames + extended

    return usernames


# ── CLI / integration helpers ─────────────────────────────────────────────────

def list_all_prefixes(config: Optional[dict] = None) -> dict:
    """
    Return all available prefix groups and their aliases for user inspection.

    Args:
        config: Loaded config dict (loaded from disk if None).

    Returns:
        Dict mapping category → list of aliases.
    """
    if config is None:
        config = load_prefix_config()

    result: dict = {}

    dept_data = config.get("department_prefixes", {})
    for dept_key, dept_val in dept_data.items():
        if isinstance(dept_val, dict) and "aliases" in dept_val:
            result[f"dept:{dept_key}"] = dept_val["aliases"]

    role_data = config.get("role_prefixes", {})
    for role_key, role_val in role_data.items():
        if isinstance(role_val, dict) and "aliases" in role_val:
            result[f"role:{role_key}"] = role_val["aliases"]

    for cat in ("contractor_prefixes", "temp_account_prefixes", "generic_prefixes"):
        val = config.get(cat, {})
        if isinstance(val, dict) and "aliases" in val:
            result[cat] = val["aliases"]

    return result
