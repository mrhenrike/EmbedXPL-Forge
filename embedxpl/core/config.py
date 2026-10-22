"""Persistent user configuration for EmbedXPL-Forge.

Stores preferences in a JSON file at ``~/.exf_config.json``
so they survive across sessions.  Environment variables prefixed
with ``EXF_`` override file values at runtime.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_CONFIG_FILE = Path(os.path.expanduser("~/.exf_config.json"))

_DEFAULTS: Dict[str, Any] = {
    "compute_mode": "auto",
    "output_format": "table",
    "verbosity": 1,
    "default_workspace": "default",
    "session_dir": str(Path.home() / ".exf_sessions"),
    "max_threads": 10,
    "timeout_s": 30,
    "color": True,
}

_VALID_VALUES: Dict[str, tuple] = {
    "compute_mode": ("auto", "cpu", "gpu"),
    "output_format": ("table", "json", "csv"),
    "verbosity": (0, 1, 2, 3),
}

_cache: Optional[Dict[str, Any]] = None


def _load() -> Dict[str, Any]:
    """Load config from disk, merging with defaults."""
    global _cache
    if _cache is not None:
        return _cache

    data: Dict[str, Any] = dict(_DEFAULTS)
    if _CONFIG_FILE.exists():
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as fh:
                disk = json.load(fh)
            if isinstance(disk, dict):
                data.update(disk)
        except Exception as exc:
            logger.debug("Config load failed (%s): %s", _CONFIG_FILE, exc)

    _apply_env(data)
    _cache = data
    return _cache


def _apply_env(data: Dict[str, Any]) -> None:
    """Override config values from EXF_ environment variables."""
    prefix = "EXF_"
    for key in _DEFAULTS:
        env_key = prefix + key.upper()
        env_val = os.environ.get(env_key)
        if env_val is None:
            continue
        default = _DEFAULTS[key]
        if isinstance(default, bool):
            data[key] = env_val.lower() in ("1", "true", "yes")
        elif isinstance(default, int):
            try:
                data[key] = int(env_val)
            except ValueError:
                logger.debug("Invalid int for %s: %s", env_key, env_val)
        else:
            data[key] = env_val


def _save() -> None:
    """Persist current config to disk."""
    if _cache is None:
        return
    try:
        with open(_CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump(_cache, fh, indent=2)
    except Exception as exc:
        logger.debug("Config save failed (%s): %s", _CONFIG_FILE, exc)


def get(key: str, default: Any = None) -> Any:
    """Read a config value."""
    return _load().get(key, default)


def set_val(key: str, value: Any, *, persist: bool = True) -> None:
    """Set a config value.

    Raises ValueError if the key has constrained valid values
    and value is not among them.
    """
    if key in _VALID_VALUES and value not in _VALID_VALUES[key]:
        raise ValueError(
            "invalid value {!r} for {!r}; expected one of {}".format(
                value, key, _VALID_VALUES[key]
            )
        )
    data = _load()
    data[key] = value
    if persist:
        _save()


def validate() -> list[str]:
    """Return a list of validation warnings for the current config."""
    warnings: list[str] = []
    data = _load()
    for key, allowed in _VALID_VALUES.items():
        val = data.get(key)
        if val is not None and val not in allowed:
            warnings.append(
                "{!r} has invalid value {!r}; expected one of {}".format(
                    key, val, allowed
                )
            )
    mt = data.get("max_threads")
    if isinstance(mt, int) and (mt < 1 or mt > 200):
        warnings.append("max_threads should be between 1 and 200")
    ts = data.get("timeout_s")
    if isinstance(ts, (int, float)) and ts <= 0:
        warnings.append("timeout_s must be positive")
    return warnings


def all_values() -> Dict[str, Any]:
    """Return a copy of the full config dict."""
    return dict(_load())


def reset_cache() -> None:
    """Clear in-memory cache (useful for testing)."""
    global _cache
    _cache = None


def config_path() -> Path:
    """Return the path to the config file."""
    return _CONFIG_FILE
