"""Persistent user configuration for RouterXPL-Forge.

Stores preferences (compute_mode, etc.) in a JSON file
at ``~/.rxf_config.json`` so they survive across sessions.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_CONFIG_FILE = Path(os.path.expanduser("~/.rxf_config.json"))

_DEFAULTS: Dict[str, Any] = {
    "compute_mode": "auto",
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

    _cache = data
    return _cache


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
    """Read a config value.

    Args:
        key: Config key (e.g. ``compute_mode``).
        default: Fallback if key not present.

    Returns:
        The stored value or *default*.
    """
    return _load().get(key, default)


def set_val(key: str, value: Any, *, persist: bool = True) -> None:
    """Set a config value.

    Args:
        key: Config key.
        value: New value.
        persist: If True (default), flush to disk immediately.
    """
    data = _load()
    data[key] = value
    if persist:
        _save()


def all_values() -> Dict[str, Any]:
    """Return a copy of the full config dict."""
    return dict(_load())


def reset_cache() -> None:
    """Clear in-memory cache (useful for testing)."""
    global _cache
    _cache = None
