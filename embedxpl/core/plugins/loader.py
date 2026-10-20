"""Entry-point discovery and loading helpers."""


import sys
from typing import List, Type

from . import PluginBase, PluginLoadError


def _entry_points(group: str):
    """Compatibility shim for importlib.metadata across Python 3.9+."""
    if sys.version_info >= (3, 12):
        from importlib.metadata import entry_points

        return entry_points(group=group)

    if sys.version_info >= (3, 10):
        from importlib.metadata import entry_points

        return entry_points(group=group)

    from importlib.metadata import entry_points as _ep

    all_eps = _ep()
    if isinstance(all_eps, dict):
        return all_eps.get(group, [])
    return all_eps.get(group, [])


def discover_entry_points(group: str) -> list[str]:
    """Return names of all entry points in *group*."""
    return [ep.name for ep in _entry_points(group)]


def load_plugin_class(name: str, group: str) -> type[PluginBase]:
    """Load a single entry-point by *name* and validate it."""
    eps = [ep for ep in _entry_points(group) if ep.name == name]
    if not eps:
        raise PluginLoadError(f"No entry point '{name}' in group '{group}'")

    try:
        cls = eps[0].load()
    except Exception as exc:
        raise PluginLoadError(f"Failed to load '{name}': {exc}") from exc

    if not (isinstance(cls, type) and issubclass(cls, PluginBase)):
        raise PluginLoadError(
            f"Entry point '{name}' resolved to {cls!r}, expected PluginBase subclass"
        )
    return cls
