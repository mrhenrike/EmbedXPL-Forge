"""Plugin system for third-party EmbedXPL modules.

Plugins are discovered via setuptools entry_points under the group
``embedxpl.plugins``.  Each entry point must resolve to a subclass of
:class:`PluginBase`.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)

__all__ = [
    "PluginBase",
    "PluginError",
    "PluginLoadError",
    "PluginMeta",
    "PluginNotFoundError",
    "PluginRegistry",
]


class PluginError(Exception):
    pass


class PluginLoadError(PluginError):
    pass


class PluginNotFoundError(PluginError):
    pass


@dataclass
class PluginMeta:
    name: str
    version: str
    description: str = ""
    author: str = ""
    module_paths: List[str] = field(default_factory=list)


class PluginBase(abc.ABC):
    """Base class for all EmbedXPL plugins.

    Subclasses must implement :meth:`meta` and :meth:`register`.
    """

    @abc.abstractmethod
    def meta(self) -> PluginMeta:
        """Return metadata about this plugin."""

    @abc.abstractmethod
    def register(self, registry: "PluginRegistry") -> None:
        """Called when the plugin is loaded into the registry."""

    def unregister(self) -> None:  # noqa: B027
        """Called when the plugin is unloaded (optional override)."""


class PluginRegistry:
    """Central registry that discovers, loads and manages plugins."""

    ENTRY_POINT_GROUP = "embedxpl.plugins"

    def __init__(self) -> None:
        self._plugins: Dict[str, PluginBase] = {}
        self._modules: Dict[str, Any] = {}

    @property
    def loaded(self) -> List[str]:
        return list(self._plugins.keys())

    def discover(self) -> List[str]:
        """Discover available plugins via entry_points (does not load them)."""
        from .loader import discover_entry_points

        return discover_entry_points(self.ENTRY_POINT_GROUP)

    def load(self, name: str) -> PluginMeta:
        """Load and register a single plugin by entry-point name."""
        if name in self._plugins:
            return self._plugins[name].meta()

        from .loader import load_plugin_class

        cls = load_plugin_class(name, self.ENTRY_POINT_GROUP)
        instance = cls()
        meta = instance.meta()
        instance.register(self)
        self._plugins[meta.name] = instance
        logger.info("Plugin loaded: %s v%s", meta.name, meta.version)
        return meta

    def load_all(self) -> List[PluginMeta]:
        """Discover and load every available plugin."""
        results: List[PluginMeta] = []
        for name in self.discover():
            try:
                results.append(self.load(name))
            except PluginLoadError as exc:
                logger.warning("Failed to load plugin %s: %s", name, exc)
        return results

    def get(self, name: str) -> PluginBase:
        if name not in self._plugins:
            raise PluginNotFoundError(f"Plugin not loaded: {name}")
        return self._plugins[name]

    def unload(self, name: str) -> None:
        plugin = self._plugins.pop(name, None)
        if plugin is not None:
            plugin.unregister()
            logger.info("Plugin unloaded: %s", name)

    def register_module(self, path: str, module: Any) -> None:
        """Register a module contributed by a plugin."""
        self._modules[path] = module

    def get_modules(self) -> Dict[str, Any]:
        return dict(self._modules)

    def list(self) -> List[PluginMeta]:
        return [p.meta() for p in self._plugins.values()]
