"""Tests for the EmbedXPL plugin system."""


import pytest

from embedxpl.core.plugins import (
    PluginBase,
    PluginError,
    PluginLoadError,
    PluginMeta,
    PluginNotFoundError,
    PluginRegistry,
)
from embedxpl.core.plugins.loader import discover_entry_points


class _DummyPlugin(PluginBase):
    """Concrete plugin for testing."""

    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="dummy",
            version="0.1.0",
            description="Test plugin",
            author="test",
        )

    def register(self, registry: PluginRegistry) -> None:
        registry.register_module("dummy.mod1", object())

    def unregister(self) -> None:
        pass


class TestPluginMeta:
    def test_required_fields(self):
        m = PluginMeta(name="x", version="1.0")
        assert m.name == "x"
        assert m.version == "1.0"
        assert m.description == ""
        assert m.module_paths == []

    def test_with_all_fields(self):
        m = PluginMeta(
            name="full",
            version="2.0",
            description="desc",
            author="auth",
            module_paths=["a.b"],
        )
        assert m.author == "auth"
        assert m.module_paths == ["a.b"]


class TestPluginBase:
    def test_abstract_cannot_instantiate(self):
        with pytest.raises(TypeError):
            PluginBase()

    def test_concrete_subclass(self):
        p = _DummyPlugin()
        m = p.meta()
        assert m.name == "dummy"
        assert m.version == "0.1.0"


class TestPluginRegistry:
    def test_empty_registry(self):
        reg = PluginRegistry()
        assert reg.loaded == []
        assert reg.list() == []
        assert reg.get_modules() == {}

    def test_manual_register_and_get(self):
        reg = PluginRegistry()
        p = _DummyPlugin()
        meta = p.meta()
        p.register(reg)
        reg._plugins[meta.name] = p
        assert "dummy" in reg.loaded
        assert reg.get("dummy") is p

    def test_get_not_found(self):
        reg = PluginRegistry()
        with pytest.raises(PluginNotFoundError):
            reg.get("nonexistent")

    def test_unload(self):
        reg = PluginRegistry()
        p = _DummyPlugin()
        reg._plugins["dummy"] = p
        reg.unload("dummy")
        assert "dummy" not in reg.loaded

    def test_unload_missing_is_noop(self):
        reg = PluginRegistry()
        reg.unload("ghost")

    def test_register_module(self):
        reg = PluginRegistry()
        sentinel = object()
        reg.register_module("test.path", sentinel)
        assert reg.get_modules()["test.path"] is sentinel

    def test_discover_no_plugins(self):
        names = discover_entry_points("embedxpl.plugins")
        assert isinstance(names, list)

    def test_list_returns_meta(self):
        reg = PluginRegistry()
        p = _DummyPlugin()
        reg._plugins["dummy"] = p
        metas = reg.list()
        assert len(metas) == 1
        assert metas[0].name == "dummy"


class TestPluginExceptions:
    def test_hierarchy(self):
        assert issubclass(PluginLoadError, PluginError)
        assert issubclass(PluginNotFoundError, PluginError)

    def test_load_error_message(self):
        exc = PluginLoadError("bad plugin")
        assert "bad plugin" in str(exc)
