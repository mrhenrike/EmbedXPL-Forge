"""Tests for embedxpl.core.evasion.hookchain_reference."""
from __future__ import annotations

import pytest

from embedxpl.core.evasion.hookchain_reference import (
    HookChainAnalyzer,
    HookChainLoaderGen,
    HookChainImplant,
    hookchain_source_dir,
    _embedxpl_bin_dir,
    implant_binary,
)


class TestHookChainAnalyzer:
    def test_instantiation(self):
        a = HookChainAnalyzer()
        assert a is not None


class TestHookChainLoaderGen:
    def test_instantiation(self):
        g = HookChainLoaderGen()
        assert g is not None


class TestHookChainImplant:
    def test_instantiation(self):
        i = HookChainImplant()
        assert i is not None


class TestHookChainFunctions:
    def test_hookchain_source_dir(self):
        result = hookchain_source_dir()
        assert result is None or hasattr(result, "exists")

    def test_embedxpl_bin_dir(self):
        result = _embedxpl_bin_dir()
        assert hasattr(result, "exists")

    def test_implant_binary(self):
        result = implant_binary()
        assert result is None or hasattr(result, "exists")
