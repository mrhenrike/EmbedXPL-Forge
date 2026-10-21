"""Tests for embedxpl.core.banner."""
from __future__ import annotations

import pytest

from embedxpl.core.banner import *
import embedxpl.core.banner as banner_mod


class TestBannerModule:
    def test_module_loads(self):
        assert banner_mod is not None

    def test_has_callable(self):
        funcs = [n for n in dir(banner_mod) if not n.startswith("_") and callable(getattr(banner_mod, n))]
        assert len(funcs) >= 1
