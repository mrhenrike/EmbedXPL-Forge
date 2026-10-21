"""Tests for embedxpl.core.soho_exploit_catalog."""
from __future__ import annotations

import pytest

from embedxpl.core.soho_exploit_catalog import resolve_soho_catalog_root


class TestSOHOCatalog:
    def test_resolve_root_returns_path(self):
        result = resolve_soho_catalog_root(must_exist=False)
        assert hasattr(result, "exists")

    def test_resolve_root_is_path_type(self):
        from pathlib import Path
        result = resolve_soho_catalog_root(must_exist=False)
        assert isinstance(result, Path)
