"""Tests for embedxpl.core.multi_lang_module."""
from __future__ import annotations

from embedxpl.core.multi_lang_module import _workspace_tmp


class TestMultiLangModule:
    def test_workspace_tmp_returns_path(self):
        from pathlib import Path
        result = _workspace_tmp()
        assert isinstance(result, Path)

    def test_workspace_tmp_consistent(self):
        r1 = _workspace_tmp()
        r2 = _workspace_tmp()
        assert r1 == r2
