"""Tests for W22.10 interpreter features: _export_data, stats, banner stats."""
from __future__ import annotations

import csv
import io
import json
import re

import pytest

from embedxpl.core.banner import _count_modules, _load_stats


class TestCountModules:
    def test_returns_dict(self):
        stats = _count_modules()
        assert isinstance(stats, dict)

    def test_expected_keys(self):
        stats = _count_modules()
        for key in ("exploits", "scanners", "payloads", "encoders", "creds", "cves"):
            assert key in stats

    def test_exploits_positive(self):
        stats = _count_modules()
        assert stats["exploits"] >= 2500

    def test_scanners_positive(self):
        stats = _count_modules()
        assert stats["scanners"] >= 200

    def test_creds_positive(self):
        stats = _count_modules()
        assert stats["creds"] >= 1000

    def test_cves_positive(self):
        stats = _count_modules()
        assert stats["cves"] >= 100


class TestLoadStats:
    def test_returns_dict(self):
        stats = _load_stats()
        assert isinstance(stats, dict)

    def test_has_timestamp(self):
        stats = _load_stats()
        assert "_ts" in stats
        assert isinstance(stats["_ts"], (int, float))

    def test_exploits_count_matches(self):
        stats = _load_stats()
        assert stats["exploits"] >= 2500


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _extract_json_array(text: str) -> list:
    """Extract first balanced JSON array from mixed text+ANSI output."""
    stripped = _strip_ansi(text)
    start = stripped.find("[")
    if start < 0:
        raise ValueError("No JSON array found")
    depth = 0
    for i in range(start, len(stripped)):
        if stripped[i] == "[":
            depth += 1
        elif stripped[i] == "]":
            depth -= 1
            if depth == 0:
                return json.loads(stripped[start : i + 1])
    raise ValueError("Unbalanced JSON array")


class TestExportData:
    @staticmethod
    def _make_interpreter():
        from embedxpl.interpreter import EmbedXPLInterpreter
        return EmbedXPLInterpreter

    def test_json_export(self, capsys):
        cls = self._make_interpreter()
        headers = ["Host", "Port", "Service"]
        rows = [["192.168.1.1", 22, "ssh"], ["10.0.0.1", 80, "http"]]
        result = cls._export_data(headers, rows, "json")
        assert result is True
        captured = capsys.readouterr().out
        data = _extract_json_array(captured)
        assert len(data) == 2
        assert data[0]["Host"] == "192.168.1.1"
        assert data[1]["Port"] == 80

    def test_csv_export(self, capsys):
        cls = self._make_interpreter()
        headers = ["Name", "Value"]
        rows = [["alpha", "1"], ["beta", "2"]]
        result = cls._export_data(headers, rows, "csv")
        assert result is True
        captured = capsys.readouterr().out
        stripped = _strip_ansi(captured)
        lines = [ln for ln in stripped.strip().split("\n") if ln.strip() and "Exported" not in ln]
        reader = csv.reader(io.StringIO("\n".join(lines[:3])))
        parsed = list(reader)
        assert parsed[0] == ["Name", "Value"]
        assert parsed[1] == ["alpha", "1"]

    def test_unknown_format_returns_false(self):
        cls = self._make_interpreter()
        result = cls._export_data(["A"], [["1"]], "xml")
        assert result is False

    def test_empty_data(self, capsys):
        cls = self._make_interpreter()
        result = cls._export_data(["A", "B"], [], "json")
        assert result is True
        captured = capsys.readouterr().out
        data = _extract_json_array(captured)
        assert data == []


class TestSearchImport:
    def test_search_module_importable(self):
        from embedxpl.tools import search as search_mod
        assert hasattr(search_mod, "search")
        assert hasattr(search_mod, "search_cve")
        assert hasattr(search_mod, "search_vendor")
        assert hasattr(search_mod, "search_cwe")
        assert callable(search_mod.search)

    def test_module_record_dataclass(self):
        from embedxpl.tools.search import ModuleRecord
        fields = ModuleRecord.__dataclass_fields__
        assert "path" in fields
        assert "category" in fields
        assert "cves" in fields
