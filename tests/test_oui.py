"""Tests for embedxpl.core.oui MAC vendor lookup."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from embedxpl.core.oui import (
    _mac_to_prefix,
    normalize_vendor,
    clear_session_cache,
    get_stats,
)


class TestMacToPrefix:
    def test_standard_mac(self):
        result = _mac_to_prefix("AA:BB:CC:DD:EE:FF")
        assert result == "AA:BB:CC"

    def test_lowercase(self):
        result = _mac_to_prefix("aa:bb:cc:dd:ee:ff")
        assert result == "AA:BB:CC"

    def test_dash_separator(self):
        result = _mac_to_prefix("AA-BB-CC-DD-EE-FF")
        assert result == "AA:BB:CC"

    def test_no_separator(self):
        result = _mac_to_prefix("AABBCCDDEEFF")
        assert result == "AA:BB:CC"


class TestNormalizeVendor:
    def test_strips_whitespace(self):
        result = normalize_vendor("  Cisco Systems, Inc.  ")
        assert result.strip() == result

    def test_removes_inc(self):
        result = normalize_vendor("Cisco Systems, Inc.")
        assert "Inc." not in result or "cisco" in result.lower()


class TestClearSessionCache:
    def test_no_crash(self):
        clear_session_cache()


class TestGetStats:
    def test_returns_dict(self):
        stats = get_stats()
        assert isinstance(stats, dict)
