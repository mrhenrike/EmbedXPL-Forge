"""Tests for embedxpl.core.creds.database (DefaultCredsDatabase)."""
from __future__ import annotations

from embedxpl.core.creds.database import DefaultCredsDatabase


class TestDefaultCredsDatabase:
    def test_init_general(self):
        db = DefaultCredsDatabase()
        assert db._ics_mode is False

    def test_init_ics(self):
        db = DefaultCredsDatabase(ics_mode=True)
        assert db._ics_mode is True

    def test_load_general(self):
        db = DefaultCredsDatabase()
        data = db._load()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_load_ics(self):
        db = DefaultCredsDatabase(ics_mode=True)
        data = db._load()
        assert isinstance(data, list)

    def test_load_entry_structure(self):
        db = DefaultCredsDatabase()
        data = db._load()
        entry = data[0]
        assert "vendor" in entry
        assert "username" in entry
        assert "password" in entry

    def test_list_vendors_exists(self):
        db = DefaultCredsDatabase()
        assert callable(db.list_vendors)
