"""Tests for embedxpl.core.database (SQLite module database)."""
from __future__ import annotations

import embedxpl.core.database as db_mod


class TestDatabaseModule:
    def test_module_loads(self):
        assert db_mod is not None

    def test_schema_file_exists(self):
        from pathlib import Path
        schema = Path(db_mod.__file__).parent / "database_schema.sql"
        assert schema.exists()

    def test_schema_valid_sql(self):
        from pathlib import Path
        schema = Path(db_mod.__file__).parent / "database_schema.sql"
        content = schema.read_text()
        assert "CREATE" in content.upper()
