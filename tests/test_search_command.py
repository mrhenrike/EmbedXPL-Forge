"""Search command regressions, using deterministic metadata without module imports."""

from types import SimpleNamespace

import pytest

from embedxpl.interpreter import EmbedXPLInterpreter
from embedxpl.tools import search as engine


@pytest.fixture
def search_command(monkeypatch):
    records = [
        engine.ModuleRecord(
            path="embedxpl.modules.exploits.routers.cisco.fixture", name="Example gateway",
            description="Buffer overflow CWE-79 MS17-010 EDB-36913", vendors=["cisco"],
            category="routers", cves=["CVE-2024-54085"], tested=True,
        ),
        engine.ModuleRecord(
            path="embedxpl.modules.exploits.cameras.other.fixture", name="Other camera",
            vendors=["other"], category="cameras", tested=False,
        ),
    ]
    monkeypatch.setattr(engine, "_MODULE_CACHE", records)
    return SimpleNamespace(modules=["generic.fixture_path"])


@pytest.mark.parametrize("query", [
    "vendor:cisco", "type:router", "tested:yes", "cve202454085", "cve cisco",
    "overflow", "cwe79", "ms17010", "edb36913",
])
def test_command_uses_metadata_and_structured_filters(search_command, query, capsys):
    EmbedXPLInterpreter.command_search(search_command, query)
    output = capsys.readouterr().out
    assert "Example gateway" in output
    assert "Other camera" not in output


def test_command_supports_keyword_arguments(search_command, capsys):
    EmbedXPLInterpreter.command_search(search_command, vendor="other", tested="no")
    output = capsys.readouterr().out
    assert "Other camera" in output
    assert "Example gateway" not in output


def test_search_falls_back_with_diagnostic(search_command, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError("index unavailable")

    monkeypatch.setattr(engine, "search", fail)
    EmbedXPLInterpreter.command_search(search_command, "fixture_path")
    output = capsys.readouterr().out
    assert "index unavailable" in output
    assert "generic/fixture_path" in output


def test_search_no_matches(search_command, capsys):
    EmbedXPLInterpreter.command_search(search_command, "absent_keyword")
    assert "No modules found" in capsys.readouterr().out


def test_cold_index_reads_metadata_without_executing_modules(tmp_path, monkeypatch):
    root = tmp_path / "embedxpl" / "modules"
    directory = root / "exploits" / "routers" / "fixture"
    directory.mkdir(parents=True)
    marker = tmp_path / "executed"
    (root / "__init__.py").write_text("raise SystemExit('must not import package')")
    (directory / "unsafe.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        "raise SystemExit('must not execute PoC')\n"
        "class Exploit:\n"
        "    __info__ = {'name': 'Fixture gateway', 'description': 'Buffer overflow', "
        "'references': ['CVE-2024-54085'], 'rank': unavailable_constant}\n"
    )
    monkeypatch.setattr(engine, "_MODULES_ROOT", root)
    monkeypatch.setattr(engine, "_MODULE_CACHE", None)
    records = engine._get_cache(use_db_cache=False)
    assert len(records) == 1
    assert records[0].name == "Fixture gateway"
    assert records[0].cves == ["CVE-2024-54085"]
    assert engine.search("vendor:fixture cve202454085") == records
    assert not marker.exists()


def test_python2_poc_remains_searchable_by_path_and_cve(tmp_path, monkeypatch):
    root = tmp_path / "embedxpl" / "modules"
    directory = root / "exploits" / "legacy"
    directory.mkdir(parents=True)
    (directory / "fixture.py").write_text("# CVE-2024-54085\nprint 'legacy PoC'\n")
    monkeypatch.setattr(engine, "_MODULES_ROOT", root)
    record = engine._extract_info("embedxpl.modules.exploits.legacy.fixture")
    assert record is not None
    assert record.cves == ["CVE-2024-54085"]
