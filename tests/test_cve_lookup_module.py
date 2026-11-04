"""Exercise the CVE module output and filter forwarding without catalog assumptions."""

from unittest.mock import Mock

import pytest

from embedxpl.core.cve.cve_db import CVEEntry
from embedxpl.modules.generic.cve import cve_lookup


@pytest.fixture
def lookup(monkeypatch):
    for name, value in {
        "vendor": "fixture", "product": "router", "version": "1.0", "banner": "",
        "remote_only": False, "show_physical": True,
    }.items():
        monkeypatch.setattr(cve_lookup.Exploit, name, value)
    db = Mock(total=3)
    db.summary.return_value = {
        "total_cves": 3, "remote": 2, "exploitable_by_exf": 1, "vendors_covered": 1,
    }
    db.lookup.return_value = [
        CVEEntry("CVE-2024-0001", "fixture", "router", exf_module="exploits/routers/fixture"),
        CVEEntry("CVE-2024-0002", "fixture", "router"),
        CVEEntry("CVE-2024-0003", "fixture", "router", access_vector="PHYSICAL"),
    ]
    monkeypatch.setattr(cve_lookup, "CVEDatabase", lambda: db)
    return cve_lookup.Exploit(), db


def test_lookup_prints_quick_commands_and_categories(lookup, capsys):
    module, db = lookup
    module.run()
    output = capsys.readouterr().out
    assert "use exploits/routers/fixture" in output
    assert "REMOTE  -  no exf module" in output
    assert "LOCAL/PHYSICAL access required" in output
    db.lookup.assert_called_once_with(
        vendor="fixture", product="router", version="1.0", banner="", remote_only=False,
    )


@pytest.mark.parametrize(("remote_only", "show_physical"), [(True, True), (False, False)])
def test_lookup_forwards_remote_filter(lookup, monkeypatch, remote_only, show_physical):
    module, db = lookup
    monkeypatch.setattr(cve_lookup.Exploit, "remote_only", remote_only)
    monkeypatch.setattr(cve_lookup.Exploit, "show_physical", show_physical)
    module.run()
    assert db.lookup.call_args.kwargs["remote_only"] is True


def test_lookup_requires_a_search_term(lookup, monkeypatch, capsys):
    module, db = lookup
    for name in ("vendor", "product", "banner"):
        monkeypatch.setattr(cve_lookup.Exploit, name, "")
    module.run()
    db.lookup.assert_not_called()
    assert "Set at least one" in capsys.readouterr().out


def test_lookup_empty_results(lookup, capsys):
    module, db = lookup
    db.lookup.return_value = []
    module.run()
    assert "No CVEs found" in capsys.readouterr().out
