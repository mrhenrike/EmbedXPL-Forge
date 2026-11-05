"""Verify SNMP consumers retain their results and configurable transport options."""

from unittest.mock import MagicMock, Mock

import pytest

from embedxpl.core.snmp import session as snmp
from embedxpl.engines.printer.modules import print_job
from embedxpl.engines.printer.protocols import firmware, network_map, storage
from embedxpl.engines.printer.utils import banner_grabber
from embedxpl.modules.exploits.network_os.mikrotik.modules.snmp import SNMPScanner
from embedxpl.modules.generic.snmp import snmp_bruteforce


@pytest.fixture
def session(monkeypatch):
    opened = MagicMock()
    opened.__enter__.return_value = opened
    opened.get.side_effect = lambda oid: (
        None, 0, 0, [(oid, 3 if "25.3.5" in oid else "Firmware 1.2.3")],
    )
    opened.set.return_value = (None, 0, 0, [])
    opened.walk.side_effect = lambda oid, **kwargs: iter([(None, 0, 0, [(oid + ".1", "fixture")])])
    factory = Mock(return_value=opened)
    monkeypatch.setattr(snmp, "SNMPSession", factory)
    return factory, opened


def test_printer_status(session):
    assert print_job._snmp_printer_status("fixture") == 3
    assert session[0].call_args.kwargs["version"] == 0


def test_network_get_and_walk(session):
    assert network_map._snmp_get("fixture", "1.3.6.1") == "Firmware 1.2.3"
    assert network_map._snmp_walk("fixture", "1.3.6.1", max_rows=7) == {"1.3.6.1.1": "fixture"}
    session[1].walk.assert_called_once_with("1.3.6.1", max_rows=7)


def test_storage_dump_and_write_preserve_custom_port(session, tmp_path):
    output = tmp_path / "mib.txt"
    assert storage.snmp_dump("fixture", output_file=str(output), verbose=False, port=1161)
    assert "fixture" in output.read_text()
    assert session[0].call_args.args[1] == 1161
    assert storage.snmp_write("fixture", "1.3.6.1", "updated", port=2161)
    session[1].set.assert_called_once_with("1.3.6.1", "updated")
    assert session[0].call_args.args[1] == 2161


def test_banner_preserves_fields_and_port(session):
    result = banner_grabber._grab_snmp("fixture", 1, port=1161)
    assert result["snmp_sys_descr"] == "Firmware 1.2.3"
    assert result["snmp_hr_device_descr"] == "Firmware 1.2.3"
    assert "snmp_error" not in result
    assert session[0].call_args.args[1] == 1161


def test_firmware_snmp_fallback(session, monkeypatch):
    monkeypatch.setattr(firmware.requests, "get", Mock(return_value=Mock(status_code=404)))
    result = firmware.get_firmware_version("fixture", snmp_port=1161)
    assert result["version"] == "1.2.3"
    assert result["source"].startswith("snmp:")
    assert session[0].call_args.args[1] == 1161


def test_mikrotik_reads_and_writes(session):
    scanner = SNMPScanner("fixture", port=1161, timeout=0.5)
    result = scanner.read_oids("public", ["1.3.6.1", "1.3.6.2"])
    assert result["success"] is True
    assert len(result["values"]) == 2
    assert scanner.try_write_probe("private")["success"] is True
    assert session[0].call_args.args == ("fixture", 1161, "private")


def test_mikrotik_preserves_partial_results_on_error(session):
    session[1].get.side_effect = [(None, 0, 0, [("1.3.6.1", "fixture")]), ("timeout", 0, 0, [])]
    result = SNMPScanner("fixture").read_oids("public", ["1.3.6.1", "1.3.6.2"])
    assert result == {"success": False, "error": "timeout", "values": {"1.3.6.1": "fixture"}}


def test_generic_community_probe(session, monkeypatch, capsys):
    monkeypatch.setattr(snmp_bruteforce.Exploit, "target", "192.0.2.1")
    monkeypatch.setattr(snmp_bruteforce.Exploit, "port", 1161)
    module = snmp_bruteforce.Exploit()
    monkeypatch.setattr(module, "_load_communities", lambda: ["fixture"])
    module.run()
    assert "VALID community: fixture" in capsys.readouterr().out
    assert session[0].call_args.args == ("192.0.2.1", 1161, "fixture")


def test_printer_failure_results(session):
    session[1].get.side_effect = None
    session[1].get.return_value = ("timeout", 0, 0, [])
    assert print_job._snmp_printer_status("fixture") == -1
    assert network_map._snmp_get("fixture", "1.3.6.1") == ""
