"""Tests for embedxpl.core.session persistence module."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from embedxpl.core.session import HostSession, ModuleResult, SessionManager, host_id


def test_host_id_deterministic():
    h1 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    h2 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert h1 == h2
    assert len(h1) == 16


def test_host_id_different_for_different_hosts():
    h1 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    h2 = host_id("192.168.1.2", "AA:BB:CC:DD:EE:FF")
    assert h1 != h2


def test_host_id_case_insensitive():
    h1 = host_id("192.168.1.1", "aa:bb:cc:dd:ee:ff")
    h2 = host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert h1 == h2


def test_host_id_no_mac():
    h = host_id("10.0.0.1")
    assert len(h) == 16


def test_module_result_to_dict():
    r = ModuleResult(
        module_path="exploits.routers.test",
        vulnerable=True,
        elapsed_s=1.234,
        port=80,
        protocol="http",
        timestamp=1000000.0,
        details="RCE confirmed",
    )
    d = r.to_dict()
    assert d["module_path"] == "exploits.routers.test"
    assert d["vulnerable"] is True
    assert d["elapsed_s"] == 1.234
    assert d["port"] == 80


def test_module_result_from_dict():
    d = {
        "module_path": "creds.routers.default",
        "vulnerable": False,
        "elapsed_s": 0.5,
        "port": 23,
        "protocol": "telnet",
        "timestamp": 999999.0,
    }
    r = ModuleResult.from_dict(d)
    assert r.module_path == "creds.routers.default"
    assert r.vulnerable is False
    assert r.port == 23


def test_module_result_roundtrip():
    r = ModuleResult(module_path="test.mod", vulnerable=True, elapsed_s=2.0)
    r2 = ModuleResult.from_dict(r.to_dict())
    assert r2.module_path == r.module_path
    assert r2.vulnerable == r.vulnerable


def test_host_session_defaults():
    s = HostSession(host_id="abc123", ip="192.168.1.1")
    assert s.ip == "192.168.1.1"
    assert s.open_ports == []
    assert s.module_results == []
    assert s.total_scans == 0


def test_host_session_modules_tested():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.module_results = [
        ModuleResult(module_path="mod.a"),
        ModuleResult(module_path="mod.b"),
        ModuleResult(module_path="mod.a"),
    ]
    tested = s.modules_tested()
    assert set(tested) == {"mod.a", "mod.b"}


def test_host_session_modules_pending():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.matched_modules = ["mod.a", "mod.b", "mod.c"]
    s.module_results = [ModuleResult(module_path="mod.a")]
    pending = s.modules_pending()
    assert "mod.b" in pending
    assert "mod.c" in pending
    assert "mod.a" not in pending


def test_host_session_add_result_vuln():
    s = HostSession(host_id="test", ip="10.0.0.1")
    r = ModuleResult(module_path="exploit.rce", vulnerable=True)
    s.add_result(r)
    assert len(s.module_results) == 1
    assert "exploit.rce" in s.vulns_found
    assert r.timestamp > 0


def test_host_session_add_result_safe():
    s = HostSession(host_id="test", ip="10.0.0.1")
    r = ModuleResult(module_path="exploit.safe", vulnerable=False)
    s.add_result(r)
    assert s.vulns_found == []
    assert "exploit.safe" in s.modules_safe()


def test_host_session_modules_errored():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.module_results = [
        ModuleResult(module_path="mod.ok", vulnerable=True),
        ModuleResult(module_path="mod.err", error="timeout"),
    ]
    errored = s.modules_errored()
    assert "mod.err" in errored
    assert "mod.ok" not in errored


def test_host_session_merge_discovery():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.open_ports = [22, 80]
    s.merge_discovery(
        ip="10.0.0.1",
        mac="AA:BB:CC:DD:EE:FF",
        hostname="router.local",
        open_ports=[80, 443, 8080],
        banners={80: "nginx"},
    )
    assert s.mac == "AA:BB:CC:DD:EE:FF"
    assert s.hostname == "router.local"
    assert 22 in s.open_ports
    assert 443 in s.open_ports
    assert 8080 in s.open_ports
    assert s.banners["80"] == "nginx"


def test_host_session_merge_preserves_existing():
    s = HostSession(host_id="test", ip="10.0.0.1", vendor="TP-Link")
    s.merge_discovery(ip="10.0.0.1")
    assert s.vendor == "TP-Link"


def test_host_session_modules_vulnerable():
    s = HostSession(host_id="test", ip="10.0.0.1")
    s.module_results = [
        ModuleResult(module_path="mod.vuln", vulnerable=True),
        ModuleResult(module_path="mod.safe", vulnerable=False),
    ]
    vulns = s.modules_vulnerable()
    assert "mod.vuln" in vulns
    assert "mod.safe" not in vulns


def test_host_session_to_dict_roundtrip():
    s = HostSession(host_id="rt1", ip="10.0.0.1", mac="AA:BB:CC:DD:EE:FF")
    s.vendor = "MikroTik"
    s.model = "RB750"
    s.open_ports = [22, 8291]
    s.add_result(ModuleResult(module_path="winbox_auth", vulnerable=True, port=8291))
    d = s.to_dict()
    s2 = HostSession.from_dict(d)
    assert s2.host_id == "rt1"
    assert s2.vendor == "MikroTik"
    assert s2.open_ports == [22, 8291]
    assert len(s2.module_results) == 1
    assert s2.module_results[0].vulnerable is True


def test_host_session_summary_line():
    s = HostSession(host_id="test", ip="10.0.0.1", vendor="TP-Link", model="WR940N")
    s.total_scans = 3
    s.matched_modules = ["a", "b", "c"]
    s.module_results = [ModuleResult(module_path="a", vulnerable=True)]
    s.vulns_found = ["a"]
    line = s.summary_line()
    assert "10.0.0.1" in line
    assert "TP-Link" in line
    assert "scans:3" in line


# -------------------------------------------------------
# SessionManager persistence tests
# -------------------------------------------------------


def test_session_manager_create_and_save(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    session = mgr.create("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert session.ip == "192.168.1.1"
    assert session.host_id
    mgr.save(session)
    assert (tmp_path / f"{session.host_id}.json").exists()
    assert (tmp_path / "_index.json").exists()


def test_session_manager_load(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    session = mgr.create("10.0.0.1")
    session.vendor = "Netgear"
    session.add_result(ModuleResult(module_path="rce_test", vulnerable=True, port=80))
    mgr.save(session)

    loaded = mgr.load("10.0.0.1")
    assert loaded is not None
    assert loaded.vendor == "Netgear"
    assert len(loaded.module_results) == 1
    assert loaded.module_results[0].vulnerable is True


def test_session_manager_get_or_create_existing(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s1 = mgr.create("10.0.0.2")
    s1.vendor = "Cisco"
    mgr.save(s1)

    s2, is_existing = mgr.get_or_create("10.0.0.2")
    assert is_existing is True
    assert s2.vendor == "Cisco"


def test_session_manager_get_or_create_new(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s, is_existing = mgr.get_or_create("10.0.0.99")
    assert is_existing is False
    assert s.ip == "10.0.0.99"


def test_session_manager_list_sessions(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        s = mgr.create(ip)
        mgr.save(s)
    listing = mgr.list_sessions()
    assert len(listing) == 3
    ips = {e["ip"] for e in listing}
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_session_manager_exists(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    assert mgr.exists("10.0.0.1") is False
    s = mgr.create("10.0.0.1")
    mgr.save(s)
    assert mgr.exists("10.0.0.1") is True


def test_session_manager_find_by_ip_only(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s = mgr.create("10.0.0.5", "11:22:33:44:55:66")
    mgr.save(s)
    found = mgr.find("10.0.0.5")
    assert found is not None


def test_session_manager_delete(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s = mgr.create("10.0.0.7")
    mgr.save(s)
    assert mgr.exists("10.0.0.7") is True
    result = mgr.delete("10.0.0.7")
    assert result is True
    assert mgr.exists("10.0.0.7") is False
    assert mgr.load("10.0.0.7") is None


def test_session_manager_delete_by_id(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s = mgr.create("10.0.0.8")
    mgr.save(s)
    hid = s.host_id
    result = mgr.delete_by_id(hid)
    assert result is True
    assert mgr.load("10.0.0.8") is None


def test_session_manager_purge_all(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    for i in range(5):
        s = mgr.create(f"10.0.0.{i}")
        mgr.save(s)
    count = mgr.purge_all()
    assert count == 5
    assert mgr.list_sessions() == []


def test_session_manager_export(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    s = mgr.create("10.0.0.10")
    s.vendor = "ASUS"
    mgr.save(s)
    exported = mgr.export_session("10.0.0.10")
    assert exported is not None
    data = json.loads(exported)
    assert data["vendor"] == "ASUS"


def test_session_manager_export_nonexistent(tmp_path):
    mgr = SessionManager(sessions_dir=tmp_path)
    assert mgr.export_session("1.2.3.4") is None
