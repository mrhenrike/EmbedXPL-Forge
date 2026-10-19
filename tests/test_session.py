"""Tests for embedxpl.core.session persistence module."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from embedxpl.core.session import HostSession, ModuleResult, host_id


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
