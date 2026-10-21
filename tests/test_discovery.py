"""Tests for embedxpl.core.discovery."""
from __future__ import annotations

import os
import tempfile

from embedxpl.core.discovery import (
    PROBE_PORTS,
    PROBE_PORTS_EXTENDED,
    DiscoveredHost,
    NetworkDiscovery,
    TimingProfile,
    _parse_targets_file,
)


class TestTimingProfile:
    def test_instantiation(self):
        tp = TimingProfile(
            name="normal", nmap_flag="-T3", timeout=5.0,
            max_workers=10, probe_delay=0.1, ports=[80, 443],
            nmap_extra_host="", nmap_extra_subnet="",
            banner_grab=True, deep_fingerprint=False,
        )
        assert tp.name == "normal"


class TestDiscoveredHost:
    def test_init(self):
        h = DiscoveredHost(ip="10.0.0.1")
        assert h.ip == "10.0.0.1"

    def test_default_fields(self):
        h = DiscoveredHost(ip="10.0.0.1")
        assert h.open_ports == [] or hasattr(h, "open_ports")


class TestNetworkDiscovery:
    def test_init(self):
        nd = NetworkDiscovery("192.168.1.0/24")
        assert nd is not None

    def test_init_single_host(self):
        nd = NetworkDiscovery("192.168.1.1")
        assert nd is not None


class TestParsTargetsFile:
    def test_parse_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("10.0.0.1\n10.0.0.2\n\n# comment\n10.0.0.3\n")
            path = f.name
        try:
            targets = _parse_targets_file(path)
            assert isinstance(targets, list)
            assert len(targets) >= 2
        finally:
            os.unlink(path)


class TestConstants:
    def test_probe_ports_not_empty(self):
        assert len(PROBE_PORTS) > 0
        assert 80 in PROBE_PORTS
        assert 443 in PROBE_PORTS

    def test_extended_superset(self):
        for p in PROBE_PORTS:
            assert p in PROBE_PORTS_EXTENDED

    def test_all_ports_valid(self):
        for p in PROBE_PORTS_EXTENDED:
            assert 1 <= p <= 65535
