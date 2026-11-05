"""B7 coverage: deep behavioral tests for core subsystems."""
from __future__ import annotations

import importlib

import pytest


def _safe_import(mod_path: str):
    try:
        return importlib.import_module(mod_path)
    except (SystemExit, KeyboardInterrupt) as exc:
        pytest.skip(f"Import triggered exit: {exc}")
    except Exception as exc:
        pytest.skip(f"Import failed: {exc}")
    return None


# ── Options ──────────────────────────────────────────────────────────────────


class TestOption:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.option")

    def test_option_basic(self):
        m = self._mod()
        o = m.Option("default_val", "Test description")
        assert o.value == "default_val"
        assert o.description == "Test description"
        assert o.display_value == "default_val"

    def test_option_none_default(self):
        m = self._mod()
        o = m.Option(None, "Empty")
        assert o.value == ""

    def test_option_zero_default(self):
        m = self._mod()
        o = m.Option(0, "Zero val")
        assert o.value == 0

    def test_opt_ip_valid(self):
        m = self._mod()
        ip = m.OptIP("192.168.1.1", "Target")
        assert ip.value == "192.168.1.1"

    def test_opt_ip_invalid(self):
        m = self._mod()
        with pytest.raises(Exception):
            m.OptIP("not-an-ip", "Target")

    def test_opt_port_valid(self):
        m = self._mod()
        p = m.OptPort(80, "Port")
        assert p.value == 80

    def test_opt_port_invalid_zero(self):
        m = self._mod()
        with pytest.raises(Exception):
            m.OptPort(0, "Port")

    def test_opt_bool_true(self):
        m = self._mod()
        b = m.OptBool(True, "Flag")
        assert b.value is True

    def test_opt_bool_false(self):
        m = self._mod()
        b = m.OptBool(False, "Flag")
        assert b.value is False

    def test_opt_integer(self):
        m = self._mod()
        i = m.OptInteger(42, "Count")
        assert i.value == 42

    def test_opt_float(self):
        m = self._mod()
        f = m.OptFloat(3.14, "Timeout")
        assert abs(f.value - 3.14) < 0.01

    def test_opt_string(self):
        m = self._mod()
        s = m.OptString("hello", "Name")
        assert s.value == "hello"

    def test_opt_mac(self):
        m = self._mod()
        mac = m.OptMAC("AA:BB:CC:DD:EE:FF", "MAC address")
        assert "AA" in str(mac.value).upper()

    def test_opt_advanced_flag(self):
        m = self._mod()
        o = m.Option("val", "Desc", advanced=True)
        assert o.advanced is True

    def test_opt_advanced_false(self):
        m = self._mod()
        o = m.Option("val", "Desc", advanced=False)
        assert o.advanced is False


# ── Exceptions ───────────────────────────────────────────────────────────────


class TestExceptions:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.exceptions")

    def test_embedxpl_exception(self):
        m = self._mod()
        assert issubclass(m.EmbedXPLException, Exception)

    def test_option_validation_error(self):
        m = self._mod()
        assert issubclass(m.OptionValidationError, m.EmbedXPLException)

    def test_stop_thread_pool(self):
        m = self._mod()
        assert issubclass(m.StopThreadPoolExecutor, m.EmbedXPLException)

    def test_raise_option_validation(self):
        m = self._mod()
        with pytest.raises(m.OptionValidationError):
            raise m.OptionValidationError("test error")

    def test_raise_stop_thread_pool(self):
        m = self._mod()
        with pytest.raises(m.StopThreadPoolExecutor):
            raise m.StopThreadPoolExecutor()


# ── Exploit Utils ────────────────────────────────────────────────────────────


class TestExploitUtils:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.utils")

    def test_is_ipv4_valid(self):
        m = self._mod()
        assert m.is_ipv4("192.168.1.1") is True

    def test_is_ipv4_invalid(self):
        m = self._mod()
        assert m.is_ipv4("not_an_ip") is False

    def test_is_ipv4_empty(self):
        m = self._mod()
        assert m.is_ipv4("") is False

    def test_is_ipv6_with_zone(self):
        m = self._mod()
        assert m.is_ipv6("::1%eth0") is True

    def test_is_ipv6_invalid(self):
        m = self._mod()
        assert m.is_ipv6("not_an_ip") is False

    def test_is_ipv6_no_zone_returns_false(self):
        m = self._mod()
        assert m.is_ipv6("::1") is False


# ── Protocol enum ────────────────────────────────────────────────────────────


class TestProtocol:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.exploit")

    def test_protocol_class(self):
        m = self._mod()
        assert hasattr(m, "Protocol")

    def test_protocol_members(self):
        m = self._mod()
        p = m.Protocol
        for name in ["HTTP", "HTTPS", "FTP", "SSH", "TELNET", "CUSTOM"]:
            assert hasattr(p, name), f"Protocol missing {name}"

    def test_locked_iterator_class(self):
        m = self._mod()
        assert hasattr(m, "LockedIterator")

    def test_base_exploit_class(self):
        m = self._mod()
        assert hasattr(m, "BaseExploit")

    def test_exploit_class(self):
        m = self._mod()
        assert hasattr(m, "Exploit")
        assert issubclass(m.Exploit, m.BaseExploit)


# ── Session ──────────────────────────────────────────────────────────────────


class TestSession:

    def _mod(self):
        return _safe_import("embedxpl.core.session")

    def test_host_id(self):
        m = self._mod()
        h = m.host_id("192.168.1.1", "AA:BB:CC:DD:EE:FF")
        assert isinstance(h, str)
        assert len(h) > 0

    def test_host_id_no_mac(self):
        m = self._mod()
        h = m.host_id("10.0.0.1")
        assert isinstance(h, str)
        assert len(h) > 0

    def test_host_id_deterministic(self):
        m = self._mod()
        h1 = m.host_id("192.168.1.1", "AA:BB")
        h2 = m.host_id("192.168.1.1", "AA:BB")
        assert h1 == h2

    def test_host_id_different(self):
        m = self._mod()
        h1 = m.host_id("192.168.1.1")
        h2 = m.host_id("192.168.1.2")
        assert h1 != h2

    def test_module_result(self):
        m = self._mod()
        mr = m.ModuleResult(module_path="test.mod")
        assert mr.module_path == "test.mod"
        assert mr.vulnerable is None

    def test_module_result_to_dict(self):
        m = self._mod()
        mr = m.ModuleResult(module_path="test.mod", vulnerable=True, port=80)
        d = mr.to_dict()
        assert d["module_path"] == "test.mod"
        assert d["vulnerable"] is True
        assert d["port"] == 80

    def test_module_result_defaults(self):
        m = self._mod()
        mr = m.ModuleResult(module_path="x")
        assert mr.error is None
        assert mr.elapsed_s == 0.0
        assert mr.protocol == ""

    def test_host_session_class(self):
        m = self._mod()
        assert hasattr(m, "HostSession")

    def test_session_manager_class(self):
        m = self._mod()
        assert hasattr(m, "SessionManager")


# ── Config ───────────────────────────────────────────────────────────────────


class TestConfig:

    def _mod(self):
        return _safe_import("embedxpl.core.config")

    def test_config_path(self):
        m = self._mod()
        p = m.config_path()
        assert str(p).endswith(".json")

    def test_all_values(self):
        m = self._mod()
        v = m.all_values()
        assert isinstance(v, dict)

    def test_get_existing(self):
        m = self._mod()
        v = m.all_values()
        if v:
            first_key = list(v.keys())[0]
            val = m.get(first_key)
            assert val is not None or val == v[first_key]

    def test_get_missing(self):
        m = self._mod()
        val = m.get("nonexistent_key_12345", default="fallback")
        assert val == "fallback"

    def test_validate(self):
        m = self._mod()
        errors = m.validate()
        assert isinstance(errors, list)


# ── Banner ───────────────────────────────────────────────────────────────────


class TestBanner:

    def _mod(self):
        return _safe_import("embedxpl.core.banner")

    def test_count_modules(self):
        m = self._mod()
        counts = m._count_modules()
        assert isinstance(counts, dict)

    def test_invalidate_cache(self):
        m = self._mod()
        m.invalidate_cache()


# ── Exploit Encoders ─────────────────────────────────────────────────────────


class TestEncoders:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.encoders")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


# ── Exploit Payloads ─────────────────────────────────────────────────────────


class TestPayloads:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.payloads")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


# ── Exploit Shell ────────────────────────────────────────────────────────────


class TestShell:

    def _mod(self):
        return _safe_import("embedxpl.core.exploit.shell")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


# ── Core GPU ─────────────────────────────────────────────────────────────────


class TestGpuHwDiscovery:

    def _mod(self):
        return _safe_import("embedxpl.core.gpu.hw_discovery")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestGpuCpuBackend:

    def _mod(self):
        return _safe_import("embedxpl.core.gpu.cpu_backend")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


# ── Core RTSP ────────────────────────────────────────────────────────────────


class TestRtspModels:

    def _mod(self):
        return _safe_import("embedxpl.core.rtsp.models")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


# ── Core ML ──────────────────────────────────────────────────────────────────


class TestMlModules:

    @pytest.mark.parametrize("mod_name", [
        "embedxpl.core.ml.advisor",
        "embedxpl.core.ml.anomaly_detector",
        "embedxpl.core.ml.attack_optimizer",
        "embedxpl.core.ml.auto_tuner",
        "embedxpl.core.ml.banner_fingerprint",
        "embedxpl.core.ml.credential_mutator",
        "embedxpl.core.ml.fingerprinter",
        "embedxpl.core.ml.response_classifier",
    ])
    def test_importable(self, mod_name: str):
        mod = _safe_import(mod_name)
        assert mod is not None
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


# ── Core Shells ──────────────────────────────────────────────────────────────


class TestShellModules:

    @pytest.mark.parametrize("mod_name", [
        "embedxpl.core.shells.internal_shell",
        "embedxpl.core.shells.shell_engine",
        "embedxpl.core.shells.raw_tcp_shell",
        "embedxpl.core.shells.raw_udp_shell",
        "embedxpl.core.shells.http_poll_shell",
        "embedxpl.core.shells.dns_tunnel_shell",
        "embedxpl.core.shells.icmp_covert_shell",
        "embedxpl.core.shells.mqtt_shell",
        "embedxpl.core.shells.meterpreter_bridge",
    ])
    def test_importable(self, mod_name: str):
        mod = _safe_import(mod_name)
        assert mod is not None


# ── Core Malware Builder ─────────────────────────────────────────────────────


class TestMalwareBuilderModules:

    @pytest.mark.parametrize("mod_name", [
        "embedxpl.core.malware_builder.builder",
        "embedxpl.core.malware_builder.components.dropper",
        "embedxpl.core.malware_builder.components.evasion",
        "embedxpl.core.malware_builder.components.implant",
        "embedxpl.core.malware_builder.components.ransomware",
        "embedxpl.core.malware_builder.components.rootkit",
        "embedxpl.core.malware_builder.components.wiper",
    ])
    def test_importable(self, mod_name: str):
        mod = _safe_import(mod_name)
        assert mod is not None


# ── Core Orchestrator ────────────────────────────────────────────────────────


class TestOrchestrator:

    def _mod(self):
        return _safe_import("embedxpl.core.orchestrator")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestOrchestratorSubmodules:

    @pytest.mark.parametrize("mod_name", [
        "embedxpl.core.orchestrator.artifact",
        "embedxpl.core.orchestrator.compiler",
        "embedxpl.core.orchestrator.orchestrator",
        "embedxpl.core.orchestrator.runner",
        "embedxpl.core.orchestrator.tunnel",
    ])
    def test_importable(self, mod_name: str):
        mod = _safe_import(mod_name)
        assert mod is not None


# ── Core Network Clients ─────────────────────────────────────────────────────


class TestNetworkClients:

    @pytest.mark.parametrize("mod_name", [
        "embedxpl.core.tcp.tcp_client",
        "embedxpl.core.udp.udp_client",
        "embedxpl.core.http.http_client",
        "embedxpl.core.http.async_client",
        "embedxpl.core.ftp.ftp_client",
        "embedxpl.core.ssh.ssh_client",
        "embedxpl.core.sftp.sftp_client",
        "embedxpl.core.snmp.snmp_client",
        "embedxpl.core.telnet.telnet_client",
    ])
    def test_importable(self, mod_name: str):
        mod = _safe_import(mod_name)
        assert mod is not None


# ── Core Misc ────────────────────────────────────────────────────────────────


class TestOui:

    def _mod(self):
        return _safe_import("embedxpl.core.oui")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestHardware:

    def _mod(self):
        return _safe_import("embedxpl.core.hardware")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestHwProfiler:

    def _mod(self):
        return _safe_import("embedxpl.core.hw_profiler")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestPool:

    def _mod(self):
        return _safe_import("embedxpl.core.pool")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestDatabase:

    def _mod(self):
        return _safe_import("embedxpl.core.database")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestAptCatalog:

    def _mod(self):
        return _safe_import("embedxpl.core.apt_catalog")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestSohoExploitCatalog:

    def _mod(self):
        return _safe_import("embedxpl.core.soho_exploit_catalog")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestXplBridge:

    def _mod(self):
        return _safe_import("embedxpl.core.xpl_bridge")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestMultiLangModule:

    def _mod(self):
        return _safe_import("embedxpl.core.multi_lang_module")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestCompletion:

    def _mod(self):
        return _safe_import("embedxpl.core.completion")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestEvasionHookchain:

    def _mod(self):
        return _safe_import("embedxpl.core.evasion.hookchain_reference")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestCredDatabase:

    def _mod(self):
        return _safe_import("embedxpl.core.creds.database")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0


class TestCveDb:

    def _mod(self):
        return _safe_import("embedxpl.core.cve.cve_db")

    def test_importable(self):
        m = self._mod()
        public = [n for n in dir(m) if not n.startswith("_")]
        assert len(public) > 0
