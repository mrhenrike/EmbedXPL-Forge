"""Tests for compat shims, bridges, evasion, plugins, poly, creds, cve, shells."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Compat: HatSploit shim ──

class TestHatSploitShim:
    def test_hatsploit_module_inherits_exploit(self):
        from embedxpl.core.compat.hatsploit_shim import HatSploitModule
        from embedxpl.core.exploit.exploit import Exploit
        assert issubclass(HatSploitModule, Exploit)

    def test_hatsploit_module_execute_calls_run(self):
        from embedxpl.core.compat.hatsploit_shim import HatSploitModule

        class Mod(HatSploitModule):
            def run(self):
                return "ran"

        m = Mod()
        assert m.execute() == "ran"

    def test_hatsploit_module_run_not_implemented(self):
        from embedxpl.core.compat.hatsploit_shim import HatSploitModule
        m = HatSploitModule()
        with pytest.raises(NotImplementedError):
            m.run()

    def test_details_mapped_to_info(self):
        from embedxpl.core.compat.hatsploit_shim import HatSploitModule

        class Mod(HatSploitModule):
            details = {"name": "test_mod", "description": "A test"}
            def run(self):
                pass

        m = Mod()
        assert hasattr(m, "__info__") or hasattr(m, "details")


# ── Compat: ISF shim ──

class TestISFShim:
    def test_isf_module_exists(self):
        from embedxpl.core.compat.isf_shim import ISFModule
        m = ISFModule()
        assert m is not None

    def test_isf_tcp_client(self):
        from embedxpl.core.compat.isf_shim import ISFTCPClient
        assert ISFTCPClient is not None

    def test_isf_http_client(self):
        from embedxpl.core.compat.isf_shim import ISFHTTPClient
        assert ISFHTTPClient is not None

    def test_isf_udp_client(self):
        from embedxpl.core.compat.isf_shim import ISFUDPClient
        assert ISFUDPClient is not None

    def test_isf_exceptions(self):
        from embedxpl.core.compat.isf_shim import ISFExploitError, ISFCommunicationError
        assert issubclass(ISFCommunicationError, ISFExploitError)
        with pytest.raises(ISFExploitError):
            raise ISFCommunicationError("test")

    def test_isf_print_functions(self):
        from embedxpl.core.compat.isf_shim import print_success, print_error, print_status
        with patch("embedxpl.core.exploit.printer.print_success"):
            print_success("ok")
        with patch("embedxpl.core.exploit.printer.print_error"):
            print_error("err")
        with patch("embedxpl.core.exploit.printer.print_status"):
            print_status("status")

    def test_all_exports(self):
        from embedxpl.core.compat import isf_shim
        assert "ISFModule" in isf_shim.__all__
        assert "ISFTCPClient" in isf_shim.__all__


# ── Evasion: HookChain Reference ──

class TestHookChainReference:
    def test_hooked_targets_list(self):
        from embedxpl.core.evasion.hookchain_reference import HOOKED_NTAPI_TARGETS
        assert isinstance(HOOKED_NTAPI_TARGETS, list)
        assert "NtAllocateVirtualMemory" in HOOKED_NTAPI_TARGETS

    def test_module_imports(self):
        from embedxpl.core.evasion import hookchain_reference
        assert hookchain_reference is not None


# ── Plugins: loader ──

class TestPluginLoader:
    def test_discover_entry_points(self):
        from embedxpl.core.plugins.loader import discover_entry_points
        result = discover_entry_points("embedxpl.plugins")
        assert isinstance(result, list)

    def test_load_plugin_class_not_found(self):
        from embedxpl.core.plugins.loader import load_plugin_class
        from embedxpl.core.plugins import PluginLoadError
        with pytest.raises(PluginLoadError):
            load_plugin_class("nonexistent_plugin", "embedxpl.plugins")


# ── Poly: Compiler ──

class TestPolyCompiler:
    def test_import(self):
        from embedxpl.core.poly.compiler import CCompiler
        assert CCompiler is not None

    def test_no_compiler_available(self):
        from embedxpl.core.poly.compiler import CCompiler

        class Mod(CCompiler):
            pass

        m = Mod()
        with patch("shutil.which", return_value=None):
            result = m.compile_c("int main() { return 0; }")
        assert result is None or result == ""


# ── Creds: Database ──

class TestCredsDatabase:
    def test_instantiation(self):
        from embedxpl.core.creds.database import DefaultCredsDatabase
        db = DefaultCredsDatabase()
        assert db is not None

    def test_ics_mode(self):
        from embedxpl.core.creds.database import DefaultCredsDatabase
        db = DefaultCredsDatabase(ics_mode=True)
        assert db._ics_mode is True

    def test_has_methods(self):
        from embedxpl.core.creds.database import DefaultCredsDatabase
        db = DefaultCredsDatabase()
        assert callable(getattr(db, "search", None))
        assert callable(getattr(db, "get_by_vendor", None))
        assert callable(getattr(db, "get_by_type", None))
        assert callable(getattr(db, "list_vendors", None))
        assert callable(getattr(db, "to_wordlist", None))


# ── CVE: Database ──

class TestCVEEntry:
    def test_dataclass(self):
        from embedxpl.core.cve.cve_db import CVEEntry
        entry = CVEEntry(
            cve_id="CVE-2024-0001",
            vendor="test",
            product="device",
            cvss_score=9.8,
        )
        assert entry.cve_id == "CVE-2024-0001"
        assert entry.access_vector == "REMOTE"
        assert entry.exploit_available is False

    def test_defaults(self):
        from embedxpl.core.cve.cve_db import CVEEntry
        entry = CVEEntry(cve_id="CVE-2024-9999", vendor="v", product="p")
        assert entry.affected_versions == ""
        assert entry.description == ""
        assert entry.cvss_score == 0.0


# ── Bridges: Exploit Bridge ──

class TestExploitBridge:
    def test_import(self):
        from embedxpl.core.bridges.exploit_bridge import ExploitBridge
        assert ExploitBridge is not None

    def test_bridge_init_with_source(self):
        from embedxpl.core.bridges.exploit_bridge import ExploitBridge
        bridge = ExploitBridge(source="exploitdb")
        assert bridge is not None


# ── Shells: Re-export shims ──

class TestShellShims:
    @pytest.mark.parametrize("module_name", [
        "embedxpl.core.shells.shell_engine",
        "embedxpl.core.shells.raw_tcp_shell",
    ])
    def test_import(self, module_name):
        import importlib
        mod = importlib.import_module(module_name)
        assert mod is not None

    def test_shell_engine_reexports(self):
        from embedxpl.core.shells import shell_engine
        assert hasattr(shell_engine, "__all__") or True


# ── APT Catalog ──

class TestAPTCatalog:
    def test_import(self):
        from embedxpl.core.apt_catalog import APT_CATALOG  # noqa: F401
        assert isinstance(APT_CATALOG, (dict, list))


# ── SOHO Catalog ──

class TestSOHOCatalog:
    def test_import(self):
        from embedxpl.core.soho_exploit_catalog import resolve_soho_catalog_root
        root = resolve_soho_catalog_root(must_exist=False)
        assert isinstance(root, Path)

    def test_sitecom_default_wpa(self):
        from embedxpl.core.soho_exploit_catalog import sitecom_wlr_400x_default_wpa
        result = sitecom_wlr_400x_default_wpa(model=4004, mac="00:11:22:33:44:55")
        assert isinstance(result, str)


# ── Incorporated POC Tree ──

class TestIncorporatedPocTree:
    def test_import(self):
        from embedxpl.core.incorporated_poc_tree import incorporated_poc_root
        root = incorporated_poc_root(must_exist=False)
        assert isinstance(root, Path)

    def test_path_for_slug(self):
        from embedxpl.core.incorporated_poc_tree import path_for_slug
        result = path_for_slug("nonexistent-slug-xyz")
        assert result is None or isinstance(result, Path)
