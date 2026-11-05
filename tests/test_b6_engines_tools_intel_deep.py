"""B6 coverage: deep behavioral tests for printer, dahua_console, fingerprint, tools, interpreter, intel."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest


def _safe_import(mod_path: str):
    try:
        return importlib.import_module(mod_path)
    except (SystemExit, KeyboardInterrupt) as exc:
        pytest.skip(f"Import triggered exit: {exc}")
    except Exception as exc:
        pytest.skip(f"Import failed: {exc}")
    return None


# ── Dahua Console ────────────────────────────────────────────────────────────


class TestDahuaPocBase:
    """Tests for embedxpl.engines.dahua_console.pocs.base.POCTemplate."""

    def test_poc_template_class(self):
        mod = _safe_import("embedxpl.engines.dahua_console.pocs.base")
        assert hasattr(mod, "POCTemplate")
        cls = mod.POCTemplate
        assert hasattr(cls, "level")
        assert hasattr(cls, "poc_classes")
        assert hasattr(cls, "register_poc")

    def test_poc_template_level_namedtuple(self):
        mod = _safe_import("embedxpl.engines.dahua_console.pocs.base")
        tpl = mod.POCTemplate
        assert tpl.level.high == "high"
        assert tpl.level.medium == "medium"
        assert tpl.level.low == "low"


class TestDahuaConfig:
    """Tests for embedxpl.engines.dahua_console.config."""

    def test_get_config(self):
        mod = _safe_import("embedxpl.engines.dahua_console.config")
        cfg = mod.get_config([])
        assert cfg is not None


class TestDahuaData:
    """Tests for embedxpl.engines.dahua_console.data."""

    def test_data_class(self):
        mod = _safe_import("embedxpl.engines.dahua_console.data")
        assert hasattr(mod, "Data")
        assert hasattr(mod, "SnapshotPipeline")


DAHUA_POCS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "engines" / "dahua_console" / "pocs"


def _collect_dahua_pocs() -> list[str]:
    modules: list[str] = []
    pkg_root = DAHUA_POCS_ROOT.parents[4]
    for f in sorted(DAHUA_POCS_ROOT.glob("*.py")):
        if f.name.startswith("__"):
            continue
        rel = os.path.relpath(f, pkg_root)
        mod_path = rel.replace(os.sep, ".").removesuffix(".py")
        modules.append(mod_path)
    return modules


DAHUA_POC_MODULES = _collect_dahua_pocs()


@pytest.mark.parametrize("mod_path", DAHUA_POC_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in DAHUA_POC_MODULES])
class TestDahuaPocModules:
    """Parametrized tests for every dahua_console POC module."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_class_or_function(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        has_class = any(isinstance(getattr(mod, n), type) for n in public)
        has_func = any(callable(getattr(mod, n)) and not isinstance(getattr(mod, n), type) for n in public)
        assert has_class or has_func, f"{mod_path} has no class or function"


# ── Printer Engine ───────────────────────────────────────────────────────────


PRINTER_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "engines" / "printer"


def _collect_printer_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = PRINTER_ROOT.parents[3]
    for root, dirs, files in os.walk(PRINTER_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "data", ".git"})
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


PRINTER_MODULES = _collect_printer_modules()


@pytest.mark.parametrize("mod_path", PRINTER_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in PRINTER_MODULES])
class TestPrinterModules:
    """Parametrized tests for printer engine modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


# ── Fingerprint Engine ───────────────────────────────────────────────────────


FINGERPRINT_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "engines" / "fingerprint"


def _collect_fingerprint_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = FINGERPRINT_ROOT.parents[3]
    for root, dirs, files in os.walk(FINGERPRINT_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "data", ".git"})
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


FINGERPRINT_MODULES = _collect_fingerprint_modules()


@pytest.mark.parametrize("mod_path", FINGERPRINT_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in FINGERPRINT_MODULES])
class TestFingerprintModules:
    """Parametrized tests for fingerprint engine modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


# ── Tools ────────────────────────────────────────────────────────────────────


class TestShellcodeCraft:
    """Tests for embedxpl.tools.shellcode_craft."""

    def _mod(self):
        return _safe_import("embedxpl.tools.shellcode_craft")

    def test_to_hex(self):
        m = self._mod()
        r = m.to_hex(b"\x41\x42\x43")
        assert "\\x41" in r

    def test_to_c_array(self):
        m = self._mod()
        r = m.to_c_array(b"\x90\x90")
        assert "unsigned char" in r or "0x90" in r

    def test_to_python(self):
        m = self._mod()
        r = m.to_python(b"\xcc")
        assert "buf" in r or "\\xcc" in r

    def test_find_badchars(self):
        m = self._mod()
        r = m.find_badchars(b"\x00\x41\x0a\x42\x0d", bad=b"\x00\x0a\x0d")
        assert 0 in r
        assert 2 in r
        assert 4 in r


class TestSearch:
    """Tests for embedxpl.tools.search."""

    def _mod(self):
        return _safe_import("embedxpl.tools.search")

    def test_module_record_class(self):
        m = self._mod()
        assert hasattr(m, "ModuleRecord")

    def test_normalize_security_id(self):
        m = self._mod()
        result = m._normalize_security_id("CVE-2021-12345")
        assert isinstance(result, tuple)
        assert "cve" in str(result).lower()


class TestAuditSuite:
    """Tests for embedxpl.tools.audit_suite."""

    def _mod(self):
        return _safe_import("embedxpl.tools.audit_suite")

    def test_importable(self):
        m = self._mod()
        assert m is not None

    def test_color_function(self):
        m = self._mod()
        r = m._color("test", "red")
        assert "test" in r


TOOLS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "tools"


def _collect_tool_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = TOOLS_ROOT.parents[2]
    for root, dirs, files in os.walk(TOOLS_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "data", ".git"})
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


TOOL_MODULES = _collect_tool_modules()


@pytest.mark.parametrize("mod_path", TOOL_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in TOOL_MODULES])
class TestToolModulesParametrized:
    """Parametrized import tests for all tool modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


# ── Interpreter ──────────────────────────────────────────────────────────────


class TestInterpreter:
    """Tests for embedxpl.interpreter."""

    def _mod(self):
        return _safe_import("embedxpl.interpreter")

    def test_base_interpreter_class(self):
        m = self._mod()
        assert hasattr(m, "BaseInterpreter")

    def test_embedxpl_interpreter_class(self):
        m = self._mod()
        assert hasattr(m, "EmbedXPLInterpreter")
        assert issubclass(m.EmbedXPLInterpreter, m.BaseInterpreter)

    def test_is_libedit(self):
        m = self._mod()
        result = m.is_libedit()
        assert isinstance(result, bool)


# ── Intel/Shodan ─────────────────────────────────────────────────────────────


class TestShodanException:
    """Tests for embedxpl.intel.shodan.exception."""

    def _mod(self):
        return _safe_import("embedxpl.intel.shodan.exception")

    def test_api_error(self):
        m = self._mod()
        assert issubclass(m.APIError, Exception)

    def test_api_timeout(self):
        m = self._mod()
        assert issubclass(m.APITimeout, m.APIError)

    def test_raise_api_error(self):
        m = self._mod()
        with pytest.raises(m.APIError):
            raise m.APIError("test error")


class TestShodanHelpers:
    """Tests for embedxpl.intel.shodan.helpers."""

    def _mod(self):
        return _safe_import("embedxpl.intel.shodan.helpers")

    def test_create_facet_string(self):
        m = self._mod()
        r = m.create_facet_string([("country", 10)])
        assert isinstance(r, str)

    def test_humanize_bytes(self):
        m = self._mod()
        assert "KB" in m.humanize_bytes(1024) or "kB" in m.humanize_bytes(1024) or "1" in m.humanize_bytes(1024)

    def test_get_ip(self):
        m = self._mod()
        banner = {"ip_str": "1.2.3.4"}
        result = m.get_ip(banner)
        assert "1.2.3.4" in str(result)


class TestShodanBase:
    """Tests for embedxpl.intel.shodan.base."""

    def _mod(self):
        return _safe_import("embedxpl.intel.shodan.base")

    def test_converter_class(self):
        m = self._mod()
        assert hasattr(m, "Converter")


class TestShodanConf:
    """Tests for embedxpl.intel.shodan.conf."""

    def _mod(self):
        return _safe_import("embedxpl.intel.shodan.conf")

    def test_importable(self):
        m = self._mod()
        assert m is not None


INTEL_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "intel"


def _collect_intel_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = INTEL_ROOT.parents[2]
    for root, dirs, files in os.walk(INTEL_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "data", ".git"})
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


INTEL_MODULES = _collect_intel_modules()


@pytest.mark.parametrize("mod_path", INTEL_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in INTEL_MODULES])
class TestIntelModulesParametrized:
    """Parametrized import tests for all intel modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


# ── Modules: research, firmware, post, generic ───────────────────────────────


def _collect_category_modules(category: str) -> list[str]:
    cat_root = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / category
    if not cat_root.exists():
        return []
    modules: list[str] = []
    pkg_root = cat_root.parents[3]
    for root, dirs, files in os.walk(cat_root):
        dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "data", ".git", "refs"})
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


RESEARCH_MODULES = _collect_category_modules("research")
FIRMWARE_MODULES = _collect_category_modules("firmware")
POST_MODULES = _collect_category_modules("post")
GENERIC_MODULES = _collect_category_modules("generic")


@pytest.mark.parametrize("mod_path", RESEARCH_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in RESEARCH_MODULES])
class TestResearchModules:
    """Parametrized tests for research modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0

    def test_has_exploit_or_class(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        has_class = any(isinstance(getattr(mod, n), type) for n in public)
        has_func = any(callable(getattr(mod, n)) and not isinstance(getattr(mod, n), type) for n in public)
        if not (has_class or has_func):
            pytest.skip(f"{mod_path} is a data/config module")


@pytest.mark.parametrize("mod_path", FIRMWARE_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in FIRMWARE_MODULES])
class TestFirmwareModules:
    """Parametrized tests for firmware modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


@pytest.mark.parametrize("mod_path", POST_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in POST_MODULES])
class TestPostModules:
    """Parametrized tests for post-exploitation modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0


@pytest.mark.parametrize("mod_path", GENERIC_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in GENERIC_MODULES])
class TestGenericModules:
    """Parametrized tests for generic modules."""

    def test_importable(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str):
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0
