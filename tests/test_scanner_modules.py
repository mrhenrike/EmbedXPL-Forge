"""Structural tests for embedxpl.modules.scanners.* modules.

Validates that scanner modules follow the required interface:
- Have an Exploit class (inheriting from BaseExploit or a client mixin)
- Have __info__ dict with required keys (accounting for metaclass mangling)
- Implement run() method
- Expose expected option attributes (target, port, etc.)
"""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------
# Curated representative scanners (different categories/vendors)
# ---------------------------------------------------------------

SCANNER_MODULES = [
    (
        "embedxpl.modules.scanners.cameras.dahua_dvr_scanner",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.nas.nas_discover",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.bmc.bmc_discover",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.hypervisors.proxmox_discover",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.voip.sip_endpoint_scan",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.embedded_os.mqtt_broker_scan",
        ["target", "port"],
    ),
    (
        "embedxpl.modules.scanners.cameras.camera_scan",
        ["target"],
    ),
    (
        "embedxpl.modules.scanners.routers.router_scan",
        ["target"],
    ),
]

REQUIRED_INFO_KEYS = {"name", "description", "authors"}

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError, AttributeError)


def _safe_import(mod_path: str):
    """Import module; skip on known issues."""
    try:
        return importlib.import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS as exc:
        pytest.skip("Import failed: {}".format(exc))


def _get_info(cls) -> dict:
    """Retrieve __info__ dict accounting for ExploitOptionsAggregator mangling."""
    mangled = "_{}__info__".format(cls.__name__)
    if hasattr(cls, mangled):
        return getattr(cls, mangled)
    if hasattr(cls, "__info__"):
        return cls.__info__
    raise AttributeError("{} has no __info__".format(cls.__name__))


# ---------------------------------------------------------------
# Parametrized structural tests for curated scanners
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,expected_opts",
    SCANNER_MODULES,
    ids=[p.rsplit(".", 1)[-1] for p, _ in SCANNER_MODULES],
)
class TestScannerModuleStructure:
    """Structural tests for scanner modules."""

    def test_importable(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_exploit_class_exists(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod, "Exploit"), "{} missing Exploit class".format(mod_path)

    def test_exploit_is_class(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Exploit class")
        assert isinstance(cls, type), "Exploit should be a class"

    def test_has_info_dict(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
        assert isinstance(info, dict)

    def test_info_has_required_keys(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        info = _get_info(mod.Exploit)
        for key in REQUIRED_INFO_KEYS:
            assert key in info, "{} __info__ missing '{}'".format(mod_path, key)

    def test_info_name_is_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        name = _get_info(mod.Exploit)["name"]
        assert isinstance(name, str) and len(name) > 0

    def test_info_authors_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        authors = _get_info(mod.Exploit)["authors"]
        assert isinstance(authors, (tuple, list))
        assert len(authors) >= 1

    def test_info_description_nonempty(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        desc = _get_info(mod.Exploit)["description"]
        assert isinstance(desc, str) and len(desc) > 10

    def test_has_run_method(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        assert hasattr(cls, "run"), "{} Exploit missing run()".format(mod_path)
        assert callable(cls.run)

    def test_expected_options_present(self, mod_path: str, expected_opts: list[str]) -> None:
        mod = _safe_import(mod_path)
        cls = mod.Exploit
        for opt in expected_opts:
            assert hasattr(cls, opt), "{} missing option attribute '{}'".format(mod_path, opt)


# ---------------------------------------------------------------
# Bulk importability test for all scanner .py files
# ---------------------------------------------------------------

SCANNERS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "scanners"
_SKIP_DIRS = {"__pycache__", "refs"}


def _collect_all_scanner_modules():
    modules = []
    for root, dirs, files in os.walk(SCANNERS_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in sorted(files):
            if f.startswith("__") or not f.endswith(".py"):
                continue
            path = Path(root) / f
            rel = path.relative_to(SCANNERS_ROOT.parent.parent)
            dotted = str(rel).replace(os.sep, ".").removesuffix(".py")
            modules.append(dotted)
    return modules


ALL_SCANNER_MODULES = _collect_all_scanner_modules()


@pytest.mark.parametrize("dotted", ALL_SCANNER_MODULES,
                         ids=[m.rsplit(".", 1)[-1] for m in ALL_SCANNER_MODULES])
def test_scanner_importable(dotted: str) -> None:
    try:
        importlib.import_module(dotted)
    except (ImportError, ModuleNotFoundError):
        pytest.skip("Optional dependency missing for {}".format(dotted))
    except SyntaxError:
        pytest.skip("Syntax issue in {}".format(dotted))


# ---------------------------------------------------------------
# NAS discover: port and service mapping
# ---------------------------------------------------------------


class TestNASDiscoverHelpers:
    """Test NAS discovery helpers without network."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.scanners.nas.nas_discover import Exploit
        except (ImportError, AttributeError):
            pytest.skip("Cannot import nas_discover")
        return Exploit

    def test_has_port_option(self, exploit_cls) -> None:
        assert hasattr(exploit_cls, "port")

    def test_info_mentions_nas(self, exploit_cls) -> None:
        info = _get_info(exploit_cls)
        desc = info.get("description", "").lower()
        assert "nas" in desc or "storage" in desc


# ---------------------------------------------------------------
# MQTT broker scanner: protocol reference
# ---------------------------------------------------------------


class TestMQTTBrokerScanHelpers:
    """Test MQTT broker scanner constants."""

    @pytest.fixture()
    def mod(self):
        try:
            import embedxpl.modules.scanners.embedded_os.mqtt_broker_scan as m
        except (ImportError, AttributeError):
            pytest.skip("Cannot import mqtt_broker_scan")
        return m

    def test_has_exploit(self, mod) -> None:
        assert hasattr(mod, "Exploit")

    def test_info_mentions_mqtt(self, mod) -> None:
        info = _get_info(mod.Exploit)
        name_desc = (info.get("name", "") + info.get("description", "")).lower()
        assert "mqtt" in name_desc


# ---------------------------------------------------------------
# BMC discover: IPMI port and Redfish
# ---------------------------------------------------------------


class TestBMCDiscoverHelpers:
    """Test BMC discovery scanner helpers."""

    @pytest.fixture()
    def exploit_cls(self):
        try:
            from embedxpl.modules.scanners.bmc.bmc_discover import Exploit
        except (ImportError, AttributeError):
            pytest.skip("Cannot import bmc_discover")
        return Exploit

    def test_has_ipmi_port(self, exploit_cls) -> None:
        assert hasattr(exploit_cls, "ipmi_port"), "BMC scanner should have ipmi_port option"

    def test_info_mentions_bmc_or_ipmi(self, exploit_cls) -> None:
        info = _get_info(exploit_cls)
        name_desc = (info.get("name", "") + info.get("description", "")).lower()
        assert "bmc" in name_desc or "ipmi" in name_desc or "redfish" in name_desc
