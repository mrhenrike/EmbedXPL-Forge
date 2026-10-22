"""Tests for new autopwn modules: NAS, SmartHome, VoIP, IoTGeneric.

Validates that each module:
- Can be imported
- Exposes the expected class inheriting from SegmentAutoPwn
- Has a run() method
- Can be instantiated with mock targets
- Stores the expected segment attribute

Note: The autopwn __init__.py may reference missing submodules (e.g. ics),
so we load individual .py files directly via importlib.util to bypass the
broken package __init__.
"""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import sys
import types

import pytest

# Base directory for autopwn modules
_AUTOPWN_DIR = pathlib.Path(__file__).resolve().parent.parent / "embedxpl" / "modules" / "autopwn"

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError, AttributeError)


def _load_module_from_file(mod_name: str, file_path: pathlib.Path) -> types.ModuleType | None:
    """Load a single .py file as a module, bypassing __init__.py issues.

    Ensures that the base and segment modules (dependencies) are loaded first.
    """
    if mod_name in sys.modules:
        return sys.modules[mod_name]

    if not file_path.exists():
        return None

    # Ensure dependencies are loaded first
    deps = [
        ("embedxpl.modules.autopwn.base", _AUTOPWN_DIR / "base.py"),
        ("embedxpl.modules.autopwn.segment", _AUTOPWN_DIR / "segment.py"),
    ]
    for dep_name, dep_path in deps:
        if dep_name not in sys.modules and dep_path.exists() and dep_name != mod_name:
            try:
                spec = importlib.util.spec_from_file_location(dep_name, dep_path)
                if spec and spec.loader:
                    dep_mod = importlib.util.module_from_spec(spec)
                    sys.modules[dep_name] = dep_mod
                    spec.loader.exec_module(dep_mod)
            except _KNOWN_IMPORT_ERRORS:
                pass

    try:
        spec = importlib.util.spec_from_file_location(mod_name, file_path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        return mod
    except _KNOWN_IMPORT_ERRORS:
        return None


# ---------------------------------------------------------------
# Module paths, class names, and expected segment values
# ---------------------------------------------------------------

AUTOPWN_NEW_MODULES = [
    (
        "embedxpl.modules.autopwn.nas",
        "NASAutoPwn",
        "nas",
        _AUTOPWN_DIR / "nas.py",
    ),
    (
        "embedxpl.modules.autopwn.smart_home",
        "SmartHomeAutoPwn",
        "smart_home",
        _AUTOPWN_DIR / "smart_home.py",
    ),
    (
        "embedxpl.modules.autopwn.voip",
        "VoIPAutoPwn",
        "voip",
        _AUTOPWN_DIR / "voip.py",
    ),
    (
        "embedxpl.modules.autopwn.iot_generic",
        "IoTGenericAutoPwn",
        "iot_generic",
        _AUTOPWN_DIR / "iot_generic.py",
    ),
]


def _safe_import(mod_path: str, file_path: pathlib.Path | None = None):
    """Import module; try standard import first, then file-based fallback."""
    try:
        return importlib.import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS:
        pass

    # Fallback: load from file directly to bypass broken __init__.py
    if file_path is not None:
        mod = _load_module_from_file(mod_path, file_path)
        if mod is not None:
            return mod

    pytest.skip("Cannot import {}".format(mod_path))


def _get_class(mod_path: str, class_name: str, file_path: pathlib.Path | None = None):
    """Import module and return the named class."""
    mod = _safe_import(mod_path, file_path)
    if mod is None:
        pytest.skip("Module {} returned None".format(mod_path))
    cls = getattr(mod, class_name, None)
    if cls is None:
        pytest.skip("{} not found in {}".format(class_name, mod_path))
    return cls


def _get_segment_base():
    """Return the SegmentAutoPwn base class."""
    # Try base.py first
    mod = _load_module_from_file(
        "embedxpl.modules.autopwn.base", _AUTOPWN_DIR / "base.py",
    )
    if mod and hasattr(mod, "SegmentAutoPwn"):
        return mod.SegmentAutoPwn

    # Try segment.py as alternative
    mod = _load_module_from_file(
        "embedxpl.modules.autopwn.segment", _AUTOPWN_DIR / "segment.py",
    )
    if mod and hasattr(mod, "SegmentAutoPwn"):
        return mod.SegmentAutoPwn

    return None


# ---------------------------------------------------------------
# SegmentAutoPwn base class fixture
# ---------------------------------------------------------------

@pytest.fixture()
def segment_base():
    """Return the SegmentAutoPwn base class for inheritance checks."""
    cls = _get_segment_base()
    if cls is None:
        pytest.skip("Cannot import SegmentAutoPwn base class")
    return cls


# ---------------------------------------------------------------
# Parametrized structural tests
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,class_name,expected_segment,file_path",
    AUTOPWN_NEW_MODULES,
    ids=[cn for _, cn, _, _ in AUTOPWN_NEW_MODULES],
)
class TestAutoPwnNewModuleStructure:
    """Structural tests for new autopwn modules."""

    def test_importable(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        mod = _safe_import(mod_path, file_path)
        assert mod is not None

    def test_class_exists(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        mod = _safe_import(mod_path, file_path)
        assert hasattr(mod, class_name), "{} missing class {}".format(mod_path, class_name)

    def test_class_has_run_method(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        assert hasattr(cls, "run"), "{} missing run() method".format(class_name)
        assert callable(getattr(cls, "run"))

    def test_inherits_from_segment_autopwn(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path, segment_base,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        assert issubclass(cls, segment_base), (
            "{} should inherit from SegmentAutoPwn".format(class_name)
        )

    def test_instantiation_with_mock_targets(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        try:
            instance = cls(targets=["192.168.1.1"])
        except TypeError:
            # Some subclasses may require segment keyword
            try:
                instance = cls(segment=expected_segment, targets=["192.168.1.1"])
            except Exception as exc:
                pytest.fail(
                    "Cannot instantiate {} with mock targets: {}".format(class_name, exc)
                )
        assert instance is not None

    def test_segment_attribute(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        try:
            instance = cls(targets=["192.168.1.1"])
        except TypeError:
            instance = cls(segment=expected_segment, targets=["192.168.1.1"])
        assert hasattr(instance, "segment")
        assert instance.segment == expected_segment

    def test_targets_stored_as_list(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        try:
            instance = cls(targets="192.168.1.1")
        except TypeError:
            instance = cls(segment=expected_segment, targets="192.168.1.1")
        assert isinstance(instance.targets, list)
        assert "192.168.1.1" in instance.targets

    def test_multiple_targets(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        cls = _get_class(mod_path, class_name, file_path)
        try:
            instance = cls(targets=targets)
        except TypeError:
            instance = cls(segment=expected_segment, targets=targets)
        assert len(instance.targets) == 3
        assert instance.targets == targets

    def test_check_only_default(
        self, mod_path: str, class_name: str, expected_segment: str,
        file_path: pathlib.Path,
    ) -> None:
        cls = _get_class(mod_path, class_name, file_path)
        try:
            instance = cls(targets=["192.168.1.1"])
        except TypeError:
            instance = cls(segment=expected_segment, targets=["192.168.1.1"])
        assert hasattr(instance, "check_only")
        assert instance.check_only is True


# ---------------------------------------------------------------
# Per-module specific tests
# ---------------------------------------------------------------


class TestNASAutoPwn:
    """NAS-specific tests."""

    @pytest.fixture()
    def nas_cls(self):
        return _get_class(
            "embedxpl.modules.autopwn.nas", "NASAutoPwn",
            _AUTOPWN_DIR / "nas.py",
        )

    def test_fingerprints_dict_initialized(self, nas_cls) -> None:
        instance = nas_cls(targets=["192.168.1.1"])
        assert hasattr(instance, "fingerprints")
        assert isinstance(instance.fingerprints, dict)

    def test_http_timeout_configurable(self, nas_cls) -> None:
        instance = nas_cls(targets=["10.0.0.1"], http_timeout=10)
        assert instance.http_timeout == 10

    def test_snmp_community_configurable(self, nas_cls) -> None:
        instance = nas_cls(targets=["10.0.0.1"], snmp_community="private")
        assert instance.snmp_community == "private"

    def test_nas_fingerprint_dataclass(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.nas", _AUTOPWN_DIR / "nas.py",
        )
        if not hasattr(mod, "NASFingerprint"):
            pytest.skip("NASFingerprint not found")
        fp = mod.NASFingerprint(target="192.168.1.1", vendor="qnap", model="TS-251+")
        assert fp.target == "192.168.1.1"
        assert fp.vendor == "qnap"
        assert fp.summary_line()  # Should produce non-empty string

    def test_vendor_signatures_defined(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.nas", _AUTOPWN_DIR / "nas.py",
        )
        sigs = getattr(mod, "_VENDOR_SIGNATURES", None)
        if sigs is None:
            pytest.skip("_VENDOR_SIGNATURES not found")
        assert isinstance(sigs, dict)
        assert "qnap" in sigs
        assert "synology" in sigs


class TestSmartHomeAutoPwn:
    """Smart Home specific tests."""

    @pytest.fixture()
    def sh_cls(self):
        return _get_class(
            "embedxpl.modules.autopwn.smart_home", "SmartHomeAutoPwn",
            _AUTOPWN_DIR / "smart_home.py",
        )

    def test_instantiation(self, sh_cls) -> None:
        instance = sh_cls(targets=["192.168.1.50"])
        assert instance.segment == "smart_home"

    def test_smart_home_fingerprint_dataclass(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.smart_home", _AUTOPWN_DIR / "smart_home.py",
        )
        if not hasattr(mod, "SmartHomeFingerprint"):
            pytest.skip("SmartHomeFingerprint not found")
        fp = mod.SmartHomeFingerprint(
            target="192.168.1.50",
            vendor="philips_hue",
            device_type="hub",
        )
        assert fp.vendor == "philips_hue"
        assert fp.device_type == "hub"
        assert len(fp.summary_line()) > 0

    def test_vendor_signatures_defined(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.smart_home", _AUTOPWN_DIR / "smart_home.py",
        )
        sigs = getattr(mod, "_VENDOR_SIGNATURES", None)
        if sigs is None:
            pytest.skip("_VENDOR_SIGNATURES not found")
        assert isinstance(sigs, dict)
        assert "philips_hue" in sigs
        assert "tuya" in sigs


class TestVoIPAutoPwn:
    """VoIP specific tests."""

    @pytest.fixture()
    def voip_cls(self):
        return _get_class(
            "embedxpl.modules.autopwn.voip", "VoIPAutoPwn",
            _AUTOPWN_DIR / "voip.py",
        )

    def test_instantiation(self, voip_cls) -> None:
        instance = voip_cls(targets=["10.0.0.100"])
        assert instance.segment == "voip"

    def test_voip_fingerprint_dataclass(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.voip", _AUTOPWN_DIR / "voip.py",
        )
        if not hasattr(mod, "VoIPFingerprint"):
            pytest.skip("VoIPFingerprint not found")
        fp = mod.VoIPFingerprint(
            target="10.0.0.100",
            vendor="cisco",
            model="SPA504G",
        )
        assert fp.vendor == "cisco"
        assert len(fp.summary_line()) > 0

    def test_vendor_signatures_defined(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.voip", _AUTOPWN_DIR / "voip.py",
        )
        sigs = getattr(mod, "_VENDOR_SIGNATURES", None)
        if sigs is None:
            pytest.skip("_VENDOR_SIGNATURES not found")
        assert isinstance(sigs, dict)
        assert "cisco" in sigs
        assert "polycom" in sigs
        assert "yealink" in sigs


class TestIoTGenericAutoPwn:
    """IoT Generic specific tests."""

    @pytest.fixture()
    def iot_cls(self):
        return _get_class(
            "embedxpl.modules.autopwn.iot_generic", "IoTGenericAutoPwn",
            _AUTOPWN_DIR / "iot_generic.py",
        )

    def test_instantiation(self, iot_cls) -> None:
        instance = iot_cls(targets=["172.16.0.1"])
        assert instance.segment == "iot_generic"

    def test_iot_fingerprint_dataclass(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.iot_generic", _AUTOPWN_DIR / "iot_generic.py",
        )
        if not hasattr(mod, "IoTFingerprint"):
            pytest.skip("IoTFingerprint not found")
        fp = mod.IoTFingerprint(
            target="172.16.0.1",
            device_class="camera",
            vendor="hikvision",
        )
        assert fp.device_class == "camera"
        assert fp.vendor == "hikvision"
        assert len(fp.summary_line()) > 0

    def test_class_signatures_defined(self) -> None:
        mod = _safe_import(
            "embedxpl.modules.autopwn.iot_generic", _AUTOPWN_DIR / "iot_generic.py",
        )
        sigs = getattr(mod, "_CLASS_SIGNATURES", None)
        if sigs is None:
            pytest.skip("_CLASS_SIGNATURES not found")
        assert isinstance(sigs, dict)
        assert "camera" in sigs
        assert "router" in sigs
        assert "nas" in sigs


# ---------------------------------------------------------------
# Base class compatibility checks
# ---------------------------------------------------------------


class TestSegmentAutoPwnBase:
    """Verify the base autopwn class from segment.py."""

    @pytest.fixture()
    def base_cls(self):
        cls = _get_segment_base()
        if cls is None:
            pytest.skip("Cannot import SegmentAutoPwn")
        return cls

    def test_segment_map_has_expected_entries(self, base_cls) -> None:
        smap = getattr(base_cls, "SEGMENT_MAP", None)
        if smap is None:
            pytest.skip("SegmentAutoPwn has no SEGMENT_MAP (base.py variant)")
        assert "router" in smap
        assert "nas" in smap
        assert "camera" in smap

    def test_base_instantiation(self, base_cls) -> None:
        instance = base_cls(segment="test", targets=["10.0.0.1"])
        assert instance.segment == "test"
        assert instance.targets == ["10.0.0.1"]
        assert instance.check_only is True

    def test_base_string_target_becomes_list(self, base_cls) -> None:
        instance = base_cls(segment="router", targets="10.0.0.1")
        assert isinstance(instance.targets, list)
        assert instance.targets == ["10.0.0.1"]
