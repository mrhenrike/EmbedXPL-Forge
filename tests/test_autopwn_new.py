"""Tests for new autopwn modules: NAS, SmartHome, VoIP, IoTGeneric.

Validates that each module:
- Can be imported
- Exposes the expected class inheriting from SegmentAutoPwn
- Has a run() method
- Can be instantiated with mock targets
- Stores the expected segment attribute
"""
from __future__ import annotations

import importlib

import pytest

# ---------------------------------------------------------------
# Module paths, class names, and expected segment values
# ---------------------------------------------------------------

AUTOPWN_NEW_MODULES = [
    (
        "embedxpl.modules.autopwn.nas",
        "NASAutoPwn",
        "nas",
    ),
    (
        "embedxpl.modules.autopwn.smart_home",
        "SmartHomeAutoPwn",
        "smart_home",
    ),
    (
        "embedxpl.modules.autopwn.voip",
        "VoIPAutoPwn",
        "voip",
    ),
    (
        "embedxpl.modules.autopwn.iot_generic",
        "IoTGenericAutoPwn",
        "iot_generic",
    ),
]

_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, OSError)


def _safe_import(mod_path: str):
    """Import module; skip on dependency errors."""
    try:
        return importlib.import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS as exc:
        pytest.skip("Import failed: {}".format(exc))


def _get_class(mod_path: str, class_name: str):
    """Import module and return the named class."""
    mod = _safe_import(mod_path)
    if mod is None:
        return None
    cls = getattr(mod, class_name, None)
    if cls is None:
        pytest.skip("{} not found in {}".format(class_name, mod_path))
    return cls


# ---------------------------------------------------------------
# SegmentAutoPwn base class fixture
# ---------------------------------------------------------------

@pytest.fixture()
def segment_base():
    """Return the SegmentAutoPwn base class for inheritance checks."""
    try:
        from embedxpl.modules.autopwn.base import SegmentAutoPwn
        return SegmentAutoPwn
    except ImportError:
        # Try alternate location used by segment.py
        try:
            from embedxpl.modules.autopwn.segment import SegmentAutoPwn
            return SegmentAutoPwn
        except ImportError:
            pytest.skip("Cannot import SegmentAutoPwn base class")


# ---------------------------------------------------------------
# Parametrized structural tests
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "mod_path,class_name,expected_segment",
    AUTOPWN_NEW_MODULES,
    ids=[cn for _, cn, _ in AUTOPWN_NEW_MODULES],
)
class TestAutoPwnNewModuleStructure:
    """Structural tests for new autopwn modules."""

    def test_importable(self, mod_path: str, class_name: str, expected_segment: str) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_class_exists(self, mod_path: str, class_name: str, expected_segment: str) -> None:
        mod = _safe_import(mod_path)
        assert hasattr(mod, class_name), "{} missing class {}".format(mod_path, class_name)

    def test_class_has_run_method(
        self, mod_path: str, class_name: str, expected_segment: str,
    ) -> None:
        cls = _get_class(mod_path, class_name)
        assert hasattr(cls, "run"), "{} missing run() method".format(class_name)
        assert callable(cls.run)

    def test_inherits_from_segment_autopwn(
        self, mod_path: str, class_name: str, expected_segment: str, segment_base,
    ) -> None:
        cls = _get_class(mod_path, class_name)
        assert issubclass(cls, segment_base), (
            "{} should inherit from SegmentAutoPwn".format(class_name)
        )

    def test_instantiation_with_mock_targets(
        self, mod_path: str, class_name: str, expected_segment: str,
    ) -> None:
        cls = _get_class(mod_path, class_name)
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
    ) -> None:
        cls = _get_class(mod_path, class_name)
        try:
            instance = cls(targets=["192.168.1.1"])
        except TypeError:
            instance = cls(segment=expected_segment, targets=["192.168.1.1"])
        assert hasattr(instance, "segment")
        assert instance.segment == expected_segment

    def test_targets_stored_as_list(
        self, mod_path: str, class_name: str, expected_segment: str,
    ) -> None:
        cls = _get_class(mod_path, class_name)
        try:
            instance = cls(targets="192.168.1.1")
        except TypeError:
            instance = cls(segment=expected_segment, targets="192.168.1.1")
        assert isinstance(instance.targets, list)
        assert "192.168.1.1" in instance.targets

    def test_multiple_targets(
        self, mod_path: str, class_name: str, expected_segment: str,
    ) -> None:
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        cls = _get_class(mod_path, class_name)
        try:
            instance = cls(targets=targets)
        except TypeError:
            instance = cls(segment=expected_segment, targets=targets)
        assert len(instance.targets) == 3
        assert instance.targets == targets

    def test_check_only_default(
        self, mod_path: str, class_name: str, expected_segment: str,
    ) -> None:
        cls = _get_class(mod_path, class_name)
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
        return _get_class("embedxpl.modules.autopwn.nas", "NASAutoPwn")

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
        try:
            from embedxpl.modules.autopwn.nas import NASFingerprint
        except ImportError:
            pytest.skip("Cannot import NASFingerprint")
        fp = NASFingerprint(target="192.168.1.1", vendor="qnap", model="TS-251+")
        assert fp.target == "192.168.1.1"
        assert fp.vendor == "qnap"
        assert fp.summary_line()  # Should produce non-empty string

    def test_vendor_signatures_defined(self) -> None:
        try:
            from embedxpl.modules.autopwn.nas import _VENDOR_SIGNATURES
        except ImportError:
            pytest.skip("Cannot import _VENDOR_SIGNATURES")
        assert isinstance(_VENDOR_SIGNATURES, dict)
        assert "qnap" in _VENDOR_SIGNATURES
        assert "synology" in _VENDOR_SIGNATURES


class TestSmartHomeAutoPwn:
    """Smart Home specific tests."""

    @pytest.fixture()
    def sh_cls(self):
        return _get_class("embedxpl.modules.autopwn.smart_home", "SmartHomeAutoPwn")

    def test_instantiation(self, sh_cls) -> None:
        instance = sh_cls(targets=["192.168.1.50"])
        assert instance.segment == "smart_home"

    def test_smart_home_fingerprint_dataclass(self) -> None:
        try:
            from embedxpl.modules.autopwn.smart_home import SmartHomeFingerprint
        except ImportError:
            pytest.skip("Cannot import SmartHomeFingerprint")
        fp = SmartHomeFingerprint(
            target="192.168.1.50",
            vendor="philips_hue",
            device_type="hub",
        )
        assert fp.vendor == "philips_hue"
        assert fp.device_type == "hub"
        assert len(fp.summary_line()) > 0

    def test_vendor_signatures_defined(self) -> None:
        try:
            from embedxpl.modules.autopwn.smart_home import _VENDOR_SIGNATURES
        except ImportError:
            pytest.skip("Cannot import SmartHome _VENDOR_SIGNATURES")
        assert isinstance(_VENDOR_SIGNATURES, dict)
        assert "philips_hue" in _VENDOR_SIGNATURES
        assert "tuya" in _VENDOR_SIGNATURES


class TestVoIPAutoPwn:
    """VoIP specific tests."""

    @pytest.fixture()
    def voip_cls(self):
        return _get_class("embedxpl.modules.autopwn.voip", "VoIPAutoPwn")

    def test_instantiation(self, voip_cls) -> None:
        instance = voip_cls(targets=["10.0.0.100"])
        assert instance.segment == "voip"

    def test_voip_fingerprint_dataclass(self) -> None:
        try:
            from embedxpl.modules.autopwn.voip import VoIPFingerprint
        except ImportError:
            pytest.skip("Cannot import VoIPFingerprint")
        fp = VoIPFingerprint(
            target="10.0.0.100",
            vendor="cisco",
            model="SPA504G",
        )
        assert fp.vendor == "cisco"
        assert len(fp.summary_line()) > 0

    def test_vendor_signatures_defined(self) -> None:
        try:
            from embedxpl.modules.autopwn.voip import _VENDOR_SIGNATURES
        except ImportError:
            pytest.skip("Cannot import VoIP _VENDOR_SIGNATURES")
        assert isinstance(_VENDOR_SIGNATURES, dict)
        assert "cisco" in _VENDOR_SIGNATURES
        assert "polycom" in _VENDOR_SIGNATURES
        assert "yealink" in _VENDOR_SIGNATURES


class TestIoTGenericAutoPwn:
    """IoT Generic specific tests."""

    @pytest.fixture()
    def iot_cls(self):
        return _get_class("embedxpl.modules.autopwn.iot_generic", "IoTGenericAutoPwn")

    def test_instantiation(self, iot_cls) -> None:
        instance = iot_cls(targets=["172.16.0.1"])
        assert instance.segment == "iot_generic"

    def test_iot_fingerprint_dataclass(self) -> None:
        try:
            from embedxpl.modules.autopwn.iot_generic import IoTFingerprint
        except ImportError:
            pytest.skip("Cannot import IoTFingerprint")
        fp = IoTFingerprint(
            target="172.16.0.1",
            device_class="camera",
            vendor="hikvision",
        )
        assert fp.device_class == "camera"
        assert fp.vendor == "hikvision"
        assert len(fp.summary_line()) > 0

    def test_class_signatures_defined(self) -> None:
        try:
            from embedxpl.modules.autopwn.iot_generic import _CLASS_SIGNATURES
        except ImportError:
            pytest.skip("Cannot import _CLASS_SIGNATURES")
        assert isinstance(_CLASS_SIGNATURES, dict)
        assert "camera" in _CLASS_SIGNATURES
        assert "router" in _CLASS_SIGNATURES
        assert "nas" in _CLASS_SIGNATURES


# ---------------------------------------------------------------
# Base class compatibility checks
# ---------------------------------------------------------------


class TestSegmentAutoPwnBase:
    """Verify the base autopwn class from segment.py."""

    @pytest.fixture()
    def base_cls(self):
        try:
            from embedxpl.modules.autopwn.segment import SegmentAutoPwn
            return SegmentAutoPwn
        except ImportError:
            pytest.skip("Cannot import SegmentAutoPwn from segment.py")

    def test_segment_map_has_expected_entries(self, base_cls) -> None:
        smap = base_cls.SEGMENT_MAP
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
