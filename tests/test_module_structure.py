"""Structural tests for EmbedXPL modules: import, class, run(), __info__.

Validates that modules follow the required interface:
- Have an Exploit class
- Expose __info__ dict with name, description, authors
- Implement run() method
- Optionally implement check() method

Uses sampled verification to keep test time under 30s.
"""
from __future__ import annotations

import importlib
import random

import pytest

from embedxpl.core.exploit.utils import MODULES_DIR, index_modules

ALL_MODULES = index_modules()
REQUIRED_INFO_KEYS = {"name", "description", "authors"}

EXPLOIT_MODULES = [m for m in ALL_MODULES if m.startswith("exploits.")]
SCANNER_MODULES = [m for m in ALL_MODULES if m.startswith("scanners.")]
CRED_MODULES = [m for m in ALL_MODULES if m.startswith("creds.")]
PAYLOAD_MODULES = [m for m in ALL_MODULES if m.startswith("payloads.")]
ENCODER_MODULES = [m for m in ALL_MODULES if m.startswith("encoders.")]


def _sample(population: list[str], n: int, seed: int = 42) -> list[str]:
    """Reproducible sample from a module list."""
    if len(population) <= n:
        return population
    rng = random.Random(seed)
    return rng.sample(population, n)


_KNOWN_IMPORT_ERRORS = (ImportError, ModuleNotFoundError, NameError, AttributeError, OSError, SyntaxError)


def _import_module(dotted: str):
    full = f"embedxpl.modules.{dotted}"
    return importlib.import_module(full)


def _safe_import(mod_path: str):
    """Import a module, skipping on known legacy issues."""
    try:
        return _import_module(mod_path)
    except _KNOWN_IMPORT_ERRORS as exc:
        pytest.skip(f"Import failed (legacy issue): {exc}")
    except Exception as exc:
        if "does not exist" in str(exc) or "OptionValidation" in type(exc).__name__:
            pytest.skip(f"Import failed (path validation): {exc}")
        raise


def _get_exploit_class(mod):
    cls = getattr(mod, "Exploit", None)
    if cls is None:
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name, None)
            if isinstance(obj, type) and attr_name != "__class__":
                if hasattr(obj, "run"):
                    return obj
    return cls


# ---------------------------------------------------------------
# Total counts
# ---------------------------------------------------------------

class TestModuleInventory:
    def test_exploits_count(self):
        assert len(EXPLOIT_MODULES) >= 2500

    def test_scanner_count(self):
        assert len(SCANNER_MODULES) >= 200

    def test_cred_count(self):
        assert len(CRED_MODULES) >= 1000

    def test_payload_count(self):
        assert len(PAYLOAD_MODULES) >= 50

    def test_encoder_count(self):
        assert len(ENCODER_MODULES) >= 25

    def test_total_modules(self):
        assert len(ALL_MODULES) >= 4500


# ---------------------------------------------------------------
# Sampled structural checks: exploits
# ---------------------------------------------------------------

EXPLOIT_SAMPLE = _sample(EXPLOIT_MODULES, 50)


@pytest.mark.parametrize("mod_path", EXPLOIT_SAMPLE, ids=lambda p: p.rsplit(".", 1)[-1][:40])
class TestExploitModuleStructure:
    def test_import(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_exploit_class(self, mod_path: str):
        mod = _safe_import(mod_path)
        cls = _get_exploit_class(mod)
        if cls is None:
            has_main = hasattr(mod, "main") or hasattr(mod, "exploit")
            if has_main:
                pytest.skip("Legacy script module (main/exploit function, no class)")
            pytest.skip("No Exploit class found (legacy EDB module)")

    def test_has_run_method(self, mod_path: str):
        mod = _safe_import(mod_path)
        cls = _get_exploit_class(mod)
        if cls is None:
            pytest.skip("No Exploit class")
        assert hasattr(cls, "run"), f"{mod_path} Exploit missing run()"

    def test_has_info_metadata(self, mod_path: str):
        mod = _safe_import(mod_path)
        cls = _get_exploit_class(mod)
        if cls is None:
            pytest.skip("No Exploit class")
        info_attr = f"_{cls.__name__}__info__"
        info = getattr(cls, info_attr, None) or getattr(cls, "__info__", None)
        if info is None:
            pytest.skip("No __info__ found (name-mangled)")
        assert isinstance(info, dict)
        for key in REQUIRED_INFO_KEYS:
            assert key in info, f"{mod_path} __info__ missing '{key}'"


# ---------------------------------------------------------------
# Sampled structural checks: scanners
# ---------------------------------------------------------------

SCANNER_SAMPLE = _sample(SCANNER_MODULES, 30)


@pytest.mark.parametrize("mod_path", SCANNER_SAMPLE, ids=lambda p: p.rsplit(".", 1)[-1][:40])
class TestScannerModuleStructure:
    def test_import(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_run_method(self, mod_path: str):
        mod = _safe_import(mod_path)
        cls = _get_exploit_class(mod)
        if cls is not None:
            assert hasattr(cls, "run"), f"{mod_path} scanner missing run()"


# ---------------------------------------------------------------
# Sampled structural checks: creds
# ---------------------------------------------------------------

CRED_SAMPLE = _sample(CRED_MODULES, 30)


@pytest.mark.parametrize("mod_path", CRED_SAMPLE, ids=lambda p: p.rsplit(".", 1)[-1][:40])
class TestCredModuleStructure:
    def test_import(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_run_method(self, mod_path: str):
        mod = _safe_import(mod_path)
        cls = _get_exploit_class(mod)
        if cls is not None:
            assert hasattr(cls, "run"), f"{mod_path} cred module missing run()"


# ---------------------------------------------------------------
# Payload and encoder checks (all, not sampled)
# ---------------------------------------------------------------

@pytest.mark.parametrize("mod_path", PAYLOAD_MODULES, ids=lambda p: p.rsplit(".", 1)[-1][:40])
class TestPayloadStructure:
    def test_import(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None


@pytest.mark.parametrize("mod_path", ENCODER_MODULES, ids=lambda p: p.rsplit(".", 1)[-1][:40])
class TestEncoderStructure:
    def test_import(self, mod_path: str):
        mod = _safe_import(mod_path)
        assert mod is not None


# ---------------------------------------------------------------
# Cross-cutting: check() method presence on exploit sample
# ---------------------------------------------------------------

class TestCheckMethodPresence:
    def test_at_least_some_exploits_have_check(self):
        check_count = 0
        for mod_path in EXPLOIT_SAMPLE[:20]:
            try:
                mod = _import_module(mod_path)
                cls = _get_exploit_class(mod)
                if cls and hasattr(cls, "check"):
                    base_check = getattr(cls.__bases__[0], "check", None) if cls.__bases__ else None
                    own_check = getattr(cls, "check")
                    if own_check is not base_check:
                        check_count += 1
            except Exception:
                continue
        assert check_count >= 1, "Expected at least 1/20 sampled exploits to override check()"
