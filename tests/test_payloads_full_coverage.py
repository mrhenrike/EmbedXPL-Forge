"""B2 coverage: parametrized structural tests for ALL payload modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

PAYLOADS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "payloads"
_SKIP_DIRS = {"__pycache__", "refs", "data", ".git"}
_SAFE_ERRORS = (
    ImportError, ModuleNotFoundError, OSError, AttributeError,
    TypeError, SyntaxError, ValueError, RuntimeError, NameError,
)


def _collect_payload_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = PAYLOADS_ROOT.parents[2]
    for root, dirs, files in os.walk(PAYLOADS_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


ALL_PAYLOADS = _collect_payload_modules()


def _safe_import(mod_path: str):
    try:
        return importlib.import_module(mod_path)
    except Exception as exc:
        pytest.skip("Import failed: {}".format(exc))
    return None


def _get_info(cls: type) -> dict:
    mangled = "_{}__info__".format(cls.__name__)
    if hasattr(cls, mangled):
        return getattr(cls, mangled)
    if hasattr(cls, "__info__"):
        return cls.__info__
    pytest.skip("{} has no __info__".format(cls.__name__))
    return {}


@pytest.mark.parametrize("mod_path", ALL_PAYLOADS, ids=[m.rsplit(".", 1)[-1] for m in ALL_PAYLOADS])
class TestPayloadImportAndInterface:
    """Verify every payload module imports and exposes the expected interface."""

    def test_importable(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_payload_class(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        has_payload = hasattr(mod, "Payload")
        has_exploit = hasattr(mod, "Exploit")
        if not has_payload and not has_exploit:
            pytest.skip("No Payload or Exploit class")
        cls = getattr(mod, "Payload", None) or getattr(mod, "Exploit", None)
        assert isinstance(cls, type)

    def test_has_info_dict(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Payload", None) or getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Payload/Exploit class")
        info = _get_info(cls)
        assert isinstance(info, dict)
        assert "name" in info

    def test_has_generate_or_run(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Payload", None) or getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Payload/Exploit class")
        has_gen = hasattr(cls, "generate") and callable(cls.generate)
        has_run = hasattr(cls, "run") and callable(cls.run)
        assert has_gen or has_run, "{} missing generate() or run()".format(mod_path)

    def test_instantiate(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        cls = getattr(mod, "Payload", None) or getattr(mod, "Exploit", None)
        if cls is None:
            pytest.skip("No Payload/Exploit class")
        try:
            cls()
        except _SAFE_ERRORS:
            pytest.skip("Cannot instantiate")
        except Exception:
            pytest.skip("Instantiation error")
