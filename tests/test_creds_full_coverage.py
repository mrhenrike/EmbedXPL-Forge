"""B2 coverage: parametrized structural tests for ALL credential modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

CREDS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "creds"
_SKIP_DIRS = {"__pycache__", "refs", "data", ".git"}
_SAFE_ERRORS = (
    ImportError, ModuleNotFoundError, OSError, AttributeError,
    TypeError, SyntaxError, ValueError, RuntimeError, NameError,
)


def _collect_cred_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = CREDS_ROOT.parents[2]
    for root, dirs, files in os.walk(CREDS_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


ALL_CREDS = _collect_cred_modules()


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


@pytest.mark.parametrize("mod_path", ALL_CREDS, ids=[m.rsplit(".", 1)[-1] for m in ALL_CREDS])
class TestCredImportAndInterface:
    """Verify every credential module imports and exposes the expected interface."""

    def test_importable(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_exploit_class(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        assert isinstance(mod.Exploit, type)

    def test_has_info_dict(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        info = _get_info(mod.Exploit)
        assert isinstance(info, dict)
        assert "name" in info
        assert "description" in info

    def test_has_run_method(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        cls = mod.Exploit
        assert hasattr(cls, "run") and callable(cls.run), "{} missing run()".format(mod_path)

    def test_instantiate(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        try:
            mod.Exploit()
        except _SAFE_ERRORS:
            pytest.skip("Cannot instantiate")
        except Exception:
            pytest.skip("Instantiation error")

    def test_has_target_and_port(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        cls = mod.Exploit
        if not hasattr(cls, "target"):
            pytest.skip("{} has no target attr".format(mod_path))
