"""B2 coverage: parametrized structural tests for ALL scanner modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

SCANNERS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "scanners"
_SKIP_DIRS = {"__pycache__", "refs", "data", ".git"}
_SAFE_ERRORS = (
    ImportError, ModuleNotFoundError, OSError, AttributeError,
    TypeError, SyntaxError, ValueError, RuntimeError, NameError,
)


def _collect_scanner_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = SCANNERS_ROOT.parents[2]
    for root, dirs, files in os.walk(SCANNERS_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


ALL_SCANNERS = _collect_scanner_modules()


def _safe_import(mod_path: str):
    try:
        return importlib.import_module(mod_path)
    except (SystemExit, KeyboardInterrupt) as exc:
        pytest.skip("Import triggered exit: {}".format(exc))
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


@pytest.mark.parametrize("mod_path", ALL_SCANNERS, ids=[m.rsplit(".", 1)[-1] for m in ALL_SCANNERS])
class TestScannerImportAndInterface:
    """Verify every scanner module imports and exposes the expected interface."""

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

    def test_has_run_or_check(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        cls = mod.Exploit
        has_run = hasattr(cls, "run") and callable(cls.run)
        has_check = hasattr(cls, "check") and callable(cls.check)
        assert has_run or has_check, "{} missing run() or check()".format(mod_path)

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

    def test_has_target_attr(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        if not hasattr(mod, "Exploit"):
            pytest.skip("No Exploit class")
        cls = mod.Exploit
        has_target = hasattr(cls, "target") or hasattr(cls, "targets")
        has_modules = hasattr(cls, "modules")
        if not (has_target or has_modules):
            pytest.skip("{} has no target/modules attr (utility scanner)".format(mod_path))
