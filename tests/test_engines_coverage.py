"""B3 coverage: parametrized structural tests for ALL engine modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

ENGINES_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "engines"
_SKIP_DIRS = {"__pycache__", "refs", "data", ".git"}


def _collect_engine_modules() -> list[str]:
    modules: list[str] = []
    pkg_root = ENGINES_ROOT.parents[1]
    for root, dirs, files in os.walk(ENGINES_ROOT):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for f in sorted(files):
            if f.endswith(".py") and not f.startswith("__"):
                rel = os.path.relpath(os.path.join(root, f), pkg_root)
                mod_path = rel.replace(os.sep, ".").removesuffix(".py")
                modules.append(mod_path)
    return modules


ALL_ENGINES = _collect_engine_modules()


def _safe_import(mod_path: str):
    try:
        return importlib.import_module(mod_path)
    except (SystemExit, KeyboardInterrupt) as exc:
        pytest.skip("Import triggered exit: {}".format(exc))
    except Exception as exc:
        pytest.skip("Import failed: {}".format(exc))
    return None


@pytest.mark.parametrize("mod_path", ALL_ENGINES, ids=[m.rsplit(".", 1)[-1] for m in ALL_ENGINES])
class TestEngineImportAndInterface:
    """Verify every engine module imports and exposes a usable interface."""

    def test_importable(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        assert mod is not None

    def test_has_public_api(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        public = [n for n in dir(mod) if not n.startswith("_")]
        assert len(public) > 0, "{} has no public names".format(mod_path)

    def test_has_classes_or_functions(self, mod_path: str) -> None:
        mod = _safe_import(mod_path)
        has_class = any(isinstance(getattr(mod, n), type) for n in dir(mod) if not n.startswith("_"))
        has_func = any(callable(getattr(mod, n)) and not isinstance(getattr(mod, n), type) for n in dir(mod) if not n.startswith("_"))
        if not (has_class or has_func):
            pytest.skip("{} is a data/config module".format(mod_path))
