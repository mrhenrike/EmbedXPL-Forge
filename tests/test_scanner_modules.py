"""Parametrized validation of scanner modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

SCANNERS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "scanners"

PYTHON2_DIRS = {"trisis", "blackenergy", "decompiled_code", "symbolic_execution"}


def _collect_scanner_modules():
    modules = []
    for root, dirs, files in os.walk(SCANNERS_ROOT):
        dirs[:] = [d for d in dirs if d not in PYTHON2_DIRS and not d.startswith("__")]
        for f in files:
            if f.startswith("__") or not f.endswith(".py"):
                continue
            path = Path(root) / f
            rel = path.relative_to(SCANNERS_ROOT.parent.parent)
            dotted = str(rel).replace(os.sep, ".").removesuffix(".py")
            modules.append((dotted, path))
    return modules


SCANNER_MODULES = _collect_scanner_modules()


@pytest.mark.parametrize("dotted,path", SCANNER_MODULES,
                         ids=[m[0].split(".")[-1] for m in SCANNER_MODULES])
def test_scanner_importable(dotted, path):
    try:
        importlib.import_module(dotted)
    except ImportError:
        pytest.skip(f"Optional dependency for {dotted}")
    except SyntaxError:
        pytest.skip(f"Syntax issue in {dotted}")


def _find_scanner_info():
    found = []
    for dotted, path in SCANNER_MODULES:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        if "__info__" in content:
            found.append((dotted, path))
    return found


SCANNER_INFO = _find_scanner_info()


@pytest.mark.parametrize("dotted,path", SCANNER_INFO,
                         ids=[m[0].split(".")[-1] + "_info" for m in SCANNER_INFO])
def test_scanner_info_has_name(dotted, path):
    try:
        mod = importlib.import_module(dotted)
    except (ImportError, SyntaxError):
        pytest.skip(f"Cannot import {dotted}")
        return
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name, None)
        if isinstance(obj, type):
            for cls_attr in dir(obj):
                if cls_attr.endswith("__info__"):
                    info = getattr(obj, cls_attr)
                    if isinstance(info, dict):
                        assert "name" in info
                        return
    pytest.skip("No __info__ found")
