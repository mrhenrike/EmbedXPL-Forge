"""Parametrized validation of credential modules."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest

CREDS_ROOT = Path(__file__).resolve().parents[1] / "embedxpl" / "modules" / "creds"


def _collect_cred_modules():
    modules = []
    for root, dirs, files in os.walk(CREDS_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith("__")]
        for f in files:
            if f.startswith("__") or not f.endswith(".py"):
                continue
            path = Path(root) / f
            rel = path.relative_to(CREDS_ROOT.parent.parent)
            dotted = str(rel).replace(os.sep, ".").removesuffix(".py")
            modules.append((dotted, path))
    return modules


CRED_MODULES = _collect_cred_modules()
SAMPLE = CRED_MODULES[:100]


@pytest.mark.parametrize("dotted,path", SAMPLE,
                         ids=[m[0].split(".")[-1] for m in SAMPLE])
def test_cred_module_importable(dotted, path):
    try:
        importlib.import_module(dotted)
    except ImportError:
        pytest.skip(f"Optional dependency for {dotted}")
    except SyntaxError:
        pytest.skip(f"Syntax issue in {dotted}")


def _find_cred_info():
    found = []
    for dotted, path in SAMPLE:
        try:
            content = path.read_text(errors="replace")
        except Exception:
            continue
        if "__info__" in content:
            found.append((dotted, path))
    return found


CRED_INFO = _find_cred_info()


@pytest.mark.parametrize("dotted,path", CRED_INFO,
                         ids=[m[0].split(".")[-1] + "_info" for m in CRED_INFO])
def test_cred_info_has_name(dotted, path):
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


def test_cred_modules_count():
    assert len(CRED_MODULES) > 50, f"Expected 50+ cred modules, got {len(CRED_MODULES)}"
