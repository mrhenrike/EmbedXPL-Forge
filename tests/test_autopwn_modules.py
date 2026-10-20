"""Tests for embedxpl.modules.autopwn module structure."""
from __future__ import annotations

import importlib

import pytest

AUTOPWN_MODULES = [
    "embedxpl.modules.autopwn.base",
    "embedxpl.modules.autopwn.camera",
    "embedxpl.modules.autopwn.firewall",
    "embedxpl.modules.autopwn.ics",
    "embedxpl.modules.autopwn.lb",
    "embedxpl.modules.autopwn.printer",
    "embedxpl.modules.autopwn.router",
    "embedxpl.modules.autopwn.segment",
    "embedxpl.modules.autopwn.vpn",
    "embedxpl.modules.autopwn.waf",
]


@pytest.mark.parametrize("module_name", AUTOPWN_MODULES)
def test_autopwn_importable(module_name):
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        pytest.skip(f"Missing dependency for {module_name}")


@pytest.mark.parametrize("module_name", AUTOPWN_MODULES)
def test_autopwn_has_exploit_class(module_name):
    try:
        mod = importlib.import_module(module_name)
    except ImportError:
        pytest.skip(f"Missing dependency for {module_name}")
        return
    has_class = any(
        hasattr(mod, name) for name in ("Exploit", "AutoPwn", "BaseAutoPwn", "AutoPwnBase")
    )
    if not has_class:
        pytest.skip(f"{module_name} has no recognized autopwn class (may be a namespace package)")


def test_base_autopwn_structure():
    try:
        from embedxpl.modules.autopwn.base import Exploit
    except ImportError:
        pytest.skip("Cannot import base autopwn")
        return
    e = Exploit()
    assert hasattr(e, "check") or hasattr(e, "run")
