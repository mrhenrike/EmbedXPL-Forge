"""
embedxpl/modules/generic/external/mikrotikapi_bf_adapter.py

Adapter that wraps MikrotikAPI-BF Exploit_CVE_* classes as EmbedXPL Exploit modules.

This adapter bridges the MikrotikAPI-BF BaseExploit contract (check()->dict)
to the EmbedXPL Exploit contract (check()->bool, run()->None).

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from embedxpl.core.exploit import *

__version__ = "1.0.0"


def _find_mikrotik_bf_root() -> Optional[Path]:
    """Locate MikrotikAPI-BF installation relative to EmbedXPL."""
    # Look in superproject submodules
    candidates = [
        Path(__file__).parents[6] / "MikrotikAPI-BF",
        Path(__file__).parents[5] / "Uniao-Geek" / "MikrotikAPI-BF",
    ]
    for c in candidates:
        if (c / "xpl" / "exploits.py").exists():
            return c
    return None


def _load_mikrotik_exploits() -> Optional[Any]:
    """Dynamically load MikrotikAPI-BF exploits module."""
    root = _find_mikrotik_bf_root()
    if root is None:
        return None
    spec = importlib.util.spec_from_file_location(
        "mikrotikapi_bf_exploits",
        str(root / "xpl" / "exploits.py"),
    )
    if spec is None:
        return None
    # Add parent to sys.path for imports
    parent = str(root)
    if parent not in sys.path:
        sys.path.insert(0, parent)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


class MikrotikCVEAdapter(Exploit):
    """Adapter: wraps any MikrotikAPI-BF Exploit_CVE_* as an EmbedXPL module.

    Usage:
        adapter = MikrotikCVEAdapter.for_cve("CVE_2018_14847")
        if adapter:
            adapter.target = "192.168.88.1"
            if adapter.check():
                adapter.run()
    """

    __info__ = {
        "name": "MikrotikAPI-BF CVE Adapter",
        "description": "Bridges MikrotikAPI-BF CVE exploit classes into EmbedXPL shell.",
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "devices": ("MikroTik RouterOS",),
        "references": ("submodules/Uniao-Geek/MikrotikAPI-BF/",),
    }

    target = OptIP("", "Target RouterOS IP")
    port = OptPort(8291, "Winbox/API port")
    cve_class_name = OptString("", "CVE class name (e.g. Exploit_CVE_2018_14847)")
    timeout = OptFloat(10.0, "Connection timeout")

    def check(self) -> bool:
        """Run the underlying MikrotikAPI-BF check() and return bool."""
        cls = self._get_cve_class()
        if cls is None:
            print(f"[-] CVE class not found: {self.cve_class_name}")
            return False
        try:
            result = cls(str(self.target), timeout=float(self.timeout)).check()
            if isinstance(result, dict):
                return result.get("vulnerable", False)
            return bool(result)
        except Exception as exc:
            print(f"[-] Adapter check error: {exc}")
            return False

    def run(self) -> None:
        """Run the underlying MikrotikAPI-BF check() and display results."""
        cls = self._get_cve_class()
        if cls is None:
            print(f"[-] CVE class not found: {self.cve_class_name}")
            return
        try:
            result = cls(str(self.target), timeout=float(self.timeout)).check()
            if isinstance(result, dict):
                for k, v in result.items():
                    print(f"  {k}: {v}")
            else:
                print(f"  Result: {result}")
        except Exception as exc:
            print(f"[-] Adapter run error: {exc}")

    def _get_cve_class(self) -> Optional[Type]:
        """Load and return the CVE class from MikrotikAPI-BF."""
        module = _load_mikrotik_exploits()
        if module is None:
            return None
        class_name = str(self.cve_class_name).strip()
        return getattr(module, class_name, None)

    @classmethod
    def for_cve(cls, cve_class_name: str) -> "MikrotikCVEAdapter":
        """Create an adapter instance for a specific CVE class name."""
        inst = cls()
        inst.cve_class_name = cve_class_name
        return inst

    @classmethod
    def list_available_cves(cls) -> List[str]:
        """List all CVE classes available in MikrotikAPI-BF."""
        module = _load_mikrotik_exploits()
        if module is None:
            return []
        return [
            name for name in dir(module)
            if name.startswith("Exploit_CVE_")
        ]
