"""Detect installed network scanning tools (Nmap, Masscan).

Author: André Henrique (@mrhenrike) | União Geek
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("firewallxpl.discovery.tool_detector")


@dataclass
class ToolInfo:
    """Information about a detected tool."""
    name: str
    path: Optional[str] = None
    version: Optional[str] = None
    available: bool = False
    root_capable: bool = False


def detect_nmap() -> ToolInfo:
    """Detect Nmap installation and capabilities."""
    path = shutil.which("nmap")
    if not path:
        return ToolInfo(name="nmap")
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
        version = out.stdout.split("\n")[0] if out.stdout else "unknown"
        return ToolInfo(name="nmap", path=path, version=version, available=True)
    except Exception:
        return ToolInfo(name="nmap", path=path, available=True)


def detect_masscan() -> ToolInfo:
    """Detect Masscan installation."""
    path = shutil.which("masscan")
    if not path:
        return ToolInfo(name="masscan")
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
        version = out.stdout.split("\n")[0] if out.stdout else "unknown"
        return ToolInfo(name="masscan", path=path, version=version, available=True)
    except Exception:
        return ToolInfo(name="masscan", path=path, available=True)


def detect_all() -> dict:
    """Detect all supported tools."""
    return {"nmap": detect_nmap(), "masscan": detect_masscan()}
