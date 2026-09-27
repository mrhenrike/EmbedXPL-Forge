"""WirelessXPL-Forge Bridge for EmbedXPL.

Subprocess bridge that invokes WirelessXPL-Forge CLI (`wlf`) or module runner
from the local submodule path, similar to the MikrotikAPI-BF bridge pattern.
Exposes discovery, run, and passive-capture sub-commands.

WirelessXPL-Forge: https://github.com/mrhenrike/WirelessXPL-Forge
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Original tool
-------------
Tool    : WirelessXPL-Forge
Source  : submodules/Uniao-Geek/WirelessXPL-Forge/
Version : 2.0.4+

EmbedXPL bridge
---------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, List, Optional

_WIRELESSXPL_PKG = "wirelessxpl"
_DEFAULT_SUBMODULE = Path(__file__).resolve().parents[6] / "submodules" / "Uniao-Geek" / "WirelessXPL-Forge"
_SUBMODULE_ENV_VAR = "WIRELESSXPL_PATH"


def _find_wirelessxpl() -> Optional[Path]:
    """Locate WirelessXPL-Forge installation or submodule."""
    # 1. Environment override
    env = os.environ.get(_SUBMODULE_ENV_VAR)
    if env:
        p = Path(env)
        if p.exists():
            return p

    # 2. Default submodule path
    if _DEFAULT_SUBMODULE.exists():
        return _DEFAULT_SUBMODULE

    # 3. pip-installed package
    if shutil.which("wlf"):
        return None  # Available as CLI

    return None


def _python_with_wirelessxpl() -> List[str]:
    """Return a Python command list with WirelessXPL-Forge on the path."""
    path = _find_wirelessxpl()
    if path:
        env = os.environ.copy()
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(path) + (":" + existing if existing else "")
        return [sys.executable]
    return [sys.executable]


def run_module(module_path: str, target: str = "", extra_args: Optional[List[str]] = None,
               timeout: int = 60) -> dict[str, Any]:
    """Run a WirelessXPL-Forge module by dotted path (e.g. 'drones.dji.dji_wifi_scan').

    Returns a dict with keys: 'returncode', 'stdout', 'stderr', 'error'.
    """
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}
    wpath = _find_wirelessxpl()

    if wpath is None and not shutil.which("python3"):
        result["error"] = "WirelessXPL-Forge not found"
        return result

    cmd = _python_with_wirelessxpl() + [
        "-m", f"wirelessxpl.modules.{module_path}",
    ]
    if target:
        cmd += ["--target", target]
    if extra_args:
        cmd += extra_args

    env = os.environ.copy()
    if wpath:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(wpath) + (":" + existing if existing else "")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def run_cli(args: List[str], timeout: int = 60) -> dict[str, Any]:
    """Run the WirelessXPL-Forge wlf CLI with the given arguments."""
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}
    wpath = _find_wirelessxpl()

    # Try direct wlf CLI
    wlf_cmd = shutil.which("wlf")
    if not wlf_cmd and wpath:
        wlf_script = wpath / "wlf.py"
        if wlf_script.exists():
            wlf_cmd = str(wlf_script)

    if not wlf_cmd:
        result["error"] = "wlf CLI not found. Install WirelessXPL-Forge or set WIRELESSXPL_PATH."
        return result

    cmd = ([sys.executable, wlf_cmd] if wlf_cmd.endswith(".py") else [wlf_cmd]) + args
    env = os.environ.copy()
    if wpath:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(wpath) + (":" + existing if existing else "")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def discover(scan_seconds: int = 30, mode: str = "wifi") -> dict[str, Any]:
    """Run WirelessXPL-Forge discovery/scan."""
    return run_cli(["discover", "--mode", mode, "--time", str(scan_seconds)])


def check_wirelessxpl() -> dict[str, Any]:
    """Check WirelessXPL-Forge availability and version."""
    path = _find_wirelessxpl()
    return {
        "available": path is not None or shutil.which("wlf") is not None,
        "submodule_path": str(path) if path else None,
        "cli_path": shutil.which("wlf"),
    }
