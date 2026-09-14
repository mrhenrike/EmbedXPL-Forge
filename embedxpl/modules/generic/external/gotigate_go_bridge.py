"""GoTigate — Go-based FortiGate/FortiOS Scanner Bridge.

Subprocess bridge to gotigate (https://github.com/gustavorobertux/gotigate)
and related Go-based FortiGate scanners/exploit tools.  Primarily targets:
  - CVE-2018-13379 (SSL-VPN path traversal credentials)
  - CVE-2022-40684 (authentication bypass)
  - CVE-2024-47575 (FortiJump)

Original tool references
------------------------
gotigate : https://github.com/gustavorobertux/gotigate (MIT)
fortiscan : https://github.com/anasbousselham/fortiscan (MIT)
            Fortinet CVE-2018-13379 mass scanner in Go

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from embedxpl.core.exploit import *


_GOTIGATE_ENV = "GOTIGATE_BIN"
_FORTISCAN_ENV = "FORTISCAN_BIN"

_DEFAULT_PATHS = (
    Path("d:/Projetos-SafeLabs/submodules/labs/gotigate/gotigate"),
    Path("d:/Projetos-SafeLabs/submodules/labs/fortiscan/fortiscan"),
    Path.home() / "go" / "bin" / "gotigate",
    Path.home() / "go" / "bin" / "fortiscan",
)


def _find_tool(env_var: str, extra_paths: tuple = ()) -> Optional[Path]:
    env = os.environ.get(env_var)
    if env:
        p = Path(env)
        if p.exists():
            return p
    for p in _DEFAULT_PATHS + extra_paths:
        if p.exists():
            return p
    # Check PATH
    for name in ("gotigate", "fortiscan"):
        which = shutil.which(name)
        if which:
            return Path(which)
    return None


def run_gotigate(target: str, args: list[str] | None = None, timeout: int = 60) -> dict[str, Any]:
    tool = _find_tool(_GOTIGATE_ENV)
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}

    if not tool:
        result["error"] = (
            "gotigate/fortiscan not found. Build from source: "
            "git clone https://github.com/gustavorobertux/gotigate && cd gotigate && go build"
        )
        return result

    cmd = [str(tool), "-t", target] + (args or [])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
    return result


class Exploit(Exploit):
    """GoTigate / Fortiscan Go Bridge (FortiOS CVE-2018-13379, 2022-40684, 2024-47575)."""

    __info__ = {
        "name": "GoTigate / Fortiscan Go Bridge",
        "description": (
            "Subprocess bridge to gotigate (gustavorobertux) and fortiscan (anasbousselham) "
            "Go-based FortiGate vulnerability scanners. Targets CVE-2018-13379 path traversal "
            "credential dump, CVE-2022-40684 auth bypass, CVE-2024-47575 FortiJump."
        ),
        "authors": (
            "Andre Henrique (@mrhenrike) | Uniao Geek",
            # gotigate: gustavorobertux (MIT)
            # fortiscan: anasbousselham (MIT)
        ),
        "references": (
            "https://github.com/gustavorobertux/gotigate",
            "https://github.com/anasbousselham/fortiscan",
        ),
        "devices": ("FortiGate / FortiOS SSL-VPN",),
    }

    target = OptIP("", "Target FortiGate IP or hostname")
    args = OptString("", "Extra args for gotigate (space-separated)")
    timeout = OptInteger(60, "Timeout in seconds")

    @mute
    def check(self) -> bool:
        return _find_tool(_GOTIGATE_ENV) is not None

    def run(self) -> None:
        target = str(self.target)
        extra = str(self.args).split() if str(self.args) else []
        timeout = int(self.timeout)

        print_status(f"GoTigate/Fortiscan bridge → {target}")

        tool = _find_tool(_GOTIGATE_ENV)
        if not tool:
            print_error("gotigate/fortiscan binary not found")
            print_info("Build: git clone https://github.com/gustavorobertux/gotigate && cd gotigate && go build")
            return

        print_info(f"Using tool: {tool}")
        result = run_gotigate(target, extra, timeout)
        if result["stdout"]:
            print_success(f"Output:\n{result['stdout'][:2000]}")
        if result["stderr"]:
            print_info(f"Stderr: {result['stderr'][:500]}")
        if result["error"]:
            print_error(result["error"])
