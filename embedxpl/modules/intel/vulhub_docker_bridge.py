"""Vulhub Docker Lab Bridge for EmbedXPL.

Provides a subprocess bridge to spin up, interact with, and tear down
Vulhub-based vulnerable Docker environments for exploit testing.
Uses the vulhub directory structure (github.com/vulhub/vulhub).

Original tool references
------------------------
vulhub : https://github.com/vulhub/vulhub
         CC BY-NC 4.0 — educational/research use only

EmbedXPL port
-------------
Maintainer : Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only — educational/lab use only
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from embedxpl.core.exploit import *


_VULHUB_ENV_VAR = "VULHUB_PATH"
_DEFAULT_VULHUB_PATHS = (
    Path("d:/Projetos-SafeLabs/submodules/labs/vulhub"),
    Path("d:/Projetos-SafeLabs/submodules/vulhub"),
    Path.home() / "vulhub",
    Path("/opt/vulhub"),
)


def _find_vulhub() -> Optional[Path]:
    env = os.environ.get(_VULHUB_ENV_VAR)
    if env:
        p = Path(env)
        if p.exists():
            return p
    for p in _DEFAULT_VULHUB_PATHS:
        if p.exists():
            return p
    return None


def _docker_available() -> bool:
    return shutil.which("docker") is not None and shutil.which("docker-compose") is not None


def list_available_labs(vulhub_path: Optional[Path] = None) -> list[str]:
    """Return list of available Vulhub lab paths (relative to vulhub root)."""
    root = vulhub_path or _find_vulhub()
    if not root:
        return []
    labs = []
    for composer in root.rglob("docker-compose.yml"):
        rel = str(composer.parent.relative_to(root))
        labs.append(rel)
    return sorted(labs)


def spin_up_lab(lab: str, vulhub_path: Optional[Path] = None, timeout: int = 120) -> dict[str, Any]:
    """docker-compose up -d a specific Vulhub lab."""
    root = vulhub_path or _find_vulhub()
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}

    if not root:
        result["error"] = "Vulhub not found. Set VULHUB_PATH or clone vulhub into submodules/labs/"
        return result
    if not _docker_available():
        result["error"] = "docker + docker-compose not available"
        return result

    lab_dir = root / lab
    if not (lab_dir / "docker-compose.yml").exists():
        result["error"] = f"Lab not found: {lab_dir}"
        return result

    try:
        proc = subprocess.run(
            ["docker-compose", "up", "-d"],
            cwd=str(lab_dir),
            capture_output=True, text=True, timeout=timeout,
        )
        result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired:
        result["error"] = f"Timeout after {timeout}s"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def tear_down_lab(lab: str, vulhub_path: Optional[Path] = None) -> dict[str, Any]:
    """docker-compose down a Vulhub lab."""
    root = vulhub_path or _find_vulhub()
    result: dict[str, Any] = {"returncode": -1, "stdout": "", "stderr": "", "error": ""}

    if not root:
        result["error"] = "Vulhub not found"
        return result

    lab_dir = root / lab
    if not lab_dir.exists():
        result["error"] = f"Lab dir not found: {lab_dir}"
        return result

    try:
        proc = subprocess.run(
            ["docker-compose", "down", "-v"],
            cwd=str(lab_dir),
            capture_output=True, text=True, timeout=60,
        )
        result.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except Exception as exc:
        result["error"] = str(exc)
    return result


class Exploit(Exploit):
    """Vulhub Docker Bridge — spin up/down vulnerable lab environments."""

    __info__ = {
        "name": "Vulhub Docker Lab Bridge",
        "description": (
            "Spins up Vulhub Docker Compose labs for exploit testing. "
            "Supports: list labs, up, down. Requires docker + docker-compose. "
            "Vulhub: github.com/vulhub/vulhub (CC BY-NC 4.0 — educational use only)."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": ("https://github.com/vulhub/vulhub",),
        "devices": ("Docker-capable Linux/Windows host",),
    }

    action = OptString("list", "Action: list | up | down")
    lab = OptString("", "Lab path (e.g. cve-2019-0708/CVE-2019-0708)")
    timeout = OptInteger(120, "docker-compose up timeout in seconds")

    @mute
    def check(self) -> bool:
        return _docker_available() and (_find_vulhub() is not None)

    def run(self) -> None:
        action = str(self.action).lower()
        lab = str(self.lab)
        timeout = int(self.timeout)

        vulhub = _find_vulhub()
        if not vulhub:
            print_error("Vulhub not found. Clone vulhub into submodules/labs/vulhub or set VULHUB_PATH.")
            print_info("git clone https://github.com/vulhub/vulhub submodules/labs/vulhub")
            return

        print_info(f"Vulhub path: {vulhub}")

        if action == "list":
            labs = list_available_labs(vulhub)
            if labs:
                print_success(f"{len(labs)} available labs:")
                for l in labs[:50]:
                    print_info(f"  {l}")
                if len(labs) > 50:
                    print_info(f"  … and {len(labs)-50} more")
            else:
                print_info("No labs found — ensure vulhub is properly cloned")

        elif action == "up":
            if not lab:
                print_error("Specify lab= (e.g. lab=apache/CVE-2021-41773)")
                return
            print_status(f"Spinning up: {lab}")
            result = spin_up_lab(lab, vulhub, timeout)
            if result["returncode"] == 0:
                print_success(f"Lab '{lab}' is up!")
            else:
                print_error(f"Failed: {result.get('error') or result.get('stderr','')[:100]}")

        elif action == "down":
            if not lab:
                print_error("Specify lab=")
                return
            result = tear_down_lab(lab, vulhub)
            if result["returncode"] == 0:
                print_success(f"Lab '{lab}' torn down")
            else:
                print_error(f"Failed: {result.get('error','')[:100]}")
        else:
            print_error(f"Unknown action: {action}. Use list | up | down")
