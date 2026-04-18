#!/usr/bin/env python3
"""Cross-platform compatibility smoke check for EmbedXPL-Forge."""

from __future__ import annotations

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

import json
import logging
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List


LOGGER = logging.getLogger("compat_smoke")


@dataclass
class CheckResult:
    """Stores the compatibility check output."""

    python_version: str
    python_ok: bool
    platform: str
    distribution: str
    is_termux: bool
    imports: Dict[str, bool] = field(default_factory=dict)
    cli_ok: bool = False
    cli_output: str = ""
    notes: List[str] = field(default_factory=list)


def _configure_logging() -> None:
    """Configure logger output."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _detect_termux() -> bool:
    """Detect whether execution is inside Termux."""
    prefix: str = os.environ.get("PREFIX", "")
    return "com.termux" in prefix or "TERMUX_VERSION" in os.environ


def _linux_distribution() -> str:
    """Return Linux distribution name when available."""
    os_release: Path = Path("/etc/os-release")
    if not os_release.exists():
        return ""

    try:
        data: str = os_release.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

    name: str = ""
    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
            break
    return name


def _check_python_version() -> tuple[bool, str]:
    """Validate Python version constraints."""
    major: int = sys.version_info.major
    minor: int = sys.version_info.minor
    if major != 3:
        return False, "Python major version must be 3."
    if minor < 8:
        return False, "Python must be >= 3.8."
    if minor > 13:
        return True, "Python > 3.13 detected; treated as best-effort."
    return True, ""


def _import_check(module_name: str) -> bool:
    """Test whether a module can be imported."""
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def _telnet_backend_check() -> bool:
    """Validate telnet backend availability for current Python runtime."""
    if sys.version_info >= (3, 13):
        return _import_check("telnetlib3")

    # Python <= 3.12 should still have stdlib telnetlib.
    return _import_check("telnetlib")


def _run_cli_help(repo_root: Path) -> tuple[bool, str]:
    """Execute `exf.py -h` and return status + first output lines."""
    cmd: List[str] = [sys.executable, str(repo_root / "exf.py"), "-h"]
    try:
        completed: subprocess.CompletedProcess[str] = subprocess.run(
            cmd,
            cwd=str(repo_root),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        return False, f"Failed to execute CLI: {exc!r}"

    output: str = (completed.stdout or "") + (completed.stderr or "")
    clipped: str = "\n".join(output.splitlines()[:20])
    return completed.returncode == 0, clipped


def main() -> int:
    """Run compatibility smoke checks."""
    _configure_logging()

    repo_root: Path = Path(__file__).resolve().parent.parent
    python_ok, python_note = _check_python_version()
    system: str = platform.system().lower()
    distribution: str = _linux_distribution() if system == "linux" else ""
    is_termux: bool = _detect_termux()

    result = CheckResult(
        python_version=platform.python_version(),
        python_ok=python_ok,
        platform=system,
        distribution=distribution,
        is_termux=is_termux,
    )

    if python_note:
        result.notes.append(python_note)

    # All declared required dependencies.
    for import_name in (
        "requests", "paramiko", "pysnmp", "Crypto",
        "rich", "aiohttp", "psutil", "colorama", "scapy",
    ):
        result.imports[import_name] = _import_check(import_name)

    # Optional deps — failure is non-fatal.
    for import_name in ("nmap", "numpy", "sklearn", "yaml"):
        result.imports["opt_" + import_name] = _import_check(import_name)

    result.imports["telnet_backend"] = _telnet_backend_check()

    cli_ok, cli_output = _run_cli_help(repo_root)
    result.cli_ok = cli_ok
    result.cli_output = cli_output

    hard_fail: bool = (not result.python_ok) or (not result.cli_ok)
    for module_name, is_ok in result.imports.items():
        if not is_ok and not module_name.startswith("opt_"):
            result.notes.append("Missing required import: {}".format(module_name))
            hard_fail = True
        elif not is_ok and module_name.startswith("opt_"):
            result.notes.append("Optional import missing (degraded): {}".format(module_name))

    # Classify Linux flavor when available.
    if result.platform == "linux" and result.distribution:
        distro_l = result.distribution.lower()
        if any(key in distro_l for key in ("ubuntu", "debian", "mint", "kali", "parrot")):
            result.notes.append("Detected Debian-based Linux.")
        if any(key in distro_l for key in ("rhel", "red hat", "rocky", "alma", "centos", "fedora")):
            result.notes.append("Detected RHEL-based Linux.")

    LOGGER.info("Compatibility result: %s", json.dumps(asdict(result), ensure_ascii=True))
    print(json.dumps(asdict(result), ensure_ascii=True, indent=2))
    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
