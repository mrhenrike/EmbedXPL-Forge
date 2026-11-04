"""Detect, create and sync EmbedXPL-Forge local .venv (PEP 668 safe).

Used by exf.py / embedxpl.__main__ so `python exf.py` works on Debian/Ubuntu
without touching system pip.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

VENV_DIR_NAME = ".venv"
REQUIREMENTS = "requirements.txt"
MARKER = ".embedxpl-venv-ready"


def repo_root(entry: Path | None = None) -> Path:
    """Find the repo root: walk up from entry until pyproject.toml is found."""
    if entry is None:
        entry = Path(sys.argv[0]).resolve()
    start = Path(entry).resolve()
    for candidate in [start, *start.parents]:
        if (candidate / "pyproject.toml").exists():
            return candidate
        if (candidate / REQUIREMENTS).exists():
            return candidate
    return start.parent if start.is_file() else start


def venv_dir(root: Path) -> Path:
    return root / VENV_DIR_NAME


def venv_python(root: Path) -> Path:
    d = venv_dir(root)
    if sys.platform == "win32":
        return d / "Scripts" / "python.exe"
    return d / "bin" / "python"


def venv_pip(root: Path) -> Path:
    d = venv_dir(root)
    if sys.platform == "win32":
        return d / "Scripts" / "pip.exe"
    return d / "bin" / "pip"


def in_virtualenv() -> bool:
    return (
        sys.prefix != sys.base_prefix
        or os.environ.get("VIRTUAL_ENV") is not None
        or os.environ.get("CONDA_PREFIX") is not None
    )


def _venv_usable(root: Path) -> bool:
    python = venv_python(root)
    marker = venv_dir(root) / MARKER
    return python.exists() and marker.exists()


def _probe_imports(python: Path) -> bool:
    probe = ["requests", "paramiko", "rich", "colorama", "scapy"]
    cmd = [str(python), "-c", "; ".join(f"import {m}" for m in probe)]
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0


def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(cmd, check=check)


def _create_venv(root: Path) -> None:
    print(f"[exf] Creating virtual environment at {venv_dir(root)} …")
    _run([sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir(root))], check=True)


def _install_deps(root: Path) -> None:
    pip = venv_pip(root)
    req = root / REQUIREMENTS
    print("[exf] Installing dependencies …")
    if req.exists():
        _run([str(pip), "install", "-q", "-r", str(req)], check=True)
    _run([str(pip), "install", "-q", "-e", str(root)], check=True)
    (venv_dir(root) / MARKER).touch()


def _sync_if_needed(root: Path) -> None:
    python = venv_python(root)
    if not _probe_imports(python):
        _install_deps(root)


def ensure_runtime(entry: Path | None = None) -> None:
    """Ensure the runtime is properly set up. No-op when already in a venv."""
    if in_virtualenv():
        return
    root = repo_root(entry)
    if not _venv_usable(root):
        _create_venv(root)
        _install_deps(root)
    else:
        _sync_if_needed(root)
    python = venv_python(root)
    script = Path(entry).resolve() if entry else Path(sys.argv[0]).resolve()
    print(f"[exf] Re-launching inside {venv_dir(root)} …")
    args = [str(python), str(script)] + sys.argv[1:]
    if sys.platform == "win32":
        import subprocess as _sp
        result = _sp.run(args)
        sys.exit(result.returncode)
    else:
        os.execv(str(python), args)
