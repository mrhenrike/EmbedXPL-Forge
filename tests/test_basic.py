"""Basic package import smoke tests for EmbedXPL-Forge."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match is not None, "version not found in pyproject.toml"
    return match.group(1)


def test_import_embedxpl() -> None:
    """Package must import cleanly for local installs and packaging checks."""
    module = importlib.import_module("embedxpl")
    assert module is not None


def test_pyproject_version_semver() -> None:
    """Declared package version must be semver X.Y.Z."""
    version = _pyproject_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version