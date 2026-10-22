"""Version consistency checks for EmbedXPL-Forge."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert m is not None
    return m.group(1)


def test_pyproject_version_semver() -> None:
    v = _pyproject_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+(-[a-z0-9.]+)?", v), v


def test_module_version_matches_pyproject() -> None:
    import embedxpl
    assert embedxpl.__version__ == _pyproject_version()
