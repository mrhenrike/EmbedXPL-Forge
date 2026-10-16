"""Validate pyproject.toml entrypoints for EmbedXPL-Forge."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _scripts() -> dict[str, str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    in_scripts = False
    scripts: dict[str, str] = {}
    for line in text.splitlines():
        if re.match(r'\[project\.scripts\]', line):
            in_scripts = True
            continue
        if in_scripts and re.match(r'\[', line):
            break
        if in_scripts:
            m = re.match(r'\s*(\S+)\s*=\s*"([^"]+)"', line)
            if m:
                scripts[m.group(1)] = m.group(2)
    return scripts


def test_exf_entrypoint_declared() -> None:
    assert "exf" in _scripts()


def test_exf_points_to_main() -> None:
    scripts = _scripts()
    assert scripts["exf"] == "embedxpl.__main__:main", scripts.get("exf")


def test_embedxpl_alias_declared() -> None:
    scripts = _scripts()
    assert "embedxpl" in scripts
