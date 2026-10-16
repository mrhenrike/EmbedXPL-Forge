"""Structural integrity checks for EmbedXPL-Forge."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_required_files_present() -> None:
    for name in ("pyproject.toml", "third_party_manifest.json", "README.md", "LICENSE"):
        assert (ROOT / name).exists(), f"Missing: {name}"


def test_required_dirs_present() -> None:
    for name in ("embedxpl", "tests"):
        assert (ROOT / name).is_dir(), f"Missing dir: {name}"


def test_main_module_parseable() -> None:
    main = ROOT / "embedxpl" / "__main__.py"
    assert main.exists()
    ast.parse(main.read_text(encoding="utf-8"))


def test_entrypoint_function_exists() -> None:
    main = ROOT / "embedxpl" / "__main__.py"
    tree = ast.parse(main.read_text(encoding="utf-8"))
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "main" in funcs, "main() not found in embedxpl/__main__.py"
