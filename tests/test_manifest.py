"""Validate third_party_manifest.json for EmbedXPL-Forge."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_present() -> None:
    assert (ROOT / "third_party_manifest.json").exists()


def test_manifest_valid_json() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    assert isinstance(data, dict)


def test_manifest_has_components() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    assert len(data.get("components", [])) >= 10


def test_manifest_forge_name() -> None:
    data = json.loads((ROOT / "third_party_manifest.json").read_text())
    name = data.get("forge", "")
    assert "EmbedXPL" in name or "embedxpl" in name.lower()
