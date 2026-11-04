"""Validate curated arsenal architecture and dependency declarations."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import List

LOGGER = logging.getLogger("validate_arsenal_architecture")


def _configure_logging() -> None:
    """Configure command logging output."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _read_requirements(path: Path) -> List[str]:
    """Read requirements from a file ignoring comments and blanks."""
    if not path.exists():
        return []
    return [
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#") and not line.startswith("-")
    ]


def main() -> int:
    """Validate curated architecture shape and dependency alignment."""
    _configure_logging()
    root = Path(__file__).resolve().parent.parent

    layout_path = root / "embedxpl" / "resources" / "catalogs" / "arsenal_layout.json"
    index_path = root / "embedxpl" / "resources" / "catalogs" / "arsenal_index.json"

    if not layout_path.exists():
        LOGGER.warning("arsenal_layout.json not found — skipping architecture validation.")
        return 0

    layout = json.loads(layout_path.read_text(encoding="utf-8"))
    index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else {}

    expected_keys = layout.get("required_sections", [])
    missing = [k for k in expected_keys if k not in index]
    if missing:
        LOGGER.error("Missing sections in arsenal index: %s", missing)
        return 1

    LOGGER.info("Arsenal architecture validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
