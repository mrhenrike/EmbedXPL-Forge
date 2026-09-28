#!/usr/bin/env python3
"""Validate curated arsenal architecture and dependency declarations."""

from __future__ import annotations

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

import json
import logging
from pathlib import Path
from typing import Dict, List


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
    rows: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
            continue
        rows.append(line)
    return rows


def main() -> int:
    """Validate curated architecture shape and dependency alignment."""
    _configure_logging()
    repo_root = Path(__file__).resolve().parents[1]
    resources_root = repo_root / "embedxpl" / "resources"
    catalogs_root = resources_root / "catalogs"
    arsenal_root = resources_root / "arsenal"

    layout_path = catalogs_root / "arsenal_layout.json"
    index_path = catalogs_root / "arsenal_index.json"
    errors: List[str] = []

    if not layout_path.exists():
        errors.append("missing catalog: {}".format(layout_path.as_posix()))
    if not index_path.exists():
        errors.append("missing catalog: {}".format(index_path.as_posix()))

    if not errors:
        layout: Dict[str, object] = json.loads(layout_path.read_text(encoding="utf-8"))
        index: Dict[str, object] = json.loads(index_path.read_text(encoding="utf-8"))

        # Validate curated subfolder paths.
        for folder in layout.get("curated_subfolders", []):
            folder_path = repo_root / str(folder.get("path", ""))
            if not folder_path.exists():
                errors.append("missing curated subfolder: {}".format(folder_path.as_posix()))

        # Validate index dependency snapshot against requirements files.
        runtime = _read_requirements(repo_root / "requirements.txt")
        development = _read_requirements(repo_root / "requirements-dev.txt")
        deps = index.get("dependencies", {})

        if deps.get("runtime", []) != runtime:
            errors.append("arsenal_index runtime dependencies out of sync")
        if deps.get("development", []) != development:
            errors.append("arsenal_index development dependencies out of sync")

        # Validate index curated root.
        curated = index.get("curated_arsenal", {})
        expected_root = "embedxpl/resources/arsenal"
        if curated.get("root") != expected_root:
            errors.append("arsenal_index curated root mismatch: expected {}".format(expected_root))

        # Validate at least one domain exists in the curated map.
        domains = curated.get("domains", {})
        if not isinstance(domains, dict) or not domains:
            errors.append("arsenal_index curated domains map is empty")

        # Validate materialized root path.
        if not arsenal_root.exists():
            errors.append("missing arsenal root folder: {}".format(arsenal_root.as_posix()))

    if errors:
        for error in errors:
            LOGGER.error(error)
        return 1

    LOGGER.info("Arsenal architecture validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
