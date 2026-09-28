#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Build a curated arsenal index for EmbedXPL-Forge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def _list_files(base: Path, pattern: str) -> List[str]:
    if not base.exists():
        return []
    return sorted([item.relative_to(base).as_posix() for item in base.rglob(pattern) if item.is_file()])


def _read_requirements(path: Path) -> List[str]:
    """Read requirement lines excluding comments and includes."""
    if not path.exists():
        return []
    items: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-r "):
            continue
        items.append(line)
    return items


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    resources_root = repo_root / "embedxpl" / "resources"
    modules_root = repo_root / "embedxpl" / "modules"
    arsenal_root = resources_root / "arsenal"
    catalogs_root = resources_root / "catalogs"
    output_path = resources_root / "catalogs" / "arsenal_index.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    runtime_deps = _read_requirements(repo_root / "requirements.txt")
    dev_deps = _read_requirements(repo_root / "requirements-dev.txt")
    curated_domains = [
        "credentials",
        "wordlists",
        "mibs",
        "firmware",
        "binaries",
        "pocs",
        "intel",
    ]

    index: Dict[str, object] = {
        "metadata": {
            "name": "EmbedXPL-Forge Arsenal Index",
            "scope": ["routers", "switches", "taps", "fw", "ngfw"],
            "out_of_scope": ["cameras", "printers", "dvr", "dvrs"],
            "generated_by": "tools/build_arsenal_index.py",
            "curated_layout_catalog": "embedxpl/resources/catalogs/arsenal_layout.json",
        },
        "catalogs": _list_files(catalogs_root, "*.json"),
        "wordlists": _list_files(resources_root / "wordlists", "*.txt"),
        "ssh_keys": _list_files(resources_root / "ssh_keys", "*.json"),
        "vendors": _list_files(resources_root / "vendors", "*.dat") + _list_files(resources_root / "vendors", "*.csv"),
        "mibs": _list_files(resources_root / "mibs", "*"),
        "dependencies": {
            "runtime": runtime_deps,
            "development": dev_deps,
        },
        "curated_arsenal": {
            "root": "embedxpl/resources/arsenal",
            "domains": {name: _list_files(arsenal_root / name, "*") for name in curated_domains},
        },
        "modules": {
            "exploits": _list_files(modules_root / "exploits", "*.py"),
            "creds": _list_files(modules_root / "creds", "*.py"),
            "scanners": _list_files(modules_root / "scanners", "*.py"),
            "generic": _list_files(modules_root / "generic", "*.py"),
            "encoders": _list_files(modules_root / "encoders", "*.py"),
            "payloads": _list_files(modules_root / "payloads", "*.py"),
        },
    }

    # Remove obvious __init__ entries from module lists
    for key in ("exploits", "creds", "scanners", "generic", "encoders", "payloads"):
        values = index["modules"][key]
        index["modules"][key] = [item for item in values if not item.endswith("__init__.py")]

    output_path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    counts = {
        "catalogs": len(index["catalogs"]),
        "wordlists": len(index["wordlists"]),
        "ssh_keys": len(index["ssh_keys"]),
        "vendors": len(index["vendors"]),
        "mibs": len(index["mibs"]),
        "deps_runtime": len(index["dependencies"]["runtime"]),
        "deps_development": len(index["dependencies"]["development"]),
        "curated_domains": len(index["curated_arsenal"]["domains"]),
        "exploits": len(index["modules"]["exploits"]),
        "creds": len(index["modules"]["creds"]),
        "scanners": len(index["modules"]["scanners"]),
        "generic": len(index["modules"]["generic"]),
        "encoders": len(index["modules"]["encoders"]),
        "payloads": len(index["modules"]["payloads"]),
    }
    print("arsenal_index={} counts={}".format(output_path.name, counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
