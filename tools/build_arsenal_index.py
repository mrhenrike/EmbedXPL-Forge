"""Build a curated arsenal index for EmbedXPL-Forge."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def _list_files(directory: Path, pattern: str) -> List[str]:
    if not directory.exists():
        return []
    return sorted(str(f.relative_to(directory.parent.parent)) for f in directory.rglob(pattern))


def _read_requirements(path: Path) -> List[str]:
    """Read requirement lines excluding comments and includes."""
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            lines.append(line)
    return lines


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    modules_dir = root / "embedxpl" / "modules"
    arsenal_dir = root / "embedxpl" / "resources" / "arsenal"
    out_path = root / "embedxpl" / "resources" / "catalogs" / "arsenal_index.json"

    index: Dict = {
        "modules": _list_files(modules_dir, "*.py"),
        "arsenal": _list_files(arsenal_dir, "*") if arsenal_dir.exists() else [],
        "requirements": _read_requirements(root / "requirements.txt"),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(f"[OK] Arsenal index written: {out_path} ({len(index['modules'])} modules)")


if __name__ == "__main__":
    main()
