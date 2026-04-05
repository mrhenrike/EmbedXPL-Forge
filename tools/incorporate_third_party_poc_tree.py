#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mirror every checkout under ``third-party-router-poc`` into the Forge arsenal tree.

Copies each top-level directory to::

    routerxpl/resources/arsenal/pocs/incorporated_third_party/<same_folder_name>/

Skips ``.git`` (and a few cache dirs) so the bundle is a plain tree suitable for packaging.

Expected layout: RouterXPL-Forge and ``third-party-router-poc`` are siblings under ``IoT/``.

Use ``--index-only`` to refresh ``incorporated_third_party_index.json`` from the existing
destination tree (no file copy), e.g. after manual cleanup or gitdir removal.

Author: André Henrique (@mrhenrique) | União Geek

"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set

LOGGER = logging.getLogger(__name__)

_RXFORGE = Path(__file__).resolve().parents[1]
_DEFAULT_SRC = _RXFORGE.parents[0] / "third-party-router-poc"
_DST_ROOT = _RXFORGE / "routerxpl" / "resources" / "arsenal" / "pocs" / "incorporated_third_party"
_INDEX_OUT = _RXFORGE / "routerxpl" / "resources" / "catalogs" / "incorporated_third_party_index.json"

_SKIP_DIR_NAMES: Set[str] = frozenset({".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox"})


def _iter_top_level_dirs(src: Path) -> Iterable[Path]:
    if not src.is_dir():
        return
    for p in sorted(src.iterdir()):
        if p.is_dir() and not p.name.startswith("."):
            yield p


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        for name in files:
            fp = Path(root) / name
            try:
                total += fp.stat().st_size
            except OSError:
                continue
    return total


def _count_files(path: Path) -> int:
    n = 0
    for root, dirs, files in os.walk(path, topdown=True):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIR_NAMES and not d.startswith(".")]
        n += len(files)
    return n


def _remove_gitdir_files(root: Path) -> int:
    """Delete files named ``.git`` (gitdir pointers); robocopy /XD skips the dir only."""

    removed = 0
    if not root.is_dir():
        return 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        if ".git" in filenames:
            p = Path(dirpath) / ".git"
            try:
                if p.is_file():
                    p.unlink()
                    removed += 1
            except OSError:
                LOGGER.debug("Could not remove %s", p, exc_info=True)
    return removed


def _robocopy_mirror(src: Path, dst: Path) -> int:
    """Return robocopy exit code (0–7 = success on Windows)."""
    dst.mkdir(parents=True, exist_ok=True)
    excludes = ["/xd", ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "/xf", ".git"]
    cmd = [
        "robocopy",
        str(src),
        str(dst),
        "/E",
        "/PURGE",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS",
        "/NC",
        "/NS",
        "/NP",
    ] + excludes
    proc = subprocess.run(cmd, check=False)
    return int(proc.returncode)


def _shutil_fallback(src: Path, dst: Path) -> None:
    import shutil

    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=lambda dirpath, names: [n for n in names if n in _SKIP_DIR_NAMES or n == ".git"],
        dirs_exist_ok=False,
    )


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--src",
        type=Path,
        default=_DEFAULT_SRC,
        help="Root containing third-party-router-poc clones (default: sibling of RouterXPL-Forge).",
    )
    parser.add_argument(
        "--dst",
        type=Path,
        default=_DST_ROOT,
        help="Destination root under arsenal/pocs.",
    )
    parser.add_argument("--dry-run", action="store_true", help="List folders only, do not copy.")
    parser.add_argument(
        "--index-only",
        action="store_true",
        help="Recompute incorporated_third_party_index.json from existing destination tree only (no robocopy).",
    )
    parser.add_argument("-v", action="store_true", help="Verbose logging.")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO)

    src: Path = args.src.expanduser().resolve()
    dst_root: Path = args.dst.expanduser().resolve()

    if args.index_only:
        if not dst_root.is_dir():
            LOGGER.error("Destination missing for --index-only: %s", dst_root)
            return 2
        entries = []
        for folder in sorted(
            [p for p in dst_root.iterdir() if p.is_dir() and not p.name.startswith(".")],
            key=lambda x: x.name.lower(),
        ):
            name = folder.name
            size_b = _dir_size_bytes(folder)
            fc = _count_files(folder)
            entries.append(
                {
                    "slug": name,
                    "relative_dest": str(folder.relative_to(_RXFORGE)).replace("\\", "/"),
                    "size_bytes": size_b,
                    "file_count": fc,
                }
            )
        payload = {
            "source_root": str(src).replace("\\", "/"),
            "dest_root": str(dst_root.relative_to(_RXFORGE)).replace("\\", "/"),
            "folder_count": len(entries),
            "entries": sorted(entries, key=lambda x: str(x["slug"])),
            "notes": "Regenerated with --index-only (sizes from current tree).",
        }
        _INDEX_OUT.parent.mkdir(parents=True, exist_ok=True)
        _INDEX_OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        LOGGER.info("Wrote %s (%s folders, index-only)", _INDEX_OUT, len(entries))
        return 0

    if not src.is_dir():
        LOGGER.error("Source missing: %s", src)
        return 2

    entries: List[Dict[str, object]] = []
    top_levels = list(_iter_top_level_dirs(src))
    if not top_levels:
        LOGGER.error("No subdirectories under %s", src)
        return 3

    use_robocopy = os.name == "nt"

    for folder in top_levels:
        name = folder.name
        dest = dst_root / name
        if args.dry_run:
            LOGGER.info("[dry-run] would mirror %s -> %s", folder, dest)
            entries.append({"slug": name, "dry_run": True})
            continue

        LOGGER.info("Mirroring %s", name)
        if use_robocopy:
            code = _robocopy_mirror(folder, dest)
            if code > 7:
                LOGGER.error("robocopy failed for %s with code %s", name, code)
                return 4
        else:
            _shutil_fallback(folder, dest)

        stripped = _remove_gitdir_files(dest)
        if stripped:
            LOGGER.info("Removed %s gitdir file(s) under %s", stripped, dest.name)

        post = dest
        if post.is_dir():
            size_b = _dir_size_bytes(post)
            fc = _count_files(post)
        else:
            size_b, fc = 0, 0

        entries.append(
            {
                "slug": name,
                "relative_dest": str(post.relative_to(_RXFORGE)).replace("\\", "/"),
                "size_bytes": size_b,
                "file_count": fc,
            }
        )

    if args.dry_run:
        return 0

    payload = {
        "source_root": str(src).replace("\\", "/"),
        "dest_root": str(dst_root.relative_to(_RXFORGE)).replace("\\", "/"),
        "folder_count": len(entries),
        "entries": sorted(entries, key=lambda x: str(x["slug"])),
        "notes": "Upstream PoC/work trees mirrored for offline use; retain CVE/PoC references in modules. "
        "Excludes .git directories and gitdir .git files after copy.",
    }
    _INDEX_OUT.parent.mkdir(parents=True, exist_ok=True)
    _INDEX_OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Wrote %s (%s folders)", _INDEX_OUT, len(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
