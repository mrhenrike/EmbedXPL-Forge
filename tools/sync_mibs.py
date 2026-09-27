#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Sync MIB corpus for EmbedXPL-Forge SNMP validations."""

from __future__ import annotations

import json
import os
import shutil
import urllib.request
import csv
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


GITHUB_API = "https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
RAW_BASE = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
MIB_EXTENSIONS = (".mib", ".my", ".smi", ".txt")


def _http_get(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "EmbedXPL-Forge-MIBSync/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def _load_tree(owner: str, repo: str, refs: Iterable[str]) -> Tuple[str, List[dict]]:
    for ref in refs:
        url = GITHUB_API.format(owner=owner, repo=repo, ref=ref)
        try:
            payload = _http_get(url).decode("utf-8", errors="ignore")
            data = json.loads(payload)
            tree = data.get("tree", [])
            if tree:
                return ref, tree
        except Exception:
            continue
    return "", []


def _collect_vendor_tokens(modules_root: Path) -> Set[str]:
    tokens: Set[str] = set()
    for root in ("exploits", "creds"):
        vendor_root = modules_root / root / "routers"
        if not vendor_root.exists():
            continue
        for item in vendor_root.iterdir():
            if item.is_dir():
                tokens.add(item.name.lower())
    tokens.update(
        {
            "fw",
            "ngfw",
            "switch",
            "router",
            "snmp",
            "trap",
            "mikrotik",
            "cisco",
            "juniper",
            "huawei",
            "dlink",
            "tp-link",
            "tplink",
            "netgear",
            "zyxel",
            "ubiquiti",
            "pfsense",
            "fortinet",
            "paloalto",
            "checkpoint",
            "arista",
        }
    )
    return tokens


def _matches_scope(path: str, tokens: Set[str], require_mibs_dir: bool = True) -> bool:
    lower = path.lower()
    if require_mibs_dir and "/mibs/" not in lower and not lower.startswith("mibs/"):
        return False

    # MIB repositories often use extensionless filenames (e.g., CISCO-FOO-MIB)
    has_known_extension = lower.endswith(MIB_EXTENSIONS)
    has_mib_like_name = "mib" in lower
    if not (has_known_extension or has_mib_like_name):
        return False

    return any(token in lower for token in tokens)


def _copy_local_mibs(source_dir: Path, target_dir: Path) -> int:
    if not source_dir.exists():
        return 0
    copied = 0
    for file_path in source_dir.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in MIB_EXTENSIONS:
            continue
        rel = file_path.relative_to(source_dir)
        out = target_dir / "local" / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, out)
        copied += 1
    return copied


def _download_repo_mibs(
    owner: str,
    repo: str,
    refs: Iterable[str],
    target_dir: Path,
    tokens: Set[str],
    require_mibs_dir: bool = True,
    max_files: int = 700,
) -> int:
    ref, tree = _load_tree(owner, repo, refs)
    if not ref:
        return 0

    selected = [
        item["path"]
        for item in tree
        if item.get("type") == "blob" and _matches_scope(item["path"], tokens, require_mibs_dir=require_mibs_dir)
    ]
    selected = sorted(set(selected))[:max_files]

    def _download_one(path: str) -> int:
        try:
            out = target_dir / "{}_{}".format(owner, repo) / path
            if out.exists():
                return 1
            url = RAW_BASE.format(owner=owner, repo=repo, ref=ref, path=path)
            data = _http_get(url, timeout=15)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            return 1
        except Exception:
            return 0

    with ThreadPoolExecutor(max_workers=12) as executor:
        return sum(executor.map(_download_one, selected))


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    modules_root = repo_root / "embedxpl" / "modules"
    mibs_root = repo_root / "embedxpl" / "resources" / "mibs"
    mibs_root.mkdir(parents=True, exist_ok=True)

    vendor_tokens = _collect_vendor_tokens(modules_root)

    local_source = Path(r"C:\Users\mrhen\Downloads\Mikrotik")
    local_count = _copy_local_mibs(local_source, mibs_root)

    # Primary public source for network MIBs
    librenms_count = _download_repo_mibs(
        owner="librenms",
        repo="librenms",
        refs=("master", "main"),
        target_dir=mibs_root,
        tokens=vendor_tokens,
        require_mibs_dir=True,
        max_files=700,
    )

    # Additional vendor-focused source
    cisco_count = _download_repo_mibs(
        owner="cisco",
        repo="cisco-mibs",
        refs=("main", "master"),
        target_dir=mibs_root,
        tokens=vendor_tokens,
        require_mibs_dir=False,
        max_files=400,
    )

    total = local_count + librenms_count + cisco_count
    catalog_file = mibs_root / "mib_catalog.csv"
    with catalog_file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source", "relative_path", "filename"])
        for file_path in sorted([p for p in mibs_root.rglob("*") if p.is_file() and p.name != "mib_catalog.csv"]):
            rel = file_path.relative_to(mibs_root).as_posix()
            source = rel.split("/", 1)[0] if "/" in rel else "unknown"
            writer.writerow([source, rel, file_path.name])

    print(
        "MIB sync complete: local={} librenms={} cisco={} total={} catalog={}".format(
            local_count, librenms_count, cisco_count, total, catalog_file.name
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
