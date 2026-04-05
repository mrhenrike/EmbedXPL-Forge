#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan ``third-party-router-poc`` mirrors and embed structured intel into RouterXPL-Forge.

Walks each sibling submodule under the superproject (excluding full ExploitDB tree walks),
extracts CVE IDs and matches tokens against ``market_priority_devices_2010_2026.json`` and
``discord_requested_devices.json``, then writes:

* ``routerxpl/resources/catalogs/embedded_third_party_poc_intel.json``
* Merges entries into ``external_tool_intel_sources.json`` (id ``local-poc-<slug>``)

Run from RouterXPL-Forge checkout with superproject layout:

    python tools/embed_local_third_party_poc_intel.py

Author: André Henrique (@mrhenrike) | União Geek

"""

from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

LOGGER = logging.getLogger(__name__)

RXFORGE_ROOT = Path(__file__).resolve().parents[1]
# tools → RouterXPL-Forge → IoT (sibling ``third-party-router-poc`` lives here)
DEFAULT_POC_ROOT = RXFORGE_ROOT.parents[0] / "third-party-router-poc"
MARKET_JSON = RXFORGE_ROOT / "routerxpl" / "resources" / "catalogs" / "market_priority_devices_2010_2026.json"
DISCORD_JSON = RXFORGE_ROOT / "routerxpl" / "resources" / "catalogs" / "discord_requested_devices.json"
OUT_INTEL = RXFORGE_ROOT / "routerxpl" / "resources" / "catalogs" / "embedded_third_party_poc_intel.json"
EXT_SOURCES = RXFORGE_ROOT / "routerxpl" / "resources" / "catalogs" / "external_tool_intel_sources.json"

SKIP_EXPLOITDB_BODY = frozenset(
    {
        "exploit-database__exploitdb",
        "exploit-database__exploitdb-bin-sploits",
    }
)

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".c",
    ".h",
    ".cpp",
    ".go",
    ".rs",
    ".pl",
    ".rb",
    ".php",
    ".java",
    ".json",
    ".yaml",
    ".yml",
    ".mk",
    ".cmake",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MAX_DEPTH = 7
MAX_FILES = 380
READ_CHUNK = 96_000


def _git_remote_url(repo_dir: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "get-url", "origin"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return (proc.stdout or "").strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def _load_device_keyword_map() -> dict[str, set[str]]:
    """Map catalog device id -> lowercase keywords for matching."""

    mid: dict[str, set[str]] = {}
    market = json.loads(MARKET_JSON.read_text(encoding="utf-8"))
    for row in market.get("device_pool") or []:
        did = row.get("id")
        if not did:
            continue
        keys: set[str] = set()
        for k in row.get("match_keywords") or []:
            keys.add(str(k).lower())
        keys.add(str(row.get("vendor", "")).lower())
        keys.add(str(row.get("product", "")).lower())
        mid[str(did)] = {x for x in keys if len(x) >= 2}

    if DISCORD_JSON.is_file():
        disc = json.loads(DISCORD_JSON.read_text(encoding="utf-8"))
        for i, row in enumerate(disc.get("entries") or []):
            did = f"discord-request-{i + 1:03d}"
            keys: set[str] = set()
            for k in row.get("match_keywords") or []:
                keys.add(str(k).lower())
            keys.add(str(row.get("vendor", "")).lower())
            keys.add(str(row.get("model", "")).lower())
            mid[did] = {x for x in keys if len(x) >= 2}
    return mid


def _iter_text_files(root: Path) -> Iterable[Path]:
    import os

    count = 0
    for dp, dns, fns in os.walk(root, topdown=True):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
        if len(Path(dp).relative_to(root).parts) > MAX_DEPTH:
            dns[:] = []
            continue
        for fn in fns:
            if count >= MAX_FILES:
                return
            p = Path(dp) / fn
            if p.suffix.lower() not in TEXT_SUFFIXES and p.name.lower() not in ("readme", "makefile"):
                continue
            try:
                if p.stat().st_size > 2_500_000:
                    continue
            except OSError:
                continue
            yield p
            count += 1


def _stream_cves_from_text_file(path: Path) -> set[str]:
    """Stream a large text file and collect CVE IDs (memory-stable)."""

    found: set[str] = set()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            found.update(m.upper() for m in CVE_RE.findall(line))
    return found


def _prio_extra_files(body_dir: Path, slug: str) -> list[Path]:
    """Large index repos: always ingest root link dumps."""

    extra: list[Path] = []
    if slug != "tg12__PoC_CVEs":
        return extra
    for name in ("cve_links.txt", "cve_links.csv", "README.md", "readme.md"):
        p = body_dir / name
        if p.is_file():
            extra.append(p)
    return extra


def _scan_repo_body(body_dir: Path, slug: str) -> dict[str, Any]:
    text_blobs: list[str] = []
    sample_paths: list[str] = []
    seen: set[str] = set()
    for fp in _prio_extra_files(body_dir, slug):
        key = str(fp.resolve())
        if key in seen:
            continue
        seen.add(key)
        try:
            if slug == "tg12__PoC_CVEs" and fp.name == "cve_links.txt":
                raw = fp.read_text(encoding="utf-8", errors="replace")
                text_blobs.append(raw[:3_000_000])
                if len(raw) > 3_000_000:
                    text_blobs.append(raw[-500_000:])
            else:
                text_blobs.append(fp.read_text(encoding="utf-8", errors="replace")[: READ_CHUNK * 4])
        except OSError:
            pass
        sample_paths.append(fp.relative_to(body_dir).as_posix())
    for fp in _iter_text_files(body_dir):
        key = str(fp.resolve())
        if key in seen:
            continue
        seen.add(key)
        try:
            chunk = fp.read_text(encoding="utf-8", errors="replace")[:READ_CHUNK]
        except OSError:
            continue
        text_blobs.append(chunk)
        rel = fp.relative_to(body_dir).as_posix()
        if len(sample_paths) < 25:
            sample_paths.append(rel)
        if len(text_blobs) >= MAX_FILES:
            break

    blob = "\n".join(text_blobs).lower()
    file_name_blob = " ".join(sample_paths).lower()
    combined = blob + " " + file_name_blob + " " + slug.lower()

    cve_set = {m.upper() for m in CVE_RE.findall(combined)}
    if slug == "tg12__PoC_CVEs":
        cl = body_dir / "cve_links.txt"
        if cl.is_file():
            cve_set |= _stream_cves_from_text_file(cl)
    cves = sorted(cve_set)

    kw_map = _device_kw_cache
    matched_ids: list[str] = []
    for did, keys in kw_map.items():
        if not keys:
            continue
        hit = False
        for k in keys:
            if len(k) >= 3 and k in combined:
                hit = True
                break
            if len(k) == 2 and k in combined:
                hit = True
                break
        if hit:
            matched_ids.append(did)

    edge_tokens = [
        "router",
        "switch",
        "firmware",
        "exploit",
        "cve-",
        "openwrt",
        "lua",
        "mips",
        "busybox",
        "httpd",
        "telnet",
        "ssh",
        "upnp",
        "dsl",
        "pon",
        "modem",
        "gateway",
        "forti",
        "mikrot",
        "cisco",
        "tplink",
        "tp-link",
        "dlink",
        "netgear",
        "huawei",
        "zte",
        "asmax",
        "intelbras",
        "zyxel",
        "vpn",
        "ngfw",
    ]
    scope_hits = sorted({t for t in edge_tokens if t in combined})
    classification = "edge_network_poc"
    if slug in SKIP_EXPLOITDB_BODY:
        classification = "exploitdb_mirror"
    elif not cves and not scope_hits:
        classification = "generic_or_offtopic"
    elif "iot" in combined or "embedded" in combined:
        classification = "iot_embedded_poc"

    rel_to_super = Path("submodules") / "IoT" / "third-party-router-poc" / slug
    origin = _git_remote_url(body_dir)
    readme_excerpt = ""
    for name in ("README.md", "README.MD", "readme.md", "Readme.md"):
        rp = body_dir / name
        if rp.is_file():
            readme_excerpt = rp.read_text(encoding="utf-8", errors="replace")[:1200]
            break

    return {
        "local_slug": slug,
        "relative_path_from_superproject_root": rel_to_super.as_posix(),
        "origin_remote": origin,
        "classification": classification,
        "cves_found": cves,
        "matched_catalog_device_ids": sorted(set(matched_ids)),
        "scope_keyword_hits": scope_hits,
        "sample_scanned_relpaths": sample_paths,
        "readme_excerpt": readme_excerpt,
        "rxforge_integration": (
            "exploitdb_embedded_lookup"
            if slug in SKIP_EXPLOITDB_BODY
            else "local_upstream_mirror_under_routerxpl_intel"
        ),
        "notes": (
            "ExploitDB espelhado em incorporated_third_party; consulta CSV via exploitdb_embedded_lookup.py (sem searchsploit)."
            if slug in SKIP_EXPLOITDB_BODY
            else "Triagem manual: licença, escopo autorizado, portar payloads para módulos RouterXPL quando aplicável."
        ),
    }


_device_kw_cache: dict[str, set[str]] = {}


def _exploitdb_row(body: Path, slug: str) -> dict[str, Any]:
    csv_path = body / "files_exploits.csv"
    csv_exists = csv_path.is_file()
    rel = Path("submodules") / "IoT" / "third-party-router-poc" / slug
    return {
        "local_slug": slug,
        "relative_path_from_superproject_root": rel.as_posix(),
        "origin_remote": _git_remote_url(body),
        "classification": "exploitdb_mirror",
        "cves_found": [],
        "matched_catalog_device_ids": [],
        "scope_keyword_hits": ["exploitdb", "files_exploits.csv"],
        "files_exploits_csv": str(csv_path.relative_to(body).as_posix()) if csv_exists else None,
        "rxforge_integration": "exploitdb_embedded_lookup",
        "notes": (
            "Mirror ExploitDB; metadados em files_exploits.csv. RouterXPL: generic/external/exploitdb_embedded_lookup.py "
            "(cópia em incorporated_third_party; sem searchsploit)."
        ),
    }


def _merge_external_sources(rows: list[dict[str, Any]]) -> None:
    payload = json.loads(EXT_SOURCES.read_text(encoding="utf-8"))
    sources: list[dict[str, Any]] = list(payload.get("sources") or [])
    existing = {str(s.get("id")) for s in sources}
    for r in rows:
        slug = r["local_slug"]
        eid = f"local-poc-{slug.replace('__', '-').lower()}"
        if eid in existing:
            continue
        origin = r.get("origin_remote") or ""
        sources.append(
            {
                "id": eid,
                "name": f"{slug} (clone local PoC)",
                "url": origin or "https://github.com",
                "type": "local-git-submodule",
                "domain": r.get("classification", "edge_network_poc"),
                "scope_alignment": "high" if r.get("cves_found") else "conditional",
                "integration_status": "embedded-local-mirror",
                "test_matrix_status": "tracked",
                "local_path_relative": r.get("relative_path_from_superproject_root", ""),
                "related_cves_hint": r.get("cves_found") or [],
                "matched_catalog_device_ids": r.get("matched_catalog_device_ids") or [],
                "notes": "Ingerido por tools/embed_local_third_party_poc_intel.py; triagem contínua.",
            }
        )
        existing.add(eid)
    payload["sources"] = sources
    EXT_SOURCES.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    global _device_kw_cache
    parser = argparse.ArgumentParser(description="Embed third-party-router-poc intel into RouterXPL-Forge.")
    parser.add_argument("--poc-root", type=Path, default=DEFAULT_POC_ROOT)
    parser.add_argument("--no-merge-external-sources", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if not args.poc_root.is_dir():
        LOGGER.error("poc-root not found: %s", args.poc_root)
        return 2

    _device_kw_cache = _load_device_keyword_map()
    repos: list[dict[str, Any]] = []
    for child in sorted(args.poc_root.iterdir(), key=lambda p: p.name.lower()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        slug = child.name
        if slug in SKIP_EXPLOITDB_BODY:
            repos.append(_exploitdb_row(child, slug))
            continue
        LOGGER.info("Scan %s", slug)
        repos.append(_scan_repo_body(child, slug))

    all_cves: set[str] = set()
    tg12_cves: set[str] = set()
    for r in repos:
        cid_list = {str(c).upper() for c in (r.get("cves_found") or []) if c}
        all_cves |= cid_list
        if r.get("local_slug") == "tg12__PoC_CVEs":
            tg12_cves = cid_list
    out_payload = {
        "title": "Embedded intel from local third-party-router-poc mirrors",
        "generated_by": "tools/embed_local_third_party_poc_intel.py",
        "superproject_relative_root": "submodules/IoT/third-party-router-poc",
        "poc_root_observed": str(args.poc_root.resolve()),
        "device_keyword_index_size": len(_device_kw_cache),
        "repositories": repos,
        "counts": {
            "repositories": len(repos),
            "total_cves_unique_all_repos": len(all_cves),
            "tg12_cve_links_index_entries": len(tg12_cves),
            "total_cves_unique_excluding_tg12_bulk_index": len(all_cves - tg12_cves),
        },
    }
    OUT_INTEL.parent.mkdir(parents=True, exist_ok=True)
    OUT_INTEL.write_text(json.dumps(out_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    LOGGER.info("Wrote %s", OUT_INTEL)

    if not args.no_merge_external_sources and EXT_SOURCES.is_file():
        _merge_external_sources(repos)
        LOGGER.info("Merged local PoC entries into %s", EXT_SOURCES.name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
