#!/usr/bin/env python3
"""Generate a full itemized catalog of all modules, CVEs, encoders, etc.

Produces FULL_CATALOG.md and FULL_CATALOG.txt with every module, exploit,
scanner, credential module, encoder, payload, CVE and attack class listed
individually in organized sections.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import ast
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Set, Tuple

LOGGER = logging.getLogger("full_catalog")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DISABLED_DOMAINS: Tuple[str, ...] = ("cameras", "printers", "dvr", "dvrs")
_SKIP_WALK_DIRS: Set[str] = frozenset(
    {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "node_modules"}
)


def _human_bytes(n: int) -> str:
    """Human-readable size (binary prefixes)."""
    if n < 0:
        n = 0
    for suf, div in (("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div:
            return "{:.2f} {}".format(n / div, suf)
    return "{} B".format(n)


def _count_py_files(root: Path) -> int:
    """Count ``*.py`` files under root (ignore __pycache__)."""

    if not root.is_dir():
        return 0
    n = 0
    for p in root.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        n += 1
    return n


def _disk_snapshot(repo_root: Path) -> Dict[str, Any]:
    """Aggregate byte sizes by top-level path and under ``embedxpl/``."""

    repo_root = repo_root.resolve()
    rx_root = repo_root / "embedxpl"
    totals_repo: MutableMapping[str, int] = defaultdict(int)
    totals_rx: MutableMapping[str, int] = defaultdict(int)
    totals_res_child: MutableMapping[str, int] = defaultdict(int)
    grand_total = 0
    files_repo = 0
    files_rx = 0

    for dirpath, dirnames, filenames in os.walk(repo_root):
        dp = Path(dirpath)
        try:
            rel = dp.relative_to(repo_root)
        except ValueError:
            continue
        if rel.parts and rel.parts[0] in _SKIP_WALK_DIRS:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK_DIRS and not d.startswith(".")]
        for name in filenames:
            fp = dp / name
            try:
                sz = fp.stat().st_size
            except OSError:
                continue
            grand_total += sz
            files_repo += 1
            if rel == Path("."):
                totals_repo["(repo root files)"] += sz
            else:
                totals_repo[rel.parts[0]] += sz
            try:
                rel_rx = dp.relative_to(rx_root)
            except ValueError:
                continue
            files_rx += 1
            if rel_rx == Path("."):
                totals_rx["(embedxpl root files)"] += sz
            else:
                totals_rx[rel_rx.parts[0]] += sz
            if len(rel_rx.parts) >= 2 and rel_rx.parts[0] == "resources":
                child = rel_rx.parts[1]
                totals_res_child[child] += sz

    return {
        "grand_total_bytes": grand_total,
        "repo_files_count": files_repo,
        "embedxpl_files_count": files_rx,
        "repo_by_top": dict(totals_repo),
        "embedxpl_by_top": dict(totals_rx),
        "resources_children": dict(totals_res_child),
    }


def _sorted_sizes(mapping: Mapping[str, int], *, limit: int = 25) -> List[Tuple[str, int]]:
    """Largest first."""

    rows = sorted(mapping.items(), key=lambda kv: (-kv[1], kv[0]))
    return rows[:limit]


def _module_category_stats(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Per category: module count and distinct vendor/group keys."""

    stats: Dict[str, Dict[str, Any]] = {}
    for r in records:
        t = str(r["type"])
        if t not in stats:
            stats[t] = {"count": 0, "vendors": set()}
        stats[t]["count"] += 1
        stats[t]["vendors"].add(str(r["vendor"]))

    out: Dict[str, Dict[str, int]] = {}
    for t, d in stats.items():
        out[t] = {"modules": d["count"], "vendor_groups": len(d["vendors"])}
    return out


def _first_party_py_counts(repo_root: Path) -> Dict[str, int]:
    """Python file counts for framework code trees (not vendored resources)."""

    rx = repo_root / "embedxpl"
    counts: Dict[str, int] = {}
    for name in ("core", "modules", "libs"):
        p = rx / name
        counts["embedxpl/{}".format(name)] = _count_py_files(p)
    counts["tools"] = _count_py_files(repo_root / "tools")
    root_py = repo_root / "rxf.py"
    counts["rxf.py"] = 1 if root_py.is_file() else 0
    return counts


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _safe_literal_eval(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _extract_info_dict(source: str) -> Dict[str, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    data = _safe_literal_eval(node.value)
                    if isinstance(data, dict):
                        return data
    return {}


def _collect_modules(modules_root: Path) -> List[Dict[str, Any]]:
    """Collect metadata from every module file."""
    records: List[Dict[str, Any]] = []
    for py_file in sorted(modules_root.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue
        rel = py_file.relative_to(modules_root).as_posix()
        parts = rel.split("/")
        module_type = parts[0] if parts else "unknown"

        # Skip out-of-scope domains
        if any(d in rel.lower() for d in DISABLED_DOMAINS):
            continue

        source = py_file.read_text(encoding="utf-8", errors="ignore")
        info = _extract_info_dict(source)
        cves = sorted({c.upper() for c in RE_CVE.findall(source)})

        name = str(info.get("name", py_file.stem))
        description = str(info.get("description", "")).replace("\n", " ").strip()
        authors = info.get("authors", ())
        devices = info.get("devices", ())
        references = info.get("references", ())

        vendor = "multi"
        if module_type in ("exploits", "creds") and len(parts) > 2:
            vendor = parts[2]
        elif module_type in ("encoders", "payloads") and len(parts) > 1:
            vendor = parts[1]
        elif module_type == "generic" and len(parts) > 1:
            vendor = parts[1]
        elif module_type == "scanners" and len(parts) > 1:
            vendor = parts[1]

        records.append({
            "path": rel,
            "type": module_type,
            "vendor": vendor,
            "name": name,
            "description": description[:200],
            "cves": cves,
            "authors": list(authors) if isinstance(authors, (list, tuple)) else [],
            "devices": list(devices) if isinstance(devices, (list, tuple)) else [],
            "references": list(references) if isinstance(references, (list, tuple)) else [],
        })
    return records


def _build_md(
    records: List[Dict[str, Any]],
    repo_root: Path,
    disk: Mapping[str, Any],
    py_counts: Mapping[str, int],
    cat_stats: Mapping[str, Mapping[str, int]],
) -> str:
    """Build the full catalog in Markdown."""
    now = datetime.now(timezone.utc).isoformat()

    # Classify
    exploits = [r for r in records if r["type"] == "exploits"]
    creds = [r for r in records if r["type"] == "creds"]
    scanners = [r for r in records if r["type"] == "scanners"]
    generic = [r for r in records if r["type"] == "generic"]
    encoders = [r for r in records if r["type"] == "encoders"]
    payloads = [r for r in records if r["type"] == "payloads"]

    all_cves: Dict[str, List[str]] = {}
    for r in records:
        for cve in r["cves"]:
            all_cves.setdefault(cve, []).append(r["path"])

    cat_rows = [
        ("exploits", "Exploits"),
        ("creds", "Credential Modules"),
        ("scanners", "Scanners"),
        ("generic", "Generic Modules"),
        ("encoders", "Encoders"),
        ("payloads", "Payloads"),
    ]

    lines: List[str] = [
        "# EmbedXPL-Forge — Full Module Catalog",
        "",
        "> Generated: {}".format(now),
        "> Author: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
        "## Summary",
        "",
        "| Category | Modules | Vendor / group buckets |",
        "|---|---:|---:|",
    ]
    for key, label in cat_rows:
        st = cat_stats.get(key) or {"modules": 0, "vendor_groups": 0}
        lines.append("| {} | {} | {} |".format(label, st["modules"], st["vendor_groups"]))
    lines.append("| **Total Modules** | **{}** | — |".format(len(records)))
    lines.append("| Distinct CVEs | {} | — |".format(len(all_cves)))

    gt = int(disk.get("grand_total_bytes", 0) or 0)
    lines.extend([
        "",
        "## Program footprint",
        "",
        "Approximate on-disk size (file bytes only; binary prefixes). "
        "Walk skips caches such as ``__pycache__`` and ``.git``.",
        "",
        "| Metric | Value |",
        "|---|---|",
        "| Repository root | `{}` |".format(repo_root.resolve().as_posix()),
        "| Total file bytes | {} |".format(_human_bytes(gt)),
        "| Files (repo walk) | {} |".format(disk.get("repo_files_count", 0)),
        "| Files under ``embedxpl/`` | {} |".format(disk.get("embedxpl_files_count", 0)),
        "",
        "### Largest top-level paths (repository)",
        "",
        "| Path | Size | Share of total |",
        "|---|---:|---:|",
    ])
    for name, sz in _sorted_sizes(disk.get("repo_by_top") or {}, limit=15):
        pct = (100.0 * sz / gt) if gt else 0.0
        lines.append("| `{}` | {} | {:.1f}% |".format(name, _human_bytes(sz), pct))

    lines.extend([
        "",
        "### ``embedxpl/`` breakdown (first-level folders)",
        "",
        "| Area | Size | Share of total |",
        "|---|---:|---:|",
    ])
    for name, sz in _sorted_sizes(disk.get("embedxpl_by_top") or {}, limit=25):
        pct = (100.0 * sz / gt) if gt else 0.0
        lines.append("| `{}` | {} | {:.1f}% |".format(name, _human_bytes(sz), pct))

    res_ch = disk.get("resources_children") or {}
    if res_ch:
        lines.extend([
            "",
            "### ``embedxpl/resources/*`` (largest direct children)",
            "",
            "| Subfolder | Size | Share of total |",
            "|---|---:|---:|",
        ])
        for name, sz in _sorted_sizes(res_ch, limit=25):
            pct = (100.0 * sz / gt) if gt else 0.0
            lines.append("| `{}` | {} | {:.1f}% |".format(name, _human_bytes(sz), pct))

    lines.extend([
        "",
        "### First-party Python files (``.py`` count, excluding ``__pycache__``)",
        "",
        "| Tree | Files |",
        "|---|---:|",
    ])
    for key in ("embedxpl/core", "embedxpl/modules", "embedxpl/libs", "tools", "rxf.py"):
        if key in py_counts:
            lines.append("| `{}` | {} |".format(key, py_counts[key]))

    lines.extend(["", "---", ""])

    def _section(title: str, items: List[Dict[str, Any]], show_cves: bool = True) -> List[str]:
        section_lines = ["## {} ({})".format(title, len(items)), ""]
        vendors: Dict[str, List[Dict[str, Any]]] = {}
        for item in items:
            vendors.setdefault(item["vendor"], []).append(item)

        idx = 0
        for vendor in sorted(vendors.keys()):
            section_lines.append("### {} ({})".format(vendor, len(vendors[vendor])))
            section_lines.append("")
            for item in sorted(vendors[vendor], key=lambda x: x["name"]):
                idx += 1
                section_lines.append("{}. **{}**".format(idx, item["name"]))
                section_lines.append("   - Path: `{}`".format(item["path"]))
                if item["description"]:
                    section_lines.append("   - {}".format(item["description"]))
                if show_cves and item["cves"]:
                    section_lines.append("   - CVEs: {}".format(", ".join(item["cves"])))
                if item["devices"]:
                    section_lines.append("   - Devices: {}".format(", ".join(str(d) for d in item["devices"][:10])))
                section_lines.append("")
        return section_lines

    lines.extend(_section("Exploits", exploits))
    lines.extend(_section("Credential Modules", creds))
    lines.extend(_section("Scanners", scanners))
    lines.extend(_section("Generic Modules", generic))
    lines.extend(_section("Encoders", encoders, show_cves=False))
    lines.extend(_section("Payloads", payloads, show_cves=False))

    # CVE master list
    lines.extend([
        "---",
        "",
        "## CVE Master List ({})".format(len(all_cves)),
        "",
        "| # | CVE ID | Modules |",
        "|---:|---|---|",
    ])
    for idx, (cve_id, paths) in enumerate(sorted(all_cves.items()), 1):
        modules_str = ", ".join("`{}`".format(p) for p in paths[:5])
        if len(paths) > 5:
            modules_str += " (+{})".format(len(paths) - 5)
        lines.append("| {} | {} | {} |".format(idx, cve_id, modules_str))

    # CVE by vendor
    cve_by_vendor: Dict[str, Set[str]] = {}
    for r in records:
        for cve in r["cves"]:
            cve_by_vendor.setdefault(r["vendor"], set()).add(cve)

    lines.extend([
        "",
        "## CVEs by Vendor",
        "",
        "| Vendor | CVE Count | CVE IDs |",
        "|---|---:|---|",
    ])
    for vendor in sorted(cve_by_vendor.keys()):
        cves_sorted = sorted(cve_by_vendor[vendor])
        lines.append("| {} | {} | {} |".format(vendor, len(cves_sorted), ", ".join(cves_sorted)))

    # Access vector classification from CVE DB
    try:
        from embedxpl.core.cve.cve_db import CVEDatabase
        db = CVEDatabase()
        lines.extend([
            "",
            "## CVE Access Vector Classification",
            "",
            "| CVE ID | CVSS | Access Vector | Exploitable by RXF | Module |",
            "|---|---:|---|---|---|",
        ])
        for cve_id in sorted(all_cves.keys()):
            matches = [e for e in db._entries if e.cve_id.upper() == cve_id.upper()]
            if matches:
                e = matches[0]
                lines.append("| {} | {:.1f} | {} | {} | {} |".format(
                    e.cve_id, e.cvss_score, e.access_vector,
                    "YES" if e.is_exploitable_by_rxf else "no",
                    "`{}`".format(e.rxf_module) if e.rxf_module else "-",
                ))
            else:
                mod_paths = ", ".join("`{}`".format(p) for p in all_cves[cve_id][:3])
                lines.append("| {} | - | - | mapped | {} |".format(cve_id, mod_paths))
    except Exception:
        pass

    lines.extend(["", "---", "", "> Generated by tools/generate_full_catalog.py"])
    return "\n".join(lines)


def _build_txt(
    records: List[Dict[str, Any]],
    repo_root: Path,
    disk: Mapping[str, Any],
    py_counts: Mapping[str, int],
    cat_stats: Mapping[str, Mapping[str, int]],
) -> str:
    """Build the full catalog in plain text."""
    now = datetime.now(timezone.utc).isoformat()
    lines: List[str] = [
        "EmbedXPL-Forge - Full Module Catalog",
        "=" * 40,
        "Generated: {}".format(now),
        "Author: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
    ]

    type_labels = {
        "exploits": "EXPLOITS",
        "creds": "CREDENTIAL MODULES",
        "scanners": "SCANNERS",
        "generic": "GENERIC MODULES",
        "encoders": "ENCODERS",
        "payloads": "PAYLOADS",
    }

    all_cves: Dict[str, List[str]] = {}
    for r in records:
        for cve in r["cves"]:
            all_cves.setdefault(cve, []).append(r["path"])

    lines.append("SUMMARY")
    lines.append("-" * 20)
    for t, label in type_labels.items():
        st = cat_stats.get(t) or {"modules": 0, "vendor_groups": 0}
        lines.append(
            "  {}: {} modules, {} vendor/group buckets".format(
                label, st["modules"], st["vendor_groups"],
            )
        )
    lines.append("  TOTAL MODULES: {}".format(len(records)))
    lines.append("  DISTINCT CVEs: {}".format(len(all_cves)))

    gt = int(disk.get("grand_total_bytes", 0) or 0)
    lines.extend([
        "",
        "PROGRAM FOOTPRINT",
        "-" * 20,
        "Repository root: {}".format(repo_root.resolve()),
        "Total file bytes: {}".format(_human_bytes(gt)),
        "Files (repo walk, excl. skipped dirs): {}".format(disk.get("repo_files_count", 0)),
        "Files under embedxpl/: {}".format(disk.get("embedxpl_files_count", 0)),
        "",
        "Largest top-level paths:",
    ])
    for name, sz in _sorted_sizes(disk.get("repo_by_top") or {}, limit=15):
        pct = (100.0 * sz / gt) if gt else 0.0
        lines.append("  {:<36} {:>12}  ({:.1f}%)".format(name, _human_bytes(sz), pct))
    lines.extend(["", "embedxpl/ first-level folders:",])
    for name, sz in _sorted_sizes(disk.get("embedxpl_by_top") or {}, limit=25):
        pct = (100.0 * sz / gt) if gt else 0.0
        lines.append("  {:<36} {:>12}  ({:.1f}%)".format(name, _human_bytes(sz), pct))
    res_ch = disk.get("resources_children") or {}
    if res_ch:
        lines.extend(["", "embedxpl/resources/* direct children (largest):",])
        for name, sz in _sorted_sizes(res_ch, limit=25):
            pct = (100.0 * sz / gt) if gt else 0.0
            lines.append("  {:<36} {:>12}  ({:.1f}%)".format(name, _human_bytes(sz), pct))
    lines.extend(["", "First-party .py file counts (excl. __pycache__):",])
    for key in ("embedxpl/core", "embedxpl/modules", "embedxpl/libs", "tools", "rxf.py"):
        if key in py_counts:
            lines.append("  {:<22} {}".format(key, py_counts[key]))
    lines.append("")

    for mod_type, label in type_labels.items():
        items = [r for r in records if r["type"] == mod_type]
        if not items:
            continue
        lines.append("{} ({})".format(label, len(items)))
        lines.append("=" * 40)

        vendors: Dict[str, List[Dict[str, Any]]] = {}
        for item in items:
            vendors.setdefault(item["vendor"], []).append(item)

        idx = 0
        for vendor in sorted(vendors.keys()):
            lines.append("")
            lines.append("[{}] ({})".format(vendor.upper(), len(vendors[vendor])))
            lines.append("-" * 30)
            for item in sorted(vendors[vendor], key=lambda x: x["name"]):
                idx += 1
                lines.append("  {}. {}".format(idx, item["name"]))
                lines.append("     Path: {}".format(item["path"]))
                if item["description"]:
                    lines.append("     {}".format(item["description"][:120]))
                if item["cves"]:
                    lines.append("     CVEs: {}".format(", ".join(item["cves"])))
                if item["devices"]:
                    lines.append("     Devices: {}".format(", ".join(str(d) for d in item["devices"][:8])))
        lines.append("")

    lines.append("CVE MASTER LIST ({})".format(len(all_cves)))
    lines.append("=" * 40)
    for idx, (cve_id, paths) in enumerate(sorted(all_cves.items()), 1):
        lines.append("  {}. {} -> {}".format(idx, cve_id, ", ".join(paths[:5])))
    lines.append("")

    # Access vector
    try:
        from embedxpl.core.cve.cve_db import CVEDatabase
        db = CVEDatabase()
        lines.append("CVE ACCESS VECTOR CLASSIFICATION")
        lines.append("=" * 40)
        for cve_id in sorted(all_cves.keys()):
            matches = [e for e in db._entries if e.cve_id.upper() == cve_id.upper()]
            if matches:
                e = matches[0]
                exploitable = "EXPLOITABLE" if e.is_exploitable_by_rxf else "no module"
                lines.append("  {} | CVSS {:.1f} | {} | {} | {}".format(
                    e.cve_id, e.cvss_score, e.access_vector, exploitable,
                    e.rxf_module or "-",
                ))
            else:
                lines.append("  {} | mapped in: {}".format(cve_id, ", ".join(all_cves[cve_id][:3])))
    except Exception:
        pass

    lines.extend(["", "--- Generated by tools/generate_full_catalog.py ---"])
    return "\n".join(lines)


def main() -> int:
    """Generate the full catalog documents."""
    _configure_logging()
    repo_root = Path(__file__).resolve().parent.parent
    modules_root = repo_root / "embedxpl" / "modules"

    records = _collect_modules(modules_root)
    LOGGER.info("Computing disk metrics and first-party counts...")
    disk = _disk_snapshot(repo_root)
    py_counts = _first_party_py_counts(repo_root)
    cat_stats = _module_category_stats(records)

    docs_dir = repo_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    md_path = docs_dir / "FULL_CATALOG.md"
    txt_path = docs_dir / "FULL_CATALOG.txt"

    md_path.write_text(
        _build_md(records, repo_root, disk, py_counts, cat_stats), encoding="utf-8",
    )
    txt_path.write_text(
        _build_txt(records, repo_root, disk, py_counts, cat_stats), encoding="utf-8",
    )

    LOGGER.info("Full catalog generated: %s and %s (%d modules, %d CVEs)",
                md_path, txt_path, len(records),
                len({c for r in records for c in r["cves"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
