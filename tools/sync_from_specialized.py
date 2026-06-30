"""Reverse sync: copy unique modules from specialized XPL-Forge repos into EmbedXPL-Forge.

Mirrors sync_to_specialized.py mappings in reverse (sibling → embed) and copies
vendor/ref trees that incorporation placed only in specialized forges.

Usage:
    python tools/sync_from_specialized.py [--target <name>] [--dry-run] [--force]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Reuse forward-sync map and helpers from sibling script.
from sync_to_specialized import (  # noqa: E402
    EMBEDXPL_ROOT,
    FileResult,
    SYNC_MAP,
    _check_check_calls_run,
    _check_hardcoded_secrets,
    _content_sha256,
    _ensure_init_py,
    _py_compile_file,
    _read_version,
    _rewrite_imports,
    _sha256,
)

VENDOR_REL = {
    "wirelessxpl": "wirelessxpl/resources/vendor",
    "firewallxpl": "firewallxpl/resources/vendor",
    "industrialxpl": "industrialxpl/resources/vendor",
    "printerxpl": "src/resources/vendor",
    "wordlistsforhacking": "resources/vendor",
    "mikrotikapi-bf": "resources/vendor",
}

REF_REL = {
    "wirelessxpl": "wirelessxpl/modules/generic/refs",
    "firewallxpl": "firewallxpl/modules/scanners/refs",
    "industrialxpl": "industrialxpl/modules/scanners/refs",
    "printerxpl": "src/modules/refs",
    "wordlistsforhacking": "wfh_modules/refs",
    "mikrotikapi-bf": "modules/refs",
}

EMBED_VENDOR = EMBEDXPL_ROOT / "embedxpl/resources/vendor"
EMBED_REFS = EMBEDXPL_ROOT / "embedxpl/modules/scanners/refs"


def sync_target_reverse(
    target_name: str,
    config: dict[str, Any],
    dry_run: bool,
    force: bool,
    verbose: bool,
) -> list[FileResult]:
    """Copy sibling exploit modules back into EmbedXPL (inverse of forward sync)."""
    repo_dir: Path = config["repo_dir"]
    pkg: str = config["pkg"]
    bridge_mode: bool = config.get("bridge_mode", False)
    results: list[FileResult] = []

    if not repo_dir.exists():
        print(f"  [SKIP] {target_name}: repo not found at {repo_dir}")
        return results

    for embed_rel, sibling_rel in config["mappings"]:
        sibling_dir = repo_dir / sibling_rel
        if not sibling_dir.exists():
            if verbose:
                print(f"  [SKIP sibling] {sibling_rel} does not exist in {target_name}")
            continue

        embed_dir = EMBEDXPL_ROOT / embed_rel
        for src_file in sorted(sibling_dir.rglob("*.py")):
            if src_file.name == "__init__.py":
                continue
            if "__pycache__" in src_file.parts:
                continue

            relative = src_file.relative_to(sibling_dir)
            dst_file = embed_dir / relative

            src_str = str(src_file.relative_to(repo_dir))
            dst_str = str(dst_file.relative_to(EMBEDXPL_ROOT))

            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                results.append(FileResult(src_str, dst_str, "error", str(exc)))
                continue

            rewritten = content if bridge_mode else _rewrite_imports(content, pkg, "embedxpl")

            secret_warnings = _check_hardcoded_secrets(rewritten)
            unsafe_check = _check_check_calls_run(rewritten)
            warn_list: list[str] = []
            if secret_warnings:
                warn_list.append(f"potential secrets: {secret_warnings[:3]}")
            if unsafe_check:
                warn_list.append("check() calls run() - UNSAFE")

            dest_hash = _content_sha256(rewritten)

            if dst_file.exists() and not force:
                if dst_file.stat().st_mtime > src_file.stat().st_mtime:
                    existing_hash = _sha256(dst_file)
                    if existing_hash != dest_hash:
                        results.append(
                            FileResult(
                                src_str,
                                dst_str,
                                "conflict",
                                "dest newer with different content (use --force)",
                                sha256=dest_hash,
                                warnings=warn_list,
                            )
                        )
                        continue

            if dst_file.exists():
                existing_hash = _sha256(dst_file)
                if existing_hash == dest_hash:
                    results.append(FileResult(src_str, dst_str, "skipped", "identical", sha256=dest_hash))
                    continue

            if dry_run:
                results.append(
                    FileResult(
                        src_str,
                        dst_str,
                        "dry_run",
                        "would be copied",
                        sha256=dest_hash,
                        warnings=warn_list,
                    )
                )
                if verbose:
                    action = "NEW" if not dst_file.exists() else "UPDATE"
                    print(f"  [DRY {action}] {dst_str}")
                continue

            dst_file.parent.mkdir(parents=True, exist_ok=True)
            _ensure_init_py(dst_file.parent)

            tmp_fd, tmp_path = tempfile.mkstemp(dir=dst_file.parent, suffix=".tmp")
            try:
                os.close(tmp_fd)
                Path(tmp_path).write_text(rewritten, encoding="utf-8", newline="\n")
                ok, err = _py_compile_file(Path(tmp_path))
                if not ok:
                    os.unlink(tmp_path)
                    results.append(
                        FileResult(
                            src_str,
                            dst_str,
                            "error",
                            f"py_compile failed: {err}",
                            sha256=dest_hash,
                            warnings=warn_list,
                        )
                    )
                    continue
                shutil.move(tmp_path, str(dst_file))
                action = "NEW" if not dst_file.exists() else "UPDATE"
                results.append(
                    FileResult(
                        src_str,
                        dst_str,
                        "copied",
                        action,
                        sha256=dest_hash,
                        warnings=warn_list,
                    )
                )
                if verbose:
                    print(f"  [OK {action}] {dst_str}")
            except Exception as exc:  # noqa: BLE001
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                results.append(FileResult(src_str, dst_str, "error", str(exc), sha256=dest_hash))

    return results


def sync_vendor_refs(
    target_name: str,
    config: dict[str, Any],
    dry_run: bool,
    force: bool,
    verbose: bool,
) -> list[FileResult]:
    """Copy vendor + ref index modules from specialized forge into Embed."""
    repo_dir: Path = config["repo_dir"]
    results: list[FileResult] = []

    vendor_rel = VENDOR_REL.get(target_name)
    ref_rel = REF_REL.get(target_name)
    if not vendor_rel or not ref_rel:
        return results

    sibling_vendor = repo_dir / vendor_rel
    sibling_refs = repo_dir / ref_rel
    if not sibling_vendor.is_dir() and not sibling_refs.is_dir():
        return results

    EMBED_VENDOR.mkdir(parents=True, exist_ok=True)
    EMBED_REFS.mkdir(parents=True, exist_ok=True)

    if sibling_vendor.is_dir():
        for entry in sorted(sibling_vendor.iterdir()):
            if not entry.is_dir():
                continue
            dst = EMBED_VENDOR / entry.name
            src_str = str(entry.relative_to(repo_dir))
            dst_str = str(dst.relative_to(EMBEDXPL_ROOT))
            if dst.exists() and not force:
                results.append(FileResult(src_str, dst_str, "skipped", "vendor exists"))
                continue
            if dry_run:
                results.append(FileResult(src_str, dst_str, "dry_run", "would copy vendor tree"))
                if verbose:
                    print(f"  [DRY vendor] {dst_str}")
                continue
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(entry, dst, symlinks=True, ignore_dangling_symlinks=True)
            results.append(FileResult(src_str, dst_str, "copied", "vendor tree"))

    if sibling_refs.is_dir():
        for src_file in sorted(sibling_refs.glob("ref_*.py")):
            dst_file = EMBED_REFS / src_file.name
            src_str = str(src_file.relative_to(repo_dir))
            dst_str = str(dst_file.relative_to(EMBEDXPL_ROOT))
            content = src_file.read_text(encoding="utf-8", errors="replace")
            pkg = config.get("pkg", "")
            if pkg:
                content = content.replace(f"{pkg}/resources/vendor", "embedxpl/resources/vendor")
            dest_hash = _content_sha256(content)
            if dst_file.exists() and not force:
                if _sha256(dst_file) == dest_hash:
                    results.append(FileResult(src_str, dst_str, "skipped", "identical"))
                    continue
            if dry_run:
                results.append(FileResult(src_str, dst_str, "dry_run", "would copy ref module"))
                continue
            dst_file.write_text(content, encoding="utf-8")
            results.append(FileResult(src_str, dst_str, "copied", "ref module"))

    return results


def write_manifest(all_results: dict[str, list[FileResult]]) -> Path:
    manifest_path = EMBEDXPL_ROOT / "tools" / ".sync_from_manifest.json"
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "embedxpl_version": _read_version(),
        "direction": "specialized_to_embed",
        "targets": {},
    }
    for target, results in all_results.items():
        data["targets"][target] = {
            "total": len(results),
            "copied": sum(1 for r in results if r.status == "copied"),
            "skipped": sum(1 for r in results if r.status == "skipped"),
            "conflict": sum(1 for r in results if r.status == "conflict"),
            "error": sum(1 for r in results if r.status == "error"),
            "dry_run": sum(1 for r in results if r.status == "dry_run"),
        }
    manifest_path.write_text(
        __import__("json").dumps(data, indent=2),
        encoding="utf-8",
    )
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reverse sync from specialized XPL-Forge repos into EmbedXPL-Forge."
    )
    parser.add_argument(
        "--target",
        choices=list(SYNC_MAP.keys()) + ["all"],
        default="all",
        help="Which source forge to pull from (default: all)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    targets = list(SYNC_MAP.keys()) if args.target == "all" else [args.target]
    all_results: dict[str, list[FileResult]] = {}

    for target_name in targets:
        config = SYNC_MAP[target_name]
        print(f"\n{'='*60}")
        print(f"  Reverse sync: {target_name} → embedxpl {'(DRY RUN)' if args.dry_run else ''}")
        print(f"{'='*60}")

        results = sync_target_reverse(
            target_name, config, args.dry_run, args.force, args.verbose
        )
        results.extend(
            sync_vendor_refs(target_name, config, args.dry_run, args.force, args.verbose)
        )
        all_results[target_name] = results

        copied = sum(1 for r in results if r.status == "copied")
        dry = sum(1 for r in results if r.status == "dry_run")
        skipped = sum(1 for r in results if r.status == "skipped")
        errors = sum(1 for r in results if r.status == "error")
        print(f"  Summary: copied={copied} dry_run={dry} skipped={skipped} errors={errors}")

    manifest = write_manifest(all_results)
    print(f"\nManifest: {manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
