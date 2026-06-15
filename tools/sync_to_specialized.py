"""One-way sync from EmbedXPL-Forge (source of truth) to specialized XPL-Forge repos.

Usage:
    python tools/sync_to_specialized.py [--target <name>] [--dry-run] [--force]

Targets: firewallxpl, industrialxpl, wirelessxpl, printerxpl, all

Flags:
    --dry-run   Show what would be copied without writing anything
    --force     Overwrite even if dest file is newer than source
    --target    Sync only the specified target (default: all)
    --verbose   Print per-file status

Security checks embedded:
    - Never overwrites a file that is newer than the source (unless --force)
    - Runs py_compile on every written file; rolls back on failure
    - Verifies no hardcoded secret patterns in synced files
    - Verifies check() does not call run() (no accidental destructive checks)
    - Logs conflicts to .sync_manifest.json for manual review
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import py_compile
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Repository root resolution ────────────────────────────────────────────────

EMBEDXPL_ROOT = Path(__file__).resolve().parent.parent
REPOS_ROOT = EMBEDXPL_ROOT.parent  # …/submodules/Uniao-Geek/

# ── Sync map ──────────────────────────────────────────────────────────────────
# Each entry: list of (src_relative_to_embedxpl, dst_relative_to_target_pkg_root)
# "pkg_root" = the directory containing the Python package (e.g. FirewallXPL-Forge/)

SYNC_MAP: dict[str, dict[str, Any]] = {
    "firewallxpl": {
        "repo_dir": REPOS_ROOT / "FirewallXPL-Forge",
        "pkg": "firewallxpl",
        "mappings": [
            ("embedxpl/modules/exploits/firewalls",  "firewallxpl/modules/exploits/perimeter"),
            ("embedxpl/modules/exploits/vpn",         "firewallxpl/modules/exploits/vpn"),
            ("embedxpl/modules/exploits/network_os",  "firewallxpl/modules/exploits/routing"),
            ("embedxpl/modules/exploits/sdwan",        "firewallxpl/modules/exploits/perimeter/sdwan"),
            ("embedxpl/modules/exploits/ngfw",         "firewallxpl/modules/exploits/perimeter/ngfw"),
        ],
    },
    "industrialxpl": {
        "repo_dir": REPOS_ROOT / "IndustrialXPL-Forge",
        "pkg": "industrialxpl",
        "mappings": [
            ("embedxpl/modules/exploits/ics",                     "industrialxpl/modules/exploits/protocols/ics"),
            ("embedxpl/modules/exploits/protocols/ot",            "industrialxpl/modules/exploits/protocols/ot"),
            ("embedxpl/modules/exploits/ot_iiot",                  "industrialxpl/modules/exploits/protocols/iiot"),
            ("embedxpl/modules/exploits/bms",                     "industrialxpl/modules/exploits/protocols/bms"),
            ("embedxpl/modules/exploits/specialized/hvac",        "industrialxpl/modules/exploits/specialized/hvac"),
            ("embedxpl/modules/exploits/specialized/medical",     "industrialxpl/modules/exploits/specialized/medical"),
            ("embedxpl/modules/exploits/specialized/elevator",    "industrialxpl/modules/exploits/specialized/elevator"),
            ("embedxpl/modules/exploits/specialized/vehicles",    "industrialxpl/modules/exploits/specialized/vehicles"),
        ],
    },
    "wirelessxpl": {
        "repo_dir": REPOS_ROOT / "WirelessXPL-Forge",
        "pkg": "wirelessxpl",
        "mappings": [
            ("embedxpl/modules/exploits/protocols/iot/wifi",     "wirelessxpl/modules/generic/iot_proto/wifi"),
            ("embedxpl/modules/exploits/protocols/iot/ble",      "wirelessxpl/modules/generic/iot_proto/ble"),
            ("embedxpl/modules/exploits/protocols/iot/zigbee",   "wirelessxpl/modules/generic/iot_proto/zigbee"),
            ("embedxpl/modules/exploits/protocols/iot/zwave",    "wirelessxpl/modules/generic/iot_proto/zwave"),
            ("embedxpl/modules/exploits/protocols/iot/lorawan",  "wirelessxpl/modules/generic/iot_proto/lorawan"),
            ("embedxpl/modules/exploits/protocols/iot/mdns",     "wirelessxpl/modules/generic/iot_proto/mdns"),
            ("embedxpl/modules/exploits/drones",                  "wirelessxpl/modules/generic/drones"),
            ("embedxpl/modules/exploits/aps",                     "wirelessxpl/modules/generic/access_points"),
            ("embedxpl/modules/exploits/wearables",               "wirelessxpl/modules/generic/wearables"),
        ],
    },
    # PrinterXPL uses a separate bridge flow (see sync_printer_bridge())
    "printerxpl": {
        "repo_dir": REPOS_ROOT / "PrinterXPL-Forge",
        "pkg": "printerxpl",  # no package rewrite needed -- bridge uses importlib directly
        "mappings": [
            ("embedxpl/modules/exploits/printers", "xpl/embedxpl_compat/printers"),
        ],
        "bridge_mode": True,
    },
}

# ── Core dependency modules to copy if missing in target ──────────────────────
# key: embedxpl import prefix → (embedxpl relative path, target relative path)
CORE_SHIMS: dict[str, tuple[str, str]] = {
    "embedxpl.core.http.http_client":   ("embedxpl/core/http/http_client.py",   "{pkg}/core/http/http_client.py"),
    "embedxpl.core.http_client":         ("embedxpl/core/http_client.py",         "{pkg}/core/http_client.py"),
    "embedxpl.core.ssh.ssh_client":      ("embedxpl/core/ssh/ssh_client.py",      "{pkg}/core/ssh/ssh_client.py"),
    "embedxpl.core.tcp.tcp_client":      ("embedxpl/core/tcp/tcp_client.py",      "{pkg}/core/tcp/tcp_client.py"),
    "embedxpl.core.udp.udp_client":      ("embedxpl/core/udp/udp_client.py",      "{pkg}/core/udp/udp_client.py"),
    "embedxpl.core.snmp.snmp_client":    ("embedxpl/core/snmp/snmp_client.py",    "{pkg}/core/snmp/snmp_client.py"),
    "embedxpl.core.ics.modbus_client":   ("embedxpl/core/ics/modbus_client.py",   "{pkg}/core/ics/modbus_client.py"),
    "embedxpl.core.ics.cip_client":      ("embedxpl/core/ics/cip_client.py",      "{pkg}/core/ics/cip_client.py"),
    "embedxpl.core.ics.s7_client":       ("embedxpl/core/ics/s7_client.py",       "{pkg}/core/ics/s7_client.py"),
    "embedxpl.core.exploit.shell_stager": ("embedxpl/core/exploit/shell_stager.py", "{pkg}/core/exploit/shell_stager.py"),
    "embedxpl.core.exploit.char_by_char": ("embedxpl/core/exploit/char_by_char.py", "{pkg}/core/exploit/char_by_char.py"),
    "embedxpl.core.exploit.option":       ("embedxpl/core/exploit/option.py",       "{pkg}/core/exploit/option.py"),
    "embedxpl.core.exploit.printer":      ("embedxpl/core/exploit/printer.py",      "{pkg}/core/exploit/printer.py"),
    "embedxpl.core.exploit.exploit":      ("embedxpl/core/exploit/exploit.py",      "{pkg}/core/exploit/exploit.py"),
}

# Security: patterns considered hardcoded secrets
_SECRET_RE = re.compile(
    r"""(password|passwd|secret|api_key|token|private_key|passphrase)\s*=\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE,
)

# Pattern to detect if check() body calls self.run() (unsafe)
_CHECK_CALLS_RUN_RE = re.compile(r"def\s+check\s*\(", re.MULTILINE)


# ── Dataclass for per-file results ────────────────────────────────────────────

@dataclass
class FileResult:
    source: str
    dest: str
    status: str  # copied | skipped | conflict | error | dry_run
    reason: str = ""
    sha256: str = ""
    warnings: list[str] = field(default_factory=list)


# ── Utilities ─────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    """SHA256 of file content, normalized to LF line endings for cross-platform consistency."""
    h = hashlib.sha256()
    # Normalize CRLF → LF so Windows-written files hash the same as in-memory strings
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    h.update(raw)
    return h.hexdigest()


def _content_sha256(content: str) -> str:
    """SHA256 of string content, normalized to LF."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _rewrite_imports(content: str, src_pkg: str, dst_pkg: str) -> str:
    """Replace all `from embedxpl.` / `import embedxpl.` with target package."""
    content = content.replace(f"from {src_pkg}.", f"from {dst_pkg}.")
    content = content.replace(f"import {src_pkg}.", f"import {dst_pkg}.")
    # Also handle: from embedxpl.modules.generic.wifi_lab._disclaimer → skip (not copied)
    return content


def _check_hardcoded_secrets(content: str) -> list[str]:
    """Return list of suspicious lines with potential hardcoded secrets."""
    warnings = []
    for i, line in enumerate(content.splitlines(), 1):
        if _SECRET_RE.search(line):
            # Exclude known safe patterns (default placeholders, empty strings)
            stripped = line.strip()
            if not any(
                ph in stripped for ph in (
                    '""', "''", '"<', "'<", '"CHANGE', "'CHANGE",
                    "default=", "description=", "# ", "placeholder",
                )
            ):
                warnings.append(f"L{i}: {stripped[:100]}")
    return warnings


def _check_check_calls_run(content: str) -> bool:
    """Return True if check() body seems to call self.run() - unsafe pattern."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "check":
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "run"
                ):
                    return True
    return False


def _ensure_init_py(directory: Path) -> None:
    """Create __init__.py in directory and all parents up to a known boundary."""
    current = directory
    boundary = current
    # Walk up until we hit an existing __init__.py or known package root
    while current != current.parent:
        init = current / "__init__.py"
        if not init.exists():
            init.touch()
        if current.name in ("modules", "exploits", "generic", "protocols"):
            break
        current = current.parent


def _py_compile_file(path: Path) -> tuple[bool, str]:
    """Run py_compile on path. Returns (ok, error_msg)."""
    try:
        py_compile.compile(str(path), doraise=True)
        return True, ""
    except py_compile.PyCompileError as exc:
        return False, str(exc)


def _copy_core_shim(
    shim_key: str,
    repo_dir: Path,
    pkg: str,
    dry_run: bool,
    verbose: bool,
) -> bool:
    """Copy a missing core module from EmbedXPL to the target repo."""
    if shim_key not in CORE_SHIMS:
        return False
    src_rel, dst_tpl = CORE_SHIMS[shim_key]
    src = EMBEDXPL_ROOT / src_rel
    if not src.exists():
        return False
    dst_rel = dst_tpl.format(pkg=pkg)
    dst = repo_dir / dst_rel
    if dst.exists():
        return True  # already there
    if verbose:
        print(f"    [shim] copy core dep: {dst_rel}")
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        _ensure_init_py(dst.parent)
        # Rewrite imports in the shim file itself
        content = src.read_text(encoding="utf-8", errors="replace")
        content = _rewrite_imports(content, "embedxpl", pkg)
        dst.write_text(content, encoding="utf-8")
        ok, err = _py_compile_file(dst)
        if not ok and verbose:
            print(f"    [shim WARN] py_compile failed for {dst_rel}: {err}")
    return True


def _resolve_missing_core_deps(
    rewritten_content: str,
    repo_dir: Path,
    pkg: str,
    dry_run: bool,
    verbose: bool,
) -> list[str]:
    """Find imports that reference pkg.core.* paths and copy missing shims.
    Returns list of unresolved imports."""
    unresolved = []
    for line in rewritten_content.splitlines():
        m = re.match(rf"from ({re.escape(pkg)}\.core\.\S+)\s+import", line)
        if not m:
            m = re.match(rf"import ({re.escape(pkg)}\.core\.\S+)", line)
        if not m:
            continue
        import_path = m.group(1)
        # Convert to file path: pkg.core.http.http_client → pkg/core/http/http_client.py
        rel_path = import_path.replace(".", "/") + ".py"
        abs_path = repo_dir / rel_path
        if abs_path.exists():
            continue
        # Try to find a matching shim key (original embedxpl version)
        embedxpl_key = import_path.replace(pkg, "embedxpl", 1)
        # Find the best shim key prefix match
        matched = False
        for shim_key in CORE_SHIMS:
            if import_path.startswith(import_path) and shim_key == embedxpl_key:
                _copy_core_shim(shim_key, repo_dir, pkg, dry_run, verbose)
                matched = True
                break
            # prefix match: e.g. embedxpl.core.ics.modbus_client matches embedxpl.core.ics.modbus_client
            if shim_key == embedxpl_key or embedxpl_key.startswith(shim_key):
                _copy_core_shim(shim_key, repo_dir, pkg, dry_run, verbose)
                matched = True
                break
        if not matched:
            unresolved.append(import_path)
    return unresolved


# ── Main sync logic ────────────────────────────────────────────────────────────

def sync_target(
    target_name: str,
    config: dict[str, Any],
    dry_run: bool,
    force: bool,
    verbose: bool,
) -> list[FileResult]:
    """Sync one target. Returns list of FileResult."""
    repo_dir: Path = config["repo_dir"]
    pkg: str = config["pkg"]
    bridge_mode: bool = config.get("bridge_mode", False)
    results: list[FileResult] = []

    if not repo_dir.exists():
        print(f"  [SKIP] {target_name}: repo not found at {repo_dir}")
        return results

    for src_rel, dst_rel in config["mappings"]:
        src_dir = EMBEDXPL_ROOT / src_rel
        if not src_dir.exists():
            if verbose:
                print(f"  [SKIP src] {src_rel} does not exist in EmbedXPL")
            continue

        for src_file in sorted(src_dir.rglob("*.py")):
            if src_file.name == "__init__.py":
                continue
            if "__pycache__" in src_file.parts:
                continue

            # Compute destination path
            relative = src_file.relative_to(src_dir)
            dst_file = repo_dir / dst_rel / relative

            src_str = str(src_file.relative_to(EMBEDXPL_ROOT))
            dst_str = str(dst_file.relative_to(repo_dir))

            # Read source
            try:
                content = src_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                results.append(FileResult(src_str, dst_str, "error", str(exc)))
                continue

            # Bridge mode: no import rewrite (PrinterXPL loads via importlib)
            if bridge_mode:
                rewritten = content
            else:
                rewritten = _rewrite_imports(content, "embedxpl", pkg)

            # Security checks
            secret_warnings = _check_hardcoded_secrets(rewritten)
            unsafe_check = _check_check_calls_run(rewritten)
            warn_list = []
            if secret_warnings:
                warn_list.append(f"potential secrets: {secret_warnings[:3]}")
            if unsafe_check:
                warn_list.append("check() calls run() - UNSAFE")

            # Compute hash of what would be written (LF-normalized)
            dest_hash = _content_sha256(rewritten)

            # Conflict check: dest exists and is newer than source AND different
            if dst_file.exists() and not force:
                if dst_file.stat().st_mtime > src_file.stat().st_mtime:
                    existing_hash = _sha256(dst_file)
                    if existing_hash != dest_hash:
                        results.append(FileResult(
                            src_str, dst_str, "conflict",
                            "dest is newer with different content (use --force to overwrite)",
                            sha256=dest_hash,
                            warnings=warn_list,
                        ))
                        if verbose:
                            print(f"  [CONFLICT] {dst_str}")
                        continue

            # Skip if identical
            if dst_file.exists():
                existing_hash = _sha256(dst_file)
                if existing_hash == dest_hash:
                    results.append(FileResult(src_str, dst_str, "skipped", "identical", sha256=dest_hash))
                    continue

            if dry_run:
                results.append(FileResult(
                    src_str, dst_str, "dry_run",
                    "would be copied",
                    sha256=dest_hash,
                    warnings=warn_list,
                ))
                if verbose:
                    action = "NEW" if not dst_file.exists() else "UPDATE"
                    print(f"  [DRY {action}] {dst_str}")
                continue

            # Resolve missing core dependencies before writing
            if not bridge_mode:
                unresolved = _resolve_missing_core_deps(rewritten, repo_dir, pkg, dry_run, verbose)
                if unresolved and verbose:
                    for u in unresolved:
                        print(f"    [dep-gap] {u}")
                warn_list.extend([f"unresolved dep: {u}" for u in unresolved])

            # Write to temp file first, then move (atomic)
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            _ensure_init_py(dst_file.parent)

            tmp_fd, tmp_path = tempfile.mkstemp(dir=dst_file.parent, suffix=".tmp")
            try:
                os.close(tmp_fd)
                # Write with explicit LF line endings to keep hashes consistent
                Path(tmp_path).write_text(rewritten, encoding="utf-8", newline="\n")

                # py_compile validation
                ok, err = _py_compile_file(Path(tmp_path))
                if not ok:
                    os.unlink(tmp_path)
                    results.append(FileResult(
                        src_str, dst_str, "error",
                        f"py_compile failed: {err}",
                        sha256=dest_hash,
                        warnings=warn_list,
                    ))
                    print(f"  [FAIL py_compile] {dst_str}: {err[:80]}")
                    continue

                # Atomic move
                shutil.move(tmp_path, str(dst_file))
                action = "NEW" if not dst_file.exists() else "UPDATE"
                results.append(FileResult(
                    src_str, dst_str, "copied",
                    action,
                    sha256=dest_hash,
                    warnings=warn_list,
                ))
                if verbose:
                    warn_tag = f" [WARN: {len(warn_list)} issue(s)]" if warn_list else ""
                    print(f"  [OK {action}] {dst_str}{warn_tag}")

            except Exception as exc:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                results.append(FileResult(src_str, dst_str, "error", str(exc), sha256=dest_hash))
                print(f"  [ERROR] {dst_str}: {exc}")

    return results


# ── Manifest ──────────────────────────────────────────────────────────────────

def write_manifest(all_results: dict[str, list[FileResult]]) -> Path:
    manifest_path = EMBEDXPL_ROOT / "tools" / ".sync_manifest.json"
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "embedxpl_version": _read_version(),
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
            "files": [
                {
                    "src": r.source,
                    "dst": r.dest,
                    "status": r.status,
                    "reason": r.reason,
                    "sha256": r.sha256,
                    "warnings": r.warnings,
                }
                for r in results
            ],
        }
    manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return manifest_path


def _read_version() -> str:
    pyproject = EMBEDXPL_ROOT / "pyproject.toml"
    if pyproject.exists():
        for line in pyproject.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("version"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().strip('"').strip("'")
    return "unknown"


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-way sync from EmbedXPL-Forge to specialized XPL-Forge repos."
    )
    parser.add_argument(
        "--target",
        choices=list(SYNC_MAP.keys()) + ["all"],
        default="all",
        help="Which target to sync (default: all)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")
    parser.add_argument("--force", action="store_true", help="Overwrite even if dest is newer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Per-file output")
    args = parser.parse_args()

    targets = list(SYNC_MAP.keys()) if args.target == "all" else [args.target]
    all_results: dict[str, list[FileResult]] = {}

    for target_name in targets:
        config = SYNC_MAP[target_name]
        print(f"\n{'='*60}")
        print(f"  Syncing: {target_name} {'(DRY RUN)' if args.dry_run else ''}")
        print(f"  Repo:    {config['repo_dir']}")
        print(f"{'='*60}")

        results = sync_target(
            target_name, config,
            dry_run=args.dry_run,
            force=args.force,
            verbose=args.verbose,
        )
        all_results[target_name] = results

        # Per-target summary
        copied  = sum(1 for r in results if r.status == "copied")
        skipped = sum(1 for r in results if r.status == "skipped")
        dry     = sum(1 for r in results if r.status == "dry_run")
        conflict= sum(1 for r in results if r.status == "conflict")
        errors  = sum(1 for r in results if r.status == "error")
        warned  = sum(1 for r in results if r.warnings)

        print(f"\n  Summary [{target_name}]:")
        print(f"    {'Would copy' if args.dry_run else 'Copied'}:    {copied + dry}")
        print(f"    Skipped:   {skipped}")
        print(f"    Conflicts: {conflict}")
        print(f"    Errors:    {errors}")
        print(f"    Warnings:  {warned}")

        if conflict:
            print(f"\n  CONFLICTS (resolve manually):")
            for r in results:
                if r.status == "conflict":
                    print(f"    {r.dest} -- {r.reason}")

        if errors:
            print(f"\n  ERRORS:")
            for r in results:
                if r.status == "error":
                    print(f"    {r.dest} -- {r.reason[:120]}")

    # Write manifest
    manifest_path = write_manifest(all_results)
    print(f"\n  Manifest written: {manifest_path}")

    # Security summary across all targets
    all_secret_warnings = [
        (r.dest, w)
        for results in all_results.values()
        for r in results
        for w in r.warnings
        if "secret" in w
    ]
    all_unsafe_checks = [
        r.dest
        for results in all_results.values()
        for r in results
        if any("UNSAFE" in w for w in r.warnings)
    ]

    if all_secret_warnings:
        print(f"\n  [SECURITY] {len(all_secret_warnings)} potential hardcoded secrets detected:")
        for dest, warn in all_secret_warnings[:10]:
            print(f"    {dest}: {warn[:100]}")

    if all_unsafe_checks:
        print(f"\n  [SECURITY] {len(all_unsafe_checks)} modules where check() calls run():")
        for dest in all_unsafe_checks[:10]:
            print(f"    {dest}")

    total_errors = sum(
        sum(1 for r in results if r.status == "error")
        for results in all_results.values()
    )
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
