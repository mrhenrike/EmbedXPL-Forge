#!/usr/bin/env python3
"""
analyze_firmware.py — Embedded Firmware Research Lab analysis pipeline
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

End-to-end pipeline: format detection → extraction → inventory → strings audit
→ CVE cross-reference → Markdown report.

Usage:
    python scripts/analyze_firmware.py --list-targets
    python scripts/analyze_firmware.py --target mikrotik_routeros_7221 --all-phases
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase extract
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase strings
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase cve-map
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase inventory
    python scripts/analyze_firmware.py --file downloads/cctv/hikvision/Firmware__V5.7.19_241207_S3000618481.zip --all-phases
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# ── UTF-8 output on Windows ───────────────────────────────────────────────────
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILES_YAML = REPO_ROOT / "analysis" / "target_profiles.yaml"
REPORTS_DIR = REPO_ROOT / "reports"
TMP_DIR = REPO_ROOT / ".tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP_DIR)
tempfile.tempdir = str(TMP_DIR)

# ── Interesting string patterns for security research ────────────────────────
_CRED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hardcoded-password", re.compile(r"(?i)password\s*[=:]\s*[\w!@#$%^&*]{4,}")),
    ("hardcoded-secret",   re.compile(r"(?i)secret\s*[=:]\s*[\w!@#$%^&*]{4,}")),
    ("hardcoded-apikey",   re.compile(r"(?i)api[_-]?key\s*[=:]\s*[A-Za-z0-9]{8,}")),
    ("default-cred",       re.compile(r"(?i)\b(admin|root|guest|user)[\s:]+(\w{3,})")),
    ("md5-hash",           re.compile(r"\b[0-9a-f]{32}\b")),
    ("sha1-hash",          re.compile(r"\b[0-9a-f]{40}\b")),
    ("private-key-pem",    re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ("aws-key",            re.compile(r"AKIA[0-9A-Z]{16}")),
]

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{8,}")
_IP_PATTERN  = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_CMD_INJECTION_PATTERN = re.compile(
    r"(?:system|popen|execv[pe]?|ShellExecute|os\.system|subprocess)\s*\("
)


# ── Target profile loader ─────────────────────────────────────────────────────

def load_profiles() -> dict[str, Any]:
    if not PROFILES_YAML.exists():
        print(f"[ERROR] Profiles not found: {PROFILES_YAML}", file=sys.stderr)
        sys.exit(1)
    with open(PROFILES_YAML, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("targets", {})


def get_target(target_id: str) -> dict[str, Any]:
    profiles = load_profiles()
    if target_id not in profiles:
        print(f"[ERROR] Unknown target '{target_id}'. Use --list-targets.", file=sys.stderr)
        sys.exit(1)
    return profiles[target_id]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run a command, return (returncode, combined output)."""
    try:
        r = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode, r.stdout + r.stderr
    except FileNotFoundError:
        return -1, f"[tool not found: {cmd[0]}]"
    except subprocess.TimeoutExpired:
        return -2, f"[timeout: {cmd[0]}]"


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ── Format detection ──────────────────────────────────────────────────────────

def detect_format(path: Path) -> dict[str, Any]:
    """Detect the container/compression format of a firmware file."""
    result: dict[str, Any] = {"path": str(path), "size": path.stat().st_size, "type": "unknown"}

    with open(path, "rb") as f:
        magic = f.read(16)

    # ZIP
    if magic[:4] == b"PK\x03\x04":
        result["type"] = "zip"
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            result["inner_files"] = names
            result["inner_count"] = len(names)
        return result

    # GZIP
    if magic[:2] == b"\x1f\x8b":
        result["type"] = "gzip"
        return result

    # ELF
    if magic[:4] == b"\x7fELF":
        arch = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM32", 0xb7: "ARM64"}.get(magic[18], "unknown")
        result["type"] = "elf"
        result["elf_arch"] = arch
        return result

    # squashfs
    if magic[:4] in (b"sqsh", b"hsqs", b"qshs", b"shsq"):
        result["type"] = "squashfs"
        return result

    # MBR/GPT disk image
    with open(path, "rb") as f:
        f.seek(510)
        mbr_sig = f.read(2)
        f.seek(512)
        gpt_sig = f.read(8)
    if mbr_sig == b"\x55\xaa":
        result["type"] = "disk-image-mbr"
        if gpt_sig == b"EFI PART":
            result["type"] = "disk-image-gpt"
    return result


# ── Phase 0: Reconnaissance ───────────────────────────────────────────────────

def phase_recon(target: dict[str, Any], fw_path: Path) -> dict[str, Any]:
    print("[phase:recon] Identifying firmware format and basic properties...")
    fmt = detect_format(fw_path)
    result = {
        "firmware_path": str(fw_path),
        "firmware_size": _human_size(fw_path.stat().st_size),
        "format": fmt,
        "target_label": target.get("label", ""),
        "architecture": target.get("architecture", "unknown"),
        "os": target.get("os", "unknown"),
        "runnable": target.get("runnable", False),
        "known_cves": [c["id"] for c in target.get("known_cves", [])],
    }
    print(f"  Format      : {fmt['type']}")
    print(f"  Size        : {result['firmware_size']}")
    print(f"  Architecture: {result['architecture']}")
    print(f"  Runnable    : {result['runnable']}")
    print(f"  Known CVEs  : {', '.join(result['known_cves']) or 'none catalogued'}")
    return result


# ── Phase 1: Extraction ───────────────────────────────────────────────────────

def phase_extract(target: dict[str, Any], fw_path: Path, out_dir: Path) -> dict[str, Any]:
    print(f"[phase:extract] Extracting to {out_dir} ...")
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"extraction_dir": str(out_dir), "method": None, "files_extracted": 0}
    fmt = detect_format(fw_path)

    if fmt["type"] == "zip":
        # Step 1: unzip outer container
        inner_names = fmt.get("inner_files", [])
        with zipfile.ZipFile(fw_path) as z:
            for name in inner_names:
                dest = out_dir / Path(name).name
                if not dest.exists():
                    print(f"  Extracting: {name} -> {dest.name}")
                    data = z.read(name)
                    dest.write_bytes(data)
            result["files_extracted"] = len(inner_names)
        result["method"] = "zipfile"

        # Step 2: if binwalk available, recurse on inner files
        if _tool_available("binwalk"):
            for inner in out_dir.iterdir():
                if inner.suffix in (".dav", ".img", ".bin", ".msd"):
                    print(f"  Running binwalk -e on {inner.name} ...")
                    rc, out = _run(["binwalk", "-e", "--run-as=root", "-C", str(out_dir), str(inner)])
                    if rc == 0:
                        result["method"] = "binwalk"
                        print("  binwalk extraction complete.")
                    else:
                        print(f"  [WARN] binwalk: {out[:200]}")
        else:
            print("  [INFO] binwalk not installed. Install with: pip install binwalk")
            print("  [INFO] Inner container left in extraction dir for manual analysis.")

    elif fmt["type"] == "gzip":
        # Decompress gz
        out_file = out_dir / fw_path.stem  # strip .gz
        if not out_file.exists():
            print(f"  Decompressing gzip -> {out_file.name}")
            with gzip.open(fw_path, "rb") as f_in:
                out_file.write_bytes(f_in.read())
        result["method"] = "gzip"
        result["files_extracted"] = 1

        if _tool_available("binwalk"):
            print(f"  Running binwalk -e on {out_file.name} ...")
            rc, out = _run(["binwalk", "-e", "--run-as=root", "-C", str(out_dir), str(out_file)])
            if rc == 0:
                result["method"] = "binwalk"

    else:
        if _tool_available("binwalk"):
            print(f"  Running binwalk -e on {fw_path.name} ...")
            rc, out = _run(["binwalk", "-e", "--run-as=root", "-C", str(out_dir), str(fw_path)])
            result["method"] = "binwalk"
        else:
            print(f"  [INFO] Format: {fmt['type']} — manual extraction required.")
            result["method"] = "manual"

    # Count extracted files
    all_extracted = list(out_dir.rglob("*"))
    result["files_extracted"] = sum(1 for f in all_extracted if f.is_file())
    print(f"  Files in extraction dir: {result['files_extracted']}")
    return result


# ── Phase 2: Strings audit ────────────────────────────────────────────────────

def phase_strings(target: dict[str, Any], search_dir: Path) -> dict[str, Any]:
    print(f"[phase:strings] Scanning for interesting strings in {search_dir} ...")
    result: dict[str, Any] = {
        "credentials": [],
        "urls": [],
        "ips": [],
        "cmd_injection_risk": [],
        "files_scanned": 0,
    }

    elf_files = [f for f in search_dir.rglob("*") if f.is_file() and f.stat().st_size < 100 * 1024 * 1024]
    result["files_scanned"] = len(elf_files)

    creds_found: list[dict[str, str]] = []
    urls_found: set[str] = set()
    ips_found: set[str] = set()
    cmd_risk: list[dict[str, str]] = []

    for fpath in elf_files:
        try:
            data = fpath.read_bytes()
        except (PermissionError, OSError):
            continue

        # Extract printable strings (min length 6)
        try:
            text = data.decode("latin-1", errors="replace")
        except Exception:
            continue

        printable = re.findall(r"[ -~]{6,}", text)

        for s in printable:
            for label, pat in _CRED_PATTERNS:
                if pat.search(s):
                    creds_found.append({"file": str(fpath.relative_to(search_dir)), "match": s[:120], "pattern": label})
                    break

            for url in _URL_PATTERN.findall(s):
                urls_found.add(url[:120])

            for ip in _IP_PATTERN.findall(s):
                if not ip.startswith("127.") and not ip.startswith("0.0.0."):
                    ips_found.add(ip)

            if _CMD_INJECTION_PATTERN.search(s):
                cmd_risk.append({"file": str(fpath.relative_to(search_dir)), "match": s[:120]})

    result["credentials"] = creds_found[:50]  # cap at 50
    result["urls"] = sorted(urls_found)[:30]
    result["ips"] = sorted(ips_found)[:30]
    result["cmd_injection_risk"] = cmd_risk[:20]

    print(f"  Files scanned      : {result['files_scanned']}")
    print(f"  Credential matches : {len(creds_found)}")
    print(f"  URLs found         : {len(urls_found)}")
    print(f"  IPs found          : {len(ips_found)}")
    print(f"  Cmd-injection risk : {len(cmd_risk)}")

    if creds_found:
        print("\n  [!] Credential patterns:")
        for c in creds_found[:5]:
            print(f"      [{c['pattern']}] {c['file']}: {c['match'][:80]}")
    return result


# ── Phase 3: File inventory ───────────────────────────────────────────────────

def phase_inventory(target: dict[str, Any], search_dir: Path) -> dict[str, Any]:
    print(f"[phase:inventory] Building file inventory in {search_dir} ...")
    result: dict[str, Any] = {
        "elf_files": [],
        "config_files": [],
        "script_files": [],
        "passwd_files": [],
        "key_cert_files": [],
        "suid_files": [],
        "total_files": 0,
    }

    elf_magic = b"\x7fELF"
    elf_files = []
    config_files = []
    script_files = []
    passwd_files = []
    key_files = []
    suid_files = []
    total = 0

    for fpath in search_dir.rglob("*"):
        if not fpath.is_file():
            continue
        total += 1
        name = fpath.name.lower()

        try:
            with open(fpath, "rb") as f:
                magic4 = f.read(4)
        except (PermissionError, OSError):
            continue

        rel = str(fpath.relative_to(search_dir))

        # ELF binary
        if magic4 == elf_magic:
            arch_byte = None
            size = fpath.stat().st_size
            try:
                with open(fpath, "rb") as f:
                    f.seek(18)
                    arch_byte = struct.unpack("<H", f.read(2))[0]
            except Exception:
                pass
            arch = {0x03: "x86", 0x3e: "x86-64", 0x28: "ARM32", 0xb7: "ARM64"}.get(arch_byte, f"0x{arch_byte:04x}" if arch_byte else "?")

            # checksec-like check (basic)
            flags = []
            raw = fpath.read_bytes()
            if b"GNU_RELRO" in raw:
                flags.append("RELRO")
            if b"__stack_chk" in raw:
                flags.append("Canary")
            if b"__libc_start_main" in raw:
                flags.append("libc")

            elf_files.append({"path": rel, "arch": arch, "size": _human_size(size), "flags": flags})

        # Config / credential files
        if name in ("passwd", "shadow", "group", "sudoers", "hosts"):
            passwd_files.append(rel)
        if fpath.suffix in (".conf", ".cfg", ".ini", ".xml", ".json", ".yaml", ".yml"):
            config_files.append(rel)
        if fpath.suffix in (".sh", ".bash", ".py", ".pl", ".rb", ".lua"):
            script_files.append(rel)
        if fpath.suffix in (".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".der"):
            key_files.append(rel)

        # SUID check (Unix permissions, may not work on all filesystems)
        try:
            if fpath.stat().st_mode & 0o4000:
                suid_files.append(rel)
        except Exception:
            pass

    result["elf_files"] = elf_files[:100]
    result["config_files"] = config_files[:50]
    result["script_files"] = script_files[:50]
    result["passwd_files"] = passwd_files
    result["key_cert_files"] = key_files
    result["suid_files"] = suid_files
    result["total_files"] = total

    print(f"  Total files        : {total}")
    print(f"  ELF binaries       : {len(elf_files)}")
    print(f"  Config files       : {len(config_files)}")
    print(f"  Scripts            : {len(script_files)}")
    print(f"  Passwd/shadow      : {len(passwd_files)}")
    print(f"  Keys/certs         : {len(key_files)}")
    print(f"  SUID files         : {len(suid_files)}")

    if passwd_files:
        print(f"\n  [!] Sensitive files: {passwd_files}")
    if key_files:
        print(f"  [!] Key/cert files : {key_files}")
    return result


# ── Phase 4: CVE cross-reference ──────────────────────────────────────────────

def phase_cve_map(target: dict[str, Any]) -> dict[str, Any]:
    print("[phase:cve-map] Cross-referencing known CVEs ...")
    cves = target.get("known_cves", [])
    result = {"cves": cves, "count": len(cves)}

    if not cves:
        print("  No CVEs catalogued for this target.")
        return result

    print(f"\n  {'CVE ID':<20}  {'CVSS':>6}  {'Status':<30}  Description")
    print("  " + "-" * 100)
    for cve in cves:
        cve_id = cve.get("id", "")
        cvss = str(cve.get("cvss", "?"))
        status = cve.get("status", "unknown")
        desc = str(cve.get("description", "")).replace("\n", " ").strip()[:60]
        print(f"  {cve_id:<20}  {cvss:>6}  {status:<30}  {desc}")

    return result


# ── Report generation ─────────────────────────────────────────────────────────

def generate_report(
    target_id: str,
    target: dict[str, Any],
    fw_path: Path,
    phases: dict[str, Any],
    report_dir: Path,
) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report_file = report_dir / "report.md"

    lines = [
        f"# Firmware Analysis Report — {target.get('label', target_id)}",
        f"> Generated: {timestamp}  ",
        f"> Author: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
        "---",
        "",
        "## Target",
        f"- **ID**: `{target_id}`",
        f"- **Label**: {target.get('label', '')}",
        f"- **Architecture**: {target.get('architecture', '')}",
        f"- **OS**: {target.get('os', '')}",
        f"- **Runnable in VM**: {target.get('runnable', False)}",
        f"- **Tier**: {target.get('tier', '?')} (1=bootable, 2=ARM/extract, 3=decrypt-first)",
        f"- **Study Order**: #{target.get('study_order', '?')}",
        f"- **Firmware file**: `{fw_path.name}`",
        f"- **File size**: {_human_size(fw_path.stat().st_size)}",
        "",
    ]

    # Recon
    if "recon" in phases:
        r = phases["recon"]
        lines += [
            "## Phase 0 — Reconnaissance",
            f"- Format detected: `{r.get('format', {}).get('type', '?')}`",
            f"- Known CVEs: {', '.join(r.get('known_cves', [])) or 'none catalogued'}",
            "",
        ]

    # CVE map
    if "cve-map" in phases:
        r = phases["cve-map"]
        lines += ["## Phase 4 — CVE Cross-Reference", ""]
        for cve in r.get("cves", []):
            lines += [
                f"### {cve.get('id', '')} — CVSS {cve.get('cvss', '?')}",
                f"- **Status**: `{cve.get('status', 'unknown')}`",
                f"- **Affects**: {cve.get('affects', 'see NVD')}",
                f"- **Description**: {str(cve.get('description', '')).replace(chr(10), ' ').strip()}",
                "",
            ]
        if not r.get("cves"):
            lines.append("No CVEs catalogued for this target.\n")

    # Inventory
    if "inventory" in phases:
        r = phases["inventory"]
        lines += [
            "## Phase 3 — File Inventory",
            f"- Total files: {r.get('total_files', 0)}",
            f"- ELF binaries: {len(r.get('elf_files', []))}",
            f"- Config files: {len(r.get('config_files', []))}",
            f"- Scripts: {len(r.get('script_files', []))}",
            "",
        ]
        if r.get("passwd_files"):
            lines += [
                "### Sensitive files (passwd/shadow)",
                *[f"- `{f}`" for f in r["passwd_files"]],
                "",
            ]
        if r.get("key_cert_files"):
            lines += [
                "### Keys and certificates",
                *[f"- `{f}`" for f in r["key_cert_files"]],
                "",
            ]
        if r.get("suid_files"):
            lines += [
                "### SUID files",
                *[f"- `{f}`" for f in r["suid_files"]],
                "",
            ]
        if r.get("elf_files"):
            lines += ["### Key ELF binaries (first 20)", ""]
            lines.append("| Binary | Arch | Size | Security flags |")
            lines.append("|--------|------|------|---------------|")
            for e in r["elf_files"][:20]:
                flags = ", ".join(e.get("flags", [])) or "none"
                lines.append(f"| `{e['path']}` | {e['arch']} | {e['size']} | {flags} |")
            lines.append("")

    # Strings
    if "strings" in phases:
        r = phases["strings"]
        lines += [
            "## Phase 2 — Strings Audit",
            f"- Files scanned: {r.get('files_scanned', 0)}",
            f"- Credential pattern matches: {len(r.get('credentials', []))}",
            f"- URLs found: {len(r.get('urls', []))}",
            f"- Internal IPs found: {len(r.get('ips', []))}",
            f"- Cmd-injection risk patterns: {len(r.get('cmd_injection_risk', []))}",
            "",
        ]
        if r.get("credentials"):
            lines += ["### Credential matches", ""]
            for c in r["credentials"][:10]:
                lines.append(f"- `[{c['pattern']}]` in `{c['file']}`: `{c['match'][:80]}`")
            lines.append("")
        if r.get("cmd_injection_risk"):
            lines += ["### Command injection risk patterns", ""]
            for c in r["cmd_injection_risk"][:10]:
                lines.append(f"- `{c['file']}`: `{c['match'][:80]}`")
            lines.append("")
        if r.get("ips"):
            lines += ["### Internal/hardcoded IPs", ""]
            for ip in r["ips"][:15]:
                lines.append(f"- `{ip}`")
            lines.append("")

    # Attack surface
    atk = target.get("attack_surface", [])
    if atk:
        lines += ["## Attack Surface", ""]
        for svc in atk:
            lines.append(f"- {svc}")
        lines.append("")

    # Research focus
    focus = target.get("research_focus", [])
    if focus:
        lines += ["## Research Focus", ""]
        if isinstance(focus, list):
            for f in focus:
                item = str(f) if not isinstance(f, str) else f
                lines.append(f"- {item}")
        else:
            lines.append(str(focus))
        lines.append("")

    lines += [
        "---",
        f"*Generated by analyze_firmware.py | Embedded Firmware Research Lab*",
        f"*Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek*",
    ]

    report_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[report] Written to {report_file}")
    return report_file


# ── CLI ───────────────────────────────────────────────────────────────────────

def cmd_list_targets() -> None:
    profiles = load_profiles()
    print(f"\n{'#':<4} {'Target ID':<36} {'Tier':<6} {'Arch':<12} {'CVEs':>5}  Label")
    print("-" * 100)
    for tid, t in sorted(profiles.items(), key=lambda x: x[1].get("study_order", 99)):
        order = t.get("study_order", "?")
        tier = t.get("tier", "?")
        arch = t.get("architecture", "?")
        cve_count = len(t.get("known_cves", []))
        label = t.get("label", "")[:50]
        print(f"{order!s:<4} {tid:<36} {tier!s:<6} {arch:<12} {cve_count:>5}  {label}")
    print()


def run_phases(
    target_id: str | None,
    target: dict[str, Any],
    fw_path: Path,
    phases_requested: list[str],
) -> None:
    tid = target_id or fw_path.stem
    report_dir = REPORTS_DIR / tid
    extract_dir = report_dir / "extraction"

    phases_results: dict[str, Any] = {}

    for phase in phases_requested:
        print(f"\n{'='*60}")
        print(f"  PHASE: {phase.upper()}")
        print(f"{'='*60}")

        if phase == "recon":
            phases_results["recon"] = phase_recon(target, fw_path)
        elif phase == "extract":
            phases_results["extract"] = phase_extract(target, fw_path, extract_dir)
        elif phase == "strings":
            scan_dir = extract_dir if extract_dir.exists() else fw_path.parent
            phases_results["strings"] = phase_strings(target, scan_dir)
        elif phase == "inventory":
            scan_dir = extract_dir if extract_dir.exists() else fw_path.parent
            phases_results["inventory"] = phase_inventory(target, scan_dir)
        elif phase == "cve-map":
            phases_results["cve-map"] = phase_cve_map(target)
        else:
            print(f"[WARN] Unknown phase: {phase}")

    generate_report(tid, target, fw_path, phases_results, report_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze_firmware.py",
        description="Embedded Firmware Research Lab — analysis pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phases:
  recon      Format detection, size, known CVEs (fast, no extraction)
  extract    Unzip / gunzip / binwalk extraction to reports/<target>/extraction/
  strings    Credential patterns, URLs, IPs, cmd-injection risk
  inventory  ELF binaries, config files, passwd, keys, SUID
  cve-map    Print CVE table for target

Examples:
  List all targets:
    python scripts/analyze_firmware.py --list-targets

  Full analysis (all phases):
    python scripts/analyze_firmware.py --target mikrotik_routeros_7221 --all-phases

  Single phase:
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase extract
    python scripts/analyze_firmware.py --target hikvision_cam_g5_v5719 --phase cve-map

  From a raw file path (no target profile needed for basic phases):
    python scripts/analyze_firmware.py --file downloads/cctv/hikvision/Firmware__V5.7.19_241207_S3000618481.zip --phase recon
        """,
    )
    parser.add_argument("--list-targets", action="store_true", help="List all targets in analysis/target_profiles.yaml")
    parser.add_argument("--target", help="Target ID from target_profiles.yaml")
    parser.add_argument("--file", help="Direct path to firmware file (bypasses target lookup)")
    parser.add_argument(
        "--phase",
        choices=["recon", "extract", "strings", "inventory", "cve-map"],
        help="Run a single analysis phase",
    )
    parser.add_argument("--all-phases", action="store_true", help="Run all phases in order")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_targets:
        cmd_list_targets()
        return

    if not args.target and not args.file:
        parser.error("--target or --file is required")
    if not args.phase and not args.all_phases:
        parser.error("--phase or --all-phases is required")

    # Resolve target profile
    if args.target:
        target = get_target(args.target)
    else:
        target = {}

    # Resolve firmware path
    if args.file:
        fw_path = Path(args.file)
    elif args.target:
        fw_key = target.get("firmware_file", "")
        fw_path = REPO_ROOT / fw_key if fw_key else None
    else:
        fw_path = None

    if fw_path is None or not fw_path.exists():
        print(f"[ERROR] Firmware file not found: {fw_path}", file=sys.stderr)
        print("  Use --file to specify a path, or verify the manifest.", file=sys.stderr)
        sys.exit(1)

    phases = (
        ["recon", "extract", "inventory", "strings", "cve-map"]
        if args.all_phases
        else [args.phase]
    )

    run_phases(args.target, target, fw_path, phases)


if __name__ == "__main__":
    main()
