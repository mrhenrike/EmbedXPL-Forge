#!/usr/bin/env python3
"""
hikvision_initramfs_extract.py — Extract initramfs from Hikvision kernel
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Parse CPIO newc format entries embedded in the decompressed kernel to
extract the root filesystem.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
KERNEL_FILE = BASE / ".tmp" / "hikvision_v4_62" / "manual_extract" / "uImage_hi3536_lzma_8024.bin"
OUT_DIR = BASE / ".tmp" / "hikvision_v4_62" / "rootfs"
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def extract_cpio():
    """Extract all CPIO entries from decompressed kernel."""
    print("=" * 70)
    print("  EXTRACTING INITRAMFS FROM KERNEL")
    print("=" * 70)

    data = KERNEL_FILE.read_bytes()
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Find all CPIO entries
    pos = 0
    entries = []

    while pos < len(data) - 110:
        idx = data.find(b"070701", pos)
        if idx == -1:
            break

        try:
            ino = int(data[idx + 6:idx + 14].decode("ascii"), 16)
            mode = int(data[idx + 14:idx + 22].decode("ascii"), 16)
            uid = int(data[idx + 22:idx + 30].decode("ascii"), 16)
            gid = int(data[idx + 30:idx + 38].decode("ascii"), 16)
            nlink = int(data[idx + 38:idx + 46].decode("ascii"), 16)
            filesize = int(data[idx + 54:idx + 62].decode("ascii"), 16)
            namesize = int(data[idx + 94:idx + 102].decode("ascii"), 16)
        except (ValueError, UnicodeDecodeError):
            pos = idx + 6
            continue

        if namesize <= 0 or namesize > 512:
            pos = idx + 6
            continue

        name_start = idx + 110
        try:
            name = data[name_start:name_start + namesize - 1].decode("ascii", errors="replace")
        except:
            pos = idx + 6
            continue

        # Align data start to 4 bytes
        data_start = (name_start + namesize + 3) & ~3
        data_end = data_start + filesize
        data_end_aligned = (data_end + 3) & ~3

        if name == "TRAILER!!!":
            entries.append({"name": name, "pos": idx, "size": 0,
                            "mode": 0, "type": "trailer"})
            pos = data_end_aligned
            continue

        is_dir = (mode & 0o170000) == 0o040000
        is_file = (mode & 0o170000) == 0o100000
        is_link = (mode & 0o170000) == 0o120000
        perms = mode & 0o7777

        entry = {
            "name": name, "pos": idx, "size": filesize,
            "mode": mode, "perms": perms, "uid": uid, "gid": gid,
            "is_dir": is_dir, "is_file": is_file, "is_link": is_link,
        }

        if is_file and filesize > 0 and data_start + filesize <= len(data):
            file_data = data[data_start:data_start + filesize]
            entry["data_offset"] = data_start

            # Save to disk
            out_path = OUT_DIR / name
            out_path.parent.mkdir(parents=True, exist_ok=True)

            # Handle duplicate names (append offset)
            if out_path.exists():
                out_path = OUT_DIR / f"{name}.0x{idx:08X}"
                out_path.parent.mkdir(parents=True, exist_ok=True)

            out_path.write_bytes(file_data)

            # Detect file type
            if file_data[:4] == b"\x7fELF":
                entry["type"] = "elf"
            elif file_data[:2] == b"#!":
                entry["type"] = "script"
            else:
                entry["type"] = "data"

            # Check for SUID
            if perms & 0o4000:
                entry["suid"] = True
                add_finding(f"F-HK4-SUID-{name.replace('/', '_')[:20]}",
                            "HIGH", f"SUID binary: {name} (perms={perms:04o})",
                            f"SUID bit set on {name}.", name)

        elif is_link and filesize > 0 and data_start + filesize <= len(data):
            target = data[data_start:data_start + filesize].decode(
                "ascii", errors="replace")
            entry["type"] = "symlink"
            entry["target"] = target

        elif is_dir:
            entry["type"] = "directory"
            dir_path = OUT_DIR / name
            dir_path.mkdir(parents=True, exist_ok=True)

        entries.append(entry)
        pos = data_end_aligned

    print(f"\n  Total entries: {len(entries)}")

    # Statistics
    type_counts = Counter(e.get("type", "unknown") for e in entries)
    for t, c in type_counts.most_common():
        print(f"    {t}: {c}")

    return entries


def analyze_extracted(entries):
    """Analyze extracted filesystem."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  FILESYSTEM ANALYSIS")
    print(sep)

    # 1. Check passwd/shadow
    print("\n  --- /etc/passwd & /etc/shadow ---")
    for name in ["etc/passwd", "etc/shadow", "etc/group"]:
        path = OUT_DIR / name
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            print(f"\n  [{name}]:")
            print(f"  {content.strip()}")

            if "shadow" in name:
                for line in content.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] and parts[1] != "*" and parts[1] != "!":
                        add_finding(f"F-HK4-SHADOW-{parts[0]}", "CRITICAL",
                                    f"Password hash for {parts[0]}: {parts[1][:30]}...",
                                    f"Default password hash in firmware.",
                                    line[:200])

            if "passwd" in name:
                for line in content.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 7:
                        user, pwd, uid_s = parts[0], parts[1], parts[2]
                        if uid_s == "0":
                            add_finding(f"F-HK4-ROOT-{user}", "HIGH",
                                        f"Root-level user: {user} (uid=0)",
                                        f"User with UID 0 in /etc/passwd.",
                                        line[:200])
        else:
            # Check with offset-suffixed names
            for f in OUT_DIR.glob(f"{name}.*"):
                content = f.read_text(encoding="utf-8", errors="replace")
                print(f"\n  [{f.name}]:")
                print(f"  {content.strip()[:500]}")

    # 2. ELF binary analysis
    print(f"\n  --- ELF BINARY ANALYSIS ---")
    elf_entries = [e for e in entries if e.get("type") == "elf"]
    print(f"  ELF binaries found: {len(elf_entries)}")

    try:
        import lief
        has_lief = True
    except ImportError:
        has_lief = False

    dangerous_imports = {
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
    }

    for e in sorted(elf_entries, key=lambda x: x["size"], reverse=True):
        name = e["name"]
        path = OUT_DIR / name
        if not path.exists():
            for p in OUT_DIR.glob(f"{name}.*"):
                path = p
                break

        if not path.exists():
            continue

        elf_data = path.read_bytes()
        sz_kb = len(elf_data) // 1024
        print(f"\n    {name} ({sz_kb} KB)")

        if has_lief:
            try:
                binary = lief.parse(str(path))
                if binary is None:
                    continue

                arch = str(binary.header.machine_type).split(".")[-1]
                imports = [s.name for s in binary.imported_symbols if s.name]
                dangerous = [i for i in imports if i in dangerous_imports]

                nx = binary.has_nx if hasattr(binary, "has_nx") else True
                pie = binary.is_pie if hasattr(binary, "is_pie") else False

                issues = []
                if dangerous:
                    issues.append(f"DANGER:{','.join(set(dangerous))}")
                if not nx:
                    issues.append("NO-NX")
                if not pie:
                    issues.append("NO-PIE")

                if issues:
                    print(f"      {arch} | {' | '.join(issues)}")
                    if dangerous:
                        dlist = ", ".join(set(dangerous))
                        add_finding(
                            f"F-HK4-ELF-{os.path.basename(name)[:12].upper()}",
                            "MEDIUM",
                            f"Dangerous imports in {name}: {dlist}",
                            f"Binary imports exploitable functions.", dlist)
                    if not nx:
                        add_finding(
                            f"F-HK4-NO-NX-{os.path.basename(name)[:12].upper()}",
                            "HIGH",
                            f"No NX in {name}",
                            "Executable stack allows shellcode.", name)
            except Exception as ex:
                print(f"      LIEF error: {ex}")

        # String analysis for each binary
        strings = re.findall(rb"[\x20-\x7e]{10,}", elf_data)
        sec_count = 0
        for s in strings:
            d = s.decode("ascii", errors="replace")
            dl = d.lower()
            if any(k in dl for k in ["password", "backdoor", "secret", "token",
                                      "hardcoded", "default"]):
                print(f"      STR: {d[:100]}")
                sec_count += 1
                if sec_count >= 5:
                    break

    # 3. Shell scripts
    print(f"\n  --- SHELL SCRIPTS ---")
    script_entries = [e for e in entries if e.get("type") == "script"]
    print(f"  Scripts found: {len(script_entries)}")

    for e in script_entries:
        name = e["name"]
        path = OUT_DIR / name
        if not path.exists():
            continue

        content = path.read_text(encoding="utf-8", errors="replace")
        issues = []
        if "chmod 777" in content:
            issues.append("chmod 777")
        if "telnetd" in content.lower():
            issues.append("telnetd")
        if "dropbear" in content.lower():
            issues.append("dropbear SSH")
        if re.search(r"password|passwd", content, re.I):
            issues.append("password ref")

        if issues:
            print(f"    {name}: {', '.join(issues)}")
            for issue in issues:
                add_finding(
                    f"F-HK4-SCRIPT-{os.path.basename(name)[:10].upper()}",
                    "MEDIUM", f"Script {name}: {issue}",
                    f"Security issue in init script.", issue)

    # 4. Config files
    print(f"\n  --- CONFIG FILES ---")
    for e in entries:
        name = e.get("name", "")
        if name.endswith((".conf", ".cfg", ".ini", ".json")):
            path = OUT_DIR / name
            if path.exists():
                content = path.read_text(encoding="utf-8", errors="replace")
                print(f"    {name}: {len(content)} bytes")
                if any(k in content.lower() for k in ["password", "secret",
                                                        "key", "token"]):
                    print(f"      !!! Contains sensitive data")
                    add_finding(f"F-HK4-CONF-{os.path.basename(name)[:12]}",
                                "HIGH", f"Sensitive config: {name}",
                                "Configuration file with credentials.", "")


def generate_report():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"
    sev_counts = Counter(f["severity"] for f in findings)

    lines = [
        "# Hikvision V4.62 NVR — Initramfs Forensic Analysis",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "> Source: Embedded initramfs from Linux-3.10.0_hi3536 kernel",
        f"> Findings: {len(findings)}",
        "",
        "---",
        "",
    ]

    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0):
            lines.append(f"- **{s}**: {sev_counts[s]}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1,
                                              "MEDIUM": 2, "LOW": 3,
                                              "INFO": 4}.get(x["severity"], 5)):
        lines.append(f"### {f['id']}")
        lines.append(f"- **Severity**: {f['severity']}")
        lines.append(f"- **Title**: {f['title']}")
        lines.append(f"- **Detail**: {f['detail']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines.append("---")
    lines.append("*Andre Henrique (@mrhenrike) | Uniao Geek*")

    path = REPORTS_DIR / "initramfs_forensic_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "initramfs_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str),
                         encoding="utf-8")


if __name__ == "__main__":
    entries = extract_cpio()
    analyze_extracted(entries)
    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")
