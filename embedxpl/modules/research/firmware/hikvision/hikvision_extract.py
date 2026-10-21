#!/usr/bin/env python3
"""
hikvision_extract.py — Extract and analyze Hikvision .dav firmware
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Parses the proprietary Hikvision digicap.dav container format:
  - Scans for squashfs, uImage, cramfs, ELF signatures
  - Extracts embedded filesystems
  - Inventories all binaries and performs security analysis
"""
from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TMP_DIR = Path(__file__).resolve().parent.parent / ".tmp" / "hikvision_g5"
DAV_FILE = TMP_DIR / "digicap.dav"
EXTRACT_DIR = TMP_DIR / "extracted"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports" / "hikvision_g5_v5719"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings: list[dict[str, Any]] = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def phase1_scan_dav():
    """Scan the DAV file for embedded filesystem signatures."""
    print("\n" + "=" * 70)
    print("  PHASE 1: DAV CONTAINER ANALYSIS")
    print("=" * 70)

    data = DAV_FILE.read_bytes()
    print(f"\n  File: {DAV_FILE.name}")
    print(f"  Size: {len(data):,} bytes ({len(data) // 1024 // 1024} MB)")
    print(f"  First 16 bytes: {data[:16].hex()}")
    print(f"  First DWORD (LE): 0x{struct.unpack('<I', data[:4])[0]:08X}")

    results = {"size": len(data), "signatures": {}}

    # SquashFS: 'hsqs' (LE) or 'sqsh' (BE)
    sqsh = []
    for magic in [b"hsqs", b"sqsh"]:
        pos = 0
        while pos < len(data):
            idx = data.find(magic, pos)
            if idx == -1:
                break
            sqsh.append({"offset": idx, "magic": magic.decode()})
            pos = idx + 4
    results["signatures"]["squashfs"] = sqsh
    print(f"\n  SquashFS signatures: {len(sqsh)}")
    for s in sqsh:
        # Parse squashfs superblock
        off = s["offset"]
        if off + 96 <= len(data):
            sb_inodes = struct.unpack_from("<I", data, off + 4)[0]
            sb_bytes = struct.unpack_from("<Q", data, off + 40)[0]
            sb_root_inode = struct.unpack_from("<Q", data, off + 48)[0]
            s["inodes"] = sb_inodes
            s["bytes_used"] = sb_bytes
            print(f"    @ 0x{off:08X}: {sb_inodes} inodes, "
                  f"{sb_bytes:,} bytes ({sb_bytes // 1024 // 1024} MB)")

    # uImage header: 0x27051956
    uimgs = []
    pos = 0
    while pos < len(data) - 64:
        idx = data.find(b"\x27\x05\x19\x56", pos)
        if idx == -1:
            break
        ih_size = struct.unpack(">I", data[idx + 12:idx + 16])[0]
        ih_load = struct.unpack(">I", data[idx + 16:idx + 20])[0]
        ih_ep = struct.unpack(">I", data[idx + 20:idx + 24])[0]
        ih_name = data[idx + 32:idx + 64].split(b"\x00")[0].decode("ascii", errors="replace")
        uimgs.append({"offset": idx, "size": ih_size, "load": ih_load,
                       "entry": ih_ep, "name": ih_name})
        pos = idx + 64
    results["signatures"]["uimage"] = uimgs
    print(f"\n  uImage headers: {len(uimgs)}")
    for u in uimgs:
        print(f"    @ 0x{u['offset']:08X}: size={u['size']:,} "
              f"load=0x{u['load']:08X} entry=0x{u['entry']:08X} "
              f"name=\"{u['name']}\"")

    # ELF binaries
    elfs = []
    pos = 0
    while pos < len(data) - 16:
        idx = data.find(b"\x7fELF", pos)
        if idx == -1:
            break
        ei_class = data[idx + 4] if idx + 4 < len(data) else 0
        ei_data = data[idx + 5] if idx + 5 < len(data) else 0
        bits = {1: 32, 2: 64}.get(ei_class, 0)
        endian = {1: "LE", 2: "BE"}.get(ei_data, "?")
        if bits > 0:
            elfs.append({"offset": idx, "bits": bits, "endian": endian})
        pos = idx + 4
        if len(elfs) >= 200:
            break
    results["signatures"]["elf"] = elfs
    print(f"\n  ELF binaries found: {len(elfs)}")
    if elfs:
        print(f"    First: @ 0x{elfs[0]['offset']:08X} "
              f"({elfs[0]['bits']}-bit {elfs[0]['endian']})")
        print(f"    Last:  @ 0x{elfs[-1]['offset']:08X} "
              f"({elfs[-1]['bits']}-bit {elfs[-1]['endian']})")
        endian_counts = Counter(e["endian"] for e in elfs)
        bits_counts = Counter(e["bits"] for e in elfs)
        print(f"    Endian distribution: {dict(endian_counts)}")
        print(f"    Bits distribution: {dict(bits_counts)}")

    # CramFS
    cramfs = []
    pos = 0
    while pos < len(data) - 4:
        idx = data.find(b"\x45\x3d\xcd\x28", pos)
        if idx == -1:
            break
        cramfs.append(idx)
        pos = idx + 4
    results["signatures"]["cramfs"] = cramfs
    if cramfs:
        print(f"\n  CramFS signatures: {len(cramfs)}")

    # JFFS2
    jffs2 = data.count(b"\x85\x19")
    if jffs2 > 10:
        print(f"\n  JFFS2 markers: {jffs2}")
        results["signatures"]["jffs2_markers"] = jffs2

    return data, results


def phase2_extract_squashfs(data, scan_results):
    """Extract squashfs filesystems using binwalk or manual extraction."""
    print("\n" + "=" * 70)
    print("  PHASE 2: EXTRACT FILESYSTEMS")
    print("=" * 70)

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

    sqsh_list = scan_results["signatures"].get("squashfs", [])
    if not sqsh_list:
        print("  No SquashFS found. Trying binwalk on entire DAV...")
        try:
            subprocess.run(
                ["binwalk", "-e", "-C", str(EXTRACT_DIR), str(DAV_FILE)],
                capture_output=True, text=True, timeout=120)
        except Exception as e:
            print(f"  binwalk failed: {e}")
        return

    for i, sq in enumerate(sqsh_list):
        off = sq["offset"]
        sz = sq.get("bytes_used", 0)
        if sz == 0:
            sz = min(len(data) - off, 100 * 1024 * 1024)

        sqfs_path = EXTRACT_DIR / f"squashfs_{i}_0x{off:08X}.sqfs"
        sqfs_path.write_bytes(data[off:off + sz])
        print(f"\n  Extracted squashfs #{i}: {sqfs_path.name} ({sz:,} bytes)")

        # Try unsquashfs
        out_dir = EXTRACT_DIR / f"squashfs_{i}_root"
        try:
            r = subprocess.run(
                ["unsquashfs", "-d", str(out_dir), "-f", str(sqfs_path)],
                capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                count = sum(1 for _ in out_dir.rglob("*") if _.is_file())
                print(f"  Extracted {count} files to {out_dir.name}/")
            else:
                print(f"  unsquashfs failed: {r.stderr[:200]}")
                # Try binwalk as fallback
                print("  Trying binwalk fallback...")
                subprocess.run(
                    ["binwalk", "-e", "-C", str(EXTRACT_DIR),
                     str(sqfs_path)],
                    capture_output=True, text=True, timeout=120)
        except FileNotFoundError:
            print("  unsquashfs not found, trying binwalk...")
            try:
                subprocess.run(
                    ["binwalk", "-e", "-C", str(EXTRACT_DIR),
                     str(sqfs_path)],
                    capture_output=True, text=True, timeout=120)
            except FileNotFoundError:
                print("  Neither unsquashfs nor binwalk available.")
                print("  Will analyze squashfs raw data directly.")


def phase2b_binwalk_full(data):
    """Run binwalk on the full DAV file as alternative extraction."""
    print("\n  Running binwalk on full DAV file...")
    try:
        r = subprocess.run(
            ["binwalk", "-e", "-C", str(EXTRACT_DIR), str(DAV_FILE)],
            capture_output=True, text=True, timeout=300)
        print(f"  binwalk stdout: {r.stdout[:500]}")
        if r.returncode != 0:
            print(f"  binwalk stderr: {r.stderr[:300]}")
    except FileNotFoundError:
        print("  binwalk not available.")
    except subprocess.TimeoutExpired:
        print("  binwalk timed out (5 min)")


def phase3_inventory():
    """Inventory all extracted files."""
    print("\n" + "=" * 70)
    print("  PHASE 3: FILESYSTEM INVENTORY")
    print("=" * 70)

    roots = list(EXTRACT_DIR.glob("*_root")) + list(EXTRACT_DIR.glob("*extracted*"))
    if not roots:
        roots = [EXTRACT_DIR]

    all_files = []
    for root in roots:
        for f in root.rglob("*"):
            if f.is_file():
                try:
                    sz = f.stat().st_size
                except OSError:
                    sz = 0
                rel = str(f.relative_to(root))
                all_files.append({"path": rel, "size": sz, "abs": str(f)})

    print(f"\n  Total files: {len(all_files)}")

    # Categorize
    categories = {
        "ELF binaries": [],
        "Shell scripts": [],
        "Config files": [],
        "Libraries (.so)": [],
        "Web files": [],
        "Certificates/Keys": [],
        "Other": [],
    }

    for f in all_files:
        p = f["path"].lower()
        if p.endswith(".so") or ".so." in p:
            categories["Libraries (.so)"].append(f)
        elif p.endswith((".sh", ".ash")):
            categories["Shell scripts"].append(f)
        elif p.endswith((".conf", ".cfg", ".ini", ".xml", ".json")):
            categories["Config files"].append(f)
        elif p.endswith((".html", ".htm", ".js", ".css", ".cgi")):
            categories["Web files"].append(f)
        elif p.endswith((".pem", ".crt", ".key", ".cert")):
            categories["Certificates/Keys"].append(f)
        elif f["size"] > 1000:
            # Check if ELF
            try:
                with open(f["abs"], "rb") as fh:
                    magic = fh.read(4)
                if magic == b"\x7fELF":
                    categories["ELF binaries"].append(f)
                    continue
            except:
                pass
            categories["Other"].append(f)
        else:
            categories["Other"].append(f)

    for cat, files in categories.items():
        if files:
            print(f"\n  {cat}: {len(files)}")
            sorted_files = sorted(files, key=lambda x: x["size"], reverse=True)
            for f in sorted_files[:15]:
                sz_kb = f["size"] // 1024
                print(f"    {sz_kb:6d} KB  {f['path']}")
            if len(files) > 15:
                print(f"    ... and {len(files) - 15} more")

    # Security-relevant files
    print("\n  --- SECURITY-RELEVANT FILES ---")
    sec_patterns = [
        "passwd", "shadow", "sudoers", "ssh", "ssl", "cert",
        "key", "token", "secret", "cred", "auth", "login",
        "webcore", "hicore", "ipc_web", "davinci", "hik",
        "sadp", "onvif", "rtsp", "isapi",
    ]
    for f in all_files:
        name = os.path.basename(f["path"]).lower()
        path_lower = f["path"].lower()
        for pat in sec_patterns:
            if pat in name or pat in path_lower:
                sz_kb = f["size"] // 1024
                print(f"    [{pat:10s}] {sz_kb:6d} KB  {f['path']}")
                break

    return all_files, categories


def phase4_binary_analysis(all_files, categories):
    """Deep analysis of key binaries."""
    print("\n" + "=" * 70)
    print("  PHASE 4: BINARY ANALYSIS")
    print("=" * 70)

    try:
        import lief
        import capstone
        has_lief = True
    except ImportError:
        has_lief = False
        print("  WARNING: lief/capstone not available, using basic analysis")

    elfs = categories.get("ELF binaries", [])
    print(f"\n  ELF binaries to analyze: {len(elfs)}")

    dangerous_imports = {
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
        "mktemp", "tmpnam", "realpath",
    }

    results = []
    for f in sorted(elfs, key=lambda x: x["size"], reverse=True)[:30]:
        try:
            elf_data = Path(f["abs"]).read_bytes()
        except:
            continue

        r = {"path": f["path"], "size": f["size"]}
        name = os.path.basename(f["path"])
        print(f"\n  --- {name} ({f['size'] // 1024} KB) ---")

        if has_lief:
            try:
                binary = lief.parse(elf_data)
                if binary is None:
                    continue

                r["machine"] = str(binary.header.machine_type)
                r["type"] = str(binary.header.file_type)
                r["bits"] = 32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else 64
                print(f"    Arch: {r['machine']} {r['bits']}-bit {r['type']}")

                # Imports
                imports = [sym.name for sym in binary.imported_symbols]
                r["imports_count"] = len(imports)
                r["dangerous"] = [i for i in imports if i in dangerous_imports]
                if r["dangerous"]:
                    dlist = ", ".join(set(r["dangerous"]))
                    print(f"    !!! DANGEROUS IMPORTS: {dlist}")
                    add_finding(
                        f"F-HK-DANGER-{name[:20].upper()}", "MEDIUM",
                        f"Dangerous imports in {name}: {dlist}",
                        f"Binary {name} imports {len(r['dangerous'])} dangerous "
                        f"functions: {dlist}. These could be exploitable if user "
                        "input reaches them without validation.",
                        dlist,
                    )

                # Exports
                r["exports"] = [sym.name for sym in binary.exported_symbols][:50]

                # Security features
                r["nx"] = binary.has_nx if hasattr(binary, "has_nx") else True
                r["pie"] = binary.is_pie if hasattr(binary, "is_pie") else False

                has_relro = False
                for seg in binary.segments:
                    if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                        has_relro = True
                r["relro"] = "partial" if has_relro else "none"

                sec_str = f"NX={r['nx']} PIE={r['pie']} RELRO={r['relro']}"
                print(f"    Security: {sec_str}")

                if not r["nx"]:
                    add_finding(
                        f"F-HK-NO-NX-{name[:20].upper()}", "HIGH",
                        f"No NX in {name} ({f['size'] // 1024} KB)",
                        "Executable stack allows direct shellcode execution.",
                        name)
                if not r["pie"]:
                    add_finding(
                        f"F-HK-NO-PIE-{name[:20].upper()}", "MEDIUM",
                        f"No PIE in {name}",
                        "Fixed base address makes ROP/ret2libc easier.",
                        name)

            except Exception as e:
                print(f"    LIEF error: {e}")
                r["error"] = str(e)
        else:
            # Basic analysis without LIEF
            if b"system\x00" in elf_data:
                print("    Contains 'system' call")
            if b"strcpy\x00" in elf_data:
                print("    Contains 'strcpy' (buffer overflow risk)")

        results.append(r)

    return results


def phase5_string_analysis(all_files):
    """Hunt for credentials, keys, and interesting strings."""
    print("\n" + "=" * 70)
    print("  PHASE 5: STRING ANALYSIS & CREDENTIAL HUNTING")
    print("=" * 70)

    import re

    patterns = {
        "HARDCODED_PASS": re.compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[\w!@#$%^&*]{3,}", re.I),
        "HARDCODED_KEY": re.compile(
            r"(?:api.?key|secret.?key|private.?key|access.?key)\s*[=:]\s*['\"]?\w{8,}", re.I),
        "PRIVATE_KEY_PEM": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "BACKDOOR_USER": re.compile(
            r"(?:backdoor|debug|test|admin|root|supervisor):\$[156]\$", re.I),
        "COMMAND_INJECTION": re.compile(
            r"(?:system|popen|exec)\s*\(\s*[\"'][^\"']*\$"),
        "SQL_INJECTION": re.compile(
            r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:WHERE|SET)\s+.*['\"]?\s*\+", re.I),
        "ISAPI_HANDLER": re.compile(r"/ISAPI/\w+", re.I),
        "SDK_ENDPOINT": re.compile(r"/SDK/\w+", re.I),
        "HTTP_ENDPOINT": re.compile(r"(?:GET|POST|PUT|DELETE)\s+/\w+"),
        "CRYPTO_CONST": re.compile(r"(?:AES|DES|RSA|SHA[12]|MD5|HMAC)", re.I),
        "IP_HARDCODED": re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
        "URL_INTERNAL": re.compile(r"https?://(?:localhost|127\.0\.0\.1|internal)", re.I),
    }

    # Focus on key binaries
    key_names = ["webcore", "hicore", "ipc_web", "davinci", "httpd",
                 "sadpd", "rtspd", "pppoe", "udhcpc", "dropbear"]

    targets = []
    for f in all_files:
        name = os.path.basename(f["path"]).lower()
        if any(k in name for k in key_names) or f["size"] > 500000:
            targets.append(f)

    # Also check passwd/shadow
    for f in all_files:
        if os.path.basename(f["path"]) in ("passwd", "shadow", "group"):
            targets.append(f)

    # Also check config files
    for f in all_files:
        if f["path"].lower().endswith((".conf", ".cfg", ".xml", ".ini")):
            if f["size"] > 0 and f["size"] < 1000000:
                targets.append(f)

    # Deduplicate
    seen = set()
    unique_targets = []
    for t in targets:
        if t["abs"] not in seen:
            seen.add(t["abs"])
            unique_targets.append(t)

    print(f"\n  Scanning {len(unique_targets)} files for secrets and patterns...\n")

    for f in unique_targets:
        try:
            raw = Path(f["abs"]).read_bytes()
        except:
            continue

        # Extract printable strings (min 6 chars)
        strings = re.findall(rb"[\x20-\x7e]{6,}", raw)
        if not strings:
            continue

        name = os.path.basename(f["path"])
        file_hits = {}
        for s in strings:
            try:
                text = s.decode("ascii", errors="replace")
            except:
                continue
            for pat_name, pat_re in patterns.items():
                if pat_re.search(text):
                    if pat_name not in file_hits:
                        file_hits[pat_name] = []
                    if len(file_hits[pat_name]) < 5:
                        file_hits[pat_name].append(text[:120])

        if file_hits:
            print(f"  {name}:")
            for pat_name, hits in file_hits.items():
                for h in hits:
                    print(f"    [{pat_name}] {h}")
                    sev = "HIGH" if "PRIVATE_KEY" in pat_name or "BACKDOOR" in pat_name else "MEDIUM"
                    if "ISAPI" in pat_name or "SDK" in pat_name or "HTTP" in pat_name:
                        sev = "INFO"
                    add_finding(
                        f"F-HK-STR-{pat_name}-{name[:15].upper()}",
                        sev,
                        f"{pat_name} in {name}: {h[:60]}",
                        f"Pattern '{pat_name}' matched in {name}.",
                        h[:200],
                    )


def generate_report():
    """Generate the final forensic report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    lines = [
        "# Hikvision G5 Camera V5.7.19 — Deep Forensic Analysis Report",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "> Tools: LIEF, Capstone, binwalk, custom Python analysis",
        "",
        "---",
        "",
        f"## Summary: {len(findings)} findings",
        "",
    ]

    sev_counts = Counter(f["severity"] for f in findings)
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0) > 0:
            lines.append(f"- **{s}**: {sev_counts[s]}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                              "LOW": 3, "INFO": 4}.get(x["severity"], 5)):
        lines.append(f"### {f['id']}")
        lines.append(f"- **Severity**: {f['severity']}")
        lines.append(f"- **Title**: {f['title']}")
        lines.append(f"- **Detail**: {f['detail']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines += [
        "---",
        "*Hikvision G5 Forensic Analysis | Embedded Firmware Research Lab*",
        "*Andre Henrique (@mrhenrike) | Uniao Geek*",
    ]

    path = REPORTS_DIR / "forensic_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "forensic_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] JSON: {json_path}")


if __name__ == "__main__":
    print("=" * 70)
    print("  HIKVISION G5 CAMERA V5.7.19 — DEEP FORENSIC ANALYSIS")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    data, scan = phase1_scan_dav()
    phase2_extract_squashfs(data, scan)
    phase2b_binwalk_full(data)
    all_files, categories = phase3_inventory()
    if all_files:
        binary_results = phase4_binary_analysis(all_files, categories)
        phase5_string_analysis(all_files)
    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")
