#!/usr/bin/env python3
"""
binary_deep_analysis.py — Deep binary analysis using lief, capstone, pefile
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Performs assembly-level analysis of ELF binaries extracted from firmware:
  - LIEF: parse ELF headers, sections, symbols, imports, security features
  - Capstone: disassemble critical functions, find dangerous patterns
"""
from __future__ import annotations

import gzip
import io
import json
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import lief
import capstone

REPO_ROOT = Path(__file__).resolve().parent.parent
TMP_DIR = REPO_ROOT / ".tmp" / "binary_analysis"
TMP_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR = REPO_ROOT / "reports"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

findings: list[dict[str, Any]] = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:2000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid} ({sev}): {title}")


def extract_mikrotik_image() -> Path:
    src = REPO_ROOT / "downloads" / "router" / "mikrotik" / "chr-7.22.1.img.zip"
    dst = TMP_DIR / "chr-7.22.1.img"
    if not dst.exists():
        print("  Extracting MikroTik disk image...")
        with zipfile.ZipFile(src) as z:
            for name in z.namelist():
                if name.endswith(".img"):
                    dst.write_bytes(z.read(name))
                    break
    sz_mb = dst.stat().st_size // 1024 // 1024
    print(f"  Image: {dst.name} ({sz_mb} MB)")
    return dst


def extract_openwrt_image() -> Path:
    src = REPO_ROOT / "downloads" / "router" / "openwrt" / "openwrt-25.12.1-x86-64-generic-ext4-combined-efi.img.gz"
    dst = TMP_DIR / "openwrt-25.12.1-x86-64.img"
    if not dst.exists():
        print("  Decompressing OpenWrt image...")
        with gzip.open(src, "rb") as fin:
            dst.write_bytes(fin.read())
    sz_mb = dst.stat().st_size // 1024 // 1024
    print(f"  Image: {dst.name} ({sz_mb} MB)")
    return dst


def extract_elf_from_disk(data: bytes) -> list[dict[str, Any]]:
    ELF_MAGIC = b"\x7fELF"
    elfs = []
    pos = 0
    while pos < len(data) - 4:
        idx = data.find(ELF_MAGIC, pos)
        if idx == -1:
            break
        if idx + 64 > len(data):
            break
        ei_class = data[idx + 4]
        if ei_class == 1:
            if idx + 52 > len(data):
                pos = idx + 4
                continue
            e_shoff = struct.unpack_from("<I", data, idx + 32)[0]
            e_shentsize = struct.unpack_from("<H", data, idx + 46)[0]
            e_shnum = struct.unpack_from("<H", data, idx + 48)[0]
        elif ei_class == 2:
            if idx + 64 > len(data):
                pos = idx + 4
                continue
            e_shoff = struct.unpack_from("<Q", data, idx + 40)[0]
            e_shentsize = struct.unpack_from("<H", data, idx + 58)[0]
            e_shnum = struct.unpack_from("<H", data, idx + 60)[0]
        else:
            pos = idx + 4
            continue
        elf_size = max(e_shoff + e_shentsize * e_shnum, 4096)
        if elf_size > 50 * 1024 * 1024:
            pos = idx + 4
            continue
        elf_end = min(idx + elf_size, len(data))
        elf_data = data[idx:elf_end]
        elfs.append({
            "offset": idx,
            "size": len(elf_data),
            "data": elf_data,
            "bits": 32 if ei_class == 1 else 64,
        })
        pos = elf_end
        if len(elfs) >= 50:
            break
    return elfs


def analyze_elf_with_lief(elf_data: bytes, label: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {"label": label, "issues": []}
    try:
        binary = lief.parse(elf_data)
        if binary is None:
            return result
        header = binary.header
        result["machine"] = str(header.machine_type)
        result["type"] = str(header.file_type)
        result["entrypoint"] = hex(header.entrypoint)
        result["bits"] = 64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32

        result["sections"] = []
        for section in binary.sections:
            result["sections"].append({
                "name": section.name,
                "size": section.size,
                "type": str(section.type),
            })

        dangerous_imports = {
            "system", "popen", "execve", "execvp", "execl",
            "sprintf", "strcpy", "strcat", "gets", "scanf",
            "mktemp", "tmpnam",
        }
        result["imports"] = []
        result["dangerous_imports"] = []
        for sym in binary.imported_symbols:
            name = sym.name
            result["imports"].append(name)
            if name in dangerous_imports:
                result["dangerous_imports"].append(name)

        if result["dangerous_imports"]:
            for fname in set(result["dangerous_imports"]):
                add_finding(
                    f"F-BIN-{fname.upper()}-0x{result.get('offset', 0) or 0:06X}",
                    "MEDIUM",
                    f"Dangerous import: {fname}() in {label}",
                    f"Binary imports {fname}() - potential buffer overflow or command injection.",
                    f"Binary: {label}",
                )

        result["exports"] = [sym.name for sym in binary.exported_symbols][:50]

        result["nx"] = binary.has_nx if hasattr(binary, 'has_nx') else True
        result["pie"] = binary.is_pie if hasattr(binary, 'is_pie') else False

        has_relro = False
        full_relro = False
        for seg in binary.segments:
            if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                has_relro = True
        for d in binary.dynamic_entries:
            if d.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                if hasattr(d, 'value') and d.value & 0x8:
                    full_relro = True
        result["relro"] = "full" if full_relro else ("partial" if has_relro else "none")

        if not result["nx"]:
            add_finding(
                f"F-BIN-NO-NX-0x{result.get('offset',0) or 0:06X}", "HIGH",
                f"No NX protection: {label}",
                "Executable stack. Direct shellcode execution via buffer overflow.",
                f"Binary: {label}",
            )
        if not result["pie"]:
            add_finding(
                f"F-BIN-NO-PIE-0x{result.get('offset',0) or 0:06X}", "MEDIUM",
                f"No PIE: {label}",
                "Fixed load address. ROP and return-to-libc attacks easier.",
                f"Binary: {label}",
            )
    except Exception as e:
        result["error"] = str(e)
    return result


def disassemble_entry(elf_data: bytes, bits: int = 64, count: int = 30) -> list[str]:
    try:
        binary = lief.parse(elf_data)
        if binary is None:
            return []
        entry = binary.header.entrypoint
        entry_section = None
        for section in binary.sections:
            if section.virtual_address <= entry < section.virtual_address + section.size:
                entry_section = section
                break
        if entry_section is None:
            return []
        offset = entry - entry_section.virtual_address
        code = bytes(entry_section.content)[offset:offset + 500]
        if bits == 64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        return [f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                for insn in list(md.disasm(code, entry))[:count]]
    except Exception as e:
        return [f"Error: {e}"]


def analyze_target(name: str, img_path: Path):
    print(f"\n{'='*70}")
    print(f"  {name} -- DEEP BINARY ANALYSIS")
    print(f"{'='*70}")

    data = img_path.read_bytes()
    print(f"  Image size: {len(data) // 1024 // 1024} MB")

    print("  Searching for ELF binaries...")
    elfs = extract_elf_from_disk(data)
    print(f"  Found {len(elfs)} ELF binaries")

    results = []
    for i, elf in enumerate(elfs[:30]):
        sz_kb = elf['size'] // 1024
        label = f"ELF@0x{elf['offset']:08X}_{sz_kb}KB"
        print(f"\n  [{i+1}/{min(len(elfs), 30)}] {label} ({elf['bits']}-bit, {sz_kb} KB)")

        r = analyze_elf_with_lief(elf["data"], label)
        r["offset"] = elf["offset"]
        r["size"] = elf["size"]

        if r.get("imports"):
            print(f"    Imports: {len(r['imports'])}")
        if r.get("dangerous_imports"):
            print(f"    !!! Dangerous: {', '.join(r['dangerous_imports'])}")

        nx = r.get("nx", "?")
        pie = r.get("pie", "?")
        relro = r.get("relro", "?")
        print(f"    Security: NX={nx} PIE={pie} RELRO={relro}")

        machine = str(r.get("machine", ""))
        if elf["bits"] == 64 and "X86_64" in machine:
            asm = disassemble_entry(elf["data"], 64, 10)
            if asm and not asm[0].startswith("Error"):
                r["entry_asm"] = asm
                print(f"    Entry ASM: {asm[0]}")

        results.append(r)

    return results


def generate_report(target_name, target_id, results):
    report_dir = REPORTS_DIR / target_id
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / "binary_analysis_report.md"
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    lines = [
        f"# {target_name} -- Deep Binary Analysis Report",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        f"> Tools: LIEF {lief.__version__}, Capstone {capstone.CS_VERSION_MAJOR}.{capstone.CS_VERSION_MINOR}",
        "", "---", "",
        "## Summary", "",
        f"- ELF binaries analyzed: {len(results)}",
        f"- Without NX: {sum(1 for r in results if not r.get('nx'))}",
        f"- Without PIE: {sum(1 for r in results if not r.get('pie'))}",
        f"- Without RELRO: {sum(1 for r in results if r.get('relro') == 'none')}",
        f"- With dangerous imports: {sum(1 for r in results if r.get('dangerous_imports'))}",
        "",
    ]

    all_dangerous = Counter()
    for r in results:
        for imp in r.get("dangerous_imports", []):
            all_dangerous[imp] += 1
    if all_dangerous:
        lines += ["## Most Common Dangerous Imports", ""]
        for func, cnt in all_dangerous.most_common(10):
            lines.append(f"- `{func}()`: found in {cnt} binaries")
        lines.append("")

    lines += ["## Binary Details", ""]
    for r in results:
        label = r.get("label", "?")
        lines += [
            f"### {label}", "",
            "| Property | Value |",
            "|----------|-------|",
            f"| Offset | `0x{r.get('offset', 0):08X}` |",
            f"| Size | {r.get('size', 0):,} bytes |",
            f"| Arch | {r.get('machine', '?')} |",
            f"| Type | {r.get('type', '?')} |",
            f"| NX | {r.get('nx', '?')} |",
            f"| PIE | {r.get('pie', '?')} |",
            f"| RELRO | {r.get('relro', '?')} |",
            "",
        ]
        if r.get("dangerous_imports"):
            di = ', '.join(r['dangerous_imports'])
            lines.append(f"**Dangerous imports**: `{di}`\n")
        if r.get("entry_asm"):
            lines += ["```asm"]
            for a in r["entry_asm"][:10]:
                lines.append(a)
            lines += ["```", ""]

    lines += [
        "---",
        "*Binary Analysis Engine | Embedded Firmware Research Lab*",
        "*Andre Henrique (@mrhenrike) | Uniao Geek*",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [OK] Report: {path}")


if __name__ == "__main__":
    print(f"\n{'='*70}")
    print(f"  DEEP BINARY ANALYSIS ENGINE")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")

    mt_img = extract_mikrotik_image()
    mt_results = analyze_target("MikroTik CHR 7.22.1", mt_img)
    generate_report("MikroTik CHR 7.22.1", "mikrotik_routeros_7221", mt_results)

    ow_img = extract_openwrt_image()
    ow_results = analyze_target("OpenWrt 25.12.1 x86-64", ow_img)
    generate_report("OpenWrt 25.12.1 x86-64", "openwrt_25121_x86", ow_results)

    fpath = REPORTS_DIR / "binary_analysis_findings.json"
    fpath.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")

    total = len(mt_results) + len(ow_results)
    print(f"\n{'='*70}")
    print(f"  COMPLETE: {len(findings)} findings across {total} binaries")
    for f in findings:
        sev = f['severity']
        ttl = f['title'][:60]
        print(f"    [{sev:8s}] {f['id']}: {ttl}")
    print(f"{'='*70}")
