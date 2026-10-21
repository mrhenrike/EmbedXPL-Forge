#!/usr/bin/env python3
"""
hikvision_re_binaries.py — Reverse engineering of key Hikvision binaries
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Focus on: ded (decryptor), psh (shell), hik_tool, hikefs
"""
from __future__ import annotations

import io
import os
import re
import sys
from pathlib import Path

import lief

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

BASE = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE / ".tmp" / "hikvision_v4_62" / "rootfs"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def analyze_binary(name: str):
    path = ROOT_DIR / name
    if not path.exists():
        print(f"  NOT FOUND: {name}")
        return

    data = path.read_bytes()
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  REVERSE ENGINEERING: {name} ({len(data):,} bytes)")
    print(sep)

    binary = lief.parse(str(path))
    if binary is None:
        print("  Failed to parse with LIEF")
        return

    # Header info
    arch = str(binary.header.machine_type).split(".")[-1]
    bits = 32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else 64
    entry = binary.header.entrypoint

    print(f"  Architecture: {arch} {bits}-bit")
    print(f"  Entry point: 0x{entry:08X}")

    has_nx = binary.has_nx if hasattr(binary, "has_nx") else "?"
    is_pie = binary.is_pie if hasattr(binary, "is_pie") else "?"
    print(f"  NX: {has_nx}")
    print(f"  PIE: {is_pie}")

    # Sections
    print(f"\n  Sections:")
    for sec in binary.sections:
        print(f"    {sec.name:20s} addr=0x{sec.virtual_address:08X} "
              f"size={sec.size:8d} flags=0x{sec.flags:X}")

    # Imports
    imports = sorted(set(s.name for s in binary.imported_symbols if s.name))
    print(f"\n  Imports ({len(imports)}):")
    for imp in imports:
        print(f"    {imp}")

    # Exports
    exports = sorted(set(s.name for s in binary.exported_symbols if s.name))
    if exports:
        print(f"\n  Exports ({len(exports)}):")
        for exp in exports:
            print(f"    {exp}")

    # ALL strings (critical for small binaries like ded)
    strings = [s.decode("ascii", errors="replace")
               for s in re.findall(rb"[\x20-\x7e]{4,}", data)]
    print(f"\n  Strings ({len(strings)}):")
    for s in strings:
        print(f"    {s}")

    # Disassembly of entry point (first 64 instructions)
    if HAS_CAPSTONE:
        print(f"\n  Entry point disassembly (first 32 instructions):")
        if arch == "ARM":
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

        # Find the .text section
        text_sec = None
        for sec in binary.sections:
            if sec.name == ".text":
                text_sec = sec
                break

        if text_sec:
            code = bytes(text_sec.content)
            addr = text_sec.virtual_address
            count = 0
            for insn in md.disasm(code[:512], addr):
                print(f"      0x{insn.address:08X}:  {insn.mnemonic:8s} {insn.op_str}")
                count += 1
                if count >= 32:
                    break


def main():
    targets = ["bin/ded", "bin/psh", "bin/hik_tool", "bin/hikefs",
               "usr/bin/hrsaverify", "usr/bin/do_update", "usr/bin/do_factory"]

    for name in targets:
        analyze_binary(name)


if __name__ == "__main__":
    main()
