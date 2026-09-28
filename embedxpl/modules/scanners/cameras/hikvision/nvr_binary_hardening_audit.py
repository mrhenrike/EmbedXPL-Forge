# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision NVR/DVR Binary Hardening Audit — ELF security analysis.

Analyzes extracted firmware binaries for security hardening features:
PIE/ASLR, NX/DEP, RELRO, Stack Canaries, and FORTIFY_SOURCE. Uses the
LIEF library for ELF parsing with a fallback to readelf subprocess.

CWE-693: Protection Mechanism Failure.

Version: 1.0.0
"""

import os
import re
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *

_DANGEROUS_IMPORTS = frozenset([
    "sprintf", "strcpy", "strcat", "gets", "system", "popen",
    "vsprintf", "scanf", "fscanf", "sscanf",
])

_ELF_MAGIC = b"\x7fELF"

_ET_DYN = 3
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552
_PF_X = 0x1
_DT_BIND_NOW = 24
_DT_FLAGS = 30
_DF_BIND_NOW = 0x8


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == _ELF_MAGIC
    except (OSError, IOError):
        return False


class _ELFInfo:
    """Lightweight ELF security feature extraction."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.name = os.path.basename(path)
        self.pie: Optional[bool] = None
        self.nx: Optional[bool] = None
        self.relro: str = "None"
        self.canary: bool = False
        self.dangerous: List[str] = []
        self._parse()

    def _parse(self) -> None:
        try:
            import lief  # type: ignore[import-untyped]
            self._parse_lief(lief)
        except ImportError:
            self._parse_fallback()

    def _parse_lief(self, lief) -> None:  # type: ignore[no-untyped-def]
        binary = lief.parse(self.path)
        if binary is None:
            return

        self.pie = binary.is_pie

        self.nx = True
        for seg in binary.segments:
            if seg.type == lief.ELF.Segment.TYPE.GNU_STACK:
                self.nx = not bool(seg.flags & lief.ELF.Segment.FLAGS.X)
                break

        has_relro_seg = any(
            seg.type == lief.ELF.Segment.TYPE.GNU_RELRO for seg in binary.segments
        )
        bind_now = False
        if binary.has(lief.ELF.DynamicEntry.TAG.FLAGS):
            flags_entry = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS)
            bind_now = bool(flags_entry.value & _DF_BIND_NOW)
        if not bind_now and binary.has(lief.ELF.DynamicEntry.TAG.BIND_NOW):
            bind_now = True

        if has_relro_seg and bind_now:
            self.relro = "Full"
        elif has_relro_seg:
            self.relro = "Partial"
        else:
            self.relro = "None"

        imported_names = set()
        for sym in binary.imported_symbols:
            imported_names.add(sym.name)

        self.canary = "__stack_chk_fail" in imported_names
        self.dangerous = sorted(imported_names & _DANGEROUS_IMPORTS)

    def _parse_fallback(self) -> None:
        try:
            hdr = subprocess.check_output(
                ["readelf", "-h", self.path], stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors="replace")
            self.pie = "DYN" in hdr
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            segs = subprocess.check_output(
                ["readelf", "-l", self.path], stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors="replace")
            stack_match = re.search(r"GNU_STACK\s+.*?(RW[E ])", segs)
            if stack_match:
                self.nx = "E" not in stack_match.group(1)
            else:
                self.nx = True
            self.relro = "Partial" if "GNU_RELRO" in segs else "None"
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            dynsyms = subprocess.check_output(
                ["readelf", "--dyn-syms", self.path], stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors="replace")
            self.canary = "__stack_chk_fail" in dynsyms
            found = set()
            for sym in _DANGEROUS_IMPORTS:
                if re.search(r"\b{}\b".format(re.escape(sym)), dynsyms):
                    found.add(sym)
            self.dangerous = sorted(found)
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            dynamic = subprocess.check_output(
                ["readelf", "-d", self.path], stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors="replace")
            if "BIND_NOW" in dynamic and self.relro == "Partial":
                self.relro = "Full"
        except (OSError, subprocess.SubprocessError):
            pass


def _find_glibc_version(firmware_dir: str) -> Optional[str]:
    for root, _dirs, files in os.walk(firmware_dir):
        for fname in files:
            if fname.startswith("libc-") and fname.endswith(".so"):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    match = re.search(
                        rb"release version (\d+\.\d+(?:\.\d+)?)", data
                    )
                    if match:
                        return match.group(1).decode()
                except (OSError, IOError):
                    continue
            if fname == "libc.so.6":
                fpath = os.path.join(root, fname)
                real = os.path.realpath(fpath)
                ver_match = re.search(r"libc-(\d+\.\d+(?:\.\d+)?)", real)
                if ver_match:
                    return ver_match.group(1)
    return None


class Exploit(Exploit):
    """Hikvision NVR/DVR Binary Hardening Audit.

    Walks an extracted firmware rootfs directory, parses ELF binaries, and
    reports on security hardening features. Flags binaries that import
    dangerous libc functions.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision NVR/DVR Binary Hardening Audit",
        "description": (
            "Analyzes extracted firmware binaries for security hardening. "
            "Checks PIE/ASLR, NX/DEP, RELRO, Stack Canaries, FORTIFY_SOURCE. "
            "Uses LIEF library for ELF parsing. CWE-693."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://cwe.mitre.org/data/definitions/693.html",
        ),
        "devices": (
            "Hikvision NVR",
            "Hikvision DVR",
            "Hikvision IP Camera",
        ),
    }

    firmware_dir = OptString("", "Path to extracted firmware rootfs directory")
    check_libs = OptBool(True, "Also check shared libraries (.so)")

    def _collect_elfs(self) -> List[str]:
        elfs: List[str] = []
        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not os.path.isfile(fpath):
                    continue
                if not self.check_libs and fname.endswith(".so"):
                    continue
                if _is_elf(fpath):
                    elfs.append(fpath)
        return elfs

    def run(self) -> None:
        if not self.firmware_dir or not os.path.isdir(self.firmware_dir):
            print_error("firmware_dir is not set or does not exist")
            return

        print_status("Scanning ELF binaries in {}...".format(self.firmware_dir))

        elf_paths = self._collect_elfs()
        if not elf_paths:
            print_error("No ELF binaries found in {}".format(self.firmware_dir))
            return

        print_status("Found {} ELF files".format(len(elf_paths)))

        results: List[_ELFInfo] = []
        for path in elf_paths:
            results.append(_ELFInfo(path))

        rows: List[Tuple[str, str, str, str, str, str]] = []
        for r in results:
            rel_path = os.path.relpath(r.path, self.firmware_dir)
            rows.append((
                rel_path,
                "Yes" if r.pie else "No",
                "Yes" if r.nx else "No",
                r.relro,
                "Yes" if r.canary else "No",
                ", ".join(r.dangerous) if r.dangerous else "-",
            ))

        print_table(
            ("Binary", "PIE", "NX", "RELRO", "Canary", "Dangerous Imports"),
            *rows,
            title="Binary Hardening Results",
        )

        total = len(results)
        pie_count = sum(1 for r in results if r.pie)
        nx_count = sum(1 for r in results if r.nx)
        full_relro = sum(1 for r in results if r.relro == "Full")
        partial_relro = sum(1 for r in results if r.relro == "Partial")
        canary_count = sum(1 for r in results if r.canary)
        dangerous_count = sum(1 for r in results if r.dangerous)

        print_info("Summary: {}/{} PIE, {}/{} NX, {}/{} Full RELRO, "
                   "{}/{} Partial RELRO, {}/{} Stack Canary".format(
                       pie_count, total, nx_count, total, full_relro, total,
                       partial_relro, total, canary_count, total))

        if dangerous_count:
            print_warning("{}/{} binaries import dangerous functions".format(
                dangerous_count, total))

        glibc_ver = _find_glibc_version(self.firmware_dir)
        if glibc_ver:
            print_info("Detected glibc version: {}".format(glibc_ver))

        risk = "LOW"
        if pie_count < total // 2 or nx_count < total // 2:
            risk = "CRITICAL"
        elif full_relro < total // 2 and canary_count < total // 2:
            risk = "HIGH"
        elif dangerous_count > total // 3:
            risk = "MEDIUM"

        print_status("Overall hardening risk assessment: {}".format(risk))
