#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""EMBA Firmware Security Analyzer Orchestrator.

Integrates EMBA (e-m-b-a/emba) firmware security analysis into EmbedXPL.
EMBA is a comprehensive firmware security analyzer that performs extraction,
static analysis, dynamic analysis (via QEMU emulation), CVE scanning,
and generates detailed HTML reports.

This module orchestrates EMBA analysis phases:
  - P-modules (Preparation): firmware extraction, filesystem mount,
    architecture detection, deep extraction with binwalk/unblob
  - S-modules (Static): binary analysis, CWE checking with cwe_checker,
    shell script analysis, weak function detection (radare2),
    password/credential scanning, crypto analysis, SBOM generation
  - L-modules (Live): QEMU system emulation, web access testing,
    network service scanning, VNC checks
  - F-modules (Findings): CVE correlation via cve-bin-tool,
    exploit matching, vulnerability scoring

Capabilities:
  - Firmware format detection (SquashFS, JFFS2, UBIFS, CramFS, ext, cpio)
  - Architecture detection (ARM, MIPS, x86, PPC, RISC-V)
  - Binary hardening checks (NX, PIE, RELRO, canary, FORTIFY)
  - Weak function scanning via radare2 decompilation
  - CWE checking via Ghidra cwe_checker plugin
  - CVE matching against extracted binaries (cve-bin-tool)
  - SBOM generation for firmware components
  - Shell script security analysis

HW_REQ: Docker (for full EMBA), or partial local analysis without Docker.

References:
  - Repository: https://github.com/e-m-b-a/emba
  - License: GPL-2.0
  - EMBA wiki: https://github.com/e-m-b-a/emba/wiki

MITRE ATT&CK:
  - T1592.002: Gather Victim Host Information: Software
  - T1082: System Information Discovery
  - T1518: Software Discovery
  - T1005: Data from Local System

Version: 1.0.0
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit,
    OptBool,
    OptInteger,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Architecture detection signatures in ELF headers
# ---------------------------------------------------------------------------
ELF_ARCH_MAP: Dict[int, str] = {
    0x03: "x86 (EM_386)",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x2B: "SPARC V9",
    0x3E: "x86-64 (EM_X86_64)",
    0xB7: "AArch64 (ARM64)",
    0xF3: "RISC-V",
    0xF7: "BPF",
}

ELF_ENDIAN_MAP: Dict[int, str] = {
    1: "little-endian",
    2: "big-endian",
}

# Filesystem signatures for firmware extraction
FS_SIGNATURES: List[Tuple[bytes, str, int]] = [
    (b"hsqs", "SquashFS (LE)", 0),
    (b"sqsh", "SquashFS (BE)", 0),
    (b"\x85\x19\x03\x20", "JFFS2 (LE)", 0),
    (b"\x19\x85\x20\x03", "JFFS2 (BE)", 0),
    (b"UBI#", "UBIFS", 0),
    (b"\x45\x3d\xcd\x28", "CramFS", 0),
    (b"\x30\x37\x30\x37\x30\x31", "cpio newc", 0),
    (b"\x30\x37\x30\x37\x30\x37", "cpio odc", 0),
]

# Binary hardening check strings
HARDENING_INDICATORS = {
    "stack_canary": [b"__stack_chk_fail", b"__stack_chk_guard"],
    "fortify_source": [b"__fortify_fail", b"__chk_fail"],
    "nx_dep": [],  # checked via ELF header GNU_STACK
    "relro": [],   # checked via ELF program headers
}

# EMBA S-module weak functions (from S14_weak_func_radare_check.sh)
WEAK_FUNCTIONS: List[str] = [
    "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
    "vsprintf", "vsnprintf", "gets", "fgets", "scanf", "fscanf",
    "sscanf", "realpath", "getwd", "strtok", "mktemp", "mkstemp",
    "tmpnam", "tempnam", "system", "popen", "exec", "execl",
    "execlp", "execle", "execv", "execvp", "execve", "wordexp",
    "setuid", "setgid", "seteuid", "setegid",
    "chown", "chmod", "access",
    "alloca", "longjmp", "getenv",
]


class EMBAFirmwareAnalyzer(Exploit):
    """EMBA firmware security analyzer orchestrator for EmbedXPL.

    Two operating modes:
      1. Docker mode: launches full EMBA via Docker container
      2. Local mode: performs subset of EMBA analysis phases locally
         (architecture detection, hardening checks, weak function scan,
          credential scan, filesystem identification)
    """

    __info__ = {
        "name": "EMBA Firmware Security Analyzer",
        "description": (
            "Comprehensive firmware security analysis orchestrator. "
            "Extraction, static analysis, binary hardening checks, "
            "weak function detection, CVE scanning, SBOM generation."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/e-m-b-a/emba",
            "https://github.com/e-m-b-a/emba/wiki",
        ),
        "devices": ("Firmware", "Routers", "IoT", "Cameras", "Industrial"),
        "cve": "N/A (analysis tool)",
        "cvss": "N/A",
        "severity": "INFO",
        "mitre_techniques": ["T1592.002", "T1082", "T1518", "T1005"],
        "mitre_tactics": [
            "Reconnaissance",
            "Discovery",
            "Collection",
        ],
        "license": "GPL-2.0",
    }

    firmware_path = OptString("", "Path to firmware image")
    output_dir = OptString("/tmp/emba_output", "Directory for analysis output")
    mode = OptString(
        "local",
        "Analysis mode: 'docker' for full EMBA, 'local' for lightweight",
    )
    emba_path = OptString("/opt/emba", "Path to EMBA installation (docker mode)")
    scan_weak_funcs = OptBool(True, "Scan for weak/dangerous function usage")
    scan_hardening = OptBool(True, "Check binary hardening mitigations")
    max_binaries = OptInteger(100, "Max binaries to analyze in local mode")

    # ------------------------------------------------------------------
    # ELF analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_elf_header(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse ELF header for architecture and hardening info."""
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None

        elf_class = data[4]  # 1=32bit, 2=64bit
        endian = data[5]     # 1=LE, 2=BE
        byte_order = "<" if endian == 1 else ">"

        if elf_class == 1:
            # 32-bit ELF
            fmt = f"{byte_order}HHIIIIIHHHHHH"
            offset = 16
        else:
            # 64-bit ELF
            fmt = f"{byte_order}HHIQQQIHHHHHH"
            offset = 16

        try:
            fields = struct.unpack(fmt, data[offset:offset + struct.calcsize(fmt)])
        except struct.error:
            return None

        e_type_map = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}
        e_machine = fields[1]

        result = {
            "class": f"{elf_class * 32}-bit",
            "endian": ELF_ENDIAN_MAP.get(endian, "unknown"),
            "type": e_type_map.get(fields[0], f"unknown({fields[0]})"),
            "machine": ELF_ARCH_MAP.get(e_machine, f"unknown(0x{e_machine:x})"),
            "machine_id": e_machine,
        }

        # Check for stack canary and FORTIFY
        has_canary = any(
            sig in data for sig in HARDENING_INDICATORS["stack_canary"]
        )
        has_fortify = any(
            sig in data for sig in HARDENING_INDICATORS["fortify_source"]
        )
        result["stack_canary"] = has_canary
        result["fortify_source"] = has_fortify

        # Check PIE (ET_DYN with entry point)
        result["pie"] = fields[0] == 3

        # Check NX via GNU_STACK program header
        result["nx"] = b"GNU_STACK" in data[:4096] or b"\x51\xe5\x74\x64" in data

        return result

    @staticmethod
    def find_elf_binaries(directory: str, max_count: int = 100) -> List[str]:
        """Find ELF binaries in extracted firmware filesystem."""
        binaries = []
        try:
            for root, _dirs, files in os.walk(directory):
                for fname in files:
                    if len(binaries) >= max_count:
                        return binaries
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "rb") as f:
                            magic = f.read(4)
                        if magic == b"\x7fELF":
                            binaries.append(fpath)
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
        return binaries

    @staticmethod
    def scan_weak_functions_in_binary(data: bytes) -> List[str]:
        """Scan binary data for references to weak/dangerous functions."""
        found = []
        for func in WEAK_FUNCTIONS:
            # Look for function name in symbol tables / string references
            if func.encode() in data:
                found.append(func)
        return found

    @staticmethod
    def detect_filesystems(data: bytes) -> List[Dict[str, Any]]:
        """Detect embedded filesystems in firmware image."""
        results = []
        for sig, fs_name, expected_offset in FS_SIGNATURES:
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                results.append({
                    "filesystem": fs_name,
                    "offset": f"0x{pos:x}",
                    "offset_dec": pos,
                })
                offset = pos + len(sig)
        return results

    @staticmethod
    def detect_architecture(data: bytes) -> Optional[str]:
        """Detect firmware architecture from ELF binaries or instruction patterns."""
        # Try ELF header first
        elf_pos = data.find(b"\x7fELF")
        if elf_pos != -1:
            endian = data[elf_pos + 5]
            byte_order = "<" if endian == 1 else ">"
            try:
                e_machine = struct.unpack(
                    f"{byte_order}H", data[elf_pos + 18:elf_pos + 20]
                )[0]
                return ELF_ARCH_MAP.get(e_machine, f"unknown(0x{e_machine:x})")
            except struct.error:
                pass

        # ARM instruction patterns
        arm_patterns = [
            b"\x00\x00\xa0\xe1",   # MOV R0, R0 (NOP) ARM LE
            b"\xe1\xa0\x00\x00",   # MOV R0, R0 (NOP) ARM BE
        ]
        for pattern in arm_patterns:
            if pattern in data[:0x10000]:
                return "ARM"

        # MIPS NOP
        if b"\x00\x00\x00\x00" in data[:0x100]:
            mips_sig = data.find(b"\x27\xbd")  # addiu sp
            if mips_sig != -1 and mips_sig < 0x10000:
                return "MIPS"

        return None

    # ------------------------------------------------------------------
    # Docker mode
    # ------------------------------------------------------------------

    def _run_emba_docker(self) -> bool:
        """Launch full EMBA analysis via Docker."""
        emba_script = os.path.join(self.emba_path, "emba")
        if not os.path.isfile(emba_script):
            print_error(f"EMBA not found at {emba_script}")
            return False

        cmd = [
            "sudo", emba_script,
            "-f", self.firmware_path,
            "-l", self.output_dir,
            "-D",  # Docker mode
        ]

        print_status(f"Launching EMBA: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,
            )
            if result.returncode == 0:
                print_success("EMBA analysis completed successfully")
                return True
            else:
                print_error(f"EMBA exited with code {result.returncode}")
                if result.stderr:
                    print_error(result.stderr[:500])
                return False
        except subprocess.TimeoutExpired:
            print_error("EMBA analysis timed out (1h limit)")
            return False
        except FileNotFoundError:
            print_error("Docker or EMBA not available")
            return False

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(self):
        """Execute firmware security analysis."""
        if not self.firmware_path or not os.path.isfile(self.firmware_path):
            print_error(f"Firmware not found: {self.firmware_path}")
            return

        os.makedirs(self.output_dir, exist_ok=True)
        print_info(f"EMBA analysis: {self.firmware_path}")
        print_info(f"Mode: {self.mode}")

        with open(self.firmware_path, "rb") as f:
            data = f.read()

        # Docker mode
        if self.mode == "docker":
            self._run_emba_docker()
            return

        # Local lightweight analysis
        report: Dict[str, Any] = {"firmware": self.firmware_path, "size": len(data)}

        # Architecture detection
        print_status("[S03] Architecture detection")
        arch = self.detect_architecture(data)
        report["architecture"] = arch
        if arch:
            print_success(f"Detected architecture: {arch}")
        else:
            print_warning("Could not determine architecture")

        # Filesystem detection
        print_status("[P60] Filesystem detection")
        filesystems = self.detect_filesystems(data)
        report["filesystems"] = filesystems
        if filesystems:
            print_success(f"Found {len(filesystems)} filesystem(s):")
            for fs in filesystems:
                print_info(f"  {fs['filesystem']} at {fs['offset']}")
        else:
            print_warning("No recognized filesystems found")

        # ELF binary analysis
        print_status("[S14] Binary analysis")
        elf_pos = data.find(b"\x7fELF")
        elf_results = []
        positions_checked = set()

        pos = 0
        count = 0
        while count < self.max_binaries:
            elf_pos = data.find(b"\x7fELF", pos)
            if elf_pos == -1:
                break
            if elf_pos in positions_checked:
                pos = elf_pos + 4
                continue
            positions_checked.add(elf_pos)

            # Extract enough for header analysis
            elf_data = data[elf_pos:elf_pos + 4096]
            info = self.parse_elf_header(elf_data)
            if info:
                elf_results.append({
                    "offset": f"0x{elf_pos:x}",
                    **info,
                })
                count += 1
            pos = elf_pos + 4

        report["elf_binaries"] = elf_results
        if elf_results:
            print_success(f"Found {len(elf_results)} ELF binary(ies)")
            # Hardening summary
            canary_count = sum(1 for e in elf_results if e.get("stack_canary"))
            pie_count = sum(1 for e in elf_results if e.get("pie"))
            nx_count = sum(1 for e in elf_results if e.get("nx"))
            fortify_count = sum(1 for e in elf_results if e.get("fortify_source"))

            print_info(f"  Stack canary: {canary_count}/{len(elf_results)}")
            print_info(f"  PIE: {pie_count}/{len(elf_results)}")
            print_info(f"  NX: {nx_count}/{len(elf_results)}")
            print_info(f"  FORTIFY: {fortify_count}/{len(elf_results)}")

        # Weak function scan
        if self.scan_weak_funcs:
            print_status("[S14] Weak function detection")
            weak_funcs = self.scan_weak_functions_in_binary(data)
            report["weak_functions"] = weak_funcs
            if weak_funcs:
                print_warning(
                    f"Weak functions found: {', '.join(weak_funcs[:20])}"
                )

        # Credential patterns
        print_status("[S85] SSH/credential scanning")
        cred_patterns = [
            (rb"root:[^:]*:0:0:", "root account entry"),
            (rb"(?:password|passwd)\s*[:=]\s*\S+", "hardcoded password"),
            (rb"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "private key"),
            (rb"ssh-(?:rsa|dss|ed25519)\s+\S+", "SSH public key"),
            (rb"(?:WPA|wpa)_passphrase\s*=\s*\S+", "WiFi passphrase"),
        ]
        cred_findings = []
        for pattern, desc in cred_patterns:
            matches = re.findall(pattern, data[:10_000_000])
            for m in matches[:5]:
                cred_findings.append({
                    "type": desc,
                    "value": m.decode("ascii", errors="replace")[:120],
                })
        report["credentials"] = cred_findings
        if cred_findings:
            print_warning(f"Found {len(cred_findings)} credential artifact(s):")
            for c in cred_findings[:10]:
                print_warning(f"  [{c['type']}] {c['value']}")

        # Save report
        report_path = os.path.join(self.output_dir, "emba_local_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print_success(f"Report saved: {report_path}")
