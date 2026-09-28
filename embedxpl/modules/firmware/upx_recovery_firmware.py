# AUTHORIZED USE ONLY — See docs/malware-research/DISCLAIMER.md
# simulate=True by default — set False only for authorized tests.
"""UPX Recovery Tool — Firmware Malware Analysis (NozomiNetworks).

Repairs anti-unpack modifications done to ELF UPX-compressed firmware binaries
by malware creators. Common in IoT/embedded malware that modifies UPX headers
to prevent automatic unpacking.

Source: github.com/NozomiNetworks/upx-recovery-tool
YARA rules: embedxpl/resources/yara/upx/ (ARM, MIPS, x86-64, PPC, i386)
Author: NozomiNetworks Research | Andre Henrique (@mrhenrike) — EmbedXPL port
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_NOZOMI_BASE = Path("d:/Projects/Labs/nozomi-research/upx-recovery-tool")
_TOOL = _NOZOMI_BASE / "upxrecoverytool.py"
_YARA_DIR = Path(__file__).resolve().parents[2] / "resources" / "yara" / "upx"

# Architecture YARA rule mapping
_ARCH_RULES = {
    "arm":   _YARA_DIR / "arm.yar",
    "mips":  _YARA_DIR / "mips.yar",
    "x86-64": _YARA_DIR / "x86-64.yar",
    "ppc":   _YARA_DIR / "powerpc.yar",
    "i386":  _YARA_DIR / "intel_80386.yar",
}

# Common anti-unpack modifications repaired by upxrecoverytool
_FIXES = [
    "`l_magic` field of `l_info` struct — UPX! magic value corrupted",
    "`p_filesize` and `p_blocksize` fields of `p_info` struct",
    "Overlay bytes modification",
]


class Exploit(HTTPClient):
    """UPX Recovery Tool — Firmware ELF Malware Unpacking (NozomiNetworks)."""

    __info__ = {
        "name": "UPX Recovery Tool for Firmware ELF Analysis (NozomiNetworks)",
        "description": (
            "Repairs anti-unpack modifications in ELF UPX-compressed firmware binaries. "
            "Malware creators modify UPX headers to prevent automatic unpacking. "
            "Repairs: l_magic corruption, p_filesize/p_blocksize, overlay bytes. "
            "Supports ARM, MIPS, x86-64, PowerPC, i386 architectures (IoT/embedded). "
            "Includes YARA rules for each architecture."
        ),
        "authors": ("NozomiNetworks Research (upx-recovery-tool)", "Andre Henrique (@mrhenrike) — EmbedXPL port"),
        "references": (
            "https://github.com/NozomiNetworks/upx-recovery-tool",
            "embedxpl/resources/yara/upx/",
            "docs/malware-research/catalogo-nozomi-ics-tools.md",
        ),
        "devices": ("IoT firmware ELF binaries", "Embedded Linux malware", "Router firmware"),
    }

    firmware_path = OptString("", "Path to UPX-compressed ELF firmware binary to repair")
    output_dir    = OptString(".tmp/upx_recovery", "Output directory")
    arch          = OptString("auto", "Architecture: arm, mips, x86-64, ppc, i386, or auto")
    yara_scan     = OptBool(True, "Run YARA architecture detection before repair")
    simulate      = OptBool(True, "Simulate mode")

    def _sha256(self, path: str) -> str:
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "unknown"

    def check(self) -> bool:
        if self.simulate:
            return True
        if not _TOOL.exists():
            print_error(f"upxrecoverytool.py not found: {_TOOL}")
            return False
        for dep in ["lief", "magic", "yara"]:
            try:
                __import__(dep)
            except ImportError:
                print_status(f"Dependency missing: pip install lief python-magic yara-python")
                return False
        return True

    def _detect_arch_yara(self, filepath: str) -> str:
        """Detect ELF architecture via YARA rules."""
        try:
            import yara
            for arch, rule_file in _ARCH_RULES.items():
                if rule_file.exists():
                    rules = yara.compile(str(rule_file))
                    matches = rules.match(filepath)
                    if matches:
                        return arch
        except Exception:
            pass
        return "unknown"

    def run(self) -> None:
        if self.simulate:
            print_status("[SIMULATE] UPX Recovery Tool — NozomiNetworks")
            print_status()
            print_status("  Anti-unpack modifications repaired:")
            for fix in _FIXES:
                print_status(f"    - {fix}")
            print_status()
            print_status("  Supported architectures + YARA rules:")
            for arch, rule in _ARCH_RULES.items():
                exists = "✓" if rule.exists() else "✗"
                print_status(f"    [{exists}] {arch}: {rule.name}")
            print_status()
            print_status("  Usage: set firmware_path <elf_binary>")
            print_status("  Output: <binary>_recovered.elf + SHA256 report")
            print_status()
            print_status(f"  Tool: {_TOOL}")
            print_status(f"  Deps: pip install lief python-magic yara-python")
            return

        if not self.check():
            return

        if not self.firmware_path:
            print_error("No firmware_path set — specify ELF binary path")
            return

        fw = Path(self.firmware_path)
        if not fw.exists():
            print_error(f"File not found: {fw}")
            return

        sha_orig = self._sha256(str(fw))
        print_status(f"Input: {fw.name} (SHA256: {sha_orig[:16]}...)")

        # Architecture detection
        arch = self.arch
        if arch == "auto" and self.yara_scan:
            print_status("Detecting architecture via YARA...")
            arch = self._detect_arch_yara(str(fw))
            print_status(f"  Detected: {arch}")

        # Run upxrecoverytool
        output = Path(self.output_dir)
        output.mkdir(parents=True, exist_ok=True)

        cmd = ["python", str(_TOOL), str(fw)]
        print_status(f"Running UPX recovery...")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(output),
            )
            for line in (result.stdout + result.stderr).split("\n"):
                if line.strip():
                    if "recovered" in line.lower() or "repaired" in line.lower():
                        print_success(f"  {line.strip()}")
                    elif "error" in line.lower():
                        print_error(f"  {line.strip()}")
                    else:
                        print_status(f"  {line.strip()}")

            # Find output file
            recovered = list(output.glob("*_recovered*"))
            if recovered:
                sha_rec = self._sha256(str(recovered[0]))
                print_success(f"Recovered: {recovered[0].name} (SHA256: {sha_rec[:16]}...)")
                print_status("  Now unpack with: upx -d <recovered_binary>")
        except subprocess.TimeoutExpired:
            print_error("Recovery timed out (30s)")
        except Exception as e:
            print_error(f"Recovery error: {e}")
