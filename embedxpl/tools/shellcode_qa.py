"""Shellcode QA Pipeline.

Wraps helviojunior/shellcodetester for automated shellcode
quality assurance in the EmbedXPL generate -> assemble -> test cycle.

shellcodetester features:
- Assemble NASM to shellcode (Windows/Linux/macOS)
- Test shellcode execution in isolated subprocess
- Detect bad characters
- Multiple output formats (hex, C, Python, raw)

Repo: https://github.com/helviojunior/shellcodetester

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SHELLCODETESTER_CMD = "shellcodetester"
# Common bad chars for shellcode
DEFAULT_BADCHARS = b"\x00\x0a\x0d"


@dataclass
class ShellcodeQAResult:
    """Result of shellcode quality assurance check."""

    shellcode_hash: str
    shellcode_len: int
    bad_chars_found: list[str]
    bad_chars_clean: bool
    test_passed: bool
    test_output: str
    hex_representation: str
    c_array: str
    python_array: str
    error: str = ""


class ShellcodeQA:
    """Automated shellcode quality assurance using shellcodetester."""

    def __init__(
        self,
        bad_chars: bytes = DEFAULT_BADCHARS,
        output_dir: Optional[str] = None,
    ) -> None:
        self.bad_chars = bad_chars
        self.output_dir = Path(output_dir or ".tmp/shellcode_qa")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _has_shellcodetester(self) -> bool:
        """Check if shellcodetester is installed."""
        return shutil.which(SHELLCODETESTER_CMD) is not None

    def _install_hint(self) -> str:
        return (
            "shellcodetester not found. Install:\n"
            "  pip install shellcodetester\n"
            "  OR: git clone https://github.com/helviojunior/shellcodetester && pip install -e ."
        )

    # ------------------------------------------------------------------
    # Bad char analysis (pure Python, no external tool needed)
    # ------------------------------------------------------------------

    def check_bad_chars(self, shellcode: bytes, bad_chars: Optional[bytes] = None) -> list[str]:
        """Scan shellcode for bad characters.

        Args:
            shellcode: Raw shellcode bytes.
            bad_chars: Bytes to consider bad. Uses instance default if None.

        Returns:
            List of found bad char hex strings (e.g., ['\\x00', '\\x0a']).
        """
        bc = bad_chars if bad_chars is not None else self.bad_chars
        found = []
        for b in bc:
            if b in shellcode:
                found.append(f"\\x{b:02x}")
        return found

    def find_all_bad_chars(self, shellcode: bytes) -> dict[str, list[int]]:
        """Find ALL bad chars with their positions.

        Args:
            shellcode: Raw shellcode bytes.

        Returns:
            Dict mapping hex char -> list of positions.
        """
        result: dict[str, list[int]] = {}
        for i, b in enumerate(shellcode):
            if b in self.bad_chars:
                key = f"\\x{b:02x}"
                result.setdefault(key, []).append(i)
        return result

    # ------------------------------------------------------------------
    # Format conversions (pure Python)
    # ------------------------------------------------------------------

    @staticmethod
    def to_hex(shellcode: bytes) -> str:
        """Convert shellcode to hex string."""
        return shellcode.hex()

    @staticmethod
    def to_c_array(shellcode: bytes, var_name: str = "shellcode") -> str:
        """Convert shellcode to C byte array."""
        lines = [f"unsigned char {var_name}[] = {{"]
        chunks = [shellcode[i:i + 16] for i in range(0, len(shellcode), 16)]
        for chunk in chunks:
            line = "  " + ", ".join(f"0x{b:02x}" for b in chunk) + ","
            lines.append(line)
        lines.append("};")
        lines.append(f"size_t {var_name}_len = {len(shellcode)};")
        return "\n".join(lines)

    @staticmethod
    def to_python_bytes(shellcode: bytes) -> str:
        """Convert shellcode to Python bytes literal."""
        escaped = "".join(f"\\x{b:02x}" for b in shellcode)
        return f'shellcode = b"{escaped}"'

    @staticmethod
    def to_powershell_array(shellcode: bytes) -> str:
        """Convert shellcode to PowerShell byte array."""
        parts = [f"0x{b:02x}" for b in shellcode]
        return "[Byte[]] $shellcode = " + ",".join(parts)

    # ------------------------------------------------------------------
    # NASM assembly
    # ------------------------------------------------------------------

    def assemble(self, asm_source: str, arch: str = "x64") -> Optional[bytes]:
        """Assemble NASM source to shellcode bytes.

        Args:
            asm_source: NASM assembly source code.
            arch: Target architecture ('x64', 'x86', 'arm', 'mips').

        Returns:
            Raw shellcode bytes or None on error.
        """
        nasm = shutil.which("nasm")
        if not nasm:
            print("[shellcode-qa] nasm not found. Install: apt-get install nasm")
            return None

        src_file = self.output_dir / "input.asm"
        out_file = self.output_dir / "output.bin"
        src_file.write_text(asm_source)

        nasm_format = {
            "x64": "elf64",
            "x86": "elf32",
            "win64": "win64",
            "win32": "win32",
        }.get(arch, "bin")

        cmd = [nasm, "-f", "bin", str(src_file), "-o", str(out_file)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"[shellcode-qa] NASM error: {result.stderr}")
                return None
            if out_file.is_file():
                return out_file.read_bytes()
        except Exception as exc:
            print(f"[shellcode-qa] Assembly failed: {exc}")
        return None

    # ------------------------------------------------------------------
    # shellcodetester integration
    # ------------------------------------------------------------------

    def test_shellcode(self, shellcode: bytes, platform: str = "linux") -> dict:
        """Test shellcode execution via shellcodetester.

        Args:
            shellcode: Raw shellcode bytes.
            platform: 'linux', 'windows', or 'macos'.

        Returns:
            Dict with 'passed', 'output', 'exit_code'.
        """
        if not self._has_shellcodetester():
            return {
                "passed": None,
                "output": self._install_hint(),
                "exit_code": -1,
            }

        sc_file = self.output_dir / "test_shellcode.bin"
        sc_file.write_bytes(shellcode)

        cmd = [SHELLCODETESTER_CMD, "--file", str(sc_file), "--platform", platform]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding="utf-8",
                errors="replace",
            )
            output = (result.stdout + result.stderr).strip()
            passed = result.returncode == 0 and "success" in output.lower()
            return {"passed": passed, "output": output, "exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"passed": False, "output": "Execution timed out", "exit_code": -1}
        except Exception as exc:
            return {"passed": False, "output": str(exc), "exit_code": -1}

    # ------------------------------------------------------------------
    # Full QA pipeline
    # ------------------------------------------------------------------

    def run_qa(
        self,
        shellcode: bytes,
        platform: str = "linux",
        test_execution: bool = True,
    ) -> ShellcodeQAResult:
        """Run complete QA pipeline on shellcode.

        Args:
            shellcode: Raw shellcode bytes.
            platform: Test platform.
            test_execution: Whether to attempt live execution test.

        Returns:
            ShellcodeQAResult with all checks.
        """
        # Compute hash
        sha256 = hashlib.sha256(shellcode).hexdigest()[:16]

        # Bad char analysis
        bad = self.check_bad_chars(shellcode)

        # Format conversions
        hex_repr = self.to_hex(shellcode)
        c_arr = self.to_c_array(shellcode)
        py_arr = self.to_python_bytes(shellcode)

        # Execution test
        test_result = {"passed": None, "output": "Test skipped", "exit_code": 0}
        if test_execution:
            test_result = self.test_shellcode(shellcode, platform)

        return ShellcodeQAResult(
            shellcode_hash=sha256,
            shellcode_len=len(shellcode),
            bad_chars_found=bad,
            bad_chars_clean=len(bad) == 0,
            test_passed=bool(test_result.get("passed")),
            test_output=test_result.get("output", ""),
            hex_representation=hex_repr,
            c_array=c_arr,
            python_array=py_arr,
        )

    def qa_from_asm(
        self,
        asm_source: str,
        arch: str = "x64",
        platform: str = "linux",
        test_execution: bool = False,
    ) -> ShellcodeQAResult:
        """Assemble NASM source and run full QA.

        Args:
            asm_source: NASM source code.
            arch: Assembly architecture.
            platform: Test platform.
            test_execution: Whether to test execution.

        Returns:
            ShellcodeQAResult.
        """
        shellcode = self.assemble(asm_source, arch)
        if shellcode is None:
            return ShellcodeQAResult(
                shellcode_hash="",
                shellcode_len=0,
                bad_chars_found=[],
                bad_chars_clean=False,
                test_passed=False,
                test_output="Assembly failed",
                hex_representation="",
                c_array="",
                python_array="",
                error="NASM assembly failed",
            )
        return self.run_qa(shellcode, platform, test_execution)

    def report_text(self, result: ShellcodeQAResult) -> str:
        """Format QA result as human-readable report."""
        lines = [
            "=" * 50,
            "SHELLCODE QA REPORT",
            f"Hash (SHA256[:16]): {result.shellcode_hash}",
            f"Length: {result.shellcode_len} bytes",
            f"Bad chars: {'CLEAN' if result.bad_chars_clean else ', '.join(result.bad_chars_found)}",
            f"Execution test: {'PASS' if result.test_passed else 'FAIL/SKIP'}",
            "=" * 50,
            "",
            "--- Python ---",
            result.python_array,
            "",
            "--- C Array ---",
            result.c_array[:500] + "..." if len(result.c_array) > 500 else result.c_array,
        ]
        if result.test_output:
            lines += ["", "--- Test Output ---", result.test_output[:200]]
        return "\n".join(lines)
