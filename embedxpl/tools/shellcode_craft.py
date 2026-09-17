"""Shellcode craft helpers (native).

Pattern, format conversion, badchar scan, JMP/CALL/POP stub and
Linux/Windows calling-convention notes as code generators.

Methodology: Sec4US shellcoding cheatsheet (Helvio Junior / M4v3r1ck)
https://github.com/sec4us-training/cheatsheets/blob/master/shellcoding.md

NASM / shellcodetester remain optional compiled accelerators.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Credits: Helvio Junior (M4v3r1ck), Sec4US Training
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


LINUX32_SYSCALL = {
    "exit": 1, "fork": 2, "read": 3, "write": 4, "open": 5, "close": 6,
    "execve": 11, "socketcall": 102, "dup2": 63,
}
LINUX64_SYSCALL = {
    "read": 0, "write": 1, "open": 2, "close": 3, "socket": 41,
    "connect": 42, "dup2": 33, "execve": 59, "exit": 60,
}


def to_hex(blob: bytes, prefix: str = "\\x") -> str:
    return "".join(f"{prefix}{b:02x}" for b in blob)


def to_c_array(blob: bytes, name: str = "sc") -> str:
    body = ", ".join(f"0x{b:02x}" for b in blob)
    return f"unsigned char {name}[] = {{ {body} }};\nunsigned int {name}_len = {len(blob)};"


def to_python(blob: bytes, name: str = "buf") -> str:
    return f"{name} = b\"{to_hex(blob)}\""


def find_badchars(blob: bytes, bad: bytes = b"\x00\x0a\x0d") -> list[int]:
    return [i for i, b in enumerate(blob) if b in bad]


def jmp_call_pop_32(text: bytes) -> str:
    """Generate NASM JMP/CALL/POP stub (Sec4US sample)."""
    escaped = "".join(f"0x{b:02x}, " for b in text)
    return f"""[BITS 32]
global _start
section .text
_start:
    jmp step1
step2:
    pop ecx
    nop
step1:
    call step2
    db {escaped}0x00
"""


def linux64_preamble() -> str:
    return """[BITS 64]
global _start
section .text
_start:
    cld
    and rsp, 0xFFFFFFFFFFFFFFF0
    xor eax, eax
    push rax
"""


def write_formats(blob: bytes, dest_dir: str) -> dict[str, str]:
    out = Path(dest_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "hex": out / "shellcode.hex",
        "c": out / "shellcode.c",
        "py": out / "shellcode.py",
    }
    files["hex"].write_text(to_hex(blob), encoding="utf-8")
    files["c"].write_text(to_c_array(blob), encoding="utf-8")
    files["py"].write_text(to_python(blob), encoding="utf-8")
    return {k: str(v) for k, v in files.items()}


def scan_file(path: str, bad: Iterable[int] = (0, 10, 13)) -> dict:
    data = Path(path).read_bytes()
    bad_b = bytes(bad)
    hits = find_badchars(data, bad_b)
    return {"path": path, "size": len(data), "bad_offsets": hits[:50], "bad_count": len(hits)}
