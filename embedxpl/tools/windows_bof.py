"""Windows traditional buffer overflow toolkit.

Native cyclic pattern, offset, badchar set and exploit skeleton.
Methodology from Sec4US cheatsheets (Eder Luis / 0xffff):
  https://github.com/sec4us-training/cheatsheets
  bufferoverflow-windows.md

Does not call msf-pattern_create / msf-pattern_offset.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Credits: Sec4US Training, Eder Luis (0xffff)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


COMMON_BADCHARS = bytes([0x00, 0x0A, 0x0D])


def cyclic(length: int) -> bytes:
    """De Bruijn-style unique pattern (Aa0Aa1...)."""
    charset_a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    charset_b = b"abcdefghijklmnopqrstuvwxyz"
    charset_c = b"0123456789"
    out = bytearray()
    for a in charset_a:
        for b in charset_b:
            for c in charset_c:
                out.extend(bytes([a, b, c]))
                if len(out) >= length:
                    return bytes(out[:length])
    while len(out) < length:
        out.extend(out)
    return bytes(out[:length])


def cyclic_find(pattern: bytes | str, haystack: Optional[bytes] = None) -> int:
    """Offset of 4-byte EIP value inside cyclic pattern."""
    if isinstance(pattern, str):
        token = pattern.strip()
        if token.startswith("0x"):
            needle = bytes.fromhex(token[2:])[::-1] if len(token) == 10 else token.encode()
        else:
            needle = token.encode("latin-1", errors="replace")
    else:
        needle = pattern
    blob = haystack if haystack is not None else cyclic(10000)
    idx = blob.find(needle[:4] if len(needle) >= 4 else needle)
    return idx


def bytearray_payload(exclude: bytes = COMMON_BADCHARS) -> bytes:
    return bytes(b for b in range(256) if b not in exclude)


@dataclass
class BofPlan:
    """Stack fit for a traditional EIP overwrite."""

    offset: int
    eip: bytes
    payload: bytes
    nopsled: int = 16

    def buffer(self) -> bytes:
        return (b"A" * self.offset) + self.eip + (b"\x90" * self.nopsled) + self.payload


class Exploit:
    """Sec4US Windows BOF helper (check/run contract)."""

    METADATA = {
        "name": "Windows traditional BOF builder",
        "source": "sec4us-training/cheatsheets",
        "author": "Andre Henrique (@mrhenrike)",
        "credits": "Eder Luis (0xffff) / Sec4US",
    }

    def __init__(
        self,
        length: int = 1000,
        eip_value: str = "",
        exclude_badchars: bytes = COMMON_BADCHARS,
        output: str = ".tmp/bof_pattern.bin",
    ) -> None:
        self.length = length
        self.eip_value = eip_value
        self.exclude_badchars = exclude_badchars
        self.output = Path(output)

    def check(self) -> bool:
        return self.length > 0

    def run(self) -> None:
        pattern = cyclic(self.length)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_bytes(pattern)
        print(f"[bof] cyclic({self.length}) -> {self.output}")
        if self.eip_value:
            off = cyclic_find(self.eip_value, pattern if self.length >= 10000 else cyclic(10000))
            print(f"[bof] offset for {self.eip_value}: {off}")
        ba = bytearray_payload(self.exclude_badchars)
        ba_path = self.output.with_suffix(".badchars.bin")
        ba_path.write_bytes(ba)
        print(f"[bof] badchar set ({len(ba)} bytes) -> {ba_path}")
