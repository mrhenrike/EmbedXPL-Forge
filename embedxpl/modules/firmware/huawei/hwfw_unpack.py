"""
embedxpl/modules/firmware/huawei/hwfw_unpack.py - Huawei Firmware Pack/Unpack Tool.

Native Python reimplementation of the Huawei firmware format parser from
hwfw-tool (submodules/IoT/third-party-router-poc/hwfw-tool/hwfw.py).

Supports reading and writing Huawei router/modem firmware images:
  - HG series (HG8245, HG8245H, EchoLife)
  - B series (B525, B818)
  - WS series (WS5200, WS7200)

The firmware format uses:
  - Fixed-size header with magic, length, CRC32 checksums, item count
  - Item table with fixed-size entries (name, type, offset, size, CRC)
  - Raw item data appended after item table

Source: Based on hwfw-tool by Xiaolan.Lee (GPLv2) - fully rewritten.

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"


def _crc32(*data_parts: bytes) -> int:
    """Compute CRC32 over one or more byte strings."""
    crc = 0
    for part in data_parts:
        crc = zlib.crc32(part, crc)
    return crc & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FirmwareHeader:
    """Huawei firmware file header (fixed 36 bytes + magic)."""
    magic: bytes = b"\x00" * 4
    file_length: int = 0
    file_crc: int = 0
    header_size: int = 0
    header_crc: int = 0
    item_count: int = 0
    extra_header_length: int = 0
    item_size: int = 0

    # struct format: '<4sIiIiI3H6s' - little endian
    # magic(4) + fileLength(4) + fileCRC(4) + headerSize(4) +
    # headerCRC(4) + itemCount(4) + pad(2) + extraHeaderLength(2) +
    # itemSize(2) + pad(6)
    _STRUCT = struct.Struct("<4sIiIiI3H6s")
    SIZE = _STRUCT.size  # 36 bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "FirmwareHeader":
        if len(data) < cls.SIZE:
            raise ValueError(f"Header too short: {len(data)} < {cls.SIZE}")
        (
            magic, file_len, file_crc, header_size, header_crc,
            item_count, _, extra_header_len, item_size, _
        ) = cls._STRUCT.unpack(data[:cls.SIZE])
        return cls(
            magic=magic,
            file_length=file_len,
            file_crc=file_crc,
            header_size=header_size,
            header_crc=header_crc,
            item_count=item_count,
            extra_header_length=extra_header_len,
            item_size=item_size,
        )

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(
            self.magic,
            self.file_length & 0xFFFFFFFF,
            self.file_crc & 0x7FFFFFFF,
            self.header_size & 0xFFFFFFFF,
            self.header_crc & 0x7FFFFFFF,
            self.item_count & 0xFFFFFFFF,
            0,
            self.extra_header_length & 0xFFFF,
            self.item_size & 0xFFFF,
            b"\x00" * 6,
        )


@dataclass
class FirmwareItem:
    """Huawei firmware partition item descriptor."""
    seq: int = 0
    crc: int = 0
    start: int = 0
    size: int = 0
    name: bytes = b""
    type_name: bytes = b""
    policy: int = 0
    unknown: int = 0
    data: bytes = field(default_factory=bytes, repr=False)

    _STRUCT = struct.Struct("<IiII256s80s2I")
    SIZE = _STRUCT.size  # 360 bytes

    @property
    def name_str(self) -> str:
        return self.name.rstrip(b"\x00").decode("ascii", errors="replace")

    @property
    def type_str(self) -> str:
        return self.type_name.rstrip(b"\x00").decode("ascii", errors="replace")

    @classmethod
    def from_bytes(cls, data: bytes) -> "FirmwareItem":
        if len(data) < cls.SIZE:
            raise ValueError(f"Item too short: {len(data)}")
        seq, crc, start, size, name, type_name, policy, unknown = cls._STRUCT.unpack(data[:cls.SIZE])
        return cls(
            seq=seq, crc=crc, start=start, size=size,
            name=name, type_name=type_name, policy=policy, unknown=unknown,
        )

    def to_bytes(self) -> bytes:
        return self._STRUCT.pack(
            self.seq, self.crc, self.start, self.size,
            self.name.ljust(256, b"\x00")[:256],
            self.type_name.ljust(80, b"\x00")[:80],
            self.policy, self.unknown,
        )


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

@dataclass
class HuaweiFirmware:
    """Huawei router firmware parser and builder.

    Usage:
        fw = HuaweiFirmware.from_file("firmware.bin")
        for item in fw.items:
            print(item.name_str, item.size)
        fw.unpack("/tmp/firmware_parts/")

        # Roundtrip
        fw2 = HuaweiFirmware.from_directory("/tmp/firmware_parts/")
        fw2.to_file("repacked.bin")
    """

    header: FirmwareHeader = field(default_factory=FirmwareHeader)
    extra_header: bytes = b""
    items: List[FirmwareItem] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, data: bytes) -> "HuaweiFirmware":
        """Parse firmware from raw bytes."""
        fw = cls()
        offset = 0

        fw.header = FirmwareHeader.from_bytes(data[offset:])
        offset += FirmwareHeader.SIZE

        if fw.header.extra_header_length > 0:
            fw.extra_header = data[offset:offset + fw.header.extra_header_length]
            offset += fw.header.extra_header_length

        item_table_end = offset + fw.header.item_count * FirmwareItem.SIZE

        for _ in range(fw.header.item_count):
            item = FirmwareItem.from_bytes(data[offset:])
            offset += FirmwareItem.SIZE
            # Load item data from absolute position
            if item.start > 0 and item.size > 0:
                item.data = data[item.start:item.start + item.size]
            fw.items.append(item)

        return fw

    @classmethod
    def from_file(cls, path: str) -> "HuaweiFirmware":
        """Parse firmware from file."""
        return cls.from_bytes(Path(path).read_bytes())

    @classmethod
    def from_directory(cls, directory: str) -> "HuaweiFirmware":
        """Reconstruct firmware from unpacked directory."""
        dir_path = Path(directory)
        header_file = dir_path / ".header"

        if not header_file.exists():
            raise FileNotFoundError(f".header file not found in {directory}")

        # Parse the header-only file
        fw = cls.from_bytes(header_file.read_bytes())

        # Load item data from individual files
        for item in fw.items:
            item_path = dir_path / item.name_str
            if item_path.exists():
                item.data = item_path.read_bytes()
                item.size = len(item.data)

        return fw

    def unpack(self, directory: str) -> Dict[str, int]:
        """Unpack firmware into directory, one file per item.

        Args:
            directory: Output directory (created if missing).

        Returns:
            {item_name: item_size} mapping.
        """
        dir_path = Path(directory)
        dir_path.mkdir(parents=True, exist_ok=True)

        # Save header-only file for repacking
        header_only = self._to_bytes(include_data=False)
        (dir_path / ".header").write_bytes(header_only)

        result = {}
        for item in self.items:
            if item.name_str and item.data:
                (dir_path / item.name_str).write_bytes(item.data)
                result[item.name_str] = len(item.data)

        return result

    def to_bytes(self) -> bytes:
        """Serialize firmware to bytes with correct CRC32."""
        return self._to_bytes(include_data=True)

    def to_file(self, path: str) -> None:
        """Write firmware to file."""
        Path(path).write_bytes(self.to_bytes())

    def _to_bytes(self, include_data: bool = True) -> bytes:
        """Build firmware bytes, recalculating layout and CRCs."""
        # Calculate item data start offset
        header_size = FirmwareHeader.SIZE
        extra_size = len(self.extra_header)
        item_table_size = len(self.items) * FirmwareItem.SIZE
        data_start = header_size + extra_size + item_table_size

        # Assign item positions
        current_offset = data_start
        for item in self.items:
            item.start = current_offset
            item.size = len(item.data) if item.data else 0
            if item.data:
                item.crc = _crc32(item.data)
            current_offset += item.size

        total_size = current_offset

        # Build item table bytes
        item_table = b"".join(i.to_bytes() for i in self.items)

        # Compute header CRC over: partial_header + extra + item_table
        self.header.item_count = len(self.items)
        self.header.extra_header_length = extra_size
        self.header.item_size = FirmwareItem.SIZE
        self.header.file_length = total_size

        # Header CRC covers bytes [12:] of header + extra + item table
        partial_hdr = self.header.to_bytes()[12:]
        self.header.header_crc = _crc32(partial_hdr, self.extra_header, item_table)

        if include_data:
            # File CRC covers everything from byte 12 onward
            all_data = b"".join(i.data for i in self.items if i.data)
            self.header.file_crc = _crc32(
                self.header.to_bytes()[12:],
                self.extra_header,
                item_table,
                all_data,
            )

        parts = [self.header.to_bytes(), self.extra_header, item_table]
        if include_data:
            for item in self.items:
                if item.data:
                    parts.append(item.data)

        return b"".join(parts)

    def describe(self) -> str:
        """Return human-readable firmware summary."""
        lines = [
            f"Huawei Firmware: magic={self.header.magic!r} items={len(self.items)}",
        ]
        for item in self.items:
            lines.append(f"  [{item.seq:2d}] {item.name_str:<30} {item.size:>10} bytes  ({item.type_str})")
        return "\n".join(lines)
