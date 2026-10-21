#!/usr/bin/env python3
"""
forensic_deep.py — Deep forensic analysis engine for Embedded Firmware Research Lab
Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek

Pure-Python engine: no binwalk/7z required.
Implements: GPT/MBR parser, ext4 reader (superblock + directory traversal +
file extraction), embedded signature scanner, entropy heatmap, strings audit,
credential hunting, CVE-pattern matching, HTML+Markdown report generation.

Usage:
    python scripts/forensic_deep.py --target mikrotik_routeros_7221
    python scripts/forensic_deep.py --target openwrt_25121_x86
    python scripts/forensic_deep.py --all
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import yaml

# ── UTF-8 stdout ──────────────────────────────────────────────────────────────
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).resolve().parent.parent
PROFILES_YAML = REPO_ROOT / "analysis" / "target_profiles.yaml"
REPORTS_DIR  = REPO_ROOT / "reports"
TMP_DIR      = REPO_ROOT / ".tmp" / "forensic"
TMP_DIR.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TMP_DIR)

# ── Known file-format magic signatures ───────────────────────────────────────
SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"\x7fELF",                       0, "ELF binary"),
    (b"hsqs",                           0, "squashfs LE"),
    (b"sqsh",                           0, "squashfs BE"),
    (b"qshs",                           0, "squashfs BE2"),
    (b"\x1f\x8b",                       0, "gzip"),
    (b"BZh",                            0, "bzip2"),
    (b"\xfd7zXZ\x00",                   0, "XZ stream"),
    (b"PK\x03\x04",                     0, "ZIP"),
    (b"\x1b\x4c\x5a\x34",              0, "LZ4 frame"),
    (b"\x02\x21\x4c\x18",              0, "LZ4 legacy"),
    (b"\x55\xAA",                     510, "MBR boot signature"),
    (b"EFI PART",                     512, "GPT header"),
    (b"\xEF\x53",                    1080, "ext4 superblock"),   # 1024+56
    (b"\x27\x05\x19\x56",              0, "uImage (uboot)"),
    (b"\x23\x20\x4c\x69",              0, "Linux kernel header"),
    (b"ANDROID!",                       0, "Android boot image"),
    (b"CRaU",                           0, "JFFS2 LE"),
    (b"qjhc",                           0, "JFFS2 BE"),
    (b"\xde\xad\xc0\xde",              0, "LZMA stream"),
    (b"\xfd7zXZ",                       0, "XZ"),
    (b"\x30\x83",                       0, "LZMA SDK"),
    (b"MVL",                            0, "ubi volume"),
    (b"UBI#",                           0, "UBI superblock"),
]

# ── CVE-specific binary patterns ─────────────────────────────────────────────
# These are strings or byte patterns indicative of known vulnerability classes
CVE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # MikroTik
    ("MIKROTIK-DEVEL",   re.compile(r"devel-?login|devel[_-]shell", re.I),
     "Developer backdoor shell access path"),
    ("MIKROTIK-NOAUTH",  re.compile(r"/nova/lib/nv/nv_auth|no.?auth|bypass[_-]auth", re.I),
     "Potential auth bypass strings"),
    ("MIKROTIK-WINBOX",  re.compile(r"winbox|/flash/rw/store/user\.dat", re.I),
     "Winbox credential storage path"),
    # OpenWrt
    ("OPENWRT-POPEN",    re.compile(r"popen\(|os\.execute\(|io\.popen\(", re.I),
     "Shell command execution in script"),
    ("OPENWRT-LUCI-EXEC",re.compile(r"luci\.sys\.call|luci\.sys\.exec", re.I),
     "LuCI system call from UI handler"),
    # Generic embedded
    ("HARDCODED-PASS",   re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([A-Za-z0-9!@#$%^&*._-]{4,})['\"]?"),
     "Hardcoded password value"),
    ("HARDCODED-KEY",    re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_-]{12,})['\"]?"),
     "Hardcoded API key or token"),
    ("PEM-PRIVATE",      re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
     "Private key PEM block"),
    ("COMMAND-INJECT",   re.compile(r"sprintf\s*\([^,]+,[^;]*%s[^;]*\)\s*;\s*(?:system|popen|execv)"),
     "sprintf+system pattern (potential command injection)"),
    ("SQL-QUERY",        re.compile(r"(?i)SELECT .{0,40} FROM|INSERT INTO|UPDATE .{0,30} SET"),
     "SQL query string (check for injection)"),
    # ── Zero-day research candidates (identified Apr-2026) ────────────────────
    # CVE-CANDIDATE-1: DHCP hostname injection → netifd ucode/shell scripts
    # Trigger: malicious DHCP server sets hostname containing shell metacharacters;
    # OpenWrt netifd passes it to ucode/sh without sanitisation in some code paths.
    ("NETIFD-DHCP-INJECT",
     re.compile(
         r"dhcp_hostname"              # explicit dhcp hostname variable
         r"|udhcpc[^\n]{0,60}hostname" # udhcpc passing hostname arg
         r"|netifd[^\n]{0,60}hostname" # netifd referencing hostname
         r"|hostname\s*[=:]\s*\$"      # hostname=$ shell variable expansion
         r"|set_hostname\s*\("         # set_hostname function call
         r"|OPTION_HOSTNAME",          # DHCP option 12 constant
         re.I,
     ),
     "DHCP hostname string used in netifd — potential unsanitised shell injection (ZD-CANDIDATE-1)"),
    ("NETIFD-UCODE-EXEC",
     re.compile(r"ucode|\.uc[\"']?\s*\)|os\.execute|io\.popen", re.I),
     "ucode script execution or shell invocation in netifd context"),
    # CVE-CANDIDATE-2: libiwinfo SSID parsing — untrusted wireless scan data
    # libiwinfo.so.20230701 is significantly older than rest of the build (Feb-2026);
    # may lack security fixes for malformed/oversized SSID (buffer overflow, format string).
    ("LIBIWINFO-SSID",
     re.compile(r"iwinfo|ssid|SSID|scan_results|iwscan|nl80211.*ssid", re.I),
     "libiwinfo SSID / wireless scan data parsing — older lib, potential OOB read (ZD-CANDIDATE-2)"),
    ("LIBIWINFO-BUFLEN",
     re.compile(r"IWINFO_ESSID_MAX_SIZE|IWINFO_BUFSIZE|memcpy.*ssid|strncpy.*ssid", re.I),
     "SSID buffer copy without explicit length check — verify bounds against libiwinfo.so.20230701"),
    # CVE-CANDIDATE-3: MikroTik REST API / script execution paths
    # /rest API added in v7; command execution endpoints may not fully sanitise input.
    ("MIKROTIK-REST-EXEC",
     re.compile(r"/rest/|api-rest|Rfc2616|/tool/fetch|/system/script/run", re.I),
     "MikroTik REST API endpoint or script execution path (ZD-CANDIDATE-3)"),
    ("MIKROTIK-SCRIPT-ENV",
     re.compile(r":global\s+\w+|:local\s+\w+|:execute\s+|/system/script", re.I),
     "RouterOS scripting keywords — check for unsanitised variable interpolation"),
    # ── Supply-chain / build-time markers ─────────────────────────────────────
    ("BUILD-TIMESTAMP",
     re.compile(r"(?:BUILD_DATE|build_date|COMPILE_DATE|compile_time)\s*[=:]\s*[\w-]{8,}"),
     "Embedded build timestamp — use for differential analysis against patched builds"),
    ("PACKAGE-VERSION",
     re.compile(r"(?:PKG_VERSION|pkg_version|PACKAGE_VERSION)[=:\s]+[\d.]{3,}"),
     "Package version string — cross-reference against CVE databases"),
]

# ── Interesting string patterns ───────────────────────────────────────────────
IP_RE    = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE   = re.compile(r"https?://[^\s\"'<>]{8,120}")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PORT_RE  = re.compile(r"\bport\s*[=:]\s*(\d{1,5})", re.I)


# ─────────────────────────────────────────────────────────────────────────────
# GPT / Partition table parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_gpt(data: bytes) -> list[dict[str, Any]]:
    """Parse a GPT partition table. data must cover at least the first 34 LBAs (17 KB)."""
    partitions: list[dict[str, Any]] = []
    if len(data) < 1024:
        return partitions
    # GPT header at LBA 1 (offset 512)
    if data[512:520] != b"EFI PART":
        return partitions
    num_entries  = struct.unpack_from("<I", data, 512 + 80)[0]
    entry_size   = struct.unpack_from("<I", data, 512 + 84)[0]
    entries_lba  = struct.unpack_from("<Q", data, 512 + 72)[0]
    entries_off  = entries_lba * 512
    for i in range(min(num_entries, 128)):
        off = entries_off + i * entry_size
        if off + entry_size > len(data):
            break
        type_guid_raw = data[off:off+16]
        if type_guid_raw == b"\x00" * 16:
            continue
        first_lba = struct.unpack_from("<Q", data, off + 32)[0]
        last_lba  = struct.unpack_from("<Q", data, off + 40)[0]
        # decode UTF-16LE name (72 bytes = 36 chars)
        name_raw = data[off + 56: off + 56 + 72]
        try:
            name = name_raw.decode("utf-16-le").rstrip("\x00")
        except Exception:
            name = "<decode_err>"
        size_mb = round((last_lba - first_lba + 1) * 512 / 1024 / 1024, 1)
        partitions.append({
            "index": i + 1,
            "name": name or f"part{i+1}",
            "first_lba": first_lba,
            "last_lba":  last_lba,
            "size_mb":   size_mb,
            "offset_bytes": first_lba * 512,
        })
    return partitions


def parse_mbr_partitions(data: bytes) -> list[dict[str, Any]]:
    """Parse the 4 MBR partition entries."""
    parts = []
    if len(data) < 512 or data[510:512] != b"\x55\xaa":
        return parts
    for i in range(4):
        off = 446 + i * 16
        ptype = data[off + 4]
        if ptype == 0:
            continue
        lba_start = struct.unpack_from("<I", data, off + 8)[0]
        lba_size  = struct.unpack_from("<I", data, off + 12)[0]
        parts.append({
            "index": i + 1,
            "type": f"0x{ptype:02x}",
            "first_lba": lba_start,
            "size_mb": round(lba_size * 512 / 1024 / 1024, 1),
            "offset_bytes": lba_start * 512,
        })
    return parts


# ─────────────────────────────────────────────────────────────────────────────
# ext4 superblock + directory traversal
# ─────────────────────────────────────────────────────────────────────────────

EXT4_MAGIC = 0xEF53
EXT4_EXTENTS_FL = 0x80000

# ext4 superblock layout (selected fields, offsets relative to superblock start)
_SB_FMT = "<IIIIIIIIIIII2sHH"  # 0..55 (partial)

def read_ext4_superblock(data: bytes, part_offset: int) -> dict[str, Any] | None:
    """Parse ext4 superblock from disk data at part_offset."""
    sb_off = part_offset + 1024
    if sb_off + 1024 > len(data):
        return None
    sb = data[sb_off: sb_off + 1024]
    magic = struct.unpack_from("<H", sb, 56)[0]
    if magic != EXT4_MAGIC:
        return None

    inode_count        = struct.unpack_from("<I", sb, 0)[0]
    blocks_count       = struct.unpack_from("<I", sb, 4)[0]
    log_block_size     = struct.unpack_from("<I", sb, 24)[0]
    blocks_per_group   = struct.unpack_from("<I", sb, 32)[0]
    inodes_per_group   = struct.unpack_from("<I", sb, 40)[0]
    inode_size         = struct.unpack_from("<H", sb, 88)[0]
    first_data_block   = struct.unpack_from("<I", sb, 20)[0]
    rev_level          = struct.unpack_from("<I", sb, 76)[0]
    feature_compat     = struct.unpack_from("<I", sb, 92)[0]
    feature_incompat   = struct.unpack_from("<I", sb, 96)[0]
    feature_ro_compat  = struct.unpack_from("<I", sb, 100)[0]
    uuid_raw           = sb[104:120]
    vol_name           = sb[120:136].rstrip(b"\x00").decode("ascii", errors="replace")
    last_mounted       = sb[136:200].rstrip(b"\x00").decode("ascii", errors="replace")
    creator_os         = struct.unpack_from("<I", sb, 72)[0]
    free_inodes        = struct.unpack_from("<I", sb, 16)[0]
    free_blocks        = struct.unpack_from("<I", sb, 12)[0]

    block_size = 1024 << log_block_size
    uuid = "-".join([
        uuid_raw[0:4].hex(), uuid_raw[4:6].hex(),
        uuid_raw[6:8].hex(), uuid_raw[8:10].hex(),
        uuid_raw[10:16].hex(),
    ])

    # Incompat features decode
    incompat_flags = []
    for bit, name in [
        (0x1,   "COMPRESSION"),  (0x2,   "FILETYPE"),
        (0x4,   "RECOVER"),      (0x8,   "JOURNAL_DEV"),
        (0x10,  "META_BG"),      (0x40,  "EXTENTS"),
        (0x80,  "64BIT"),        (0x200, "FLEX_BG"),
        (0x1000,"ENCRYPT"),
    ]:
        if feature_incompat & bit:
            incompat_flags.append(name)

    return {
        "valid":             True,
        "block_size":        block_size,
        "inode_count":       inode_count,
        "inode_size":        inode_size,
        "blocks_count":      blocks_count,
        "free_inodes":       free_inodes,
        "free_blocks":       free_blocks,
        "blocks_per_group":  blocks_per_group,
        "inodes_per_group":  inodes_per_group,
        "first_data_block":  first_data_block,
        "rev_level":         rev_level,
        "vol_name":          vol_name,
        "uuid":              uuid,
        "last_mounted":      last_mounted,
        "creator_os":        {0: "Linux", 1: "Hurd", 2: "Masix", 3: "FreeBSD", 4: "Lites"}.get(creator_os, str(creator_os)),
        "features_incompat": incompat_flags,
        "feature_compat":    feature_compat,
        "feature_ro_compat": feature_ro_compat,
        "sb_offset":         sb_off,
    }


def _get_inode_table_offset(data: bytes, part_offset: int, sb: dict[str, Any], group: int) -> int:
    """Return byte offset of inode table for block group `group`."""
    block_size = sb["block_size"]
    # BGD table starts at block (first_data_block + 1), or block 2 for 1K block size
    bgd_block = sb["first_data_block"] + 1
    bgd_offset = part_offset + bgd_block * block_size

    # Descriptor size: 32 bytes (normal) or 64 bytes (64BIT feature)
    has_64bit = 0x80 in [sb["feature_compat"] & 0x80] or ("64BIT" in sb["features_incompat"])
    desc_size = 64 if has_64bit else 32

    desc_off = bgd_offset + group * desc_size
    if desc_off + 12 > len(data):
        return -1

    bg_inode_table_lo = struct.unpack_from("<I", data, desc_off + 8)[0]
    return part_offset + bg_inode_table_lo * block_size


def _read_inode(data: bytes, part_offset: int, sb: dict[str, Any], inode_num: int) -> bytes | None:
    """Read raw inode bytes for inode_num (1-based)."""
    if inode_num < 1:
        return None
    idx = inode_num - 1
    group = idx // sb["inodes_per_group"]
    inode_idx_in_group = idx % sb["inodes_per_group"]

    table_off = _get_inode_table_offset(data, part_offset, sb, group)
    if table_off < 0:
        return None

    inode_off = table_off + inode_idx_in_group * sb["inode_size"]
    if inode_off + sb["inode_size"] > len(data):
        return None
    return data[inode_off: inode_off + sb["inode_size"]]


def _parse_inode(raw: bytes) -> dict[str, Any]:
    i_mode        = struct.unpack_from("<H", raw, 0)[0]
    i_uid         = struct.unpack_from("<H", raw, 2)[0]
    i_size_lo     = struct.unpack_from("<I", raw, 4)[0]
    i_links_count = struct.unpack_from("<H", raw, 26)[0]
    i_flags       = struct.unpack_from("<I", raw, 32)[0]
    i_blocks_lo   = struct.unpack_from("<I", raw, 28)[0]
    # i_block is 60 bytes at offset 40
    i_block       = raw[40:100]
    i_size_hi     = struct.unpack_from("<I", raw, 108)[0] if len(raw) > 112 else 0
    size = i_size_lo | (i_size_hi << 32)
    ftype = {
        0o100000: "regular", 0o120000: "symlink", 0o040000: "dir",
        0o060000: "blkdev",  0o020000: "chrdev",  0o010000: "fifo",
        0o140000: "socket",
    }.get(i_mode & 0o170000, "unknown")
    perms = oct(i_mode & 0o7777)
    suid  = bool(i_mode & 0o4000)
    sgid  = bool(i_mode & 0o2000)
    return {
        "mode":     i_mode, "uid": i_uid, "size": size,
        "links":    i_links_count, "flags": i_flags,
        "type":     ftype, "perms": perms, "suid": suid, "sgid": sgid,
        "i_block":  i_block, "blocks_lo": i_blocks_lo,
    }


def _extent_blocks(i_block: bytes, data: bytes, part_offset: int, block_size: int) -> list[int]:
    """Return list of data block numbers from an extent tree (depth 0 only)."""
    blocks = []
    if len(i_block) < 12:
        return blocks
    if i_block[:2] == b"\x0a\xf3":  # ext4_extent_header magic 0xF30A LE
        n_entries = struct.unpack_from("<H", i_block, 2)[0]
        depth     = struct.unpack_from("<H", i_block, 6)[0]
        if depth == 0:
            for j in range(min(n_entries, 4)):
                ext_off = 12 + j * 12
                if ext_off + 12 > len(i_block):
                    break
                ee_len     = struct.unpack_from("<H", i_block, ext_off + 4)[0]
                ee_start_hi= struct.unpack_from("<H", i_block, ext_off + 6)[0]
                ee_start_lo= struct.unpack_from("<I", i_block, ext_off + 8)[0]
                start_blk  = (ee_start_hi << 32) | ee_start_lo
                for b in range(min(ee_len, 512)):
                    blocks.append(start_blk + b)
    return blocks


def _direct_blocks(i_block: bytes) -> list[int]:
    """Return list of block numbers from traditional (non-extent) direct block array."""
    blocks = []
    # 12 direct pointers at i_block[0..47]
    for i in range(12):
        blk = struct.unpack_from("<I", i_block, i * 4)[0]
        if blk != 0:
            blocks.append(blk)
    # Note: indirect blocks (i_block[12..14]) not implemented for simplicity
    return blocks


def _read_inode_data(data: bytes, part_offset: int, sb: dict[str, Any], inode_d: dict[str, Any], max_bytes: int = 65536) -> bytes:
    """Read up to max_bytes of file/dir content from an inode (extents + direct blocks)."""
    block_size = sb["block_size"]
    i_block = inode_d["i_block"]
    flags   = inode_d["flags"]
    buf = b""

    if flags & EXT4_EXTENTS_FL:
        blocks = _extent_blocks(i_block, data, part_offset, block_size)
    else:
        blocks = _direct_blocks(i_block)

    for blk in blocks:
        off = part_offset + blk * block_size
        if off < 0 or off + block_size > len(data):
            continue
        buf += data[off: off + block_size]
        if len(buf) >= max_bytes:
            break

    return buf[:min(inode_d["size"], max_bytes)]


def list_directory(data: bytes, part_offset: int, sb: dict[str, Any], inode_num: int) -> list[dict[str, Any]]:
    """List contents of a directory given its inode number."""
    raw = _read_inode(data, part_offset, sb, inode_num)
    if not raw:
        return []
    inode_d = _parse_inode(raw)
    if inode_d["type"] != "dir":
        return []
    dir_data = _read_inode_data(data, part_offset, sb, inode_d, max_bytes=65536)
    entries = []
    pos = 0
    while pos < len(dir_data):
        if pos + 8 > len(dir_data):
            break
        ino    = struct.unpack_from("<I", dir_data, pos)[0]
        reclen = struct.unpack_from("<H", dir_data, pos + 4)[0]
        namelen= struct.unpack_from("<B", dir_data, pos + 6)[0]
        ftype  = struct.unpack_from("<B", dir_data, pos + 7)[0]
        if reclen < 8 or reclen > 4096:
            break
        if ino > 0 and namelen > 0:
            try:
                name = dir_data[pos + 8: pos + 8 + namelen].decode("utf-8", errors="replace")
            except Exception:
                name = "<err>"
            if name not in (".", ".."):
                ft = {1: "regular", 2: "dir", 7: "symlink"}.get(ftype, "other")
                entries.append({"name": name, "inode": ino, "ftype": ft})
        pos += reclen
    return entries


def find_inode_by_path(data: bytes, part_offset: int, sb: dict[str, Any], path: str) -> int | None:
    """Walk a path from root and return the inode number, or None."""
    parts = [p for p in path.strip("/").split("/") if p]
    current_ino = 2  # root
    for part in parts:
        entries = list_directory(data, part_offset, sb, current_ino)
        found = next((e for e in entries if e["name"] == part), None)
        if not found:
            return None
        current_ino = found["inode"]
    return current_ino


def read_file_from_ext4(data: bytes, part_offset: int, sb: dict[str, Any], path: str, max_bytes: int = 65536) -> bytes | None:
    """Read a file from ext4 by path. Returns content bytes or None."""
    ino = find_inode_by_path(data, part_offset, sb, path)
    if ino is None:
        return None
    raw = _read_inode(data, part_offset, sb, ino)
    if not raw:
        return None
    inode_d = _parse_inode(raw)
    if inode_d["type"] not in ("regular", "symlink"):
        return None
    return _read_inode_data(data, part_offset, sb, inode_d, max_bytes=max_bytes)


def walk_ext4(data: bytes, part_offset: int, sb: dict[str, Any], start_path: str = "/", max_depth: int = 4) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """Recursively walk ext4 filesystem. Yields (full_path, inode_num, inode_parsed)."""
    def _walk(path: str, ino: int, depth: int) -> Iterator[tuple[str, int, dict[str, Any]]]:
        if depth > max_depth:
            return
        raw = _read_inode(data, part_offset, sb, ino)
        if not raw:
            return
        inode_d = _parse_inode(raw)
        yield path, ino, inode_d
        if inode_d["type"] == "dir":
            entries = list_directory(data, part_offset, sb, ino)
            for e in entries:
                child_path = path.rstrip("/") + "/" + e["name"]
                yield from _walk(child_path, e["inode"], depth + 1)

    start_ino = find_inode_by_path(data, part_offset, sb, start_path) or 2
    yield from _walk(start_path, start_ino, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Entropy analysis
# ─────────────────────────────────────────────────────────────────────────────

def block_entropy(data: bytes) -> float:
    """Shannon entropy of a byte block (0-8 bits)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    # Guard against log2(0) — only non-zero counts contribute
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def entropy_heatmap(data: bytes, block_size: int = 4096) -> list[dict[str, Any]]:
    """Compute entropy for every block. Returns list of {offset, entropy, label}."""
    results = []
    for i in range(0, len(data), block_size):
        block = data[i: i + block_size]
        if not block:
            continue
        ent = block_entropy(block)
        if ent < 1.0:
            label = "zero/repeated"
        elif ent < 4.0:
            label = "structured data"
        elif ent < 6.5:
            label = "text/code"
        elif ent < 7.5:
            label = "compressed"
        else:
            label = "encrypted/random"
        results.append({"offset": i, "entropy": round(ent, 3), "label": label})
    return results


def entropy_summary(heatmap: list[dict[str, Any]]) -> dict[str, Any]:
    if not heatmap:
        return {}
    vals = [b["entropy"] for b in heatmap]
    avg = sum(vals) / len(vals)
    label_counts: dict[str, int] = defaultdict(int)
    for b in heatmap:
        label_counts[b["label"]] += 1
    high_ent = [b for b in heatmap if b["entropy"] > 7.0]
    low_ent  = [b for b in heatmap if b["entropy"] < 1.0]
    return {
        "avg_entropy": round(avg, 3),
        "min": round(min(vals), 3),
        "max": round(max(vals), 3),
        "blocks_total": len(heatmap),
        "high_entropy_blocks": len(high_ent),
        "low_entropy_blocks":  len(low_ent),
        "label_distribution": dict(label_counts),
        "high_entropy_regions": [
            {"offset_mb": round(b["offset"] / 1024 / 1024, 2), "entropy": b["entropy"]}
            for b in high_ent[:20]
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Signature scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_signatures(data: bytes, max_hits: int = 200) -> list[dict[str, Any]]:
    """Scan data for known file magic signatures."""
    hits: list[dict[str, Any]] = []
    for magic, rel_offset, label in SIGNATURES:
        if rel_offset > 0:
            # Fixed-offset check (e.g. MBR at 510)
            pos = rel_offset
            if pos + len(magic) <= len(data) and data[pos:pos + len(magic)] == magic:
                hits.append({"offset": pos, "label": label, "offset_mb": round(pos / 1024 / 1024, 3)})
        else:
            # Scan entire buffer
            start = 0
            while len(hits) < max_hits:
                idx = data.find(magic, start)
                if idx < 0:
                    break
                hits.append({
                    "offset": idx,
                    "label": label,
                    "offset_mb": round(idx / 1024 / 1024, 3),
                })
                start = idx + 1
    hits.sort(key=lambda h: h["offset"])
    # deduplicate exact offset duplicates
    seen: set[tuple[int, str]] = set()
    unique = []
    for h in hits:
        k = (h["offset"], h["label"])
        if k not in seen:
            seen.add(k)
            unique.append(h)
    return unique[:max_hits]


# ─────────────────────────────────────────────────────────────────────────────
# Strings + credential + CVE pattern analysis
# ─────────────────────────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 7) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _run_sysinternals_strings(path: Path) -> list[str]:
    """Use Sysinternals strings.exe if available (Windows only)."""
    exe = shutil.which("strings")
    if not exe:
        return []
    try:
        r = subprocess.run(
            [exe, "-n", "8", "-nobanner", str(path)],
            capture_output=True, text=True, timeout=120,
        )
        return [l.strip() for l in r.stdout.splitlines() if len(l.strip()) >= 8]
    except Exception:
        return []


def analyze_strings(strings: list[str], max_items: int = 40) -> dict[str, Any]:
    ips: set[str] = set()
    urls: set[str] = set()
    emails: set[str] = set()
    cve_hits: list[dict[str, str]] = []
    cred_hits: list[dict[str, str]] = []
    # Per-pattern cap: each pattern contributes at most this many unique matches.
    # Prevents a broad pattern (e.g. LIBIWINFO-SSID hitting every SSID string)
    # from monopolising the max_items budget and hiding rarer, higher-value hits.
    MAX_PER_PATTERN = 4
    cve_per_pattern: dict[str, int] = {}
    cve_seen: set[tuple[str, str]] = set()
    cred_seen: set[str] = set()

    for s in strings:
        for ip in IP_RE.findall(s):
            if not ip.startswith("0.") and ip not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                ips.add(ip)
        for url in URL_RE.findall(s):
            urls.add(url)
        for em in EMAIL_RE.findall(s):
            emails.add(em)
        for label, pat, desc in CVE_PATTERNS:
            if cve_per_pattern.get(label, 0) >= MAX_PER_PATTERN:
                continue
            m = pat.search(s)
            if m:
                key = (label, s[:120])
                if key not in cve_seen:
                    cve_seen.add(key)
                    cve_hits.append({"pattern": label, "desc": desc, "match": s[:120]})
                    cve_per_pattern[label] = cve_per_pattern.get(label, 0) + 1
        # Credential patterns
        for cpat in [
            re.compile(r"(?i)password\s*[=:]\s*(\S{4,30})"),
            re.compile(r"(?i)secret\s*[=:]\s*(\S{4,30})"),
            re.compile(r"(?i)passwd\s*[=:]\s*(\S{4,20})"),
        ]:
            m = cpat.search(s)
            if m:
                norm = s[:120]
                if norm not in cred_seen:
                    cred_seen.add(norm)
                    cred_hits.append({"match": norm})

    return {
        "unique_ips":   sorted(ips)[:max_items],
        "unique_urls":  sorted(urls)[:max_items],
        "unique_emails":sorted(emails)[:max_items],
        "cve_patterns": cve_hits[:max_items],
        "cred_patterns":cred_hits[:max_items],
        "total_strings": len(strings),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main forensic engine
# ─────────────────────────────────────────────────────────────────────────────

def run_forensic(target_id: str, target: dict[str, Any]) -> dict[str, Any]:
    """Full forensic pipeline. Returns a rich results dict."""
    results: dict[str, Any] = {
        "target_id":    target_id,
        "label":        target.get("label", target_id),
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "architecture": target.get("architecture", "?"),
        "os":           target.get("os", "?"),
        "runnable":     target.get("runnable", False),
        "tier":         target.get("tier", "?"),
        "study_order":  target.get("study_order", "?"),
        "stages":       {},
    }

    fw_key = target.get("firmware_file", "")
    fw_path = REPO_ROOT / fw_key
    if not fw_path.exists():
        results["error"] = f"Firmware file not found: {fw_path}"
        return results

    results["firmware_file"]    = fw_path.name
    results["firmware_size_mb"] = round(fw_path.stat().st_size / 1024 / 1024, 1)

    # ── Stage 1: decompress / extract ─────────────────────────────────────────
    print(f"  [1/6] Decompressing {fw_path.name} ...")
    img_path: Path | None = None

    if fw_path.suffix == ".gz":
        img_path = TMP_DIR / fw_path.stem
        if not img_path.exists():
            print(f"       gunzip → {img_path.name}")
            with gzip.open(fw_path, "rb") as fin:
                img_path.write_bytes(fin.read())
    elif fw_path.suffix == ".zip":
        inner = target.get("disk_image") or target.get("firmware_inner")
        if inner:
            img_path = TMP_DIR / Path(inner).name
            if not img_path.exists():
                with zipfile.ZipFile(fw_path) as z:
                    for name in z.namelist():
                        if Path(name).name == Path(inner).name:
                            print(f"       unzip inner: {name}")
                            img_path.write_bytes(z.read(name))
                            break
    else:
        img_path = fw_path

    if img_path is None or not img_path.exists():
        # Fall back: just use the original archive for raw string scan
        print("       [WARN] Could not extract disk image — using archive for string scan")
        img_path = fw_path

    img_size = img_path.stat().st_size
    results["img_path"]    = str(img_path)
    results["img_size_mb"] = round(img_size / 1024 / 1024, 1)
    print(f"       Disk image: {img_path.name} ({results['img_size_mb']} MB)")

    # ── Stage 2: read image into memory (or mmap for large files) ────────────
    print("  [2/6] Reading image into memory ...")
    # Cap at 200 MB to avoid OOM; for MikroTik (128 MB) we read all
    read_limit = min(img_size, 200 * 1024 * 1024)
    with open(img_path, "rb") as f:
        data = f.read(read_limit)
    print(f"       Read {len(data) // 1024 // 1024} MB (limit 200 MB)")

    # ── Stage 3: partition table ───────────────────────────────────────────────
    print("  [3/6] Parsing partition table ...")
    partitions = parse_gpt(data)
    if not partitions:
        partitions = parse_mbr_partitions(data)
    results["stages"]["partitions"] = partitions
    for p in partitions:
        print(f"       Part {p['index']}: '{p.get('name','')}' LBA {p.get('first_lba',0)} — {p.get('size_mb',0)} MB")

    # ── Stage 4: ext4 analysis per partition ──────────────────────────────────
    print("  [4/6] Analysing ext4 filesystems ...")
    ext4_results: list[dict[str, Any]] = []

    for p in partitions:
        part_offset = p["offset_bytes"]
        sb = read_ext4_superblock(data, part_offset)
        if sb is None:
            continue
        print(f"       Partition {p['index']} — ext4 OK | block={sb['block_size']}B | inodes={sb['inode_count']} | vol='{sb['vol_name']}'")

        fs_result: dict[str, Any] = {
            "partition": p["index"],
            "partition_name": p.get("name", ""),
            "superblock": sb,
            "root_listing": [],
            "key_files": {},
            "suid_files": [],
            "elf_files": [],
            "interesting_paths": [],
        }

        # Root directory listing
        try:
            root_entries = list_directory(data, part_offset, sb, 2)
            fs_result["root_listing"] = [e["name"] for e in root_entries]
        except Exception as exc:
            fs_result["root_listing"] = [f"<err: {exc}>"]

        # Walk filesystem for interesting items
        INTERESTING_PATHS = [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/etc/openwrt_release", "/etc/os-release",
            "/etc/config",              # OpenWrt UCI config dir
            "/etc/config/network",      # OpenWrt network UCI config
            "/etc/config/wireless",     # OpenWrt wireless UCI config (SSID/keys)
            "/etc/config/dhcp",         # OpenWrt DHCP/dnsmasq config
            "/nova/etc/devel-login",    # MikroTik devel shell
            "/nova/lib/nv",             # MikroTik nova libraries
            "/flash/rw/store/user.dat", # MikroTik credentials DB
            "/usr/sbin/uhttpd",         # OpenWrt web server
            "/usr/sbin/dnsmasq",        # OpenWrt DNS
            "/usr/lib/dropbear",        # OpenWrt SSH
            # ZD-CANDIDATE-1: netifd DHCP hostname injection vectors
            "/lib/netifd/netifd-proto.sh",
            "/lib/netifd/proto/dhcp.sh",
            "/usr/share/udhcpc/default.script",
            # ZD-CANDIDATE-2: libiwinfo / LuCI wireless interface
            "/usr/lib/lua/luci/controller/admin/network.lua",
            "/usr/lib/lua/luci/model/cbi/admin_network/wifi.lua",
            # ZD-CANDIDATE-3: MikroTik REST API / scripting dirs
            "/nova/etc/scripts",
            "/flash/rw/store/sys.idx",
        ]
        for ipath in INTERESTING_PATHS:
            content = read_file_from_ext4(data, part_offset, sb, ipath, max_bytes=4096)
            if content is not None:
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = f"<binary {len(content)} bytes>"
                fs_result["key_files"][ipath] = text[:2000]
                print(f"         [FOUND] {ipath} ({len(content)} bytes)")

        # Walk and collect ELF + SUID files
        try:
            for fpath, ino, inode_d in walk_ext4(data, part_offset, sb, "/", max_depth=4):
                if inode_d["type"] == "regular":
                    if inode_d["suid"]:
                        fs_result["suid_files"].append({"path": fpath, "perms": inode_d["perms"]})
                    # Check ELF magic (read first 4 bytes)
                    content = _read_inode_data(data, part_offset, sb, inode_d, max_bytes=4)
                    if content and content[:4] == b"\x7fELF":
                        sz = inode_d["size"]
                        fs_result["elf_files"].append({"path": fpath, "size": sz})
                        # Extract strings from ELF (up to 32KB)
                        elf_content = _read_inode_data(data, part_offset, sb, inode_d, max_bytes=32768)
                        elf_strings = extract_strings(elf_content, min_len=8)
                        elf_str_result = analyze_strings(elf_strings, max_items=20)
                        if elf_str_result["cve_patterns"] or elf_str_result["cred_patterns"]:
                            fs_result["interesting_paths"].append({
                                "path": fpath,
                                "cve_hits": elf_str_result["cve_patterns"],
                                "cred_hits": elf_str_result["cred_patterns"],
                                "ips": elf_str_result["unique_ips"][:5],
                                "urls": elf_str_result["unique_urls"][:5],
                            })
        except Exception as exc:
            fs_result["walk_error"] = str(exc)

        print(f"         ELF files found: {len(fs_result['elf_files'])}")
        print(f"         SUID files found: {len(fs_result['suid_files'])}")
        ext4_results.append(fs_result)

    results["stages"]["ext4"] = ext4_results

    # ── Stage 5: entropy + signature scan ────────────────────────────────────
    print("  [5/6] Entropy heatmap + signature scan ...")
    heatmap = entropy_heatmap(data, block_size=16384)
    ent_summary = entropy_summary(heatmap)
    sigs = scan_signatures(data)
    results["stages"]["entropy"] = ent_summary
    results["stages"]["signatures"] = sigs
    print(f"       Avg entropy: {ent_summary.get('avg_entropy','?')} bits")
    print(f"       High-entropy blocks (>7.0): {ent_summary.get('high_entropy_blocks',0)}")
    print(f"       Signatures found: {len(sigs)}")

    # ── Stage 6: strings analysis ──────────────────────────────────────────────
    print("  [6/6] Strings + CVE pattern analysis ...")
    # Try sysinternals first (better Unicode handling), fallback to Python
    raw_strings = _run_sysinternals_strings(img_path)
    if not raw_strings:
        raw_strings = extract_strings(data, min_len=8)
    str_results = analyze_strings(raw_strings)
    results["stages"]["strings"] = str_results
    print(f"       Total strings extracted: {str_results['total_strings']}")
    print(f"       Unique IPs: {len(str_results['unique_ips'])}")
    print(f"       Unique URLs: {len(str_results['unique_urls'])}")
    print(f"       CVE pattern hits: {len(str_results['cve_patterns'])}")
    print(f"       Credential pattern hits: {len(str_results['cred_patterns'])}")

    # CVE cross-reference from profile
    results["stages"]["cves"] = target.get("known_cves", [])
    results["stages"]["attack_surface"] = target.get("attack_surface", [])
    results["stages"]["research_focus"] = target.get("research_focus", [])
    results["stages"]["vm_notes"] = target.get("vm_notes", "")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Report generation — Markdown
# ─────────────────────────────────────────────────────────────────────────────

def _severity_bar(entropy: float) -> str:
    """Visual entropy bar."""
    filled = int(entropy / 8 * 20)
    return "[" + "#" * filled + "-" * (20 - filled) + "]"


def generate_markdown_report(r: dict[str, Any], out_path: Path) -> None:
    ts  = r.get("timestamp", "")[:19].replace("T", " ") + " UTC"
    lines = [
        f"# Forensic Analysis Report — {r['label']}",
        f"> Generated: {ts}  ",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "> Methodology: Static forensic analysis (pure Python, no binwalk)",
        "",
        "---",
        "",
        "## 1. Target Overview",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Target ID | `{r['target_id']}` |",
        f"| Study Priority | #{r['study_order']} |",
        f"| Tier | {r['tier']} (1=bootable VM, 2=ARM/extract, 3=decrypt-first) |",
        f"| Architecture | {r['architecture']} |",
        f"| OS | {r['os']} |",
        f"| Runnable in VM | {r['runnable']} |",
        f"| Firmware file | `{r['firmware_file']}` |",
        f"| Firmware size | {r['firmware_size_mb']} MB |",
        f"| Disk image | `{Path(r.get('img_path','')).name}` — {r.get('img_size_mb','?')} MB |",
        "",
    ]

    # Partition table
    parts = r["stages"].get("partitions", [])
    if parts:
        lines += [
            "## 2. Partition Table",
            "",
            "| # | Name | First LBA | Size |",
            "|---|------|-----------|------|",
        ]
        for p in parts:
            lines.append(f"| {p['index']} | {p.get('name','')} | {p.get('first_lba',0):,} | {p.get('size_mb',0)} MB |")
        lines.append("")

    # ext4 filesystems
    ext4 = r["stages"].get("ext4", [])
    if ext4:
        lines += ["## 3. Filesystem Analysis (ext4)", ""]
        for fs in ext4:
            sb = fs["superblock"]
            lines += [
                f"### Partition {fs['partition']} — {fs['partition_name'] or 'unnamed'}",
                "",
                "**Superblock**",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Volume name | `{sb['vol_name'] or '(none)'}` |",
                f"| UUID | `{sb['uuid']}` |",
                f"| Block size | {sb['block_size']} bytes |",
                f"| Inode count | {sb['inode_count']:,} |",
                f"| Free inodes | {sb['free_inodes']:,} |",
                f"| Blocks count | {sb['blocks_count']:,} |",
                f"| Free blocks | {sb['free_blocks']:,} |",
                f"| Last mounted at | `{sb['last_mounted'] or '(none)'}` |",
                f"| Creator OS | {sb['creator_os']} |",
                f"| Features (incompat) | {', '.join(sb['features_incompat']) or 'none'} |",
                "",
            ]
            # Root listing
            root = fs.get("root_listing", [])
            if root:
                lines += [
                    "**Root directory contents**",
                    "",
                    "```",
                    "/  →  " + "  ".join(root),
                    "```",
                    "",
                ]

            # Key files
            kfiles = fs.get("key_files", {})
            if kfiles:
                lines += ["**Key files extracted**", ""]
                for fpath, content in kfiles.items():
                    lines += [
                        "<details>",
                        f"<summary><code>{fpath}</code></summary>",
                        "",
                        "```",
                        content[:1000],
                        "```",
                        "",
                        "</details>",
                        "",
                    ]

            # SUID
            suid = fs.get("suid_files", [])
            if suid:
                lines += ["**SUID files**", ""]
                for sf in suid[:20]:
                    lines.append(f"- `{sf['path']}` ({sf['perms']})")
                lines.append("")

            # ELF inventory
            elfs = fs.get("elf_files", [])
            if elfs:
                lines += [f"**ELF binaries ({len(elfs)} found, first 20)**", ""]
                for ef in elfs[:20]:
                    lines.append(f"- `{ef['path']}` — {_human_size(ef['size'])}")
                lines.append("")

    # Entropy
    ent = r["stages"].get("entropy", {})
    if ent:
        lines += [
            "## 4. Entropy Analysis",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Average entropy | {ent.get('avg_entropy','?')} / 8.0 bits |",
            f"| Min entropy | {ent.get('min','?')} |",
            f"| Max entropy | {ent.get('max','?')} |",
            f"| Blocks analyzed | {ent.get('blocks_total','?'):,} |",
            f"| High-entropy blocks (>7.0) | {ent.get('high_entropy_blocks',0)} (encrypted/compressed) |",
            f"| Low-entropy blocks (<1.0) | {ent.get('low_entropy_blocks',0)} (zero/repeated) |",
            "",
        ]
        dist = ent.get("label_distribution", {})
        if dist:
            lines += ["**Block distribution by entropy class**", ""]
            for label, count in sorted(dist.items(), key=lambda x: -x[1]):
                lines.append(f"- `{label}`: {count} blocks")
            lines.append("")
        high = ent.get("high_entropy_regions", [])
        if high:
            lines += ["**High-entropy regions (potential encrypted sections)**", ""]
            for h in high[:10]:
                lines.append(f"- Offset {h['offset_mb']} MB — entropy {h['entropy']}")
            lines.append("")

    # Signatures
    sigs = r["stages"].get("signatures", [])
    if sigs:
        sig_by_label: dict[str, list[dict]] = defaultdict(list)
        for s in sigs:
            sig_by_label[s["label"]].append(s)
        lines += [
            "## 5. Embedded Signatures",
            "",
            "| Type | Count | First Offset |",
            "|------|-------|-------------|",
        ]
        for label, items in sorted(sig_by_label.items()):
            lines.append(f"| {label} | {len(items)} | {items[0]['offset_mb']} MB |")
        lines.append("")

        # Detail notable ones
        for notable in ["ELF binary", "squashfs LE", "squashfs BE", "gzip", "uImage (uboot)"]:
            hits = sig_by_label.get(notable, [])
            if hits:
                lines += [f"**{notable} locations**", ""]
                for h in hits[:10]:
                    lines.append(f"- Offset `0x{h['offset']:08X}` ({h['offset_mb']} MB)")
                lines.append("")

    # Strings analysis
    str_r = r["stages"].get("strings", {})
    if str_r:
        lines += [
            "## 6. Strings & Credential Analysis",
            "",
            f"- Total strings extracted: {str_r.get('total_strings', 0):,}",
            f"- Unique IPs found: {len(str_r.get('unique_ips', []))}",
            f"- Unique URLs found: {len(str_r.get('unique_urls', []))}",
            f"- Emails found: {len(str_r.get('unique_emails', []))}",
            f"- CVE-pattern hits: {len(str_r.get('cve_patterns', []))}",
            f"- Credential-pattern hits: {len(str_r.get('cred_patterns', []))}",
            "",
        ]

        cve_p = str_r.get("cve_patterns", [])
        if cve_p:
            lines += ["### CVE-pattern hits (significant — review manually)", ""]
            for h in cve_p[:20]:
                lines += [
                    f"**[{h['pattern']}]** — {h['desc']}",
                    f"> `{h['match'][:100]}`",
                    "",
                ]

        cred_p = str_r.get("cred_patterns", [])
        if cred_p:
            lines += ["### Credential patterns found", ""]
            for h in cred_p[:15]:
                lines.append(f"- `{h['match'][:100]}`")
            lines.append("")

        ips = str_r.get("unique_ips", [])
        if ips:
            lines += ["### Hardcoded IPs", ""]
            for ip in ips[:20]:
                lines.append(f"- `{ip}`")
            lines.append("")

        urls = str_r.get("unique_urls", [])
        if urls:
            lines += ["### Hardcoded URLs", ""]
            for url in urls[:15]:
                lines.append(f"- `{url}`")
            lines.append("")

    # CVE cross-reference from profile
    cves = r["stages"].get("cves", [])
    if cves:
        lines += [
            "## 7. CVE Cross-Reference",
            "",
            "| CVE ID | CVSS | Status | Summary |",
            "|--------|------|--------|---------|",
        ]
        for cve in cves:
            desc = str(cve.get("description", "")).replace("\n", " ").strip()[:80]
            lines.append(f"| {cve.get('id','')} | {cve.get('cvss','?')} | `{cve.get('status','')}` | {desc} |")
        lines.append("")

    # Attack surface
    atk = r["stages"].get("attack_surface", [])
    if atk:
        lines += ["## 8. Attack Surface", ""]
        for svc in atk:
            lines.append(f"- {svc}")
        lines.append("")

    # VM / lab setup
    vm = r["stages"].get("vm_notes", "")
    if vm:
        lines += [
            "## 9. Lab Setup Instructions",
            "",
            "```bash",
            vm.strip(),
            "```",
            "",
        ]

    # Research focus
    focus = r["stages"].get("research_focus", [])
    if focus:
        lines += ["## 10. Research Focus (Next Steps)", ""]
        if isinstance(focus, list):
            for f in focus:
                item = str(f) if not isinstance(f, str) else f
                lines.append(f"- {item}")
        else:
            lines.append(str(focus))
        lines.append("")

    # Footer
    lines += [
        "---",
        "",
        "> **Disclaimer**: This report is generated for authorized security research only.  ",
        "> All findings must be handled responsibly. Do not use against production systems without explicit authorization.",
        "",
        "*Forensic engine: forensic_deep.py | Embedded Firmware Research Lab*  ",
        "*Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek*",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def load_profiles() -> dict[str, Any]:
    with open(PROFILES_YAML, encoding="utf-8") as f:
        return (yaml.safe_load(f) or {}).get("targets", {})


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deep forensic analysis of embedded firmware disk images",
        prog="forensic_deep.py",
    )
    parser.add_argument("--target", help="Single target ID from target_profiles.yaml")
    parser.add_argument("--all", action="store_true", help="Analyze top-2 priority targets")
    args = parser.parse_args()

    if not args.target and not args.all:
        parser.error("Use --target <id> or --all")

    profiles = load_profiles()

    if args.all:
        target_ids = [
            tid for tid, _ in
            sorted(profiles.items(), key=lambda x: x[1].get("study_order", 99))
        ][:2]
    else:
        target_ids = [args.target]

    for tid in target_ids:
        if tid not in profiles:
            print(f"[ERROR] Unknown target: {tid}", file=sys.stderr)
            continue

        target = profiles[tid]
        print(f"\n{'='*70}")
        print(f"  FORENSIC ANALYSIS: {target.get('label', tid)}")
        print(f"{'='*70}")

        results = run_forensic(tid, target)

        report_dir = REPORTS_DIR / tid
        report_path = report_dir / "forensic_report.md"
        print("\n  Generating Markdown report ...")
        generate_markdown_report(results, report_path)
        print(f"  [OK] Report: {report_path}")


if __name__ == "__main__":
    main()
