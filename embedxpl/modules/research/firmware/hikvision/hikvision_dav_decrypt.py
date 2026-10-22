#!/usr/bin/env python3
"""
hikvision_dav_decrypt.py — Decrypt Hikvision .dav firmware containers
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Hikvision uses several obfuscation/encryption schemes for their firmware:
  1. XOR with known keys
  2. Custom header + compressed payload
  3. LZMA/zlib compressed sections
  4. AES-128-ECB in newer firmwares

This script attempts multiple decryption strategies.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import struct
import sys
import zlib
from pathlib import Path

TMP_DIR = Path(__file__).resolve().parent.parent / ".tmp" / "hikvision_g5"
DAV_FILE = TMP_DIR / "digicap.dav"
OUT_DIR = TMP_DIR / "decrypted"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def scan_for_signatures(data: bytes, label: str = "") -> list[dict]:
    """Scan a blob for known firmware signatures."""
    sigs = {
        b"hsqs": "SquashFS (LE)",
        b"sqsh": "SquashFS (BE)",
        b"\x27\x05\x19\x56": "uImage",
        b"\x7fELF": "ELF",
        b"\x45\x3d\xcd\x28": "CramFS",
        b"PK\x03\x04": "ZIP",
        b"\x1f\x8b": "gzip",
        b"\xfd7zXZ\x00": "XZ",
        b"\x5d\x00\x00": "LZMA",
        b"HIKV": "Hikvision Header",
        b"IKVH": "Hikvision Header (rev)",
        b"\x89PNG": "PNG",
        b"JFIF": "JPEG",
        b"\xd0\x0d\xfe\xed": "Device Tree",
        b"#!/bin": "Shell Script",
        b"Linux": "Linux string",
        b"U-Boot": "U-Boot string",
        b"<!DOCTYPE": "HTML",
    }
    found = []
    for magic, desc in sigs.items():
        pos = 0
        count = 0
        while pos < len(data) and count < 20:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            found.append({"offset": idx, "magic": magic.hex(), "desc": desc})
            pos = idx + len(magic)
            count += 1
    return sorted(found, key=lambda x: x["offset"])


def try_xor_decrypt(data: bytes, key: bytes, label: str) -> bytes | None:
    """XOR decrypt with a key and check for known signatures."""
    decrypted = bytearray(len(data))
    key_len = len(key)
    for i in range(len(data)):
        decrypted[i] = data[i] ^ key[i % key_len]
    result = bytes(decrypted)
    sigs = scan_for_signatures(result[:4096], label)
    if sigs:
        return result
    return None


def analyze_header_structure(data: bytes):
    """Deep analysis of the DAV header to identify encryption/structure."""
    print("\n  === HEADER STRUCTURE ANALYSIS ===")

    # Byte frequency analysis (can reveal XOR encryption)
    freq = [0] * 256
    for b in data[:65536]:
        freq[b] += 1

    # Entropy
    total = sum(freq)
    entropy = 0
    for f in freq:
        if f > 0:
            p = f / total
            entropy -= p * (p and __import__("math").log2(p))
    print(f"  Header entropy (first 64KB): {entropy:.4f} bits/byte")
    print("    (7.0+ = encrypted/compressed, 4-6 = code/data, <4 = text)")

    # Most common bytes
    top = sorted(range(256), key=lambda x: freq[x], reverse=True)[:10]
    print(f"  Top bytes (first 64KB): {' '.join(f'0x{b:02X}({freq[b]})' for b in top)}")

    # Check for repeating XOR patterns
    # If XOR'd with a short key, the key repeats and can be detected
    # via autocorrelation
    print("\n  Checking for XOR key patterns (autocorrelation)...")
    for klen in [1, 2, 4, 8, 16, 32]:
        matches = 0
        test_len = min(4096, len(data) - klen)
        for i in range(test_len):
            if data[i] == data[i + klen]:
                matches += 1
        ratio = matches / test_len
        if ratio > 0.05:
            print(f"    Key length {klen:3d}: correlation={ratio:.4f} "
                  f"({'likely' if ratio > 0.15 else 'maybe' if ratio > 0.08 else 'low'})")

    # Try to identify the header format
    # Hikvision firmware header (known structure):
    #   0x00-0x03: encrypted magic
    #   0x04-0x07: header size or version
    #   0x08-0x0B: total file size or checksum
    #   0x0C-0x0F: flags / encryption type
    #   0x10+: partition table or key material
    print("\n  First 128 bytes (DWORD dump):")
    for i in range(0, 128, 16):
        dwords = [struct.unpack_from("<I", data, i + j)[0] for j in range(0, 16, 4)]
        hex_str = " ".join(f"{d:08X}" for d in dwords)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16])
        print(f"    {i:04X}: {hex_str}  {ascii_str}")


def try_hikvision_known_keys(data: bytes):
    """Try known Hikvision decryption keys."""
    print("\n  === KNOWN KEY DECRYPTION ATTEMPTS ===")

    # Known Hikvision XOR keys from public research
    known_keys = [
        ("hik-classic-4", bytes([0x73, 0x73, 0x8E, 0x8E])),
        ("hik-alt-4", bytes([0x4C, 0x4C, 0xB3, 0xB3])),
        ("hik-new-4", bytes([0x49, 0x4B, 0x56, 0x48])),  # "IKVH"
        ("hik-v2-8", bytes([0x73, 0x73, 0x8E, 0x8E, 0x73, 0x73, 0x8E, 0x8E])),
        ("hik-simple-1a", bytes([0xFF])),
        ("hik-simple-1b", bytes([0x5A])),
        ("hik-simple-1c", bytes([0xA5])),
        ("hik-header-xor", bytes([0x8A, 0xFF, 0xF7, 0xB6])),  # XOR with first 4 bytes
    ]

    # Also try XOR that would produce known magic bytes
    # If first 4 bytes XOR'd = "HIKV" (48 49 4B 56)
    first4 = data[:4]
    for target_magic in [b"HIKV", b"IKVH", b"\x27\x05\x19\x56", b"hsqs",
                         b"\x7fELF", b"PK\x03\x04", b"\x1f\x8b\x08\x00"]:
        key = bytes(a ^ b for a, b in zip(first4, target_magic, strict=False))
        known_keys.append((f"derive-{target_magic.hex()}", key))

    for name, key in known_keys:
        # Try on first 64KB
        test = data[:65536]
        decrypted = bytearray(len(test))
        kl = len(key)
        for i in range(len(test)):
            decrypted[i] = test[i] ^ key[i % kl]
        dec = bytes(decrypted)

        sigs = scan_for_signatures(dec)
        if sigs:
            print(f"\n  [HIT!] Key '{name}' ({key.hex()}) found signatures:")
            for s in sigs[:10]:
                print(f"    @ 0x{s['offset']:06X}: {s['desc']}")
            return name, key, sigs
        else:
            # Quick check for ASCII text increase
            ascii_count = sum(1 for b in dec[:4096] if 32 <= b < 127)
            orig_ascii = sum(1 for b in test[:4096] if 32 <= b < 127)
            if ascii_count > orig_ascii * 1.5 and ascii_count > 2000:
                print(f"  Key '{name}': ASCII density improved "
                      f"({orig_ascii} -> {ascii_count})")

    print("\n  No known XOR key produced valid signatures.")
    return None, None, None


def try_header_skip(data: bytes):
    """Try skipping various header sizes to find embedded data."""
    print("\n  === HEADER SKIP ANALYSIS ===")
    print("  Scanning at various offsets for embedded signatures...")

    for off in [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
                32768, 65536, 0x10000, 0x20000, 0x40000, 0x80000,
                0x100000, 0x200000]:
        if off >= len(data):
            break
        sigs = scan_for_signatures(data[off:off + 4096])
        if sigs:
            print(f"\n  [FOUND] Offset 0x{off:06X} ({off:,}):")
            for s in sigs[:5]:
                actual_off = off + s["offset"]
                print(f"    @ 0x{actual_off:08X}: {s['desc']}")
            return off, sigs

    # Brute force scan for key signatures
    print("\n  Brute-force scanning for key signatures across entire file...")
    key_sigs = [
        (b"hsqs", "SquashFS"),
        (b"\x27\x05\x19\x56", "uImage"),
        (b"\x45\x3d\xcd\x28", "CramFS"),
        (b"\xfd7zXZ\x00", "XZ"),
    ]
    for magic, desc in key_sigs:
        pos = 0
        while pos < len(data):
            idx = data.find(magic, pos)
            if idx == -1:
                break
            print(f"  [FOUND] {desc} @ 0x{idx:08X} ({idx:,})")
            return idx, [{"offset": idx, "desc": desc}]
    return None, None


def try_zlib_lzma_scan(data: bytes):
    """Scan for zlib/LZMA compressed regions."""
    print("\n  === COMPRESSED REGION SCAN ===")

    # zlib: try decompressing at various offsets
    for off in range(0, min(len(data), 0x100000), 256):
        if data[off] == 0x78 and data[off + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            try:
                dec = zlib.decompress(data[off:off + 65536])
                if len(dec) > 100:
                    sigs = scan_for_signatures(dec)
                    print(f"  [ZLIB] @ 0x{off:06X}: decompressed {len(dec)} bytes")
                    if sigs:
                        for s in sigs[:5]:
                            print(f"    -> {s['desc']} @ 0x{s['offset']:06X}")
                    return off, dec
            except:
                pass

    # LZMA: try at various offsets
    try:
        import lzma
        for off in [0, 64, 128, 256, 512, 1024]:
            if off + 13 >= len(data):
                continue
            if data[off] == 0x5D and data[off + 1] == 0x00:
                try:
                    dec = lzma.decompress(data[off:off + 65536])
                    if len(dec) > 100:
                        print(f"  [LZMA] @ 0x{off:06X}: decompressed {len(dec)} bytes")
                        return off, dec
                except:
                    pass
    except ImportError:
        pass

    print("  No compressed regions found in first 1MB.")
    return None, None


def try_hikvision_v3_header(data: bytes):
    """
    Parse Hikvision firmware v3 header structure.
    Based on public reverse engineering of the DAV format:

    The header may contain:
    - 48-byte global header
    - Partition table with offsets and sizes
    - Each partition may be individually XOR'd or compressed
    """
    print("\n  === HIKVISION V3 HEADER PARSE ===")

    # The header might start with a version/type indicator after encryption
    # Try reading as if XOR with repeating byte patterns
    # The "standard" Hikvision header after decryption:
    #   Bytes 0-3: "HIKV" or similar magic
    #   Bytes 4-7: header version
    #   Bytes 8-11: total partitions
    #   Each partition entry: offset(4) + size(4) + type(4) + checksum(4) = 16 bytes

    # Try XOR with the most common byte in the first 48 bytes
    header48 = data[:48]
    freq = [0] * 256
    for b in header48:
        freq[b] += 1
    most_common = max(range(256), key=lambda x: freq[x])

    # If the header is padded with a fill byte, XOR with that
    print(f"  Most common byte in header: 0x{most_common:02X}")

    # Analyze DWORD patterns in the first 256 bytes
    print("\n  DWORD analysis (potential partition table):")
    dwords = []
    for i in range(0, min(256, len(data)), 4):
        d = struct.unpack_from("<I", data, i)[0]
        dwords.append(d)
        if i < 128:
            # Check if value looks like a file offset
            if 0x1000 < d < len(data):
                print(f"    @ {i:3d} (0x{i:02X}): 0x{d:08X} ({d:,}) "
                      f"<-- possible offset into file")
            elif d == len(data):
                print(f"    @ {i:3d} (0x{i:02X}): 0x{d:08X} ({d:,}) "
                      f"<-- matches file size!")

    # Check for Hikvision magic after common header skip
    for skip in [48, 64, 80, 96, 128, 256, 512]:
        chunk = data[skip:skip + 16]
        print(f"  @ skip={skip}: {chunk.hex()[:32]}")


def deep_entropy_analysis(data: bytes):
    """Block-by-block entropy analysis to find data boundaries."""
    import math

    print("\n  === ENTROPY MAP (64KB blocks) ===")
    block_size = 65536
    transitions = []
    prev_ent = None

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        freq = [0] * 256
        for b in block:
            freq[b] += 1
        total = len(block)
        ent = 0
        for f in freq:
            if f > 0:
                p = f / total
                ent -= p * math.log2(p)

        bar = "#" * int(ent * 4)
        if ent < 5:
            label = "TEXT/STRUCT"
        elif ent < 7:
            label = "CODE/DATA"
        elif ent < 7.8:
            label = "COMPRESSED"
        else:
            label = "ENCRYPTED"

        if prev_ent is not None and abs(ent - prev_ent) > 1.0:
            transitions.append(i)
            print(f"  0x{i:08X}: {ent:5.2f} {bar:32s} [{label}] <-- BOUNDARY")
        else:
            if i % (block_size * 8) == 0:
                print(f"  0x{i:08X}: {ent:5.2f} {bar:32s} [{label}]")
        prev_ent = ent

    if transitions:
        print(f"\n  Significant transitions at: "
              f"{', '.join(f'0x{t:08X}' for t in transitions)}")
    return transitions


def try_decrypt_with_openssl_pattern(data: bytes):
    """
    Some Hikvision firmware uses a pattern where:
    - First N bytes are a custom header (not encrypted)
    - Remaining data is XOR'd with a key derived from the header
    - OR the entire file is XOR'd with a static key, but the key
      varies by model/version
    """
    print("\n  === MODEL-SPECIFIC KEY DERIVATION ===")

    # For G5 cameras, try the known V5.x.x firmware format
    # The first 4 bytes of the original file: 0x8A 0xFF 0xF7 0xB6
    # If we XOR with "HIKV" (0x48 0x49 0x4B 0x56):
    #   0x8A^0x48 = 0xC2, 0xFF^0x49 = 0xB6, 0xF7^0x4B = 0xBC, 0xB6^0x56 = 0xE0
    # That gives key = C2 B6 BC E0 -- not a standard pattern

    # Another approach: some firmwares have a 256-byte header followed by
    # the actual content which is a concatenation of partitions
    # Each partition has its own 16-byte header with magic, type, size

    # Let's try a sliding window looking for any recognizable pattern
    # after XOR with various single-byte keys
    print("  Testing single-byte XOR on first 64KB...")
    best_key = None
    best_score = 0

    for key_byte in range(256):
        # Quick test: XOR first 4096 bytes and count printable ASCII + known signatures
        score = 0
        test = bytes(b ^ key_byte for b in data[:4096])
        # Count ASCII
        score += sum(1 for b in test if 32 <= b < 127)
        # Check for signatures
        for sig in [b"hsqs", b"\x27\x05\x19\x56", b"\x7fELF", b"HIKV",
                    b"Linux", b"root:", b"/bin/", b"U-Boot"]:
            if sig in test:
                score += 1000

        if score > best_score:
            best_score = score
            best_key = key_byte

    if best_key is not None:
        test = bytes(b ^ best_key for b in data[:4096])
        sigs = scan_for_signatures(test)
        ascii_pct = sum(1 for b in test if 32 <= b < 127) / 4096 * 100
        print(f"  Best single-byte key: 0x{best_key:02X} "
              f"(ASCII: {ascii_pct:.1f}%, sigs: {len(sigs)})")
        if sigs:
            for s in sigs[:5]:
                print(f"    {s['desc']} @ 0x{s['offset']:06X}")
            return best_key
        print(f"  First 32 bytes after XOR: {test[:32].hex()}")

    return None


def search_known_offsets(data: bytes):
    """
    Try known Hikvision firmware offset patterns.
    Some models have firmware starting at specific offsets.
    """
    print("\n  === KNOWN OFFSET PATTERNS ===")

    # Hikvision typically has:
    # - Firmware header: 0x00 - variable (48-512 bytes)
    # - Boot loader / uImage: first partition
    # - Root FS: second partition (squashfs or cramfs)

    # Scan every 256 bytes in first 2MB for any magic
    hits = []
    for off in range(0, min(len(data), 2 * 1024 * 1024), 256):
        chunk = data[off:off + 8]
        if len(chunk) < 8:
            break

        # Check various magic bytes
        dword_le = struct.unpack_from("<I", chunk)[0]
        dword_be = struct.unpack_from(">I", chunk)[0]

        if dword_be == 0x27051956:  # uImage
            hits.append((off, "uImage"))
        elif chunk[:4] == b"hsqs":  # SquashFS LE
            hits.append((off, "SquashFS"))
        elif chunk[:4] == b"sqsh":  # SquashFS BE
            hits.append((off, "SquashFS-BE"))
        elif chunk[:4] == b"\x7fELF":  # ELF
            hits.append((off, "ELF"))
        elif chunk[:4] == b"\x45\x3d\xcd\x28":  # CramFS
            hits.append((off, "CramFS"))
        elif chunk[:4] == b"HIKV" or chunk[:4] == b"IKVH":
            hits.append((off, "Hikvision-Magic"))
        elif chunk[:2] == b"\x1f\x8b":  # gzip
            hits.append((off, "gzip"))

    if hits:
        print(f"  Found {len(hits)} signatures:")
        for off, desc in hits[:20]:
            print(f"    0x{off:08X} ({off:>10,}): {desc}")
    else:
        print("  No signatures found in first 2MB at 256-byte boundaries.")

    return hits


def try_hikvision_aes_decrypt(data: bytes):
    """
    Newer Hikvision firmware (2023+) uses AES-128-ECB.
    Known keys from public research.
    """
    print("\n  === AES DECRYPTION ATTEMPTS ===")
    try:
        from Crypto.Cipher import AES
        has_crypto = True
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            has_crypto = "cryptography"
        except ImportError:
            has_crypto = False

    if not has_crypto:
        print("  PyCryptodome/cryptography not available.")
        print("  Install with: pip install pycryptodome")

        # Fallback: manual AES-ECB implementation for known keys
        # This is just for detection, not full decryption
        print("  Attempting manual key detection via block patterns...")

        # In AES-ECB, identical plaintext blocks produce identical ciphertext blocks
        # Count repeated 16-byte blocks
        block_counts = {}
        for i in range(0, min(len(data), 1024 * 1024), 16):
            block = data[i:i + 16]
            if len(block) == 16:
                h = block.hex()
                block_counts[h] = block_counts.get(h, 0) + 1

        repeated = {k: v for k, v in block_counts.items() if v > 3}
        if repeated:
            print(f"  Repeated 16-byte blocks found: {len(repeated)}")
            for block_hex, count in sorted(repeated.items(),
                                            key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {block_hex}: {count} occurrences")
            print("  This suggests AES-ECB encryption (identical blocks = identical cipher)")
        else:
            print("  No repeated 16-byte blocks (not AES-ECB or uses unique blocks)")
        return

    # Known Hikvision AES keys from public research
    known_aes_keys = [
        b"279977BAB5B1B69A",  # Hikvision common key
        b"HikvisionKey1234",  # Placeholder
    ]

    if has_crypto == "cryptography":
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        for key in known_aes_keys:
            try:
                cipher = Cipher(algorithms.AES(key[:16]), modes.ECB())
                dec = cipher.decryptor()
                result = dec.update(data[:4096]) + dec.finalize()
                sigs = scan_for_signatures(result)
                if sigs:
                    print(f"  [AES HIT] Key: {key}")
                    for s in sigs[:5]:
                        print(f"    {s['desc']} @ 0x{s['offset']:06X}")
                    return key
            except Exception as e:
                pass
    else:
        for key in known_aes_keys:
            try:
                cipher = AES.new(key[:16], AES.MODE_ECB)
                result = cipher.decrypt(data[:4096])
                sigs = scan_for_signatures(result)
                if sigs:
                    print(f"  [AES HIT] Key: {key}")
                    for s in sigs[:5]:
                        print(f"    {s['desc']} @ 0x{s['offset']:06X}")
                    return key
            except Exception as e:
                pass

    print("  No known AES key worked.")
    return None


def try_partial_decryption(data: bytes):
    """
    Some Hikvision firmwares only encrypt the first N bytes (header)
    while the actual firmware data starts later unencrypted.
    Try scanning deeper into the file.
    """
    print("\n  === DEEP FILE SCAN ===")
    print("  Scanning entire file for unencrypted regions...")

    # Quick scan at every 4KB boundary
    found = []
    for off in range(0, len(data), 4096):
        chunk = data[off:off + 32]
        if len(chunk) < 32:
            break

        for sig, desc in [(b"hsqs", "SquashFS"), (b"\x27\x05\x19\x56", "uImage"),
                          (b"\x7fELF", "ELF"), (b"\x45\x3d\xcd\x28", "CramFS"),
                          (b"HIKV", "Hikvision"), (b"Linux", "Linux-str"),
                          (b"\x1f\x8b", "gzip"), (b"\xfd7zXZ", "XZ")]:
            idx = chunk.find(sig)
            if idx != -1:
                found.append((off + idx, desc))

    if found:
        print(f"  Found {len(found)} signatures deep in file:")
        for off, desc in found[:20]:
            ctx = data[off:off + 32]
            print(f"    0x{off:08X}: {desc} -- {ctx.hex()[:32]}")
    else:
        # More aggressive: every 512 bytes
        print("  No hits at 4KB boundaries. Trying 512-byte intervals...")
        for off in range(0, len(data), 512):
            dword = struct.unpack_from(">I", data, off)[0] if off + 4 <= len(data) else 0
            if dword == 0x27051956:  # uImage
                found.append((off, "uImage"))
            le = struct.unpack_from("<I", data, off)[0] if off + 4 <= len(data) else 0
            if le == 0x73717368:  # "sqsh" in LE = hsqs
                found.append((off, "SquashFS"))

        if found:
            for off, desc in found:
                print(f"    0x{off:08X}: {desc}")

    return found


def try_jffs2_analysis(data: bytes):
    """Analyze JFFS2 markers if present."""
    # JFFS2 magic: 0x1985 (LE) or 0x8519 (BE)
    marker_le = b"\x85\x19"
    marker_be = b"\x19\x85"

    positions_le = []
    positions_be = []
    pos = 0
    while pos < len(data) - 2:
        idx = data.find(marker_le, pos)
        if idx == -1:
            break
        # Verify: next 2 bytes should be a valid node type
        if idx + 4 <= len(data):
            node_type = struct.unpack_from("<H", data, idx + 2)[0]
            if node_type in (0x2001, 0x2002, 0x2003, 0x2004, 0x2006, 0xE001, 0xE002):
                positions_le.append(idx)
        pos = idx + 2
        if len(positions_le) > 50:
            break

    if positions_le:
        print("\n  === JFFS2 ANALYSIS ===")
        print(f"  Valid JFFS2 nodes found: {len(positions_le)}")
        first = positions_le[0]
        print(f"  First JFFS2 node @ 0x{first:08X}")

        # Try to extract JFFS2 region
        if len(positions_le) > 10:
            jffs2_start = positions_le[0]
            jffs2_end = positions_le[-1] + 4096
            jffs2_path = OUT_DIR / "jffs2_region.bin"
            jffs2_path.write_bytes(data[jffs2_start:jffs2_end])
            print(f"  Extracted JFFS2 region: {jffs2_path} "
                  f"({(jffs2_end - jffs2_start) // 1024} KB)")
            return jffs2_path

    return None


if __name__ == "__main__":
    print("=" * 70)
    print("  HIKVISION DAV FIRMWARE DECRYPTION / ANALYSIS")
    print("=" * 70)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    data = DAV_FILE.read_bytes()
    print(f"\n  Input: {DAV_FILE}")
    print(f"  Size: {len(data):,} bytes")
    print(f"  MD5: {hashlib.md5(data).hexdigest()}")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")

    # Step 1: Analyze header
    analyze_header_structure(data)

    # Step 2: Try known XOR keys
    name, key, sigs = try_hikvision_known_keys(data)
    if key:
        print(f"\n  >>> DECRYPTING WITH KEY: {name} ({key.hex()}) <<<")
        decrypted = bytearray(len(data))
        kl = len(key)
        for i in range(len(data)):
            decrypted[i] = data[i] ^ key[i % kl]
        dec_path = OUT_DIR / f"decrypted_{name}.bin"
        dec_path.write_bytes(bytes(decrypted))
        print(f"  Saved: {dec_path}")
        data = bytes(decrypted)

    # Step 3: Try header skip
    off, sigs = try_header_skip(data)
    if off:
        print(f"\n  Data found at offset 0x{off:08X}!")

    # Step 4: Try single-byte XOR
    best_key = try_decrypt_with_openssl_pattern(data)

    # Step 5: Entropy analysis
    transitions = deep_entropy_analysis(data)

    # Step 6: Search known offsets
    hits = search_known_offsets(data)

    # Step 7: zlib/LZMA scan
    zoff, zdec = try_zlib_lzma_scan(data)

    # Step 8: AES attempt
    try_hikvision_aes_decrypt(data)

    # Step 9: Hikvision v3 header
    try_hikvision_v3_header(data)

    # Step 10: Deep file scan
    deep_hits = try_partial_decryption(data)

    # Step 11: JFFS2 analysis
    jffs2 = try_jffs2_analysis(data)

    print("\n" + "=" * 70)
    print("  ANALYSIS COMPLETE")
    print("=" * 70)
    if key:
        print(f"  Decryption key found: {name} -> {key.hex()}")
    if deep_hits:
        print(f"  Deep scan hits: {len(deep_hits)}")
    if jffs2:
        print(f"  JFFS2 region extracted: {jffs2}")
    if not key and not deep_hits and not jffs2:
        print("  NO DECRYPTION METHOD WORKED.")
        print("  The firmware is likely using a proprietary/unknown encryption.")
        print("  Next steps:")
        print("    1. Try hikvision-firmware-tools (GitHub)")
        print("    2. Capture OTA update traffic for key extraction")
        print("    3. JTAG/UART dump from physical device")
