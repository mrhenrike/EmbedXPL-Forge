#!/usr/bin/env python3
"""
hikvision_key_derive.py — Attempt to derive AES key from repeating block
Author: Andre Henrique (@mrhenrike) | Uniao Geek

The firmware at 0x039AE000 has a repeating 16-byte block which could be
AES-ECB(zero_pad) — if so, the key can be derived via known-plaintext attack.
"""
from __future__ import annotations

import io
import struct
import sys
from ctypes import c_uint
from pathlib import Path

from Crypto.Cipher import AES

TMP_DIR = Path(__file__).resolve().parent.parent / ".tmp" / "hikvision_g5"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

KEY_XOR = b"\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"

LIST_KEY_AES = {
    "0x850000": bytes([0xE5,0xBF,0x66,0x8F,0x7D,0x8C,0xDB,0x8D,
                       0x38,0x1F,0xAB,0x79,0x77,0xBB,0x72,0x76,
                       0x5D,0x2D,0x2F,0xF2,0xC9,0xB4,0xF7,0x1A,
                       0xDE,0xC1,0xF5,0x74,0x3E,0x42,0xD0,0x8E]),
    "0x850001": bytes([0x91,0x8D,0xA7,0xB3,0x26,0x69,0x0E,0x52,
                       0x71,0x94,0x2D,0x6C,0xCD,0x1C,0xD6,0x82,
                       0x1D,0xD9,0x25,0x51,0x5E,0x98,0x8D,0xD4,
                       0x0D,0x98,0x75,0xF1,0xDA,0xD0,0xB1,0x3D]),
    "0x850100": bytes([0x51,0xE8,0x46,0xD7,0x0B,0x8E,0x23,0xDA,
                       0xCE,0x16,0x09,0x46,0x3A,0xF2,0xB2,0xF1,
                       0x4A,0x21,0x57,0x40,0x9F,0x49,0x31,0xBD,
                       0x50,0xE4,0x40,0xFF,0x76,0xA6,0x0A,0x4D]),
    "0x850101": bytes([0x81,0xEC,0xAE,0xB2,0x0C,0x6F,0x8D,0xE0,
                       0xFD,0xE3,0xD4,0xAF,0xB4,0xAC,0xE9,0x0A,
                       0x9C,0xB0,0xE5,0x9D,0x19,0xD3,0xB7,0xB7,
                       0x00,0x34,0xA4,0x24,0x3C,0xF3,0x97,0x54]),
}


def gen_aes_key(raw_key: bytes, length: int) -> bytes:
    key_gen = bytearray(length)
    for i in range(length):
        k = raw_key[i]
        v5 = (((i * i) & 0xFF) + ((k * k) & 0xFF) +
              ((k % length) & 0xFF) + ((k * length * i) & 0xFF))
        key_gen[i] = (v5 & 0xFF) ^ k
    return bytes(key_gen)


def xor_block(data: bytes, offset: int) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        idx = offset + i
        key_idx = (c_uint(idx >> 4).value + idx) & 0xF
        result[i] = data[i] ^ KEY_XOR[key_idx]
    return bytes(result)


def main():
    raw = (TMP_DIR / "digicap.dav").read_bytes()

    # The repeating block at 0x039AE000
    off = 0x039AE000
    repeat_raw = raw[off:off + 16]
    repeat_xor = xor_block(repeat_raw, off)

    print(f"Repeating block (raw): {repeat_raw.hex()}")
    print(f"Repeating block (xor): {repeat_xor.hex()}")
    print()

    # Also get the block at different offsets to check if it changes with XOR
    for test_off in [0x039AE010, 0x039AE020, 0x039AE100, 0x039AF000]:
        block = raw[test_off:test_off + 16]
        xored = xor_block(block, test_off)
        same_raw = block == repeat_raw
        same_xor = xored == repeat_xor
        print(f"  0x{test_off:08X}: raw_same={same_raw}, xor_same={same_xor}")
        if not same_raw:
            print(f"    raw: {block.hex()}")
        if not same_xor:
            print(f"    xor: {xored.hex()}")

    print()

    # Try all key combinations
    print("=== Testing AES keys ===")
    for key_name, raw_key in LIST_KEY_AES.items():
        for kl in [16, 32]:
            derived = gen_aes_key(raw_key, kl)
            cipher = AES.new(derived, AES.MODE_ECB)

            for src_name, block in [("raw", repeat_raw), ("xor", repeat_xor)]:
                dec = cipher.decrypt(block)
                unique_bytes = len(set(dec))
                if unique_bytes == 1:
                    print(f"  [{key_name} AES-{kl*8} {src_name}] UNIFORM: 0x{dec[0]:02X}")
                elif unique_bytes <= 3:
                    print(f"  [{key_name} AES-{kl*8} {src_name}] Near-uniform ({unique_bytes}): {dec.hex()}")

    # Try raw keys (no derivation)
    print("\n=== Raw keys (no derivation) ===")
    for key_name, raw_key in LIST_KEY_AES.items():
        for kl in [16, 32]:
            cipher = AES.new(raw_key[:kl], AES.MODE_ECB)
            for src_name, block in [("raw", repeat_raw), ("xor", repeat_xor)]:
                dec = cipher.decrypt(block)
                if len(set(dec)) <= 2:
                    print(f"  [{key_name} RAW-{kl*8} {src_name}] {dec.hex()}")

    # Try password-based keys
    print("\n=== Password-based keys ===")
    passwords = [
        b"hiklinux\x00\x00\x00\x00\x00\x00\x00\x00",
        b"hikvision\x00\x00\x00\x00\x00\x00\x00",
        b"279977BAB5B1B69A",
        b"hikconnect12345\x00",
        b"HikvisionKey1234",
        b"admin12345\x00\x00\x00\x00\x00\x00",
        b"HIKVISION_FW_KEY",
        b"hikipc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ]
    for pwd in passwords:
        cipher = AES.new(pwd[:16], AES.MODE_ECB)
        for src_name, block in [("raw", repeat_raw), ("xor", repeat_xor)]:
            dec = cipher.decrypt(block)
            if len(set(dec)) <= 2:
                label = pwd.rstrip(b"\x00").decode("ascii", errors="replace")
                print(f"  [{label} {src_name}] MATCH: {dec.hex()}")

    # The repeating block in the RAW file is identical across offsets, meaning
    # the XOR key doesn't change these blocks. But after XOR, the blocks
    # are different at each position because the XOR key shifts.
    # This means the repeating pattern is in the RAW (encrypted) data,
    # which means it's likely AES-ECB of a constant plaintext block.

    # Let's try to identify the XOR key phase at the repeating block offset
    print("\n=== XOR key phase analysis ===")
    for i in range(16):
        idx = off + i
        key_idx = (c_uint(idx >> 4).value + idx) & 0xF
        print(f"  byte {i}: file_idx=0x{idx:08X}, key_idx={key_idx}, "
              f"xor_key=0x{KEY_XOR[key_idx]:02X}")

    # The real test: is the block identical in the RAW file across 256KB?
    repeat_count = 0
    for test_off in range(off, min(off + 262144, len(raw)), 16):
        if raw[test_off:test_off + 16] == repeat_raw:
            repeat_count += 1
        else:
            break
    print(f"\n  Identical 16-byte blocks from 0x{off:08X}: {repeat_count}")
    print(f"  Total repeated region: {repeat_count * 16:,} bytes")

    # This is a fill/padding region. In AES-ECB, identical plaintext
    # produces identical ciphertext. So this region is likely flash
    # erase fill (0xFF) encrypted with AES-ECB.

    # If we know the plaintext (0xFF*16) and ciphertext (repeat_raw),
    # we can try to find the key, but AES is one-way without the key.

    # Alternative: check if the firmware has AES in OFB/CTR mode
    # where the keystream would be constant for the padding
    print("\n=== Checking for stream-cipher-like behavior ===")
    # If XOR-only: ciphertext XOR plaintext = keystream
    # If plaintext is 0xFF*16: keystream = ciphertext XOR 0xFF*16
    potential_keystream = bytes(b ^ 0xFF for b in repeat_raw)
    print(f"  If padding is 0xFF: keystream = {potential_keystream.hex()}")

    # Try using this "keystream" to decrypt adjacent data
    test_start = off - 256
    test_data = raw[test_start:test_start + 16]
    dec_with_ks = bytes(a ^ b for a, b in zip(test_data, potential_keystream))
    ascii_ct = sum(1 for b in dec_with_ks if 32 <= b < 127)
    print(f"  Decrypt 0x{test_start:08X} with keystream: {dec_with_ks.hex()} "
          f"(ASCII: {ascii_ct}/16)")

    # Try 0x00 as padding
    potential_keystream_0 = repeat_raw  # If padding is 0x00, keystream = ciphertext
    test_dec = bytes(a ^ b for a, b in zip(test_data, potential_keystream_0))
    ascii_ct2 = sum(1 for b in test_dec if 32 <= b < 127)
    print(f"  Decrypt with raw block as keystream: {test_dec.hex()} "
          f"(ASCII: {ascii_ct2}/16)")


if __name__ == "__main__":
    main()
