#!/usr/bin/env python3
"""
hikvision_aes_decrypt.py — Decrypt Hikvision DAV firmware using AES
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Based on public research from HaToan/Decrypt-Firmware-Hikvision.
Applies XOR + AES-ECB decryption with known device-specific keys.
"""
from __future__ import annotations

import io
import os
import re
import struct
import sys
from ctypes import c_uint
from pathlib import Path

TMP_DIR = Path(__file__).resolve().parent.parent / ".tmp" / "hikvision_g5"
DAV_FILE = TMP_DIR / "digicap.dav"
OUT_DIR = TMP_DIR / "decrypted"

try:
    from Crypto.Cipher import AES
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    class AES:
        MODE_ECB = 1

        @staticmethod
        def new(key, mode):
            class _C:
                def __init__(self, k):
                    self._c = Cipher(algorithms.AES(k), modes.ECB())

                def decrypt(self, data):
                    d = self._c.decryptor()
                    return d.update(data) + d.finalize()
            return _C(key)


if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


KEY_XOR = b"\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"

LIST_KEY_AES = {
    "0x850000": bytes([0xE5, 0xBF, 0x66, 0x8F, 0x7D, 0x8C, 0xDB, 0x8D,
                       0x38, 0x1F, 0xAB, 0x79, 0x77, 0xBB, 0x72, 0x76,
                       0x5D, 0x2D, 0x2F, 0xF2, 0xC9, 0xB4, 0xF7, 0x1A,
                       0xDE, 0xC1, 0xF5, 0x74, 0x3E, 0x42, 0xD0, 0x8E]),
    "0x850001": bytes([0x91, 0x8D, 0xA7, 0xB3, 0x26, 0x69, 0x0E, 0x52,
                       0x71, 0x94, 0x2D, 0x6C, 0xCD, 0x1C, 0xD6, 0x82,
                       0x1D, 0xD9, 0x25, 0x51, 0x5E, 0x98, 0x8D, 0xD4,
                       0x0D, 0x98, 0x75, 0xF1, 0xDA, 0xD0, 0xB1, 0x3D]),
    "0x850100": bytes([0x51, 0xE8, 0x46, 0xD7, 0x0B, 0x8E, 0x23, 0xDA,
                       0xCE, 0x16, 0x09, 0x46, 0x3A, 0xF2, 0xB2, 0xF1,
                       0x4A, 0x21, 0x57, 0x40, 0x9F, 0x49, 0x31, 0xBD,
                       0x50, 0xE4, 0x40, 0xFF, 0x76, 0xA6, 0x0A, 0x4D]),
    "0x850101": bytes([0x81, 0xEC, 0xAE, 0xB2, 0x0C, 0x6F, 0x8D, 0xE0,
                       0xFD, 0xE3, 0xD4, 0xAF, 0xB4, 0xAC, 0xE9, 0x0A,
                       0x9C, 0xB0, 0xE5, 0x9D, 0x19, 0xD3, 0xB7, 0xB7,
                       0x00, 0x34, 0xA4, 0x24, 0x3C, 0xF3, 0x97, 0x54]),
}


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    result = bytearray(len(data))
    for i in range(len(data)):
        key_idx = (c_uint(i >> 4).value + i) & 0xF
        result[i] = data[i] ^ key[key_idx]
    return bytes(result)


def gen_aes_key(raw_key: bytes, length: int) -> bytes:
    key_gen = bytearray(length)
    for i in range(length):
        k = raw_key[i]
        v5 = (((i * i) & 0xFF) +
              ((k * k) & 0xFF) +
              ((k % length) & 0xFF) +
              ((k * length * i) & 0xFF))
        key_gen[i] = (v5 & 0xFF) ^ k
    return bytes(key_gen)


def scan_sigs(data: bytes, label: str = "") -> list:
    found = []
    sigs = [
        (b"hsqs", "SquashFS-LE"), (b"sqsh", "SquashFS-BE"),
        (b"\x27\x05\x19\x56", "uImage"), (b"\x7fELF", "ELF"),
        (b"\x45\x3d\xcd\x28", "CramFS"), (b"\x1f\x8b", "gzip"),
        (b"\xfd7zXZ\x00", "XZ"), (b"\x5d\x00\x00", "LZMA"),
        (b"Linux", "Linux-str"), (b"U-Boot", "U-Boot"),
        (b"/bin/", "/bin/"), (b"root:", "root:"),
        (b"#!/bin", "shebang"), (b"HIKV", "HIKV"),
    ]
    for magic, desc in sigs:
        idx = data.find(magic)
        if idx != -1:
            found.append((idx, desc))
    return found


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    raw = DAV_FILE.read_bytes()
    print(f"File size: {len(raw):,} bytes")

    # Step 1: XOR decrypt entire file
    print("XOR decrypting...")
    xor_dec = xor_decrypt(raw, KEY_XOR)

    magic = xor_dec[:4]
    print(f"Decrypted magic: {magic.hex()}")

    header_len = struct.unpack_from("<I", xor_dec, 8)[0]
    num_files = struct.unpack_from("<I", xor_dec, 12)[0]
    device_class = struct.unpack_from("<I", xor_dec, 20)[0]
    print(f"Header length: {header_len}")
    print(f"Files: {num_files}")
    print(f"Device class: {device_class}")

    # Check for model string in header
    model_str = xor_dec[0x30:0x50]
    model_text = model_str.split(b"\x00")[0].decode("ascii", errors="replace")
    print(f"Model string: {model_text}")

    # Step 2: Try AES decryption with each known key
    payload_starts = [header_len, 0x80, 0x100, 0x200, 0x6C]
    payload_starts = sorted(set(s for s in payload_starts if s > 0 and s < len(raw)))

    best_result = None
    best_key_name = None
    best_ascii = 0

    for payload_start in payload_starts:
        # Align to 16 bytes
        if payload_start % 16 != 0:
            payload_start = (payload_start // 16 + 1) * 16

        print(f"\n--- Trying payload start: 0x{payload_start:X} ---")

        for key_name, raw_key in LIST_KEY_AES.items():
            for key_len in [16, 32]:
                aes_key = gen_aes_key(raw_key, key_len)
                aes_type = f"AES-{key_len*8}"

                for src_name, src_data in [("xor+aes", xor_dec), ("raw+aes", raw)]:
                    try:
                        cipher = AES.new(aes_key, AES.MODE_ECB)
                        test_payload = src_data[payload_start:payload_start + 4096]
                        if len(test_payload) % 16 != 0:
                            pad = 16 - (len(test_payload) % 16)
                            test_payload += b"\x00" * pad
                        dec = cipher.decrypt(test_payload)

                        sigs = scan_sigs(dec)
                        ascii_ct = sum(1 for b in dec[:1024] if 32 <= b < 127)
                        ascii_pct = ascii_ct / 1024 * 100

                        if sigs:
                            print(f"  [{key_name} {aes_type} {src_name}] "
                                  f"SIGNATURES FOUND:")
                            for off, desc in sigs:
                                print(f"    @ 0x{off:04X}: {desc}")

                            if ascii_pct > best_ascii:
                                best_ascii = ascii_pct
                                best_key_name = f"{key_name}_{aes_type}_{src_name}"
                                best_result = (key_name, aes_key, src_data, payload_start)

                        if ascii_pct > 40:
                            print(f"  [{key_name} {aes_type} {src_name}] "
                                  f"ASCII: {ascii_pct:.1f}%")
                            if ascii_pct > best_ascii:
                                best_ascii = ascii_pct
                                best_key_name = f"{key_name}_{aes_type}_{src_name}"
                                best_result = (key_name, aes_key, src_data, payload_start)

                    except Exception as e:
                        if "key" in str(e).lower() or "size" in str(e).lower():
                            pass
                        else:
                            print(f"  [{key_name} {aes_type} {src_name}] Error: {e}")

    if best_result:
        key_name, aes_key, src_data, payload_start = best_result
        print(f"\n{'='*70}")
        print(f"  BEST MATCH: {best_key_name} (ASCII: {best_ascii:.1f}%)")
        print(f"{'='*70}")

        # Full decryption
        print("  Decrypting full payload...")
        cipher = AES.new(aes_key, AES.MODE_ECB)
        full_payload = src_data[payload_start:]
        pad = 16 - (len(full_payload) % 16)
        if pad < 16:
            full_payload += b"\x00" * pad
        full_dec = cipher.decrypt(full_payload)

        out_path = OUT_DIR / f"aes_decrypted_{best_key_name}.bin"
        out_path.write_bytes(full_dec)
        print(f"  Saved: {out_path}")
        print(f"  Size: {len(full_dec):,} bytes")

        # Scan for signatures in full decrypted file
        print("\n  Full file signature scan:")
        for magic, desc in [
            (b"hsqs", "SquashFS"), (b"\x27\x05\x19\x56", "uImage"),
            (b"\x7fELF", "ELF"), (b"\x45\x3d\xcd\x28", "CramFS"),
            (b"\x1f\x8b", "gzip"), (b"Linux", "Linux"),
            (b"/bin/", "/bin/"), (b"root:", "root:"),
        ]:
            pos = 0
            count = 0
            while pos < len(full_dec):
                idx = full_dec.find(magic, pos)
                if idx == -1:
                    break
                if count == 0:
                    print(f"    {desc}: first @ 0x{idx:08X}")
                count += 1
                pos = idx + len(magic)
            if count > 1:
                print(f"    {desc}: total {count} occurrences")

        # Extract strings
        strings = re.findall(rb"[\x20-\x7e]{15,}", full_dec)
        print(f"\n  Strings (>=15 chars): {len(strings)}")
        for s in strings[:20]:
            d = s.decode("ascii", errors="replace")
            print(f"    {d[:100]}")
    else:
        print(f"\n{'='*70}")
        print("  NO KNOWN KEY PRODUCED VALID DECRYPTION")
        print(f"{'='*70}")
        print("  This firmware uses an unknown/newer encryption key.")
        print("  The device model '240005004111111001' doesn't match")
        print("  known key identifiers (0x850000-0x850101).")
        print()
        print("  Possible approaches:")
        print("    1. Physical extraction via UART/JTAG")
        print("    2. Intercept OTA update traffic")
        print("    3. Locate key in SADP protocol exchange")
        print("    4. Find key in device bootloader dump")


if __name__ == "__main__":
    main()
