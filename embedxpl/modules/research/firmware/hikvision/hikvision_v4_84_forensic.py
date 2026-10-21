#!/usr/bin/env python3
"""
hikvision_v4_84_forensic.py — Complete forensic extraction & analysis of
Hikvision NVR firmware V4.84.101 build 251212
Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek

Steps:
  1. Parse DAV container via hiktools
  2. Extract uImage kernels, decompress LZMA payloads
  3. Locate and extract CPIO initramfs → rootfs/
  4. RSA key extraction from bin/psh with V4.62.225 comparison
  5. Binary hardening audit (PIE, NX, RELRO, canaries, dangerous funcs)
  6. Boot-script audit (chmod 777, telnetd, dropbear, credentials)
  7. String analysis on psh, ded, busybox
  8. Generate markdown report
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent
TMP_DIR = BASE / ".tmp" / "hikvision_v4_84"
DAV_PATH = TMP_DIR / "digicap.dav"
EXTRACTED_DIR = TMP_DIR / "extracted"
ROOTFS_DIR = TMP_DIR / "rootfs"
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings: list[dict[str, Any]] = []
report_sections: dict[str, str] = OrderedDict()


V462_RSA_KEYS = {
    "key1_n_prefix": 0xe67048b79c066b23,
    "key2_n_prefix": 0xe67fa01c39146310,
    "key3_n_prefix": 0xf73b68ba7fd1e4a6,
}


def add_finding(fid: str, sev: str, title: str, detail: str, evidence: str = ""):
    findings.append({
        "id": fid, "severity": sev, "title": title,
        "detail": detail, "evidence": evidence[:3000],
    })
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


# ── STEP 2: DAV extraction ──────────────────────────────────────────────
def step2_extract_dav() -> list[dict]:
    """Extract files from the Hikvision DAV container."""
    print("\n" + "=" * 70)
    print("  STEP 2: DAV CONTAINER EXTRACTION")
    print("=" * 70)

    from hiktools import fmod

    EXTRACTED_DIR.mkdir(parents=True, exist_ok=True)
    extracted = []

    with fmod.DigiCap(str(DAV_PATH)) as dcap:
        h = dcap.head
        hdr_info = (
            f"Magic: 0x{h.magic:08X}, Files: {h.files}, "
            f"Device class: {h.device_class}"
        )
        print(f"  {hdr_info}")
        report_sections["dav_header"] = hdr_info

        key = dcap.KEY_XOR
        raw_data = DAV_PATH.read_bytes()

        from ctypes import c_uint
        decrypted = bytearray(len(raw_data))
        for i in range(len(raw_data)):
            key_idx = (c_uint(i >> 4).value + i) & 0xF
            decrypted[i] = raw_data[i] ^ key[key_idx]
        dec_data = bytes(decrypted)

        for file_info in dcap:
            fname, flen, fpos, fchk = file_info
            if flen <= 0 or fpos <= 0:
                continue
            if fpos + flen > len(dec_data):
                print(f"  SKIP {fname}: out of bounds")
                continue

            file_data = dec_data[fpos:fpos + flen]
            out_path = EXTRACTED_DIR / fname
            out_path.write_bytes(file_data)
            sz_kb = len(file_data) // 1024
            sha256 = hashlib.sha256(file_data).hexdigest()[:16]
            print(f"  Extracted: {fname} ({sz_kb:,} KB) sha256={sha256}...")
            extracted.append({
                "name": fname, "size": len(file_data),
                "path": str(out_path), "sha256_prefix": sha256,
            })

    report_sections["dav_files"] = json.dumps(extracted, indent=2)
    return extracted


# ── STEP 3: kernel + initramfs extraction ────────────────────────────────
def _find_uimage_headers(data: bytes) -> list[dict]:
    """Scan for uImage magic (0x27051956) in the data."""
    headers = []
    pos = 0
    while pos < len(data) - 64:
        idx = data.find(b"\x27\x05\x19\x56", pos)
        if idx == -1:
            break
        try:
            (magic, hcrc, time_val, size, load, ep,
             dcrc, os_val, arch, img_type, comp) = struct.unpack(
                ">IIIIIIIBBBB", data[idx:idx + 28])
            name_raw = data[idx + 32:idx + 64]
            name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")
            headers.append({
                "offset": idx, "size": size, "load": load, "ep": ep,
                "arch": arch, "comp": comp, "name": name,
            })
        except Exception:
            pass
        pos = idx + 4
    return headers


def _decompress_lzma_kernel(data: bytes) -> bytes | None:
    """Find and decompress LZMA stream from kernel zImage."""
    pos = 0
    while pos < len(data) - 13:
        idx = data.find(b"\x5d\x00\x00", pos)
        if idx == -1:
            break
        for window in (b"\x00\x80", b"\x00\x40", b"\x00\x20",
                       b"\x00\x10", b"\x00\x04", b"\x00\x02"):
            if idx >= 2 and data[idx - 2:idx] == window:
                try:
                    decompressed = lzma.decompress(data[idx - 2:])
                    if len(decompressed) > 500_000:
                        return decompressed
                except Exception:
                    pass
        for trial_start in range(max(0, idx - 5), idx + 1):
            try:
                decompressed = lzma.decompress(data[trial_start:])
                if len(decompressed) > 500_000:
                    return decompressed
            except Exception:
                pass
        pos = idx + 1
    return None


def _extract_cpio(data: bytes, out_dir: Path) -> list[dict]:
    """Extract CPIO newc entries from data."""
    out_dir.mkdir(parents=True, exist_ok=True)
    pos = 0
    entries = []

    while pos < len(data) - 110:
        idx = data.find(b"070701", pos)
        if idx == -1:
            break
        try:
            ino = int(data[idx + 6:idx + 14].decode("ascii"), 16)
            mode = int(data[idx + 14:idx + 22].decode("ascii"), 16)
            uid = int(data[idx + 22:idx + 30].decode("ascii"), 16)
            gid = int(data[idx + 30:idx + 38].decode("ascii"), 16)
            filesize = int(data[idx + 54:idx + 62].decode("ascii"), 16)
            namesize = int(data[idx + 94:idx + 102].decode("ascii"), 16)
        except (ValueError, UnicodeDecodeError):
            pos = idx + 6
            continue

        if namesize <= 0 or namesize > 512:
            pos = idx + 6
            continue

        name_start = idx + 110
        try:
            name = data[name_start:name_start + namesize - 1].decode(
                "ascii", errors="replace")
        except Exception:
            pos = idx + 6
            continue

        data_start = (name_start + namesize + 3) & ~3
        data_end = data_start + filesize
        data_end_aligned = (data_end + 3) & ~3

        if name == "TRAILER!!!":
            entries.append({"name": name, "type": "trailer"})
            pos = data_end_aligned
            continue

        is_dir = (mode & 0o170000) == 0o040000
        is_file = (mode & 0o170000) == 0o100000
        is_link = (mode & 0o170000) == 0o120000
        perms = mode & 0o7777

        entry: dict[str, Any] = {
            "name": name, "size": filesize, "mode": mode,
            "perms": perms, "uid": uid, "gid": gid,
            "is_dir": is_dir, "is_file": is_file, "is_link": is_link,
        }

        if is_file and filesize > 0 and data_start + filesize <= len(data):
            file_data = data[data_start:data_start + filesize]
            out_path = out_dir / name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if out_path.exists():
                out_path = out_dir / f"{name}.dup_0x{idx:08X}"
                out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(file_data)
            if file_data[:4] == b"\x7fELF":
                entry["type"] = "elf"
            elif file_data[:2] == b"#!":
                entry["type"] = "script"
            else:
                entry["type"] = "data"
            if perms & 0o4000:
                entry["suid"] = True
                add_finding(
                    f"F-V484-SUID-{name.replace('/', '_')[:20]}",
                    "HIGH", f"SUID binary: {name} (perms={perms:04o})",
                    f"SUID bit set on {name}.", name)
        elif is_link and filesize > 0 and data_start + filesize <= len(data):
            target = data[data_start:data_start + filesize].decode(
                "ascii", errors="replace")
            entry["type"] = "symlink"
            entry["target"] = target
        elif is_dir:
            entry["type"] = "directory"
            (out_dir / name).mkdir(parents=True, exist_ok=True)

        entries.append(entry)
        pos = data_end_aligned

    return entries


def step3_extract_kernel_and_rootfs() -> tuple[list[dict], list[dict]]:
    """Extract kernels, decompress LZMA, extract CPIO initramfs."""
    print("\n" + "=" * 70)
    print("  STEP 3: KERNEL + INITRAMFS EXTRACTION")
    print("=" * 70)

    dav_data = DAV_PATH.read_bytes()
    uimage_headers = _find_uimage_headers(dav_data)
    print(f"  Found {len(uimage_headers)} uImage headers in DAV")

    kernel_info = []
    rootfs_entries = []

    for i, hdr in enumerate(uimage_headers):
        print(f"\n  uImage #{i}: '{hdr['name']}' @ 0x{hdr['offset']:08X}, "
              f"size={hdr['size']:,}, load=0x{hdr['load']:08X}, "
              f"comp={'LZMA' if hdr['comp'] == 3 else hdr['comp']}")
        kernel_info.append(hdr)

        payload_start = hdr["offset"] + 64
        payload_end = payload_start + hdr["size"]
        if payload_end > len(dav_data):
            payload_end = len(dav_data)
        payload = dav_data[payload_start:payload_end]

        kernel_out = EXTRACTED_DIR / f"uImage_{i}_{hdr['name'][:30].replace(' ', '_')}.bin"
        kernel_out.write_bytes(payload)
        print(f"    Saved kernel payload: {kernel_out.name} ({len(payload):,} bytes)")

        print(f"    Decompressing LZMA...")
        decompressed = _decompress_lzma_kernel(payload)
        if decompressed:
            dec_path = EXTRACTED_DIR / f"kernel_{i}_decompressed.bin"
            dec_path.write_bytes(decompressed)
            print(f"    Decompressed: {len(decompressed):,} bytes")

            strings_raw = re.findall(rb"[\x20-\x7e]{10,}", decompressed)
            print(f"    Strings (10+ chars): {len(strings_raw)}")

            linux_ver = None
            for s in strings_raw:
                d = s.decode("ascii", errors="replace")
                if "Linux version" in d:
                    linux_ver = d[:120]
                    print(f"    KERNEL: {linux_ver}")
                    break

            hdr["linux_version"] = linux_ver
            hdr["decompressed_size"] = len(decompressed)
            hdr["string_count"] = len(strings_raw)

            cpio_idx = decompressed.find(b"070701")
            if cpio_idx != -1:
                print(f"    CPIO initramfs found @ 0x{cpio_idx:08X}")
                entries = _extract_cpio(decompressed[cpio_idx:], ROOTFS_DIR)
                print(f"    Extracted {len(entries)} CPIO entries")
                rootfs_entries = entries

                type_counts = Counter(e.get("type", "unknown") for e in entries)
                for t, c in type_counts.most_common():
                    print(f"      {t}: {c}")
        else:
            print(f"    LZMA decompression failed for kernel #{i}")

    report_sections["kernels"] = json.dumps(kernel_info, indent=2, default=str)
    return kernel_info, rootfs_entries


# ── STEP 4: RSA key extraction ──────────────────────────────────────────
def _parse_der_rsa_pubkey(der_bytes: bytes) -> tuple[int, int] | None:
    """Parse a DER-encoded RSA public key (PKCS#1 or SubjectPublicKeyInfo)."""
    try:
        if der_bytes[0] != 0x30:
            return None

        def read_length(data, offset):
            if data[offset] < 0x80:
                return data[offset], offset + 1
            num_bytes = data[offset] & 0x7F
            length = int.from_bytes(data[offset + 1:offset + 1 + num_bytes], "big")
            return length, offset + 1 + num_bytes

        def read_integer(data, offset):
            if data[offset] != 0x02:
                return None, offset
            length, offset = read_length(data, offset + 1)
            value = int.from_bytes(data[offset:offset + length], "big")
            return value, offset + length

        _, pos = read_length(der_bytes, 1)

        if der_bytes[pos] == 0x30:
            _, pos = read_length(der_bytes, pos + 1)
            if der_bytes[pos] == 0x06:
                oid_len = der_bytes[pos + 1]
                pos += 2 + oid_len
                if pos < len(der_bytes) and der_bytes[pos] == 0x05:
                    pos += 2
            if pos < len(der_bytes) and der_bytes[pos] == 0x03:
                pos += 1
                _, pos = read_length(der_bytes, pos)
                if der_bytes[pos] == 0x00:
                    pos += 1
                if der_bytes[pos] == 0x30:
                    _, pos = read_length(der_bytes, pos + 1)

        n, pos = read_integer(der_bytes, pos)
        e, pos = read_integer(der_bytes, pos)
        if n and e and n > 1:
            return (n, e)
    except Exception:
        pass
    return None


def step4_extract_rsa_keys() -> list[dict]:
    """Extract RSA keys from bin/psh and compare with V4.62.225."""
    print("\n" + "=" * 70)
    print("  STEP 4: RSA KEY EXTRACTION FROM bin/psh")
    print("=" * 70)

    psh_path = ROOTFS_DIR / "bin" / "psh"
    if not psh_path.exists():
        for p in ROOTFS_DIR.rglob("psh"):
            if p.is_file():
                psh_path = p
                break
        for p in ROOTFS_DIR.rglob("psh.*"):
            if p.is_file():
                psh_path = p
                break

    if not psh_path.exists():
        print("  ERROR: bin/psh not found in rootfs!")
        add_finding("F-V484-PSH-MISSING", "HIGH",
                    "bin/psh not found in extracted rootfs",
                    "Cannot analyze RSA keys without psh binary.", "")
        return []

    psh_data = psh_path.read_bytes()
    print(f"  psh binary: {len(psh_data):,} bytes ({psh_path})")

    strings_raw = re.findall(rb"[\x20-\x7e]{8,}", psh_data)
    strings = [s.decode("ascii", errors="replace") for s in strings_raw]

    b64_pattern = re.compile(r"MIGJ[A-Za-z0-9+/=]{40,}")
    rsa_keys = []

    for s in strings:
        for match in b64_pattern.finditer(s):
            b64_str = match.group(0)
            try:
                der_bytes = base64.b64decode(b64_str)
                result = _parse_der_rsa_pubkey(der_bytes)
                if result:
                    n, e = result
                    bit_length = n.bit_length()
                    n_prefix = (n >> (bit_length - 64)) & 0xFFFFFFFFFFFFFFFF
                    rsa_keys.append({
                        "b64_prefix": b64_str[:40] + "...",
                        "modulus_bits": bit_length,
                        "exponent": e,
                        "modulus_hex_prefix": f"0x{n_prefix:016x}",
                        "modulus_full": hex(n),
                    })
                    print(f"  RSA Key #{len(rsa_keys)}: "
                          f"{bit_length}-bit, e={e}, N prefix=0x{n_prefix:016x}")
            except Exception:
                pass

    hex_mod_pattern = re.compile(r"[0-9A-Fa-f]{64,}")
    for s in strings:
        for match in hex_mod_pattern.finditer(s):
            hex_str = match.group(0)
            if len(hex_str) >= 256 and len(hex_str) <= 520:
                try:
                    n = int(hex_str, 16)
                    bl = n.bit_length()
                    if 1020 <= bl <= 1028 or 2044 <= bl <= 2052:
                        n_prefix = (n >> (bl - 64)) & 0xFFFFFFFFFFFFFFFF
                        rsa_keys.append({
                            "source": "hex_modulus",
                            "modulus_bits": bl,
                            "exponent": 65537,
                            "modulus_hex_prefix": f"0x{n_prefix:016x}",
                            "modulus_full": hex(n),
                        })
                        print(f"  RSA Key (hex) #{len(rsa_keys)}: "
                              f"{bl}-bit, N prefix=0x{n_prefix:016x}")
                except Exception:
                    pass

    print(f"\n  Total RSA keys found: {len(rsa_keys)}")

    print("\n  --- COMPARISON WITH V4.62.225 ---")
    comparison_results = []
    for i, key in enumerate(rsa_keys):
        n_prefix = int(key["modulus_hex_prefix"], 16)
        match_found = False
        for v462_name, v462_prefix in V462_RSA_KEYS.items():
            if n_prefix == v462_prefix:
                status = "IDENTICAL"
                match_found = True
                print(f"  Key #{i + 1}: {status} to V4.62.225 {v462_name}")
                comparison_results.append({
                    "key_index": i + 1,
                    "bits": key["modulus_bits"],
                    "status": status,
                    "v462_match": v462_name,
                })
                break
        if not match_found:
            known_prefixes = list(V462_RSA_KEYS.values())
            close = any(abs(n_prefix - kp) < 0x100 for kp in known_prefixes)
            if close:
                status = "SIMILAR (possible variant)"
            else:
                status = "DIFFERENT (new key)"
            print(f"  Key #{i + 1}: {status} — N prefix=0x{n_prefix:016x}")
            comparison_results.append({
                "key_index": i + 1,
                "bits": key["modulus_bits"],
                "status": status,
                "n_prefix": key["modulus_hex_prefix"],
            })

    if rsa_keys:
        all_1024 = all(k["modulus_bits"] == 1024 for k in rsa_keys)
        if all_1024:
            add_finding(
                "F-V484-RSA-1024", "CRITICAL",
                f"All {len(rsa_keys)} RSA keys are 1024-bit (deprecated since NIST 2013)",
                "RSA-1024 protecting debug root access in psh binary.",
                f"Keys: {len(rsa_keys)}, all 1024-bit")
        else:
            bit_lengths = set(k["modulus_bits"] for k in rsa_keys)
            add_finding(
                "F-V484-RSA-MIXED", "HIGH",
                f"RSA keys found with bit lengths: {bit_lengths}",
                "Cryptographic key analysis.", str(bit_lengths))

    identical_count = sum(1 for c in comparison_results if c.get("status") == "IDENTICAL")
    if identical_count > 0:
        add_finding(
            "F-V484-RSA-SAME-KEYS", "CRITICAL",
            f"{identical_count}/{len(rsa_keys)} RSA keys IDENTICAL to V4.62.225",
            "Same hardcoded keys across firmware versions — CWE-798.",
            json.dumps(comparison_results, indent=2))

    report_sections["rsa_keys"] = json.dumps(rsa_keys, indent=2, default=str)
    report_sections["rsa_comparison"] = json.dumps(comparison_results, indent=2)
    return rsa_keys


# ── STEP 5: Binary hardening audit ──────────────────────────────────────
def step5_binary_hardening() -> list[dict]:
    """Check all ELF binaries for PIE, NX, RELRO, stack canaries, dangerous funcs."""
    print("\n" + "=" * 70)
    print("  STEP 5: BINARY HARDENING AUDIT")
    print("=" * 70)

    import lief

    dangerous_imports = {
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "mktemp", "tmpnam", "realpath",
    }

    results = []
    glibc_version = None

    elf_files = []
    for f in ROOTFS_DIR.rglob("*"):
        if f.is_file() and f.stat().st_size > 100:
            try:
                magic = f.read_bytes()[:4]
                if magic == b"\x7fELF":
                    elf_files.append(f)
            except Exception:
                pass

    print(f"  ELF binaries found: {len(elf_files)}")

    for elf_path in sorted(elf_files, key=lambda p: p.stat().st_size, reverse=True):
        try:
            binary = lief.parse(str(elf_path))
            if binary is None:
                continue

            name = str(elf_path.relative_to(ROOTFS_DIR))
            size = elf_path.stat().st_size

            imports = [s.name for s in binary.imported_symbols if s.name]
            exports = [s.name for s in binary.exported_symbols if s.name]
            dangerous = sorted(set(i for i in imports if i in dangerous_imports))

            nx = getattr(binary, "has_nx", True)
            pie = getattr(binary, "is_pie", False)

            has_relro = False
            full_relro = False
            has_canary = "__stack_chk_fail" in imports or "__stack_chk_guard" in imports
            for seg in binary.segments:
                if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                    has_relro = True

            for dyn in binary.dynamic_entries:
                if dyn.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                    if hasattr(dyn, "value") and (dyn.value & 0x8):
                        full_relro = True

            if "libc" in name.lower() and ".so" in name.lower():
                for s_obj in binary.exported_symbols:
                    if s_obj.name and "glibc" in s_obj.name.lower():
                        glibc_version = s_obj.name

                raw = elf_path.read_bytes()
                ver_match = re.search(
                    rb"GNU C Library.*?release version (\d+\.\d+)",
                    raw)
                if ver_match:
                    glibc_version = ver_match.group(1).decode()
                else:
                    ver_match2 = re.search(
                        rb"glibc (\d+\.\d+)", raw, re.IGNORECASE)
                    if ver_match2:
                        glibc_version = ver_match2.group(1).decode()
                    else:
                        libc_name_match = re.search(
                            r"libc-(\d+\.\d+)\.so", name)
                        if libc_name_match:
                            glibc_version = libc_name_match.group(1)

            arch = str(binary.header.machine_type).split(".")[-1]
            bits = 32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else 64

            result = {
                "name": name, "size": size,
                "arch": f"{arch}/{bits}",
                "pie": pie, "nx": nx,
                "relro": "Full" if full_relro else ("Partial" if has_relro else "None"),
                "canary": has_canary,
                "dangerous": dangerous,
                "imports_count": len(imports),
                "exports_count": len(exports),
            }
            results.append(result)

            issues = []
            if not pie:
                issues.append("NO-PIE")
            if not nx:
                issues.append("NO-NX")
            if not has_relro:
                issues.append("NO-RELRO")
            if not has_canary:
                issues.append("NO-CANARY")
            if dangerous:
                issues.append(f"DANGER:{','.join(dangerous[:5])}")

            if issues:
                print(f"  {name} ({size // 1024} KB, {arch}/{bits}): "
                      f"{' | '.join(issues)}")

        except Exception as e:
            pass

    if glibc_version:
        print(f"\n  glibc version: {glibc_version}")
        report_sections["glibc_version"] = glibc_version
    else:
        for f in ROOTFS_DIR.rglob("libc-*.so"):
            m = re.search(r"libc-(\d+\.\d+)\.so", f.name)
            if m:
                glibc_version = m.group(1)
                print(f"  glibc version (from filename): {glibc_version}")
                report_sections["glibc_version"] = glibc_version
                break
        for f in ROOTFS_DIR.rglob("libc.so.*"):
            raw = f.read_bytes()
            m = re.search(rb"(\d+\.\d+)", raw[:100])
            if m:
                glibc_version = m.group(1).decode()
                report_sections["glibc_version"] = glibc_version
                break

    no_pie_count = sum(1 for r in results if not r["pie"])
    no_nx_count = sum(1 for r in results if not r["nx"])
    no_relro_count = sum(1 for r in results if r["relro"] == "None")
    no_canary_count = sum(1 for r in results if not r["canary"])
    danger_count = sum(1 for r in results if r["dangerous"])

    print(f"\n  HARDENING SUMMARY:")
    print(f"    Total ELF: {len(results)}")
    print(f"    No PIE:    {no_pie_count}/{len(results)}")
    print(f"    No NX:     {no_nx_count}/{len(results)}")
    print(f"    No RELRO:  {no_relro_count}/{len(results)}")
    print(f"    No Canary: {no_canary_count}/{len(results)}")
    print(f"    Dangerous: {danger_count}/{len(results)}")

    if no_pie_count == len(results):
        add_finding(
            "F-V484-NO-PIE-ALL", "HIGH",
            f"ALL {len(results)} binaries lack PIE — no ASLR possible",
            "Complete absence of Position Independent Executables.", "")

    if glibc_version:
        try:
            major, minor = map(int, glibc_version.split(".")[:2])
            if major == 2 and minor <= 17:
                add_finding(
                    "F-V484-GLIBC-OLD", "HIGH",
                    f"Obsolete glibc {glibc_version} with known CVEs",
                    "Vulnerable to GHOST (CVE-2015-0235), getaddrinfo "
                    "(CVE-2015-7547), stack clash (CVE-2017-1000366).",
                    glibc_version)
        except Exception:
            pass

    report_sections["binary_hardening"] = json.dumps(results, indent=2)
    return results


# ── STEP 6: Boot script audit ───────────────────────────────────────────
def step6_boot_script_audit() -> list[dict]:
    """Check init scripts for chmod 777, telnetd, dropbear, credentials."""
    print("\n" + "=" * 70)
    print("  STEP 6: BOOT SCRIPT AUDIT")
    print("=" * 70)

    script_findings = []

    for f in sorted(ROOTFS_DIR.rglob("*")):
        if not f.is_file():
            continue
        try:
            raw = f.read_bytes()
        except Exception:
            continue

        if raw[:2] != b"#!" and not any(
            f.name.endswith(ext) for ext in (".sh", ".ash", ".conf", ".cfg")):
            if b"#!/" not in raw[:256]:
                continue

        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        rel_name = str(f.relative_to(ROOTFS_DIR))
        issues = []

        if "chmod 777" in content:
            issues.append("chmod 777 (world-writable)")
        if "chmod 666" in content:
            issues.append("chmod 666 (world-writable files)")
        if re.search(r"\btelnetd\b", content, re.I):
            issues.append("telnetd reference")
        if re.search(r"\bdropbear\b", content, re.I):
            issues.append("dropbear SSH")
        if re.search(r"\bsshd\b", content, re.I):
            issues.append("sshd reference")
        if "mount -o remount,rw" in content:
            issues.append("remount rw")
        if re.search(r"iptables\s+(-F|--flush)", content):
            issues.append("firewall flush")
        if re.search(r"password|passwd", content, re.I):
            issues.append("password reference")

        if issues:
            script_findings.append({
                "script": rel_name, "issues": issues,
                "preview": content[:500],
            })
            print(f"  {rel_name}: {', '.join(issues)}")
            for issue in issues:
                sev = "MEDIUM"
                if "chmod 777" in issue:
                    sev = "MEDIUM"
                if "telnetd" in issue:
                    sev = "HIGH"
                add_finding(
                    f"F-V484-BOOT-{os.path.basename(rel_name)[:12].upper()}-{len(findings):03d}",
                    sev, f"Boot script {rel_name}: {issue}",
                    f"Insecure pattern in init script.", issue)

    print("\n  --- /etc/passwd & /etc/shadow ---")
    for name in ["etc/passwd", "etc/shadow", "etc/group"]:
        path = ROOTFS_DIR / name
        if not path.exists():
            for p in ROOTFS_DIR.glob(f"{name}.*"):
                path = p
                break
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            print(f"\n  [{name}]:")
            for line in content.strip().split("\n"):
                print(f"    {line}")
                if "shadow" in name:
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] and parts[1] not in ("*", "!", "x", ""):
                        add_finding(
                            f"F-V484-SHADOW-{parts[0]}", "CRITICAL",
                            f"Password hash for {parts[0]}: {parts[1][:30]}...",
                            "Default password hash in firmware.", line[:200])
                if "passwd" in name and "shadow" not in name:
                    parts = line.split(":")
                    if len(parts) >= 7 and parts[2] == "0":
                        add_finding(
                            f"F-V484-ROOT-{parts[0]}", "HIGH",
                            f"Root-level user: {parts[0]} (uid=0)",
                            "User with UID 0.", line[:200])

    report_sections["boot_scripts"] = json.dumps(script_findings, indent=2)
    return script_findings


# ── STEP 7: String analysis ─────────────────────────────────────────────
def step7_string_analysis() -> dict:
    """Analyze strings in psh, ded, busybox for security-relevant content."""
    print("\n" + "=" * 70)
    print("  STEP 7: STRING ANALYSIS (psh, ded, busybox)")
    print("=" * 70)

    target_names = ["psh", "ded", "busybox", "hik_tool", "hrsaverify",
                    "do_update", "do_factory", "hikefs"]
    string_results = {}

    interesting_patterns = {
        "debug": re.compile(r"\bdebug\b", re.I),
        "hikded_dev": re.compile(r"/dev/hikded"),
        "psh_rsa_conf": re.compile(r"psh_rsa\.conf"),
        "ttyAuth": re.compile(r"ttyAuth", re.I),
        "password": re.compile(r"\bpassword\b|\bpasswd\b", re.I),
        "backdoor": re.compile(r"\bbackdoor\b", re.I),
        "telnet": re.compile(r"\btelnet\b", re.I),
        "root_shell": re.compile(r"/bin/sh|/bin/bash|/bin/ash"),
        "crypto_ref": re.compile(r"\brsa\b|\baes\b|\bdes\b|\bcipher\b", re.I),
        "exec_func": re.compile(r"\bexecvp?\b|\bsystem\b|\bpopen\b"),
        "cmd_pattern": re.compile(r"resetPasswd|setCloudPassword|connectSlave"),
        "isapi": re.compile(r"/ISAPI/"),
        "sdk": re.compile(r"/SDK/"),
        "cloud": re.compile(r"cloud|hik-connect|ezviz", re.I),
        "update_ref": re.compile(r"firmware.*update|upgrade", re.I),
    }

    for target_name in target_names:
        found_path = None
        for f in ROOTFS_DIR.rglob("*"):
            if f.is_file() and f.name == target_name:
                found_path = f
                break
        if not found_path:
            for f in ROOTFS_DIR.rglob(f"{target_name}.*"):
                if f.is_file():
                    found_path = f
                    break

        if not found_path:
            continue

        raw = found_path.read_bytes()
        strings_raw = re.findall(rb"[\x20-\x7e]{8,}", raw)
        strings = [s.decode("ascii", errors="replace") for s in strings_raw]

        print(f"\n  {target_name} ({len(raw):,} bytes, {len(strings)} strings):")

        hits: dict[str, list[str]] = {}
        for s in strings:
            for pat_name, pat_re in interesting_patterns.items():
                if pat_re.search(s):
                    if pat_name not in hits:
                        hits[pat_name] = []
                    if len(hits[pat_name]) < 5:
                        hits[pat_name].append(s[:150])

        for pat_name, examples in sorted(hits.items()):
            for ex in examples[:3]:
                print(f"    [{pat_name}] {ex[:100]}")

        string_results[target_name] = {
            "size": len(raw), "string_count": len(strings),
            "hits": {k: v[:3] for k, v in hits.items()},
        }

    report_sections["string_analysis"] = json.dumps(string_results, indent=2)
    return string_results


# ── STEP 8: Report generation ───────────────────────────────────────────
def step8_generate_report(
    kernel_info: list[dict],
    rootfs_entries: list[dict],
    rsa_keys: list[dict],
    hardening: list[dict],
    boot_scripts: list[dict],
    string_results: dict,
):
    """Generate the comprehensive forensic report."""
    print("\n" + "=" * 70)
    print("  STEP 8: GENERATING REPORT")
    print("=" * 70)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sev_counts = Counter(f["severity"] for f in findings)

    glibc_ver = report_sections.get("glibc_version", "unknown")
    rsa_comparison = json.loads(report_sections.get("rsa_comparison", "[]"))

    identical_keys = [c for c in rsa_comparison if c.get("status") == "IDENTICAL"]
    different_keys = [c for c in rsa_comparison if "DIFFERENT" in c.get("status", "")]

    type_counts = Counter(e.get("type", "unknown") for e in rootfs_entries)

    lines = [
        "# Hikvision NVR Firmware V4.84.101 — Complete Forensic Analysis Report",
        "",
        f"> **Generated**: {ts}  ",
        "> **Analyst**: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek  ",
        "> **Target**: Hikvision NVR firmware V4.84.101 build 251212  ",
        "> **Source**: `Firmware_3000693671_ML_V4.84.101_251212.zip`  ",
        "> **Methods**: DAV extraction, kernel decompression, initramfs forensics, "
        "binary RE, cryptographic analysis  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Deep forensic analysis of Hikvision NVR firmware V4.84.101 yielded "
        f"**{len(findings)} security findings**:",
        "",
    ]
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0):
            lines.append(f"- **{s}**: {sev_counts[s]}")
    lines.append("")

    lines.extend([
        "Key results:",
        "",
        f"- **RSA keys**: {len(rsa_keys)} keys extracted from `bin/psh`; "
        f"**{len(identical_keys)} IDENTICAL** to V4.62.225, "
        f"**{len(different_keys)} DIFFERENT/NEW**",
        f"- **Binary hardening**: {sum(1 for h in hardening if not h['pie'])}/{len(hardening)} "
        f"binaries lack PIE (no ASLR)",
        f"- **glibc**: version {glibc_ver}",
        f"- **Rootfs**: {len(rootfs_entries)} CPIO entries "
        f"({type_counts.get('elf', 0)} ELFs, {type_counts.get('script', 0)} scripts, "
        f"{type_counts.get('symlink', 0)} symlinks)",
        "",
        "---",
        "",
        "## 1. Extraction Methodology",
        "",
        "### 1.1 DAV Container",
        "",
        f"```",
        report_sections.get("dav_header", "N/A"),
        f"```",
        "",
        "### 1.2 Kernel Extraction",
        "",
    ])

    for ki in kernel_info:
        lines.extend([
            f"- **{ki.get('name', 'unknown')}** @ 0x{ki['offset']:08X}",
            f"  - Size: {ki['size']:,} bytes",
            f"  - Load address: 0x{ki['load']:08X}",
            f"  - Compression: {'LZMA' if ki['comp'] == 3 else ki['comp']}",
            f"  - Decompressed: {ki.get('decompressed_size', 'N/A'):,} bytes" if ki.get('decompressed_size') else "",
            f"  - Linux version: {ki.get('linux_version', 'N/A')}" if ki.get('linux_version') else "",
            f"  - Strings (10+): {ki.get('string_count', 'N/A'):,}" if ki.get('string_count') else "",
        ])
    lines.append("")

    lines.extend([
        "### 1.3 Initramfs Extraction",
        "",
        f"| Category | Count |",
        f"|----------|-------|",
    ])
    for t, c in type_counts.most_common():
        lines.append(f"| {t} | {c} |")
    lines.extend(["", "---", ""])

    # RSA comparison section
    lines.extend([
        "## 2. RSA Key Analysis — V4.84.101 vs V4.62.225",
        "",
        "### 2.1 Extracted Keys",
        "",
        "| # | Bits | Exponent | Modulus Prefix | V4.62.225 Match |",
        "|---|------|----------|----------------|-----------------|",
    ])
    for i, key in enumerate(rsa_keys):
        comp = rsa_comparison[i] if i < len(rsa_comparison) else {}
        status = comp.get("status", "N/A")
        v462_ref = comp.get("v462_match", "—")
        lines.append(
            f"| {i + 1} | {key['modulus_bits']} | {key['exponent']} | "
            f"`{key['modulus_hex_prefix']}` | **{status}** ({v462_ref}) |")

    lines.extend([
        "",
        "### 2.2 Key Comparison Verdict",
        "",
    ])
    if identical_keys:
        lines.append(
            f"**{len(identical_keys)} of {len(rsa_keys)} RSA keys are IDENTICAL** "
            f"to V4.62.225. This confirms CWE-798 (Use of Hard-coded Credentials) "
            f"persists across firmware versions. The same RSA-1024 keys protect "
            f"debug root access on both V4.62.225 and V4.84.101 devices.")
    elif rsa_keys:
        lines.append(
            "RSA keys have been **CHANGED** from V4.62.225. "
            "Further analysis needed to determine if security has improved.")
    else:
        lines.append("No RSA keys found — methodology may need updating.")
    lines.extend(["", "---", ""])

    # Binary hardening section
    lines.extend([
        "## 3. Binary Hardening Status",
        "",
        "| Binary | Size | PIE | NX | RELRO | Canary | Dangerous Imports |",
        "|--------|------|-----|----|----- -|--------|-------------------|",
    ])

    priority_names = ["psh", "ded", "busybox", "hik_tool", "hrsaverify",
                      "do_update", "do_factory", "hikefs"]
    shown = set()
    for pname in priority_names:
        for h in hardening:
            if pname in h["name"].lower() and h["name"] not in shown:
                dng = ", ".join(h["dangerous"][:4]) if h["dangerous"] else "—"
                lines.append(
                    f"| {h['name']} | {h['size'] // 1024} KB | "
                    f"{'YES' if h['pie'] else '**NO**'} | "
                    f"{'YES' if h['nx'] else '**NO**'} | "
                    f"{h['relro']} | "
                    f"{'YES' if h['canary'] else '**NO**'} | "
                    f"{dng} |")
                shown.add(h["name"])

    for h in sorted(hardening, key=lambda x: x["size"], reverse=True):
        if h["name"] not in shown and (h["dangerous"] or not h["pie"]):
            if len(shown) >= 20:
                break
            dng = ", ".join(h["dangerous"][:4]) if h["dangerous"] else "—"
            lines.append(
                f"| {h['name']} | {h['size'] // 1024} KB | "
                f"{'YES' if h['pie'] else '**NO**'} | "
                f"{'YES' if h['nx'] else '**NO**'} | "
                f"{h['relro']} | "
                f"{'YES' if h['canary'] else '**NO**'} | "
                f"{dng} |")
            shown.add(h["name"])

    lines.extend(["", "---", ""])

    # glibc CVE mapping
    lines.extend([
        "## 4. glibc Version & CVE Mapping",
        "",
        f"**Detected version**: glibc {glibc_ver}",
        "",
    ])
    if glibc_ver != "unknown":
        lines.extend([
            "| CVE | Description | CVSS |",
            "|-----|-------------|------|",
            "| CVE-2015-0235 | GHOST heap overflow in gethostbyname() | 7.5 |",
            "| CVE-2015-7547 | Stack buffer overflow in getaddrinfo() | 8.1 |",
            "| CVE-2014-5119 | Off-by-one in transliteration | 7.5 |",
            "| CVE-2017-1000366 | Stack clash vulnerability | 7.8 |",
            "| CVE-2018-11236 | Integer overflow in realpath() | 9.8 |",
            "| CVE-2021-35942 | Integer overflow in wordexp() | 9.8 |",
            "",
        ])
    lines.extend(["---", ""])

    # Boot script findings
    lines.extend([
        "## 5. Boot Script Findings",
        "",
    ])
    for bs in boot_scripts:
        lines.append(f"- **{bs['script']}**: {', '.join(bs['issues'])}")
    lines.extend(["", "---", ""])

    # String analysis
    lines.extend([
        "## 6. String Analysis — Key Binaries",
        "",
    ])
    for binary_name, data in string_results.items():
        lines.append(f"### {binary_name}")
        lines.append(f"- Size: {data['size']:,} bytes")
        lines.append(f"- Strings: {data['string_count']}")
        if data.get("hits"):
            for pat, examples in data["hits"].items():
                for ex in examples[:2]:
                    lines.append(f"  - `[{pat}]` {ex[:80]}")
        lines.append("")
    lines.extend(["---", ""])

    # All findings table
    lines.extend([
        "## 7. Complete Findings Table",
        "",
        "| ID | Severity | Title |",
        "|----|----------|-------|",
    ])
    for f in sorted(findings, key=lambda x: {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
    }.get(x["severity"], 5)):
        lines.append(f"| {f['id']} | **{f['severity']}** | {f['title'][:80]} |")

    lines.extend([
        "",
        "---",
        "",
        "## 8. Recommendations",
        "",
        "| Priority | Recommendation |",
        "|----------|---------------|",
        "| CRITICAL | Upgrade RSA keys from 1024-bit to ≥2048-bit (preferably 4096) |",
        "| CRITICAL | Implement unique per-device RSA keypairs (not firmware-wide static) |",
        "| HIGH | Enable PIE compilation for ALL binaries to support ASLR |",
        "| HIGH | Upgrade glibc to current stable (2.38+) |",
        "| HIGH | Implement MAC-based firmware integrity verification |",
        "| MEDIUM | Replace chmod 777 with minimal required permissions |",
        "| MEDIUM | Disable debug mode in production firmware |",
        "| MEDIUM | Move firmware decryption to hardware security module |",
        "| LOW | Upgrade Linux kernel to current LTS (6.x) |",
        "",
        "---",
        "",
        "## 9. Responsible Disclosure Timeline",
        "",
        "| Date | Action |",
        "|------|--------|",
        f"| {datetime.now().strftime('%Y-%m-%d')} | V4.84.101 analysis completed |",
        "| 2026-04-18 | V4.62.225 analysis completed |",
        "| TBD | Vendor notification via Hikvision PSIRT |",
        "| TBD + 90 days | Public disclosure |",
        "",
        "---",
        "",
        "*Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek*",
    ])

    report_path = REPORTS_DIR / "V4_84_101_FORENSIC_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {report_path}")

    json_path = TMP_DIR / "v4_84_101_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] JSON: {json_path}")

    return report_path


# ── MAIN ─────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  HIKVISION V4.84.101 — COMPLETE FORENSIC ANALYSIS")
    print(f"  DAV: {DAV_PATH}")
    print("=" * 70)

    if not DAV_PATH.exists():
        print(f"  ERROR: DAV file not found: {DAV_PATH}")
        sys.exit(1)

    print(f"\n  DAV size: {DAV_PATH.stat().st_size:,} bytes")
    print(f"  SHA256: {hashlib.sha256(DAV_PATH.read_bytes()).hexdigest()}")

    extracted = step2_extract_dav()
    kernel_info, rootfs_entries = step3_extract_kernel_and_rootfs()
    rsa_keys = step4_extract_rsa_keys()
    hardening = step5_binary_hardening()
    boot_scripts = step6_boot_script_audit()
    string_results = step7_string_analysis()

    report_path = step8_generate_report(
        kernel_info, rootfs_entries, rsa_keys,
        hardening, boot_scripts, string_results)

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE: {len(findings)} findings")
    print(f"  Report: {report_path}")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
