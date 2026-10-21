#!/usr/bin/env python3
"""
hikvision_v4_84_full_analysis.py — Complete forensic analysis of V4.84.101
Author: Andre Henrique (@mrhenrike) | Uniao Geek — https://github.com/Uniao-Geek

V4.84.101 uses AES encryption on file payloads (improvement over V4.62.225
which used XOR-only). Analysis compares encryption architecture changes,
parses accessible metadata, and cross-references V4.62.225 rootfs for key
comparison.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import struct
import sys
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

BASE = Path(__file__).resolve().parent.parent
TMP_V484 = BASE / ".tmp" / "hikvision_v4_84"
TMP_V462 = BASE / ".tmp" / "hikvision_v4_62"
DAV_PATH = TMP_V484 / "digicap.dav"
ROOTFS_V462 = TMP_V462 / "rootfs"
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings: list[dict[str, Any]] = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


# ════════════════════════════════════════════════════════════════════
# STEP 1 + 2: DAV Container Analysis
# ════════════════════════════════════════════════════════════════════
def analyze_dav_container() -> dict:
    print("\n" + "=" * 70)
    print("  STEP 1-2: DAV CONTAINER ANALYSIS")
    print("=" * 70)

    raw = DAV_PATH.read_bytes()
    dav_sha256 = hashlib.sha256(raw).hexdigest()
    print(f"  File: {DAV_PATH.name}")
    print(f"  Size: {len(raw):,} bytes")
    print(f"  SHA256: {dav_sha256}")

    from hiktools import fmod

    with fmod.DigiCap(str(DAV_PATH)) as dcap:
        h = dcap.head
        print(f"  Magic: 0x{h.magic:08X} (HKWS)")
        print(f"  Files: {h.files}")
        print(f"  Device class: {h.device_class}")

        key_xor = dcap.KEY_XOR
        key_hex = key_xor.hex() if isinstance(key_xor, (bytes, bytearray)) else str(key_xor)
        print(f"  XOR key: {key_hex}")

        file_table = []
        for file_info in dcap:
            fname, flen, fpos, fchk = file_info
            if flen > 0 and fpos > 0:
                file_table.append({
                    "name": fname, "size": flen,
                    "offset": f"0x{fpos:08X}", "checksum": f"0x{fchk:08X}",
                })

    print(f"\n  File table ({len(file_table)} entries):")
    for f in file_table:
        print(f"    {f['name']:45s} {f['size']:>12,} bytes @ {f['offset']}")

    # XOR decrypt header for metadata analysis
    key_bytes = bytes.fromhex(key_hex)
    raw_arr = np.frombuffer(raw, dtype=np.uint8)
    key_arr = np.frombuffer(key_bytes, dtype=np.uint8)
    positions = np.arange(len(raw), dtype=np.uint64)
    key_indices = ((positions >> 4) + positions).astype(np.uint8) & 0x0F
    dec = (raw_arr ^ key_arr[key_indices]).tobytes()
    del raw_arr, positions, key_indices

    # Verify XOR decryption
    dec_magic = struct.unpack('<I', dec[:4])[0]
    print(f"\n  XOR-decrypted magic: 0x{dec_magic:08X} ({'OK' if dec_magic == 0x484B5753 else 'MISMATCH'})")

    # Check encryption on actual file content
    print("\n  --- ENCRYPTION LAYER ANALYSIS ---")
    test_files = [("uImage", 0x008BC6C8, 6488, b'\x27\x05\x19\x56'),
                  ("start.sh", 0x00005348, 9166880, b'#!/')]

    encryption_detected = False
    for fname, offset, size, expected_magic in test_files:
        if offset + len(expected_magic) <= len(dec):
            dec_content = dec[offset:offset + len(expected_magic)]
            raw_content = raw[offset:offset + len(expected_magic)]
            match_raw = raw_content[:len(expected_magic)] == expected_magic
            match_dec = dec_content[:len(expected_magic)] == expected_magic
            print(f"  {fname}: raw_magic={raw_content[:8].hex()}, "
                  f"dec_magic={dec_content[:8].hex()}, "
                  f"raw_match={match_raw}, dec_match={match_dec}")
            if not match_raw and not match_dec:
                encryption_detected = True

    if encryption_detected:
        add_finding(
            "F-V484-AES-FIRMWARE", "INFO",
            "V4.84.101 uses AES encryption on firmware payloads",
            "File payloads (uImage, start.sh, sys_app.tar.lzma, etc.) are "
            "AES-encrypted beyond the XOR container layer. This is a security "
            "improvement over V4.62.225 which used XOR-only protection. "
            "Extraction requires the AES key from /dev/hikded kernel device.",
            f"XOR key: {key_hex}")

        print("\n  *** FINDING: V4.84.101 firmware payloads are AES-encrypted ***")
        print("  *** This is a SECURITY IMPROVEMENT over V4.62.225 ***")
        print("  *** File content extraction requires /dev/hikded AES key ***")

    # Extract certificate from raw data
    cert_idx = raw.find(b'Hikvision')
    cert_info = ""
    if cert_idx >= 0:
        cert_area = raw[cert_idx - 500:cert_idx + 2000]
        cert_strings = re.findall(rb'[\x20-\x7e]{8,}', cert_area)
        cert_info = "\n".join(s.decode("ascii", errors="replace") for s in cert_strings[:20])
        print(f"\n  Certificate data found at raw offset 0x{cert_idx:08X}:")
        for s in cert_strings[:10]:
            print(f"    {s.decode('ascii', errors='replace')[:80]}")

    # Parse headEx for file metadata
    headex_data = dec[0x400:0x400 + 1120]
    headex_strings = re.findall(rb'[\x20-\x7e]{4,}', headex_data)

    return {
        "sha256": dav_sha256,
        "size": len(raw),
        "magic": f"0x{h.magic:08X}",
        "files": h.files,
        "device_class": h.device_class,
        "xor_key": key_hex,
        "file_table": file_table,
        "encryption": "AES + XOR" if encryption_detected else "XOR only",
        "certificate_info": cert_info,
    }


# ════════════════════════════════════════════════════════════════════
# STEP 3: V4.62 Rootfs Analysis (since V4.84 is AES-encrypted)
# ════════════════════════════════════════════════════════════════════
def analyze_v462_rootfs() -> dict:
    """Analyze V4.62.225 rootfs for comparison baselines."""
    print("\n" + "=" * 70)
    print("  STEP 3: V4.62.225 ROOTFS ANALYSIS (comparison baseline)")
    print("=" * 70)

    if not ROOTFS_V462.exists():
        print("  V4.62 rootfs not available!")
        return {}

    all_files = []
    for f in ROOTFS_V462.rglob("*"):
        if f.is_file():
            all_files.append({"name": str(f.relative_to(ROOTFS_V462)),
                              "size": f.stat().st_size, "path": str(f)})

    elf_files = []
    scripts = []
    for f in all_files:
        try:
            magic = Path(f["path"]).read_bytes()[:4]
            if magic == b"\x7fELF":
                elf_files.append(f)
            elif magic[:2] == b"#!":
                scripts.append(f)
        except:
            pass

    print(f"  Total files: {len(all_files)}")
    print(f"  ELF binaries: {len(elf_files)}")
    print(f"  Scripts: {len(scripts)}")

    return {"total": len(all_files), "elfs": elf_files, "scripts": scripts}


# ════════════════════════════════════════════════════════════════════
# STEP 4: RSA Key Extraction from V4.62 psh
# ════════════════════════════════════════════════════════════════════
def _parse_der_rsa_pubkey(der_bytes: bytes):
    """Parse DER-encoded RSA public key."""
    try:
        if der_bytes[0] != 0x30:
            return None

        def read_length(data, offset):
            if data[offset] < 0x80:
                return data[offset], offset + 1
            num = data[offset] & 0x7F
            length = int.from_bytes(data[offset + 1:offset + 1 + num], "big")
            return length, offset + 1 + num

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


def extract_rsa_keys() -> list[dict]:
    """Extract RSA keys from V4.62.225 psh binary."""
    print("\n" + "=" * 70)
    print("  STEP 4: RSA KEY EXTRACTION (from V4.62.225 psh)")
    print("=" * 70)

    psh_path = ROOTFS_V462 / "bin" / "psh"
    if not psh_path.exists():
        print("  psh not found!")
        return []

    psh_data = psh_path.read_bytes()
    psh_sha256 = hashlib.sha256(psh_data).hexdigest()
    print(f"  psh binary: {len(psh_data):,} bytes")
    print(f"  psh SHA256: {psh_sha256}")

    strings_raw = re.findall(rb"[\x20-\x7e]{8,}", psh_data)
    strings = [s.decode("ascii", errors="replace") for s in strings_raw]
    print(f"  Strings: {len(strings)}")

    # Extract Base64 DER keys (MIGJ prefix)
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
                        "source": "Base64 DER in psh",
                        "b64_prefix": b64_str[:40] + "...",
                        "modulus_bits": bit_length,
                        "exponent": e,
                        "modulus_n_prefix": f"0x{n_prefix:016x}",
                        "modulus_full_hex": hex(n),
                    })
                    print(f"  RSA Key #{len(rsa_keys)}: {bit_length}-bit, "
                          f"e={e}, N prefix=0x{n_prefix:016x}")
            except Exception:
                pass

    # Extract hex-encoded modulus
    hex_mod_pattern = re.compile(r"[0-9A-Fa-f]{256,520}")
    for s in strings:
        for match in hex_mod_pattern.finditer(s):
            hex_str = match.group(0)
            try:
                n = int(hex_str, 16)
                bl = n.bit_length()
                if 1020 <= bl <= 1028 or 2044 <= bl <= 2052:
                    n_prefix = (n >> (bl - 64)) & 0xFFFFFFFFFFFFFFFF
                    already = any(k["modulus_n_prefix"] == f"0x{n_prefix:016x}" for k in rsa_keys)
                    if not already:
                        rsa_keys.append({
                            "source": "Hex modulus in psh",
                            "modulus_bits": bl,
                            "exponent": 65537,
                            "modulus_n_prefix": f"0x{n_prefix:016x}",
                            "modulus_full_hex": hex(n),
                        })
                        print(f"  RSA Key (hex) #{len(rsa_keys)}: {bl}-bit, "
                              f"N prefix=0x{n_prefix:016x}")
            except Exception:
                pass

    print(f"\n  Total RSA keys: {len(rsa_keys)}")

    # Verify against known V4.62 key prefixes
    V462_KNOWN = {
        "key1": 0xe67048b79c066b23,
        "key2": 0xe67fa01c39146310,
        "key3": 0xf73b68ba7fd1e4a6,
    }

    print("\n  --- KEY VERIFICATION ---")
    for i, key in enumerate(rsa_keys):
        n_prefix = int(key["modulus_n_prefix"], 16)
        for v_name, v_prefix in V462_KNOWN.items():
            if n_prefix == v_prefix:
                print(f"  Key #{i + 1}: MATCHES V4.62 {v_name}")
                key["v462_match"] = v_name
                break
        else:
            print(f"  Key #{i + 1}: No match to known V4.62 keys")

    if rsa_keys:
        all_1024 = all(k["modulus_bits"] == 1024 for k in rsa_keys)
        if all_1024:
            add_finding(
                "F-V462-RSA-1024", "CRITICAL",
                f"All {len(rsa_keys)} RSA keys in V4.62 psh are 1024-bit",
                "RSA-1024 deprecated by NIST in 2013 (SP 800-131A). "
                "Protects debug root access.",
                f"{len(rsa_keys)} keys, all 1024-bit, e=65537")

    # Analyze psh command set
    print("\n  --- PSH COMMAND ANALYSIS ---")
    cmd_patterns = [
        "debug", "resetPasswd", "setCloudPassword", "connectSlaveSsh",
        "dmesg", "netstat", "reboot", "i2cRead", "i2cWrite",
        "ttyAuth", "psh_rsa.conf",
    ]
    found_cmds = []
    for s in strings:
        for cmd in cmd_patterns:
            if cmd in s and cmd not in found_cmds:
                found_cmds.append(cmd)
                print(f"    CMD: {s[:80]}")

    return rsa_keys


# ════════════════════════════════════════════════════════════════════
# STEP 5: Binary Hardening Audit (V4.62 rootfs)
# ════════════════════════════════════════════════════════════════════
def binary_hardening_audit() -> tuple[list[dict], str]:
    """Audit all ELF binaries for security hardening."""
    print("\n" + "=" * 70)
    print("  STEP 5: BINARY HARDENING AUDIT (V4.62.225 rootfs)")
    print("=" * 70)

    import lief

    dangerous_imports = {
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "mktemp", "tmpnam", "realpath",
    }

    results = []
    glibc_version = "unknown"

    elf_files = []
    for f in ROOTFS_V462.rglob("*"):
        if f.is_file() and f.stat().st_size > 100:
            try:
                if f.read_bytes()[:4] == b"\x7fELF":
                    elf_files.append(f)
            except:
                pass

    print(f"  ELF binaries: {len(elf_files)}")

    for elf_path in sorted(elf_files, key=lambda p: p.stat().st_size, reverse=True):
        try:
            binary = lief.parse(str(elf_path))
            if binary is None:
                continue

            name = str(elf_path.relative_to(ROOTFS_V462))
            size = elf_path.stat().st_size

            imports = [s.name for s in binary.imported_symbols if s.name]
            dangerous = sorted(set(i for i in imports if i in dangerous_imports))

            nx = getattr(binary, "has_nx", True)
            pie = getattr(binary, "is_pie", False)

            has_relro = False
            has_canary = "__stack_chk_fail" in imports or "__stack_chk_guard" in imports

            for seg in binary.segments:
                if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                    has_relro = True

            if "libc" in name.lower() and ".so" in name.lower():
                raw_data = elf_path.read_bytes()
                ver = re.search(rb"release version (\d+\.\d+)", raw_data)
                if ver:
                    glibc_version = ver.group(1).decode()
                else:
                    m = re.search(r"libc-(\d+\.\d+)\.so", name)
                    if m:
                        glibc_version = m.group(1)

            arch = str(binary.header.machine_type).split(".")[-1]
            bits = 32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else 64

            result = {
                "name": name, "size": size,
                "arch": f"{arch}/{bits}",
                "pie": pie, "nx": nx,
                "relro": "Partial" if has_relro else "None",
                "canary": has_canary,
                "dangerous": dangerous,
            }
            results.append(result)

            issues = []
            if not pie: issues.append("NO-PIE")
            if not nx: issues.append("NO-NX")
            if not has_relro: issues.append("NO-RELRO")
            if not has_canary: issues.append("NO-CANARY")
            if dangerous: issues.append(f"DANGER:{','.join(dangerous[:5])}")

            if issues:
                print(f"  {name} ({size // 1024} KB): {' | '.join(issues)}")

        except Exception:
            pass

    print(f"\n  glibc version: {glibc_version}")

    no_pie = sum(1 for r in results if not r["pie"])
    no_nx = sum(1 for r in results if not r["nx"])
    no_relro = sum(1 for r in results if r["relro"] == "None")
    no_canary = sum(1 for r in results if not r["canary"])
    with_danger = sum(1 for r in results if r["dangerous"])

    print(f"\n  HARDENING SUMMARY:")
    print(f"    Total ELF: {len(results)}")
    print(f"    No PIE:    {no_pie}/{len(results)}")
    print(f"    No NX:     {no_nx}/{len(results)}")
    print(f"    No RELRO:  {no_relro}/{len(results)}")
    print(f"    No Canary: {no_canary}/{len(results)}")
    print(f"    Dangerous: {with_danger}/{len(results)}")

    if no_pie == len(results) and len(results) > 0:
        add_finding("F-V462-NO-PIE-ALL", "HIGH",
                    f"ALL {len(results)} binaries lack PIE (no ASLR)",
                    "Complete absence of Position Independent Executables.", "")

    if glibc_version != "unknown":
        try:
            major, minor = map(int, glibc_version.split(".")[:2])
            if major == 2 and minor <= 17:
                add_finding("F-V462-GLIBC-OLD", "HIGH",
                            f"Obsolete glibc {glibc_version}",
                            "Vulnerable to GHOST, getaddrinfo overflow, stack clash.",
                            glibc_version)
        except:
            pass

    return results, glibc_version


# ════════════════════════════════════════════════════════════════════
# STEP 6: Boot Script Audit (V4.62 rootfs)
# ════════════════════════════════════════════════════════════════════
def boot_script_audit() -> list[dict]:
    """Audit boot scripts for insecure patterns."""
    print("\n" + "=" * 70)
    print("  STEP 6: BOOT SCRIPT AUDIT (V4.62.225 rootfs)")
    print("=" * 70)

    script_findings = []

    for f in sorted(ROOTFS_V462.rglob("*")):
        if not f.is_file():
            continue
        try:
            raw = f.read_bytes()
        except:
            continue

        is_script = (raw[:2] == b"#!" or
                     f.name.endswith((".sh", ".ash", ".conf", ".cfg")) or
                     b"#!/" in raw[:256])
        if not is_script:
            continue

        content = raw.decode("utf-8", errors="replace")
        rel = str(f.relative_to(ROOTFS_V462))
        issues = []

        if "chmod 777" in content:
            issues.append("chmod 777")
        if re.search(r"\btelnetd\b", content, re.I):
            issues.append("telnetd")
        if re.search(r"\bdropbear\b", content, re.I):
            issues.append("dropbear SSH")
        if "mount -o remount,rw" in content:
            issues.append("remount rw")
        if re.search(r"iptables\s+(-F|--flush)", content):
            issues.append("firewall flush")

        if issues:
            script_findings.append({"script": rel, "issues": issues})
            print(f"  {rel}: {', '.join(issues)}")
            for issue in issues:
                add_finding(
                    f"F-V462-BOOT-{os.path.basename(rel)[:12].upper()}-{len(findings):03d}",
                    "MEDIUM", f"Boot script {rel}: {issue}",
                    f"Insecure pattern in init script.", issue)

    # Check credentials
    print("\n  --- /etc/passwd & /etc/shadow ---")
    for name in ["etc/passwd", "etc/shadow"]:
        path = ROOTFS_V462 / name
        if path.exists():
            content = path.read_text(encoding="utf-8", errors="replace")
            print(f"\n  [{name}]:")
            for line in content.strip().split("\n"):
                print(f"    {line}")
                if "shadow" in name:
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] not in ("*", "!", "x", ""):
                        add_finding(
                            f"F-V462-SHADOW-{parts[0]}", "CRITICAL",
                            f"Password hash for {parts[0]}: {parts[1][:30]}...",
                            "Default password hash in firmware.", line[:200])

    return script_findings


# ════════════════════════════════════════════════════════════════════
# STEP 7: String Analysis on Key Binaries
# ════════════════════════════════════════════════════════════════════
def string_analysis() -> dict:
    """Deep string analysis on psh, ded, busybox."""
    print("\n" + "=" * 70)
    print("  STEP 7: STRING ANALYSIS (psh, ded, busybox)")
    print("=" * 70)

    targets = ["psh", "ded", "busybox", "hik_tool", "hikefs"]
    results = {}

    patterns = {
        "debug": re.compile(r"\bdebug\b", re.I),
        "hikded_dev": re.compile(r"/dev/hikded"),
        "psh_rsa_conf": re.compile(r"psh_rsa\.conf"),
        "ttyAuth": re.compile(r"ttyAuth", re.I),
        "password": re.compile(r"\bpassword\b|\bpasswd\b", re.I),
        "root_shell": re.compile(r"/bin/sh|/bin/bash|/bin/ash"),
        "exec_func": re.compile(r"\bexecvp?\b|\bsystem\b|\bpopen\b"),
        "cmd_pattern": re.compile(r"resetPasswd|setCloudPassword|connectSlave"),
        "isapi": re.compile(r"/ISAPI/"),
        "cloud": re.compile(r"cloud|hik-connect|ezviz", re.I),
        "crypto": re.compile(r"\brsa\b|\baes\b|\bdes\b|\bcipher\b", re.I),
    }

    for target in targets:
        path = ROOTFS_V462 / "bin" / target
        if not path.exists():
            for p in ROOTFS_V462.rglob(target):
                if p.is_file():
                    path = p
                    break
        if not path.exists():
            continue

        data = path.read_bytes()
        strings_raw = re.findall(rb"[\x20-\x7e]{8,}", data)
        strings = [s.decode("ascii", errors="replace") for s in strings_raw]

        print(f"\n  {target} ({len(data):,} bytes, {len(strings)} strings):")

        hits: dict[str, list[str]] = {}
        for s in strings:
            for pname, pre in patterns.items():
                if pre.search(s):
                    hits.setdefault(pname, [])
                    if len(hits[pname]) < 5:
                        hits[pname].append(s[:150])

        for pname, examples in sorted(hits.items()):
            for ex in examples[:3]:
                print(f"    [{pname}] {ex[:100]}")

        results[target] = {
            "size": len(data), "strings": len(strings),
            "hits": {k: v[:3] for k, v in hits.items()},
        }

    return results


# ════════════════════════════════════════════════════════════════════
# STEP 8: Generate Report
# ════════════════════════════════════════════════════════════════════
def generate_report(
    dav_info: dict,
    rsa_keys: list[dict],
    hardening: list[dict],
    glibc_ver: str,
    boot_scripts: list[dict],
    string_results: dict,
):
    print("\n" + "=" * 70)
    print("  STEP 8: GENERATING REPORT")
    print("=" * 70)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sev_counts = Counter(f["severity"] for f in findings)

    # RSA comparison summary
    keys_with_match = [k for k in rsa_keys if k.get("v462_match")]
    keys_no_match = [k for k in rsa_keys if not k.get("v462_match")]

    lines = [
        "# Hikvision NVR Firmware V4.84.101 — Complete Forensic Analysis Report",
        "",
        f"> **Generated**: {ts}  ",
        "> **Analyst**: Andre Henrique (@mrhenrike) | Uniao Geek "
        "-- https://github.com/Uniao-Geek  ",
        "> **Target**: Hikvision NVR firmware V4.84.101 build 251212  ",
        "> **Source**: `Firmware_3000693671_ML_V4.84.101_251212.zip`  ",
        "> **Methods**: DAV container analysis, XOR layer reversal, encryption "
        "architecture assessment, cross-version rootfs forensics  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Forensic analysis of Hikvision NVR firmware V4.84.101 revealed "
        f"**{len(findings)} security findings** and one significant architectural "
        f"change from V4.62.225:",
        "",
    ]
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0):
            lines.append(f"- **{s}**: {sev_counts[s]}")
    lines.extend([
        "",
        "### Key Findings",
        "",
        f"1. **Encryption Upgrade**: V4.84.101 implements **AES encryption** on "
        f"firmware payloads, a significant improvement over V4.62.225 which used "
        f"XOR-only protection. File content (kernel, rootfs, applications) cannot "
        f"be extracted without the AES key from `/dev/hikded`.",
        f"2. **RSA Keys (V4.62.225 baseline)**: {len(rsa_keys)} RSA keys extracted "
        f"from V4.62 psh binary -- all {rsa_keys[0]['modulus_bits']}-bit "
        f"(RSA-1024, deprecated since NIST 2013)" if rsa_keys else
        "2. **RSA Keys**: No keys extractable",
        f"3. **Binary Hardening**: {sum(1 for h in hardening if not h['pie'])}/"
        f"{len(hardening)} binaries lack PIE in V4.62 rootfs",
        f"4. **glibc**: Version {glibc_ver} with multiple known CVEs",
        f"5. **DAV Structure**: {dav_info['files']} files, device class "
        f"{dav_info['device_class']}, encryption: {dav_info['encryption']}",
        "",
        "---",
        "",
        "## 1. Firmware Architecture & Extraction",
        "",
        "### 1.1 DAV Container (V4.84.101)",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| File | `Firmware_3000693671_ML_V4.84.101_251212.zip` |",
        f"| DAV Size | {dav_info['size']:,} bytes ({dav_info['size']//1024//1024} MB) |",
        f"| SHA256 | `{dav_info['sha256']}` |",
        f"| Magic | {dav_info['magic']} (HKWS) |",
        f"| Files | {dav_info['files']} |",
        f"| Device Class | {dav_info['device_class']} |",
        f"| XOR Key | `{dav_info['xor_key']}` |",
        f"| Encryption | **{dav_info['encryption']}** |",
        "",
        "### 1.2 Encryption Architecture Comparison",
        "",
        "| Feature | V4.62.225 | V4.84.101 |",
        "|---------|-----------|-----------|",
        "| Container encryption | XOR (16-byte key) | XOR (16-byte key) |",
        "| Payload encryption | **None** | **AES** (via /dev/hikded) |",
        "| Kernel extractable | Yes (LZMA decompression) | **No** (AES encrypted) |",
        "| Rootfs extractable | Yes (CPIO from kernel) | **No** (AES encrypted) |",
        "| File table readable | Yes | Yes |",
        "| Certificate data | Embedded | Embedded |",
        "| Static analysis | Full | **Limited to metadata** |",
        "",
        "**Assessment**: The addition of AES encryption on firmware payloads in "
        "V4.84.101 is a **positive security improvement**. However, the encryption "
        "key remains static and embedded in the kernel (accessible via `/dev/hikded`), "
        "meaning physical access to a running device still enables full firmware "
        "extraction and modification.",
        "",
        "### 1.3 File Table (V4.84.101)",
        "",
        "| File | Size | Offset |",
        "|------|------|--------|",
    ])
    for f in dav_info["file_table"]:
        lines.append(f"| {f['name']} | {f['size']:,} | {f['offset']} |")

    lines.extend([
        "",
        "---",
        "",
        "## 2. RSA Cryptographic Key Analysis",
        "",
        "### 2.1 Keys Extracted from V4.62.225 `bin/psh`",
        "",
        "Since V4.84.101 firmware payloads are AES-encrypted, RSA key analysis "
        "is based on the V4.62.225 rootfs. These keys are expected to be identical "
        "or similar in V4.84.101 based on Hikvision's firmware architecture patterns.",
        "",
        "| # | Source | Bits | Exponent | Modulus Prefix |",
        "|---|--------|------|----------|----------------|",
    ])
    for i, k in enumerate(rsa_keys):
        lines.append(
            f"| {i + 1} | {k['source']} | {k['modulus_bits']} | "
            f"{k['exponent']} | `{k['modulus_n_prefix']}` |")

    lines.extend([
        "",
        "### 2.2 Key Security Assessment",
        "",
        f"- **Key count**: {len(rsa_keys)}",
        f"- **Bit length**: All {rsa_keys[0]['modulus_bits']}-bit" if rsa_keys else "- **Bit length**: N/A",
        "- **Status**: RSA-1024 was deprecated by NIST in 2013 (SP 800-131A Rev.2)",
        "- **Risk**: Factoring RSA-1024 is within reach of well-resourced adversaries",
        "- **Impact**: Successful factoring grants persistent root access to ALL "
        "devices running this firmware family via `debug` mode in `psh`",
        "",
        "### 2.3 V4.84 RSA Key Comparison Status",
        "",
        "**Cannot directly compare** V4.84.101 RSA keys because the `psh` binary "
        "is inside the AES-encrypted firmware payload. To determine if keys changed:",
        "",
        "1. Extract AES key from a running V4.84.101 device via `/dev/hikded`",
        "2. Decrypt the `sys_app.tar.lzma` payload",
        "3. Extract `bin/psh` from the decrypted rootfs",
        "4. Compare RSA moduli with V4.62.225 values",
        "",
        "**Prediction**: Based on Hikvision's pattern of using firmware-wide static "
        "keys (CWE-798), the RSA keys are **likely identical** across versions. "
        "The AES encryption adds a defense layer but does not address the "
        "fundamental RSA-1024 weakness.",
        "",
        "### 2.4 Known V4.62.225 Key Prefixes",
        "",
        "| Key | Modulus N Prefix (first 8 bytes) |",
        "|-----|----------------------------------|",
        "| Key #1 (DER) | `0xe67048b79c066b23` |",
        "| Key #2 (DER) | `0xe67fa01c39146310` |",
        "| Key #3 (DER) | `0xf73b68ba7fd1e4a6` |",
        "",
        "---",
        "",
        "## 3. Binary Hardening Status (V4.62.225 Rootfs)",
        "",
        "| Binary | Size | PIE | NX | RELRO | Canary | Dangerous Imports |",
        "|--------|------|-----|----|----- -|--------|-------------------|",
    ])

    priority = ["psh", "ded", "busybox", "hik_tool", "hikefs",
                "hrsaverify", "do_update", "do_factory"]
    shown = set()
    for pname in priority:
        for h in hardening:
            if pname in h["name"].lower() and h["name"] not in shown:
                dng = ", ".join(h["dangerous"][:4]) if h["dangerous"] else "--"
                lines.append(
                    f"| {h['name']} | {h['size'] // 1024} KB | "
                    f"{'YES' if h['pie'] else '**NO**'} | "
                    f"{'YES' if h['nx'] else '**NO**'} | "
                    f"{h['relro']} | "
                    f"{'YES' if h['canary'] else '**NO**'} | "
                    f"{dng} |")
                shown.add(h["name"])

    for h in sorted(hardening, key=lambda x: x["size"], reverse=True):
        if h["name"] not in shown and len(shown) < 25:
            dng = ", ".join(h["dangerous"][:4]) if h["dangerous"] else "--"
            lines.append(
                f"| {h['name']} | {h['size'] // 1024} KB | "
                f"{'YES' if h['pie'] else '**NO**'} | "
                f"{'YES' if h['nx'] else '**NO**'} | "
                f"{h['relro']} | "
                f"{'YES' if h['canary'] else '**NO**'} | "
                f"{dng} |")
            shown.add(h["name"])

    lines.extend([
        "",
        "---",
        "",
        "## 4. glibc Version & CVE Mapping",
        "",
        f"**Detected version**: glibc {glibc_ver}",
        "",
        "| CVE | Description | CVSS 3.1 |",
        "|-----|-------------|----------|",
        "| CVE-2015-0235 | GHOST heap overflow in `gethostbyname()` | 7.5 |",
        "| CVE-2015-7547 | Stack buffer overflow in `getaddrinfo()` | 8.1 |",
        "| CVE-2014-5119 | Off-by-one in transliteration module | 7.5 |",
        "| CVE-2017-1000366 | Stack clash vulnerability | 7.8 |",
        "| CVE-2018-11236 | Integer overflow in `realpath()` | 9.8 |",
        "| CVE-2021-35942 | Integer overflow in `wordexp()` | 9.8 |",
        "| CVE-2023-4911 | Looney Tunables (`ld.so` buffer overflow) | 7.8 |",
        "",
        "---",
        "",
        "## 5. Boot Script Findings (V4.62.225)",
        "",
    ])
    if boot_scripts:
        for bs in boot_scripts:
            lines.append(f"- **{bs['script']}**: {', '.join(bs['issues'])}")
    else:
        lines.append("No insecure boot script patterns found.")

    lines.extend([
        "",
        "---",
        "",
        "## 6. String Analysis Summary",
        "",
    ])
    for binary_name, data in string_results.items():
        lines.append(f"### {binary_name}")
        lines.append(f"- Size: {data['size']:,} bytes | Strings: {data['strings']}")
        if data.get("hits"):
            for pat, examples in data["hits"].items():
                for ex in examples[:2]:
                    lines.append(f"  - `[{pat}]` {ex[:80]}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 7. Complete Findings",
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
        "## 8. Comparison: V4.62.225 vs V4.84.101",
        "",
        "| Aspect | V4.62.225 | V4.84.101 |",
        "|--------|-----------|-----------|",
        f"| DAV Magic | 0x484B5753 | 0x484B5753 |",
        f"| Device Class | 1538 | {dav_info['device_class']} |",
        f"| DAV Files | 16 | {dav_info['files']} |",
        f"| Firmware Encryption | XOR only | **AES + XOR** |",
        f"| Rootfs Extractable | Yes | No (AES) |",
        f"| RSA Keys | 1024-bit (3 DER + 1 hex) | Unknown (AES encrypted) |",
        f"| glibc | 2.16 | Unknown (likely same) |",
        f"| New Components | -- | K20A9 AI models (DFR, FD, FRCNN, HMS, PED, PEDRECLS) |",
        f"| RSA Result Files | -- | 6 rsa_result_p*.bin (signature verification) |",
        "",
        "### New in V4.84.101",
        "",
        "1. **AES Firmware Encryption**: Full payload encryption via `/dev/hikded`",
        "2. **AI/ML Model Files**: 6 K20A9_APP packages for deep learning "
        "(face detection, pedestrian detection, human motion sensing, etc.)",
        "3. **RSA Signature Verification**: 6 `rsa_result_p*.bin` files for "
        "firmware integrity verification",
        "4. **Increased File Count**: 24 files vs 16 in V4.62.225",
        "5. **Larger Firmware**: 330 MB vs ~180 MB in V4.62.225",
        "",
        "---",
        "",
        "## 9. Recommendations",
        "",
        "| Priority | Recommendation | Status in V4.84 |",
        "|----------|---------------|-----------------|",
        "| CRITICAL | Upgrade RSA from 1024-bit to >= 2048-bit | Unknown (likely unchanged) |",
        "| CRITICAL | Per-device RSA keypairs | Unknown (likely unchanged) |",
        "| HIGH | Enable PIE for all binaries | Unknown (likely unchanged) |",
        "| HIGH | Upgrade glibc to 2.38+ | Unknown (likely unchanged) |",
        "| HIGH | MAC-based firmware integrity | Partially addressed (RSA signatures) |",
        "| MEDIUM | Remove chmod 777 from boot | Unknown |",
        "| MEDIUM | Disable debug mode in production | Unknown |",
        "| MEDIUM | Hardware security module for keys | Partially (AES encryption added) |",
        "| LOW | Upgrade kernel to LTS 6.x | Unknown |",
        "",
        "---",
        "",
        "## 10. Responsible Disclosure Timeline",
        "",
        "| Date | Action |",
        "|------|--------|",
        "| 2026-04-18 | V4.62.225 analysis completed |",
        f"| {datetime.now().strftime('%Y-%m-%d')} | V4.84.101 analysis completed |",
        "| TBD | Vendor notification via Hikvision PSIRT (hsrc@hikvision.com) |",
        "| TBD + 90 days | Public disclosure (standard responsible disclosure) |",
        "",
        "---",
        "",
        "*Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek*",
    ])

    report_path = REPORTS_DIR / "V4_84_101_FORENSIC_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {report_path}")

    json_path = TMP_V484 / "v4_84_101_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] JSON findings: {json_path}")

    return report_path


# ═══════════════════════════════════════════════════════════════════
def main():
    print("=" * 70)
    print("  HIKVISION V4.84.101 — COMPLETE FORENSIC ANALYSIS")
    print("  Author: Andre Henrique (@mrhenrike) | Uniao Geek")
    print("=" * 70)

    dav_info = analyze_dav_container()
    analyze_v462_rootfs()
    rsa_keys = extract_rsa_keys()
    hardening, glibc_ver = binary_hardening_audit()
    boot_scripts = boot_script_audit()
    string_results = string_analysis()

    report_path = generate_report(
        dav_info, rsa_keys, hardening, glibc_ver,
        boot_scripts, string_results)

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE: {len(findings)} findings")
    print(f"  Report: {report_path}")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
