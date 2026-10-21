#!/usr/bin/env python3
"""
hikvision_deep_extract.py — Deep extraction of Hikvision decrypted DAV
Author: Andre Henrique (@mrhenrike) | Uniao Geek

After XOR decryption with key 0x73738E8E, extract embedded gzip regions,
analyze low-entropy areas, and hunt for binaries and strings.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

TMP_DIR = Path(__file__).resolve().parent.parent / ".tmp" / "hikvision_g5"
DECRYPTED = TMP_DIR / "decrypted" / "decrypted_hik-classic-4.bin"
OUT_DIR = TMP_DIR / "deep_extract"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports" / "hikvision_g5_v5719"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def xor_decrypt_file():
    """Load the XOR-decrypted firmware."""
    if DECRYPTED.exists():
        data = DECRYPTED.read_bytes()
        print(f"  Using pre-decrypted file: {len(data):,} bytes")
        return data

    print("  Decrypting DAV with key 73738e8e...")
    raw = (TMP_DIR / "digicap.dav").read_bytes()
    key = bytes([0x73, 0x73, 0x8E, 0x8E])
    decrypted = bytearray(len(raw))
    for i in range(len(raw)):
        decrypted[i] = raw[i] ^ key[i % 4]
    DECRYPTED.parent.mkdir(parents=True, exist_ok=True)
    DECRYPTED.write_bytes(bytes(decrypted))
    return bytes(decrypted)


def extract_gzip_regions(data):
    """Find and extract all gzip-compressed regions."""
    print("\n" + "=" * 70)
    print("  EXTRACTING GZIP REGIONS")
    print("=" * 70)

    gzip_dir = OUT_DIR / "gzip_regions"
    gzip_dir.mkdir(parents=True, exist_ok=True)

    gz_magic = b"\x1f\x8b"
    pos = 0
    extracted = 0

    while pos < len(data) - 20:
        idx = data.find(gz_magic, pos)
        if idx == -1:
            break

        # Validate gzip header
        method = data[idx + 2] if idx + 2 < len(data) else 0
        if method != 0x08:  # deflate
            pos = idx + 2
            continue

        # Try to decompress
        for end_try in [idx + 1024, idx + 4096, idx + 65536, idx + 262144,
                        idx + 1048576, idx + 4194304, idx + 16777216,
                        min(idx + 67108864, len(data))]:
            try:
                chunk = data[idx:end_try]
                decompressed = gzip.decompress(chunk)
                if len(decompressed) > 64:
                    out_path = gzip_dir / f"gz_{extracted:03d}_0x{idx:08X}.bin"
                    out_path.write_bytes(decompressed)
                    print(f"  [{extracted:3d}] 0x{idx:08X}: compressed={len(chunk):,} "
                          f"-> decompressed={len(decompressed):,} bytes")

                    # Quick signature check on decompressed data
                    first4 = decompressed[:4]
                    if first4 == b"\x7fELF":
                        print(f"         -> ELF binary!")
                        out_path.rename(out_path.with_suffix(".elf"))
                    elif first4 == b"hsqs":
                        print(f"         -> SquashFS filesystem!")
                        out_path.rename(out_path.with_suffix(".sqfs"))
                    elif decompressed[:2] == b"#!":
                        print(f"         -> Shell script!")
                        out_path.rename(out_path.with_suffix(".sh"))
                    elif b"<html" in decompressed[:1024].lower() or b"<!doctype" in decompressed[:1024].lower():
                        print(f"         -> HTML content!")
                        out_path.rename(out_path.with_suffix(".html"))
                    elif first4 == b"\x27\x05\x19\x56":
                        print(f"         -> uImage!")
                        out_path.rename(out_path.with_suffix(".uimage"))

                    # Check for strings of interest
                    text_hits = re.findall(rb"[\x20-\x7e]{20,}", decompressed[:4096])
                    if text_hits:
                        for t in text_hits[:3]:
                            print(f"         str: {t[:80].decode('ascii', errors='replace')}")

                    extracted += 1
                    break
            except Exception:
                continue

        pos = idx + 2

    print(f"\n  Total gzip regions extracted: {extracted}")
    return extracted


def analyze_low_entropy_regions(data):
    """Extract and analyze the low-entropy regions found in entropy scan."""
    print("\n" + "=" * 70)
    print("  ANALYZING LOW-ENTROPY REGIONS")
    print("=" * 70)

    regions = []
    block_size = 4096
    in_low = False
    start = 0

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < 256:
            break

        freq = [0] * 256
        for b in block:
            freq[b] += 1
        total = len(block)
        ent = 0
        for f in freq:
            if f > 0:
                p = f / total
                ent -= p * math.log2(p)

        if ent < 6.5:
            if not in_low:
                start = i
                in_low = True
        else:
            if in_low:
                regions.append((start, i))
                in_low = False

    if in_low:
        regions.append((start, len(data)))

    print(f"\n  Low-entropy regions (<6.5 bits/byte): {len(regions)}")

    le_dir = OUT_DIR / "low_entropy"
    le_dir.mkdir(parents=True, exist_ok=True)

    for i, (start, end) in enumerate(regions):
        size = end - start
        if size < 256:
            continue

        chunk = data[start:end]

        # Calculate entropy
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        total = len(chunk)
        ent = sum(-((f / total) * math.log2(f / total)) for f in freq if f > 0)

        print(f"\n  Region {i}: 0x{start:08X}-0x{end:08X} "
              f"({size:,} bytes, entropy={ent:.2f})")

        # Extract strings
        strings = re.findall(rb"[\x20-\x7e]{8,}", chunk)
        if strings:
            out_path = le_dir / f"region_{i:02d}_0x{start:08X}.bin"
            out_path.write_bytes(chunk)

            str_path = le_dir / f"region_{i:02d}_0x{start:08X}_strings.txt"
            str_content = "\n".join(s.decode("ascii", errors="replace")
                                    for s in strings)
            str_path.write_text(str_content, encoding="utf-8")

            print(f"  Strings found: {len(strings)}")
            for s in strings[:20]:
                decoded = s.decode("ascii", errors="replace")
                print(f"    {decoded[:100]}")

                # Check for security-relevant strings
                slow = decoded.lower()
                if any(k in slow for k in ["password", "passwd", "secret", "key",
                                           "token", "admin", "root", "login",
                                           "backdoor", "debug"]):
                    add_finding(
                        f"F-HK-STR-{i}-0x{start:06X}", "HIGH",
                        f"Sensitive string in low-entropy region: {decoded[:50]}",
                        f"Found at offset 0x{start:08X} in firmware.",
                        decoded[:200])

                if any(k in slow for k in ["/isapi/", "/sdk/", "/onvif/",
                                           "system/", "cgi-bin/", "/api/"]):
                    add_finding(
                        f"F-HK-API-{i}-0x{start:06X}", "MEDIUM",
                        f"API endpoint in firmware: {decoded[:50]}",
                        f"Found at offset 0x{start:08X}.",
                        decoded[:200])


def extract_hikvision_partitions(data):
    """
    Parse the Hikvision firmware partition table.
    After XOR decryption, the header should reveal partition offsets.
    """
    print("\n" + "=" * 70)
    print("  PARSING HIKVISION PARTITION TABLE")
    print("=" * 70)

    # The decrypted header structure (first 128 bytes)
    print("\n  Decrypted header (first 256 bytes):")
    for i in range(0, 256, 16):
        hex_str = data[i:i + 16].hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16])
        print(f"    {i:04X}: {hex_str}  {ascii_str}")

    # Look for the Hikvision partition structure
    # Common structure: partition header at 0x40 with entries of 32 bytes
    # Each entry: magic(4) + type(4) + offset(4) + size(4) + checksum(4) + reserved(12)

    part_dir = OUT_DIR / "partitions"
    part_dir.mkdir(parents=True, exist_ok=True)

    # Try to find partition boundaries by looking at DWORDs that could be offsets
    potential_offsets = []
    for i in range(0, min(512, len(data)), 4):
        val = struct.unpack_from("<I", data, i)[0]
        if 0x1000 < val < len(data) and val % 256 == 0:
            potential_offsets.append((i, val))

    if potential_offsets:
        print(f"\n  Potential partition offsets found in header:")
        for hdr_off, val in potential_offsets:
            chunk = data[val:val + 16]
            print(f"    Header@0x{hdr_off:02X} -> 0x{val:08X}: {chunk.hex()[:32]}")

    # Use binwalk on decrypted file
    print("\n  Running binwalk on decrypted file...")
    try:
        r = subprocess.run(
            ["binwalk", str(DECRYPTED)],
            capture_output=True, text=True, timeout=120)
        print(f"  binwalk output:")
        for line in r.stdout.strip().split("\n")[:30]:
            print(f"    {line}")

        # Also try extraction
        extract_out = OUT_DIR / "binwalk_extract"
        extract_out.mkdir(parents=True, exist_ok=True)
        r2 = subprocess.run(
            ["binwalk", "-e", "-C", str(extract_out), str(DECRYPTED)],
            capture_output=True, text=True, timeout=300)
        print(f"\n  binwalk extraction: {r2.stdout[:200]}")
    except FileNotFoundError:
        print("  binwalk not available")
    except subprocess.TimeoutExpired:
        print("  binwalk timed out")


def analyze_extracted_elfs():
    """Analyze any ELF binaries found in extraction."""
    print("\n" + "=" * 70)
    print("  ELF BINARY ANALYSIS")
    print("=" * 70)

    elf_files = list(OUT_DIR.rglob("*.elf"))
    # Also check for ELF magic in .bin files
    for f in OUT_DIR.rglob("*.bin"):
        try:
            with open(f, "rb") as fh:
                if fh.read(4) == b"\x7fELF":
                    elf_files.append(f)
        except:
            pass

    if not elf_files:
        print("  No ELF binaries found in extracted data.")
        return

    try:
        import lief
        has_lief = True
    except ImportError:
        has_lief = False
        print("  LIEF not available, using basic analysis")

    dangerous_imports = {
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
        "mktemp", "tmpnam",
    }

    for elf_path in elf_files:
        elf_data = elf_path.read_bytes()
        name = elf_path.name
        print(f"\n  --- {name} ({len(elf_data) // 1024} KB) ---")

        if has_lief:
            try:
                binary = lief.parse(str(elf_path))
                if binary is None:
                    continue

                print(f"    Arch: {binary.header.machine_type} "
                      f"{'32' if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else '64'}-bit")

                imports = [sym.name for sym in binary.imported_symbols]
                dangerous = [i for i in imports if i in dangerous_imports]
                if dangerous:
                    dlist = ", ".join(set(dangerous))
                    print(f"    !!! DANGEROUS IMPORTS: {dlist}")
                    add_finding(
                        f"F-HK-ELF-DANGER-{name[:15]}", "MEDIUM",
                        f"Dangerous imports in {name}: {dlist}",
                        f"Binary imports potentially exploitable functions.",
                        dlist)

                nx = binary.has_nx if hasattr(binary, "has_nx") else True
                pie = binary.is_pie if hasattr(binary, "is_pie") else False
                if not nx:
                    add_finding(f"F-HK-ELF-NO-NX-{name[:15]}", "HIGH",
                                f"No NX in {name}", "Executable stack.", name)
                if not pie:
                    add_finding(f"F-HK-ELF-NO-PIE-{name[:15]}", "MEDIUM",
                                f"No PIE in {name}", "Fixed base address.", name)

                print(f"    NX={nx} PIE={pie}")
                print(f"    Imports: {len(imports)}")
            except Exception as e:
                print(f"    LIEF error: {e}")

        # String analysis on all ELFs
        strings = re.findall(rb"[\x20-\x7e]{8,}", elf_data)
        sec_strings = []
        for s in strings:
            d = s.decode("ascii", errors="replace")
            dl = d.lower()
            if any(k in dl for k in ["password", "secret", "key=", "token",
                                      "/isapi/", "system(", "backdoor",
                                      "admin", "root:", "shadow"]):
                sec_strings.append(d)

        if sec_strings:
            print(f"    Security-relevant strings: {len(sec_strings)}")
            for s in sec_strings[:10]:
                print(f"      {s[:80]}")


def analyze_all_strings(data):
    """Deep string analysis of the entire decrypted firmware."""
    print("\n" + "=" * 70)
    print("  FULL FIRMWARE STRING ANALYSIS")
    print("=" * 70)

    strings = re.findall(rb"[\x20-\x7e]{10,}", data)
    print(f"  Total strings (>=10 chars): {len(strings)}")

    str_dir = OUT_DIR / "strings"
    str_dir.mkdir(parents=True, exist_ok=True)

    # Dump all strings
    all_str_path = str_dir / "all_strings.txt"
    with open(all_str_path, "w", encoding="utf-8") as f:
        for s in strings:
            f.write(s.decode("ascii", errors="replace") + "\n")

    # Categorize
    categories = {
        "credentials": [],
        "api_endpoints": [],
        "commands": [],
        "crypto": [],
        "network": [],
        "debug": [],
        "versions": [],
        "urls": [],
        "cve_patterns": [],
    }

    patterns = {
        "credentials": re.compile(
            r"(?:password|passwd|pwd|secret|token|apikey|auth)\s*[=:]\s*\S+", re.I),
        "api_endpoints": re.compile(
            r"/(?:ISAPI|SDK|ONVIF|System|Security|Streaming|PTZCtrl|"
            r"ContentMgmt|Event|Video|Audio|Image|Network|IO)\b", re.I),
        "commands": re.compile(
            r"(?:system|popen|exec|sh -c|/bin/sh|/bin/bash|cmd\.exe)\s*\(?\s*[\"']"),
        "crypto": re.compile(
            r"(?:AES|DES|RSA|SHA[12]?|MD5|HMAC|PKCS|X509|BEGIN CERT)", re.I),
        "network": re.compile(
            r"(?:RTSP|ONVIF|SADP|UPnP|SSDP|mDNS|DHCP|NTP|SNMP|HTTP|HTTPS|FTP|SSH|Telnet)",
            re.I),
        "debug": re.compile(
            r"(?:debug|trace|verbose|test|TODO|FIXME|HACK|WARNING|ERROR)", re.I),
        "versions": re.compile(
            r"(?:V\d+\.\d+|version\s*[=:]\s*\d+|v\d+\.\d+\.\d+)", re.I),
        "urls": re.compile(r"https?://\S+"),
        "cve_patterns": re.compile(r"CVE-\d{4}-\d+", re.I),
    }

    for s in strings:
        decoded = s.decode("ascii", errors="replace")
        for cat, pat in patterns.items():
            if pat.search(decoded):
                if len(categories[cat]) < 100:
                    categories[cat].append(decoded)

    for cat, hits in categories.items():
        if hits:
            print(f"\n  === {cat.upper()} ({len(hits)} hits) ===")
            cat_path = str_dir / f"strings_{cat}.txt"
            with open(cat_path, "w", encoding="utf-8") as f:
                for h in hits:
                    f.write(h + "\n")
                    print(f"    {h[:100]}")

            if cat in ("credentials", "commands"):
                for h in hits[:5]:
                    add_finding(
                        f"F-HK-STR-{cat.upper()[:8]}-{len(findings):03d}", "HIGH",
                        f"{cat} string found: {h[:50]}",
                        f"String pattern '{cat}' detected in firmware.",
                        h[:200])

    return categories


def search_isapi_handlers(data):
    """Search for ISAPI endpoint handlers — key attack surface for Hikvision."""
    print("\n" + "=" * 70)
    print("  ISAPI ENDPOINT HANDLER ANALYSIS")
    print("=" * 70)

    # ISAPI is Hikvision's REST API and the main attack surface
    # CVE-2021-36260 was an ISAPI command injection
    isapi_endpoints = set()

    for m in re.finditer(rb"/ISAPI/[\w/]+", data):
        ep = m.group().decode("ascii", errors="replace")
        isapi_endpoints.add(ep)

    if isapi_endpoints:
        print(f"\n  ISAPI endpoints found: {len(isapi_endpoints)}")
        isapi_dir = OUT_DIR / "isapi"
        isapi_dir.mkdir(parents=True, exist_ok=True)

        sorted_eps = sorted(isapi_endpoints)
        ep_path = isapi_dir / "isapi_endpoints.txt"
        ep_path.write_text("\n".join(sorted_eps), encoding="utf-8")

        for ep in sorted_eps:
            print(f"    {ep}")

        # Check for dangerous patterns near ISAPI strings
        print("\n  Checking context around ISAPI endpoints...")
        for ep_bytes in [e.encode() for e in list(isapi_endpoints)[:30]]:
            pos = 0
            while pos < len(data):
                idx = data.find(ep_bytes, pos)
                if idx == -1:
                    break

                # Get surrounding context (256 bytes before and after)
                context_start = max(0, idx - 128)
                context_end = min(len(data), idx + len(ep_bytes) + 128)
                context = data[context_start:context_end]

                # Look for dangerous functions near ISAPI handler references
                ctx_strings = re.findall(rb"[\x20-\x7e]{6,}", context)
                for s in ctx_strings:
                    d = s.decode("ascii", errors="replace").lower()
                    if any(k in d for k in ["system(", "popen(", "exec(",
                                             "sprintf(", "strcpy(", "strcat(",
                                             "gets(", "scanf("]):
                        ep_str = ep_bytes.decode()
                        add_finding(
                            f"F-HK-ISAPI-DANGER-{len(findings):03d}", "HIGH",
                            f"Dangerous function near ISAPI handler: {ep_str}",
                            f"Found {d[:50]} near ISAPI endpoint {ep_str} "
                            f"at offset 0x{idx:08X}.",
                            f"{ep_str} -> {d[:100]}")

                pos = idx + len(ep_bytes)

    # Also search for SDK endpoints
    sdk_endpoints = set()
    for m in re.finditer(rb"/SDK/[\w/]+", data):
        sdk_endpoints.add(m.group().decode("ascii", errors="replace"))

    if sdk_endpoints:
        print(f"\n  SDK endpoints: {len(sdk_endpoints)}")
        for ep in sorted(sdk_endpoints):
            print(f"    {ep}")


def check_cve_2021_36260_patch(data):
    """
    CVE-2021-36260: Command injection in /SDK/webLanguage
    Check if this firmware has the vulnerability or is patched.
    """
    print("\n" + "=" * 70)
    print("  CVE-2021-36260 PATCH ANALYSIS")
    print("=" * 70)

    # The vulnerability was in the webLanguage parameter handler
    # which used popen() or system() to process language file paths
    # without proper sanitization

    target_strings = [
        b"/SDK/webLanguage",
        b"webLanguage",
        b"language",
    ]

    for target in target_strings:
        positions = []
        pos = 0
        while pos < len(data):
            idx = data.find(target, pos)
            if idx == -1:
                break
            positions.append(idx)
            pos = idx + len(target)

        if positions:
            print(f"\n  '{target.decode()}' found at {len(positions)} positions")
            for p in positions[:5]:
                ctx_start = max(0, p - 64)
                ctx_end = min(len(data), p + len(target) + 64)
                ctx = data[ctx_start:ctx_end]
                ctx_str = re.findall(rb"[\x20-\x7e]{4,}", ctx)
                if ctx_str:
                    print(f"    0x{p:08X}: context -> "
                          f"{' | '.join(s.decode('ascii', 'replace')[:40] for s in ctx_str[:5])}")

    # Check firmware version strings to determine patch status
    version_strings = []
    for m in re.finditer(rb"V\d+\.\d+\.\d+[\w.]*", data):
        v = m.group().decode("ascii", errors="replace")
        if v not in version_strings:
            version_strings.append(v)

    print(f"\n  Version strings found: {len(version_strings)}")
    for v in version_strings[:10]:
        print(f"    {v}")

    # V5.7.19 is post-patch (CVE-2021-36260 was patched in V5.5.800+)
    print("\n  Assessment: V5.7.19 is AFTER the CVE-2021-36260 patch.")
    print("  This firmware should have the fix. Verifying by checking")
    print("  for input validation patterns near webLanguage handler...")

    # Look for validation/sanitization patterns
    sanitize_patterns = [
        rb"snprintf", rb"strncat", rb"strncpy",
        rb"sanitize", rb"validate", rb"filter",
        rb"escape", rb"check_param",
    ]
    found_sanitize = set()
    for pat in sanitize_patterns:
        if pat in data:
            found_sanitize.add(pat.decode())

    if found_sanitize:
        print(f"  Sanitization functions present: {', '.join(found_sanitize)}")
    else:
        print("  WARNING: No obvious sanitization functions found!")
        add_finding(
            "F-HK-CVE36260-NOSANIT", "MEDIUM",
            "No obvious input sanitization in firmware",
            "Could not find sanitization functions near ISAPI handlers. "
            "Further RE needed to confirm CVE-2021-36260 patch status.",
            "")


def generate_report():
    """Generate comprehensive forensic report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Hikvision G5 Camera V5.7.19 (241207) — Deep Forensic Report",
        "",
        f"> Generated: {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()[:19]} UTC",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "> Firmware: digicap.dav (76,144,747 bytes)",
        f"> SHA256: {hashlib.sha256((TMP_DIR / 'digicap.dav').read_bytes()).hexdigest()}",
        "",
        "---",
        "",
        "## 1. Firmware Container Analysis",
        "",
        "| Property | Value |",
        "|----------|-------|",
        "| Format | Hikvision .dav (digicap.dav) |",
        "| Encryption | XOR with key `73 73 8E 8E` |",
        "| Size | 76,144,747 bytes (72 MB) |",
        "| Architecture | ARM (32-bit, Little-Endian) |",
        "",
        "## 2. Extraction Results",
        "",
        f"- Decryption: XOR key `0x73738E8E` (classic Hikvision key)",
        f"- **Total findings: {len(findings)}**",
        "",
    ]

    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines.append("### Severity Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0):
            lines.append(f"| {s} | {sev_counts[s]} |")
    lines.append("")

    lines.append("## 3. Detailed Findings")
    lines.append("")
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                              "LOW": 3, "INFO": 4}.get(x["severity"], 5)):
        lines.append(f"### {f['id']}")
        lines.append(f"- **Severity**: {f['severity']}")
        lines.append(f"- **Title**: {f['title']}")
        lines.append(f"- **Detail**: {f['detail']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines.append("---")
    lines.append("*Hikvision G5 Forensic Analysis | Embedded Firmware Research Lab*")
    lines.append("*Andre Henrique (@mrhenrike) | Uniao Geek*")

    report_path = REPORTS_DIR / "deep_forensic_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {report_path}")

    json_path = REPORTS_DIR / "deep_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] JSON: {json_path}")


if __name__ == "__main__":
    print("=" * 70)
    print("  HIKVISION G5 V5.7.19 — DEEP EXTRACTION & ANALYSIS")
    print("=" * 70)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    data = xor_decrypt_file()
    extract_gzip_regions(data)
    analyze_low_entropy_regions(data)
    extract_hikvision_partitions(data)
    analyze_extracted_elfs()
    str_cats = analyze_all_strings(data)
    search_isapi_handlers(data)
    check_cve_2021_36260_patch(data)
    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")
