#!/usr/bin/env python3
"""
hikvision_v4_extract.py — Extract and analyze Hikvision V4.x firmware
Author: Andre Henrique (@mrhenrike) | Uniao Geek

V4.x firmware uses the multi-file DAV container that hiktools can parse.
This script extracts all embedded files and performs deep binary analysis.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import lzma
import os
import re
import struct
import subprocess
import sys
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings: list[dict[str, Any]] = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def extract_firmware(dav_path: str, out_dir: Path) -> list[dict]:
    """Extract all files from a Hikvision DAV container."""
    from hiktools import fmod

    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = []

    with fmod.DigiCap(dav_path) as dcap:
        h = dcap.head
        print(f"  Magic: 0x{h.magic:08X}, Files: {h.files}, "
              f"Device class: {h.device_class}")

        key = dcap.KEY_XOR
        raw_f = open(dav_path, "rb")
        raw_data = raw_f.read()
        raw_f.close()

        # XOR decrypt the entire file using hiktools algorithm
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

            # Read the file data from the decrypted stream
            if fpos + flen <= len(dec_data):
                file_data = dec_data[fpos:fpos + flen]
            else:
                print(f"  SKIP {fname}: offset 0x{fpos:X} + size {flen:,} exceeds file")
                continue

            out_path = out_dir / fname
            out_path.write_bytes(file_data)
            sz_kb = len(file_data) // 1024
            print(f"  Extracted: {fname} ({sz_kb:,} KB)")
            extracted.append({"name": fname, "size": len(file_data),
                              "path": str(out_path)})

    return extracted


def decompress_archives(out_dir: Path) -> list[Path]:
    """Decompress .tar.lzma, .tar.gz files."""
    roots = []
    for f in out_dir.iterdir():
        if not f.is_file():
            continue

        extract_to = None
        if f.name.endswith(".tar.lzma") or f.name.endswith(".tar.gz") or \
           f.name.endswith(".tar.gz_dav5") or f.name.endswith(".tar.gz_dav4"):
            extract_to = out_dir / f.stem.replace(".tar", "").replace(".gz_dav5", "").replace(".gz_dav4", "").replace(".gz", "").replace(".lzma", "")

        if extract_to:
            extract_to.mkdir(parents=True, exist_ok=True)
            print(f"\n  Decompressing: {f.name} -> {extract_to.name}/")
            try:
                # Try tarfile with appropriate mode
                if ".lzma" in f.name:
                    mode = "r:xz"
                    try:
                        with tarfile.open(str(f), mode) as tf:
                            tf.extractall(str(extract_to), filter="data")
                    except Exception:
                        # Try raw lzma + tar
                        try:
                            raw = f.read_bytes()
                            decompressed = lzma.decompress(raw)
                            tar_path = extract_to / "content.tar"
                            tar_path.write_bytes(decompressed)
                            with tarfile.open(str(tar_path)) as tf:
                                tf.extractall(str(extract_to), filter="data")
                            tar_path.unlink()
                        except Exception as e2:
                            print(f"    LZMA decompress failed: {e2}")
                            continue
                elif ".gz" in f.name:
                    try:
                        with tarfile.open(str(f), "r:gz") as tf:
                            tf.extractall(str(extract_to), filter="data")
                    except Exception:
                        # Maybe not gzip-compressed tar
                        try:
                            raw = f.read_bytes()
                            decompressed = gzip.decompress(raw)
                            tar_path = extract_to / "content.tar"
                            tar_path.write_bytes(decompressed)
                            with tarfile.open(str(tar_path)) as tf:
                                tf.extractall(str(extract_to), filter="data")
                            tar_path.unlink()
                        except Exception as e2:
                            print(f"    GZ decompress failed: {e2}")
                            continue

                count = sum(1 for _ in extract_to.rglob("*") if _.is_file())
                print(f"    Extracted {count} files")
                roots.append(extract_to)
            except Exception as e:
                print(f"    Extract error: {e}")

    return roots


def inventory_extracted(out_dir: Path) -> tuple[list[dict], dict]:
    """Inventory all extracted files."""
    print("\n" + "=" * 70)
    print("  FILE INVENTORY")
    print("=" * 70)

    all_files = []
    for f in out_dir.rglob("*"):
        if f.is_file():
            try:
                sz = f.stat().st_size
            except OSError:
                sz = 0
            rel = str(f.relative_to(out_dir))
            all_files.append({"path": rel, "size": sz, "abs": str(f)})

    print(f"\n  Total files: {len(all_files)}")

    categories = {
        "ELF binaries": [],
        "Shell scripts": [],
        "Config files": [],
        "Libraries (.so)": [],
        "Web files": [],
        "Certificates/Keys": [],
        "Other": [],
    }

    for f in all_files:
        p = f["path"].lower()
        if p.endswith(".so") or ".so." in p:
            categories["Libraries (.so)"].append(f)
        elif p.endswith((".sh", ".ash")):
            categories["Shell scripts"].append(f)
        elif p.endswith((".conf", ".cfg", ".ini", ".xml", ".json")):
            categories["Config files"].append(f)
        elif p.endswith((".html", ".htm", ".js", ".css", ".cgi", ".php")):
            categories["Web files"].append(f)
        elif p.endswith((".pem", ".crt", ".key", ".cert", ".der")):
            categories["Certificates/Keys"].append(f)
        elif f["size"] > 500:
            try:
                with open(f["abs"], "rb") as fh:
                    magic = fh.read(4)
                if magic == b"\x7fELF":
                    categories["ELF binaries"].append(f)
                    continue
                elif magic[:2] == b"#!":
                    categories["Shell scripts"].append(f)
                    continue
            except:
                pass
            categories["Other"].append(f)
        else:
            categories["Other"].append(f)

    for cat, files in categories.items():
        if files:
            print(f"\n  {cat}: {len(files)}")
            sorted_f = sorted(files, key=lambda x: x["size"], reverse=True)
            for f in sorted_f[:20]:
                print(f"    {f['size'] // 1024:6d} KB  {f['path']}")
            if len(files) > 20:
                print(f"    ... and {len(files) - 20} more")

    # Security-relevant files
    print("\n  --- SECURITY-RELEVANT FILES ---")
    sec_patterns = [
        "passwd", "shadow", "sudoers", "ssh", "ssl", "cert",
        "key", "token", "secret", "cred", "auth", "login",
        "webcore", "hicore", "ipc_web", "davinci", "hik",
        "sadp", "onvif", "rtsp", "isapi", "httpd", "cgi",
    ]
    for f in all_files:
        name = os.path.basename(f["path"]).lower()
        for pat in sec_patterns:
            if pat in name:
                print(f"    [{pat:10s}] {f['size'] // 1024:6d} KB  {f['path']}")
                break

    return all_files, categories


def analyze_binaries(categories: dict):
    """Deep analysis of ELF binaries using LIEF and Capstone."""
    print("\n" + "=" * 70)
    print("  BINARY SECURITY ANALYSIS")
    print("=" * 70)

    try:
        import lief
        has_lief = True
    except ImportError:
        has_lief = False
        print("  LIEF not available")
        return

    dangerous_imports = {
        "system", "popen", "execve", "execvp", "execl", "execlp",
        "sprintf", "strcpy", "strcat", "gets", "scanf", "vsprintf",
        "mktemp", "tmpnam", "realpath",
    }

    elfs = categories.get("ELF binaries", [])
    libs = categories.get("Libraries (.so)", [])
    targets = sorted(elfs + libs, key=lambda x: x["size"], reverse=True)

    print(f"\n  Analyzing {len(targets)} binaries...")

    for f in targets[:50]:
        name = os.path.basename(f["path"])
        try:
            binary = lief.parse(f["abs"])
            if binary is None:
                continue

            imports = [sym.name for sym in binary.imported_symbols if sym.name]
            dangerous = [i for i in imports if i in dangerous_imports]

            nx = binary.has_nx if hasattr(binary, "has_nx") else True
            pie = binary.is_pie if hasattr(binary, "is_pie") else False

            has_relro = False
            for seg in binary.segments:
                if seg.type == lief.ELF.Segment.TYPE.GNU_RELRO:
                    has_relro = True

            issues = []
            if dangerous:
                issues.append(f"DANGER:{','.join(set(dangerous))}")
            if not nx:
                issues.append("NO-NX")
            if not pie:
                issues.append("NO-PIE")
            if not has_relro:
                issues.append("NO-RELRO")

            if issues:
                arch = str(binary.header.machine_type).split(".")[-1]
                bits = 32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else 64
                print(f"\n  {name} ({f['size'] // 1024} KB, {arch}/{bits}bit):")
                print(f"    Issues: {' | '.join(issues)}")
                print(f"    Imports: {len(imports)}")

                if dangerous:
                    dlist = ", ".join(set(dangerous))
                    add_finding(
                        f"F-HK4-DANGER-{name[:15].upper()}", "MEDIUM",
                        f"Dangerous imports in {name}: {dlist}",
                        f"Binary imports {len(dangerous)} dangerous functions.",
                        dlist)

                if not nx:
                    add_finding(
                        f"F-HK4-NO-NX-{name[:15].upper()}", "HIGH",
                        f"No NX (executable stack) in {name}",
                        "Allows direct shellcode execution on stack.", name)

        except Exception as e:
            pass


def hunt_credentials_and_secrets(all_files: list):
    """Deep string analysis for credentials, backdoors, and secrets."""
    print("\n" + "=" * 70)
    print("  CREDENTIAL & SECRET HUNTING")
    print("=" * 70)

    patterns = {
        "HARDCODED_PASS": re.compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[\w!@#$%^&*]{3,}", re.I),
        "HARDCODED_KEY": re.compile(
            r"(?:api.?key|secret.?key|private.?key|access.?key)\s*[=:]\s*['\"]?\w{8,}", re.I),
        "PRIVATE_KEY_PEM": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "BACKDOOR_USER": re.compile(
            r"(?:backdoor|debug|test|admin|root|supervisor|manufacturer):\$[156]\$", re.I),
        "SHADOW_HASH": re.compile(r"^\w+:\$[156]\$[^\s:]+:", re.MULTILINE),
        "CMD_INJECTION": re.compile(
            r'(?:system|popen|exec[lv]?p?)\s*\(\s*["\'][^"\']*(?:\$|%s|sprintf)'),
        "ISAPI_HANDLER": re.compile(r"/ISAPI/\w+"),
        "SDK_ENDPOINT": re.compile(r"/SDK/\w+"),
        "TELNET_ENABLE": re.compile(r"telnet.*enable|dropbear|sshd", re.I),
        "HARDCODED_IP": re.compile(
            r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
        "CRYPTO_KEY_MATERIAL": re.compile(r"[A-Fa-f0-9]{32,}"),
        "HTTP_AUTH": re.compile(r"(?:Basic|Bearer|Digest)\s+[A-Za-z0-9+/=]{10,}", re.I),
    }

    for f in all_files:
        if f["size"] < 100 or f["size"] > 100_000_000:
            continue

        try:
            raw = Path(f["abs"]).read_bytes()
        except:
            continue

        strings = re.findall(rb"[\x20-\x7e]{8,}", raw)
        if not strings:
            continue

        name = os.path.basename(f["path"])
        file_hits = {}

        for s in strings:
            try:
                text = s.decode("ascii", errors="replace")
            except:
                continue

            for pat_name, pat_re in patterns.items():
                if pat_re.search(text):
                    if pat_name not in file_hits:
                        file_hits[pat_name] = []
                    if len(file_hits[pat_name]) < 5:
                        file_hits[pat_name].append(text[:150])

        if file_hits:
            important = any(k in file_hits for k in
                           ["HARDCODED_PASS", "PRIVATE_KEY_PEM", "BACKDOOR_USER",
                            "SHADOW_HASH", "CMD_INJECTION"])
            if important or len(file_hits) > 2:
                print(f"\n  {f['path']}:")
                for pat_name, hits in file_hits.items():
                    for h in hits[:3]:
                        print(f"    [{pat_name}] {h[:100]}")
                        sev = "HIGH"
                        if pat_name in ("ISAPI_HANDLER", "SDK_ENDPOINT",
                                       "HARDCODED_IP", "HTTP_AUTH"):
                            sev = "MEDIUM"
                        if pat_name == "CRYPTO_KEY_MATERIAL":
                            sev = "INFO"
                        add_finding(
                            f"F-HK4-{pat_name[:10]}-{name[:10].upper()}-{len(findings):03d}",
                            sev, f"{pat_name} in {name}: {h[:50]}",
                            f"Pattern found in {f['path']}.", h[:200])


def analyze_shell_scripts(categories: dict):
    """Analyze shell scripts for security issues."""
    print("\n" + "=" * 70)
    print("  SHELL SCRIPT ANALYSIS")
    print("=" * 70)

    scripts = categories.get("Shell scripts", [])
    print(f"\n  Scripts to analyze: {len(scripts)}")

    for f in scripts:
        try:
            content = Path(f["abs"]).read_text(encoding="utf-8", errors="replace")
        except:
            continue

        name = os.path.basename(f["path"])
        issues = []

        # Check for insecure patterns
        if "chmod 777" in content:
            issues.append("chmod 777 (world writable)")
        if "telnetd" in content.lower():
            issues.append("telnetd enabled")
        if re.search(r"echo\s+.*password", content, re.I):
            issues.append("password in echo")
        if re.search(r"curl\s+.*-k", content):
            issues.append("curl -k (insecure)")
        if re.search(r"wget\s+.*--no-check", content):
            issues.append("wget --no-check-certificate")
        if "mount -o remount,rw" in content:
            issues.append("remount rw")
        if "iptables -F" in content or "iptables --flush" in content:
            issues.append("firewall flush")

        if issues:
            print(f"\n  {f['path']}:")
            for issue in issues:
                print(f"    !!! {issue}")
                add_finding(
                    f"F-HK4-SCRIPT-{name[:12].upper()}-{len(findings):03d}",
                    "MEDIUM",
                    f"Insecure pattern in {name}: {issue}",
                    f"Shell script {f['path']} contains: {issue}",
                    issue)


def check_web_security(categories: dict):
    """Analyze web interface for vulnerabilities."""
    print("\n" + "=" * 70)
    print("  WEB INTERFACE SECURITY")
    print("=" * 70)

    web_files = categories.get("Web files", [])
    print(f"\n  Web files: {len(web_files)}")

    for f in web_files:
        if f["size"] < 50 or f["size"] > 10_000_000:
            continue

        try:
            content = Path(f["abs"]).read_bytes()
            text = content.decode("utf-8", errors="replace")
        except:
            continue

        name = os.path.basename(f["path"])
        issues = []

        # XSS patterns
        if re.search(r"innerHTML\s*=", text):
            issues.append("innerHTML assignment (potential XSS)")
        if re.search(r"document\.write\(", text):
            issues.append("document.write (potential XSS)")
        if re.search(r"eval\(", text):
            issues.append("eval() usage")

        # Hardcoded credentials in web files
        if re.search(r"password.*['\"][a-zA-Z0-9]+['\"]", text, re.I):
            issues.append("hardcoded password in web file")

        # Debug/test endpoints
        if re.search(r"/debug|/test|/admin|/backdoor", text, re.I):
            issues.append("debug/test endpoint reference")

        if issues:
            print(f"\n  {f['path']}:")
            for issue in issues:
                print(f"    {issue}")


def generate_report():
    """Generate comprehensive report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    sev_counts = Counter(f["severity"] for f in findings)

    lines = [
        "# Hikvision V4.x NVR/DVR Firmware — Deep Forensic Analysis",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
        "---",
        "",
        f"## Summary: {len(findings)} findings",
        "",
    ]

    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0) > 0:
            lines.append(f"- **{s}**: {sev_counts[s]}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1,
                                              "MEDIUM": 2, "LOW": 3,
                                              "INFO": 4}.get(x["severity"], 5)):
        lines.append(f"### {f['id']}")
        lines.append(f"- **Severity**: {f['severity']}")
        lines.append(f"- **Title**: {f['title']}")
        lines.append(f"- **Detail**: {f['detail']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines.append("---")
    lines.append("*Andre Henrique (@mrhenrike) | Uniao Geek*")

    path = REPORTS_DIR / "deep_forensic_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str),
                         encoding="utf-8")
    print(f"  [OK] JSON: {json_path}")


def main():
    print("=" * 70)
    print("  HIKVISION V4.x FIRMWARE — DEEP EXTRACTION & ANALYSIS")
    print("=" * 70)

    # Process V4.62.225 first (smaller, more manageable)
    for label, dav_path in [
        ("V4.62.225", str(BASE / ".tmp" / "hikvision_v4_62" / "digicap.dav")),
    ]:
        print(f"\n{'=' * 70}")
        print(f"  FIRMWARE: {label}")
        print(f"{'=' * 70}")

        out_dir = BASE / ".tmp" / f"hikvision_{label.replace('.', '_')}" / "extracted"
        out_dir.mkdir(parents=True, exist_ok=True)

        print("\n  Phase 1: Extracting DAV container...")
        extracted = extract_firmware(dav_path, out_dir)

        if not extracted:
            print("  No files extracted!")
            continue

        print("\n  Phase 2: Decompressing archives...")
        roots = decompress_archives(out_dir)

        print("\n  Phase 3: Inventory...")
        all_files, categories = inventory_extracted(out_dir)

        if all_files:
            print("\n  Phase 4: Binary analysis...")
            analyze_binaries(categories)

            print("\n  Phase 5: Credential hunting...")
            hunt_credentials_and_secrets(all_files)

            print("\n  Phase 6: Script analysis...")
            analyze_shell_scripts(categories)

            print("\n  Phase 7: Web security...")
            check_web_security(categories)

    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
