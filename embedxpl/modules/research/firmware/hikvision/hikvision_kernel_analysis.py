#!/usr/bin/env python3
"""
hikvision_kernel_analysis.py — Analyze extracted Hikvision kernels and scripts
Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""
from __future__ import annotations

import io
import json
import os
import re
import struct
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EXTRACT_DIR = BASE / ".tmp" / "hikvision_v4_62" / "manual_extract"
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def analyze_shell_script():
    """Analyze the boot shell script."""
    print("=" * 70)
    print("  SHELL SCRIPT ANALYSIS: start_k20a8.sh")
    print("=" * 70)

    path = EXTRACT_DIR / "start_k20a8.sh"
    content = path.read_bytes().decode("ascii", errors="replace")

    print(f"\n  Size: {len(content)} bytes")
    print(f"\n  === CONTENT ===")
    print(content[:5000])

    # Security issues
    issues = []
    if "chmod 777" in content:
        issues.append("chmod 777 (world-writable)")
    if "chmod 666" in content:
        issues.append("chmod 666 (world-writable)")
    if "telnetd" in content.lower():
        issues.append("telnetd enabled")
    if re.search(r"password|passwd", content, re.I):
        issues.append("password reference")
    if "mount -o remount,rw" in content:
        issues.append("remount root filesystem as rw")
    if "iptables -F" in content:
        issues.append("firewall flush")
    if "dropbear" in content.lower():
        issues.append("dropbear SSH")
    if "insmod" in content or "modprobe" in content:
        issues.append("kernel module loading")
    if re.search(r"curl|wget", content, re.I):
        issues.append("network download")
    if "eval " in content:
        issues.append("eval usage")

    if issues:
        print(f"\n  Security issues found: {len(issues)}")
        for i in issues:
            print(f"    !!! {i}")
            add_finding(f"F-HK4-SCRIPT-{len(findings):03d}", "MEDIUM",
                        f"Boot script issue: {i}",
                        f"start_k20a8.sh contains: {i}", i)

    # Extract paths and commands
    paths = re.findall(r"/[\w/.-]+", content)
    print(f"\n  Paths referenced: {len(set(paths))}")
    for p in sorted(set(paths)):
        print(f"    {p}")


def analyze_kernel(name: str):
    """Deep analysis of extracted ARM kernel."""
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  KERNEL ANALYSIS: {name}")
    print(sep)

    path = EXTRACT_DIR / name
    data = path.read_bytes()
    print(f"  Size: {len(data):,} bytes")

    # Parse uImage header
    if data[:4] == b"\x27\x05\x19\x56":
        ih_hcrc = struct.unpack(">I", data[4:8])[0]
        ih_time = struct.unpack(">I", data[8:12])[0]
        ih_size = struct.unpack(">I", data[12:16])[0]
        ih_load = struct.unpack(">I", data[16:20])[0]
        ih_ep = struct.unpack(">I", data[20:24])[0]
        ih_dcrc = struct.unpack(">I", data[24:28])[0]
        ih_os = data[28]
        ih_arch = data[29]
        ih_type = data[30]
        ih_comp = data[31]
        ih_name = data[32:64].split(b"\x00")[0].decode("ascii", errors="replace")

        print(f"\n  uImage Header:")
        print(f"    Name: {ih_name}")
        print(f"    Size: {ih_size:,} bytes")
        print(f"    Load addr: 0x{ih_load:08X}")
        print(f"    Entry point: 0x{ih_ep:08X}")
        print(f"    OS: {ih_os} (5=Linux)")
        print(f"    Arch: {ih_arch} (2=ARM)")
        print(f"    Compression: {ih_comp} (0=none, 1=gzip, 2=bzip2)")

        kernel_data = data[64:]
    else:
        kernel_data = data

    # Extract ALL strings
    strings = re.findall(rb"[\x20-\x7e]{10,}", kernel_data)
    print(f"\n  Total strings (>=10 chars): {len(strings)}")

    categories = {
        "credentials": [],
        "hikvision_specific": [],
        "network_services": [],
        "filesystem": [],
        "crypto": [],
        "versions": [],
        "kernel_config": [],
        "security_features": [],
        "dangerous_patterns": [],
        "urls_ips": [],
        "hardware": [],
    }

    for s in strings:
        d = s.decode("ascii", errors="replace")
        dl = d.lower()

        if any(k in dl for k in ["password", "passwd", "secret", "key=",
                                   "token", "credential", "auth"]):
            categories["credentials"].append(d)
        elif any(k in dl for k in ["hiklinux", "hikvision", "hikistor",
                                    "hikroot", "hik_", "davinci", "hisilicon"]):
            categories["hikvision_specific"].append(d)
        elif any(k in dl for k in ["telnet", "ssh", "dropbear", "httpd",
                                    "ftpd", "rtsp", "onvif", "sadp",
                                    "isapi", "netfilter", "iptables"]):
            categories["network_services"].append(d)
        elif any(k in dl for k in ["/dev/", "mount", "rootfs", "squashfs",
                                    "jffs2", "yaffs", "cramfs", "ext4",
                                    "initramfs"]):
            categories["filesystem"].append(d)
        elif any(k in dl for k in ["aes", "des_", "rsa", "sha1", "sha256",
                                    "md5", "hmac", "cipher", "encrypt"]):
            categories["crypto"].append(d)
        elif re.search(r"v\d+\.\d+|version|linux-\d", dl):
            categories["versions"].append(d)
        elif dl.startswith("config_"):
            categories["kernel_config"].append(d)
        elif any(k in dl for k in ["selinux", "apparmor", "capability",
                                    "seccomp", "audit", "smack"]):
            categories["security_features"].append(d)
        elif any(k in dl for k in ["system(", "execve", "call_usermodehelper",
                                    "run_cmd", "do_exec"]):
            categories["dangerous_patterns"].append(d)
        elif re.search(r"https?://|(?:\d{1,3}\.){3}\d{1,3}", dl):
            categories["urls_ips"].append(d)
        elif any(k in dl for k in ["hi3536", "hi3559", "hi3516", "arm926",
                                    "cortex", "neon", "vfp"]):
            categories["hardware"].append(d)

    for cat, items in categories.items():
        if items:
            unique = list(dict.fromkeys(items))[:20]
            print(f"\n  --- {cat.upper()} ({len(items)} hits) ---")
            for item in unique:
                print(f"    {item[:120]}")

            if cat == "credentials":
                for item in unique[:5]:
                    add_finding(
                        f"F-HK4-KERN-CRED-{len(findings):03d}", "HIGH",
                        f"Credential pattern in kernel: {item[:50]}",
                        f"Found in {name} kernel image.", item[:200])

            if cat == "hikvision_specific":
                for item in unique[:3]:
                    add_finding(
                        f"F-HK4-KERN-HIK-{len(findings):03d}", "INFO",
                        f"Hikvision-specific string: {item[:50]}",
                        f"Proprietary identifier in {name}.", item[:200])

    # Check kernel security features
    print("\n  === KERNEL SECURITY CONFIGURATION ===")

    config_items = [s.decode("ascii", errors="replace")
                    for s in strings if s.startswith(b"CONFIG_")]
    if config_items:
        security_configs = {
            "CONFIG_SECURITY": False,
            "CONFIG_SECCOMP": False,
            "CONFIG_AUDIT": False,
            "CONFIG_SELINUX": False,
            "CONFIG_APPARMOR": False,
            "CONFIG_FORTIFY_SOURCE": False,
            "CONFIG_HARDENED_USERCOPY": False,
            "CONFIG_STACKPROTECTOR": False,
            "CONFIG_STRICT_KERNEL_RWX": False,
            "CONFIG_RANDOMIZE_BASE": False,
        }

        for c in config_items:
            for key in security_configs:
                if key in c and "=y" in c:
                    security_configs[key] = True

        for key, val in security_configs.items():
            status = "ENABLED" if val else "DISABLED/NOT FOUND"
            print(f"    {key}: {status}")

            if not val and key in ("CONFIG_SECURITY", "CONFIG_STACKPROTECTOR"):
                add_finding(
                    f"F-HK4-KERN-NOSEC-{key[-8:]}", "HIGH",
                    f"Kernel security feature missing: {key}",
                    f"Kernel {name} does not have {key} enabled.", key)

    # Look for default root password hash
    print("\n  === ROOT PASSWORD SEARCH ===")
    passwd_patterns = [
        rb"root:\$[156]\$[^\s:]+",
        rb"root:[^:]+:0:0:",
        rb"hiklinux",
        rb"admin:\$",
    ]
    for pat in passwd_patterns:
        matches = re.findall(pat, kernel_data)
        if matches:
            for m in matches:
                d = m.decode("ascii", errors="replace")
                print(f"    FOUND: {d}")
                add_finding(
                    f"F-HK4-KERN-PASSWD-{len(findings):03d}", "CRITICAL",
                    f"Root password hash in kernel: {d[:50]}",
                    f"Default/hardcoded root password found in {name}.",
                    d[:200])

    # Search for ISAPI endpoint strings
    print("\n  === ISAPI ENDPOINTS IN KERNEL ===")
    isapi = set()
    for m in re.finditer(rb"/ISAPI/[\w/]+", kernel_data):
        isapi.add(m.group().decode("ascii", errors="replace"))
    for m in re.finditer(rb"/SDK/[\w/]+", kernel_data):
        isapi.add(m.group().decode("ascii", errors="replace"))
    if isapi:
        print(f"    Found {len(isapi)} endpoints:")
        for ep in sorted(isapi):
            print(f"      {ep}")


def scan_full_dav_strings():
    """Scan the full V4.62 DAV file for interesting cleartext strings."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  FULL DAV FILE STRING SCAN (cleartext regions)")
    print(sep)

    dav_path = BASE / ".tmp" / "hikvision_v4_62" / "digicap.dav"
    data = dav_path.read_bytes()

    # Focus on strings > 20 chars for quality
    strings = re.findall(rb"[\x20-\x7e]{20,}", data)
    print(f"  Total strings (>=20 chars): {len(strings)}")

    # Filter for security-relevant
    sec_strings = []
    for s in strings:
        d = s.decode("ascii", errors="replace")
        dl = d.lower()
        if any(k in dl for k in [
            "password", "secret", "token", "credential", "backdoor",
            "root:", "admin:", "shadow", "hiklinux", "/etc/passwd",
            "private key", "begin cert", "base64",
            "isapi", "onvif", "sadp", "cgi-bin",
            "telnetd", "dropbear", "sshd",
            "system(", "popen(", "exec(",
            "chmod 777", "chmod 666",
            "copyright", "hikvision",
            "version", "build",
            "curl", "wget", "tftp",
            "nfs", "mount",
        ]):
            sec_strings.append(d)

    print(f"  Security-relevant strings: {len(sec_strings)}")
    unique_sec = list(dict.fromkeys(sec_strings))
    for s in unique_sec[:50]:
        print(f"    {s[:120]}")

    # Look for embedded certificates
    print("\n  === EMBEDDED CERTIFICATES/KEYS ===")
    certs = re.findall(rb"-----BEGIN [A-Z ]+-----", data)
    if certs:
        for c in certs:
            print(f"    {c.decode()}")
            add_finding(f"F-HK4-CERT-{len(findings):03d}", "HIGH",
                        f"Embedded certificate/key: {c.decode()[:40]}",
                        "Embedded crypto material in firmware.", c.decode())


def generate_report():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    sev_counts = Counter(f["severity"] for f in findings)

    lines = [
        "# Hikvision V4.62.225 / V4.84.101 NVR — Deep Forensic Analysis",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "> Targets: Hikvision V4.62.225, V4.84.101 NVR/DVR firmware",
        "",
        "---",
        "",
        f"## Summary: {len(findings)} findings",
        "",
    ]

    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev_counts.get(s, 0):
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

    path = REPORTS_DIR / "kernel_analysis_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "kernel_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str),
                         encoding="utf-8")
    print(f"  [OK] JSON: {json_path}")


if __name__ == "__main__":
    analyze_shell_script()
    analyze_kernel("uImage_hi3536.bin")
    analyze_kernel("uImage_A8.bin")
    scan_full_dav_strings()
    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")
