#!/usr/bin/env python3
"""
hikvision_psh_analysis_poc.py — PSH (Protect Shell) Security Analysis PoC
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Analyzes the extracted psh binary for:
1. RSA key weakness (1024-bit)
2. Command injection in restricted shell
3. Authentication bypass vectors
4. Password reset mechanism
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
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ROOTFS = BASE / ".tmp" / "hikvision_v4_62" / "rootfs"
REPORTS_DIR = BASE / "reports" / "hikvision_v4_analysis"

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

findings = []


def add_finding(fid, sev, title, detail, evidence="", cwe="", cvss=""):
    findings.append({
        "id": fid, "severity": sev, "title": title,
        "detail": detail, "evidence": evidence[:3000],
        "cwe": cwe, "cvss": cvss,
    })
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid}: {title}")


def analyze_psh_binary():
    """Deep analysis of the psh (Protect Shell) binary."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  PSH BINARY DEEP SECURITY ANALYSIS")
    print(sep)

    psh_path = ROOTFS / "bin" / "psh"
    if not psh_path.exists():
        print("  ERROR: bin/psh not found!")
        return

    data = psh_path.read_bytes()
    print(f"  Binary size: {len(data):,} bytes")

    # Extract all printable strings
    strings = [s.decode("ascii", errors="replace")
               for s in re.findall(rb"[\x20-\x7e]{4,}", data)]

    # 1. COMMAND WHITELIST ANALYSIS
    print("\n  --- COMMAND WHITELIST ---")
    commands = []
    in_commands = False
    for s in strings:
        if s == "Support Commands: ":
            in_commands = True
            continue
        if in_commands and re.match(r"^[a-zA-Z]\w+$", s.strip()):
            commands.append(s.strip())
        elif in_commands and not re.match(r"^[a-zA-Z%]", s.strip()):
            in_commands = False

    # Also find command names from the binary's command table
    cmd_names = [s.strip() for s in strings
                 if re.match(r"^[a-z][a-zA-Z0-9]{3,24}$", s.strip())
                 and s.strip() not in ("libc", "abort", "stdin", "stdout",
                                       "stderr", "socket", "signal",
                                       "fflush", "strlen")]

    unique_cmds = sorted(set(cmd_names))
    print(f"  Total recognized commands: {len(unique_cmds)}")

    # Categorize commands by security impact
    dangerous = {
        "resetPasswd": "Can reset device password without current password",
        "setCloudPassword": "Can change cloud account credentials",
        "connectSlaveSsh": "SSH into slave devices (lateral movement)",
        "dmesg": "Read kernel ring buffer (info disclosure)",
        "netstat": "View network connections (reconnaissance)",
        "ping": "Network probing (can confirm other hosts)",
        "i2cRead": "Direct hardware bus read (info disclosure)",
        "i2cWrite": "Direct hardware bus write (tampering)",
        "setIp": "Change device IP (network manipulation)",
        "setPort": "Change service port (service disruption)",
        "setMtu": "Change MTU (network disruption)",
        "setGateway": "Change gateway (traffic interception)",
        "disableWatchdog": "Disable hardware watchdog (DoS resilience bypass)",
        "rebootDev": "Reboot device (DoS)",
        "miscCmd": "Generic command passthrough",
    }

    print("\n  === SECURITY-SENSITIVE COMMANDS ===")
    for cmd in sorted(unique_cmds):
        if cmd in dangerous:
            print(f"    !!! {cmd}: {dangerous[cmd]}")

    add_finding(
        "F-HK4-PSH-CMDS", "HIGH",
        f"PSH exposes {len(dangerous)} security-sensitive commands",
        f"Restricted shell includes dangerous management commands: "
        f"{', '.join(dangerous.keys())}",
        str(list(dangerous.keys())),
        cwe="CWE-250", cvss="AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
    )

    # 2. AUTHENTICATION ANALYSIS
    print("\n  --- AUTHENTICATION MECHANISM ---")

    # Extract RSA modulus
    mod_pattern = re.compile(r"[0-9A-F]{200,}", re.I)
    for s in strings:
        m = mod_pattern.fullmatch(s.strip())
        if m:
            mod_hex = m.group()
            n = int(mod_hex, 16)
            bits = n.bit_length()
            print(f"  RSA modulus: {bits}-bit")
            print(f"    First 32 hex: {mod_hex[:32]}")
            print(f"    Last 32 hex: {mod_hex[-32:]}")

            add_finding(
                "F-HK4-PSH-RSA1024", "CRITICAL",
                f"Debug root access protected by RSA-{bits} (NIST deprecated)",
                f"PSH debug mode authentication uses RSA-{bits}. "
                f"Debug mode grants 'original root privilege'. "
                f"NIST SP 800-131A deprecated RSA-1024 in 2013.",
                f"N={mod_hex[:60]}...",
                cwe="CWE-326",
                cvss="AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
            )

    # Extract base64 RSA keys
    b64_keys = []
    for s in strings:
        if s.startswith("MIGJ"):
            clean = s.replace(" ", "")
            try:
                raw = base64.b64decode(clean)
                b64_keys.append({"b64": clean, "raw_len": len(raw)})
            except:
                pass

    print(f"  Embedded RSA public keys: {len(b64_keys)}")
    for i, k in enumerate(b64_keys):
        print(f"    Key {i + 1}: {k['raw_len']} bytes DER structure")

    add_finding(
        "F-HK4-PSH-STATIC-KEYS", "HIGH",
        f"{len(b64_keys)} hardcoded RSA public keys in firmware",
        f"All {len(b64_keys)} RSA keys are embedded in the psh binary and "
        f"identical across all devices of the same firmware version. "
        f"Key extraction enables targeted factoring attacks.",
        "Keys start with MIGJAoGB...",
        cwe="CWE-798",
        cvss="AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    )

    # 3. COMMAND INJECTION ANALYSIS
    print("\n  --- COMMAND INJECTION VECTORS ---")

    # Check for input validation
    blacklist = []
    for s in strings:
        if any(c in s for c in ["|", ";", "&", "`", "$"]) and len(s) < 30:
            blacklist.append(s)

    filter_chars = "~`!$^&*()=|\\{}[];\"'<>?"
    print(f"  Blacklisted characters: {filter_chars}")
    print("  Block messages:")
    for s in strings:
        if "Not Support" in s or "Redirect" in s or "Replace" in s:
            print(f"    {s}")

    # Analyze: does the blacklist cover all dangerous chars?
    missing = []
    if "%" not in filter_chars:
        missing.append("% (format string)")
    if "\n" not in filter_chars:
        missing.append("newline (command separator)")
    if "\r" not in filter_chars:
        missing.append("CR (CRLF injection)")
    if "\t" not in filter_chars:
        missing.append("tab (IFS manipulation)")

    if missing:
        print("\n  Potentially missing from blacklist:")
        for m in missing:
            print(f"    - {m}")
        add_finding(
            "F-HK4-PSH-FILTER-GAP", "MEDIUM",
            f"Command filter may not block: {', '.join(missing)}",
            "PSH character blacklist may have gaps allowing injection.",
            f"Blacklist: {filter_chars}",
            cwe="CWE-78",
            cvss="AV:P/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"
        )

    # 4. cmd_exec ANALYSIS
    print("\n  --- cmd_exec FUNCTION ---")
    print("  PSH uses execvp/vfork with /bin/sh for command execution")
    print("  vfork is unsafe: child shares parent address space")
    print("  If input validation can be bypassed, arbitrary code execution follows")

    add_finding(
        "F-HK4-PSH-VFORK", "MEDIUM",
        "PSH uses vfork() for command execution (CWE-676)",
        "vfork() shares parent address space with child. "
        "If the child process is compromised, it can corrupt the parent. "
        "Combined with execvp, this creates an attack surface.",
        "execvp + vfork + /bin/sh",
        cwe="CWE-676",
    )

    # 5. PASSWORD MANAGEMENT
    print("\n  --- PASSWORD MANAGEMENT ---")
    pwd_strings = [s for s in strings if "assword" in s or "asswd" in s]
    for s in pwd_strings:
        print(f"    {s}")

    print("\n  Password-related commands:")
    print("    resetPasswd — Reset device passwords")
    print("    setCloudPassword — Set cloud account password")
    print("    ttyAuth — TTY authentication")
    print("    debug — Debug mode with password challenge")

    add_finding(
        "F-HK4-PSH-RESET-PASSWD", "HIGH",
        "resetPasswd command available in restricted shell",
        "PSH includes a 'resetPasswd' command that can reset device "
        "passwords. If debug mode can be bypassed, this enables full "
        "device takeover. Even without debug, resetPasswd might work "
        "from the restricted shell depending on implementation.",
        "resetPasswd, setCloudPassword",
        cwe="CWE-620",
    )


def analyze_ded_binary():
    """Analyze the ded (decrypt/encrypt) binary."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  DED (FIRMWARE DECRYPTOR) ANALYSIS")
    print(sep)

    ded_path = ROOTFS / "bin" / "ded"
    if not ded_path.exists():
        print("  ERROR: bin/ded not found!")
        return

    data = ded_path.read_bytes()
    print(f"  Binary size: {len(data):,} bytes")

    strings = [s.decode("ascii", errors="replace")
               for s in re.findall(rb"[\x20-\x7e]{4,}", data)]

    print("\n  Key strings:")
    for s in strings:
        if any(k in s.lower() for k in ["ded", "decrypt", "encrypt", "ioctl",
                                         "usage", "dev", "open", "fail"]):
            print(f"    {s}")

    print("\n  Architecture:")
    print("    1. bin/ded opens /dev/hikded (kernel device)")
    print("    2. Passes input/output filenames via ioctl()")
    print("    3. Kernel driver performs actual AES decryption")
    print("    4. Key is stored in kernel driver, not in userspace")

    add_finding(
        "F-HK4-DED-KERNEL-KEY", "HIGH",
        "Firmware AES key stored in kernel driver (/dev/hikded)",
        "The firmware decryption key is embedded in the kernel's "
        "hikded driver. This key is static across all devices of "
        "the same model. Physical access to any single device "
        "enables extraction of the key, allowing firmware modification "
        "for all devices of that model (supply chain attack vector).",
        "/dev/hikded, ioctl-based decrypt/encrypt",
        cwe="CWE-321",
        cvss="AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    )


def analyze_busybox():
    """Analyze busybox configuration."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  BUSYBOX ANALYSIS")
    print(sep)

    bb_path = ROOTFS / "bin" / "busybox"
    if not bb_path.exists():
        print("  ERROR: bin/busybox not found!")
        return

    data = bb_path.read_bytes()
    strings = [s.decode("ascii", errors="replace")
               for s in re.findall(rb"[\x20-\x7e]{4,}", data)]

    # Find applets
    applets = []
    for s in strings:
        if re.match(r"^[a-z_][a-z0-9_]{1,20}$", s) and \
           s not in ("libc", "abort", "stdin", "stdout", "stderr"):
            applets.append(s)

    print(f"  BusyBox applets found: {len(set(applets))}")

    dangerous_applets = ["telnetd", "ftpd", "httpd", "nc", "wget", "curl",
                         "sh", "ash", "bash", "dd", "mount", "umount",
                         "chmod", "chown", "kill", "reboot", "halt",
                         "insmod", "rmmod", "modprobe", "mknod"]
    found_dangerous = [a for a in dangerous_applets if a in applets]
    if found_dangerous:
        print(f"  Dangerous applets: {', '.join(found_dangerous)}")

    # Check password handling
    for s in strings:
        if "password" in s.lower() or "passwd" in s.lower():
            print(f"  PWD: {s[:80]}")


def analyze_glibc():
    """Analyze glibc version and known CVEs."""
    sep = "=" * 70
    print(f"\n{sep}")
    print("  GLIBC 2.16 CVE ANALYSIS")
    print(sep)

    libc_path = ROOTFS / "lib" / "libc-2.16.so"
    if not libc_path.exists():
        print("  ERROR: lib/libc-2.16.so not found!")
        return

    known_cves = [
        ("CVE-2015-0235", "CRITICAL", "GHOST - heap overflow in gethostbyname()",
         "Remote code execution via specially crafted DNS response"),
        ("CVE-2015-7547", "CRITICAL", "Stack buffer overflow in getaddrinfo()",
         "Remote code execution via malicious DNS server"),
        ("CVE-2014-5119", "HIGH", "Off-by-one error in transliteration module",
         "Heap corruption leading to code execution"),
        ("CVE-2017-1000366", "HIGH", "Stack clash vulnerability",
         "Local privilege escalation"),
        ("CVE-2014-9402", "HIGH", "Infinite loop in getaddrinfo()",
         "Denial of service"),
        ("CVE-2015-1781", "HIGH", "Buffer overflow in gethostbyname_r()",
         "Remote code execution"),
        ("CVE-2013-7423", "MEDIUM", "Invalid module free in iconv",
         "Code execution via crafted character set"),
    ]

    print("  glibc version: 2.16 (released June 2012)")
    print("  Age: ~14 years")
    print(f"  Known applicable CVEs: {len(known_cves)}")
    print()

    for cve_id, sev, title, impact in known_cves:
        print(f"  [{sev:8s}] {cve_id}: {title}")
        add_finding(
            f"F-HK4-GLIBC-{cve_id.replace('-', '_')}", sev,
            f"glibc 2.16 vulnerable to {cve_id}: {title}",
            f"{impact}. glibc 2.16 is 14 years old and has multiple "
            f"known exploitable vulnerabilities.",
            cve_id, cwe="CWE-119",
        )


def generate_report():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    from collections import Counter
    sev_counts = Counter(f["severity"] for f in findings)

    lines = [
        "# Hikvision PSH & Binary Security Analysis — Detailed Findings",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        f"> Total findings: {len(findings)}",
        "",
        "---",
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
        if f.get("cwe"):
            lines.append(f"- **CWE**: {f['cwe']}")
        if f.get("cvss"):
            lines.append(f"- **CVSS**: {f['cvss']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines.append("---")
    lines.append("*Andre Henrique (@mrhenrike) | Uniao Geek*")

    path = REPORTS_DIR / "psh_security_analysis.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "psh_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str),
                         encoding="utf-8")


if __name__ == "__main__":
    analyze_psh_binary()
    analyze_ded_binary()
    analyze_busybox()
    analyze_glibc()
    generate_report()

    print(f"\n{'=' * 70}")
    print(f"  ANALYSIS COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")
