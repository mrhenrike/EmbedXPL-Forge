#!/usr/bin/env python3
"""
hikvision_kernel_deep.py — Deep analysis of decompressed Hikvision kernels
Author: Andre Henrique (@mrhenrike) | Uniao Geek

52K+ strings in hi3536, 41K+ strings in A8 — hunt for everything.
"""
from __future__ import annotations

import io
import json
import os
import re
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


def analyze_decompressed_kernel(name: str):
    sep = "=" * 70
    print(f"\n{sep}")
    print(f"  DEEP KERNEL ANALYSIS: {name}")
    print(sep)

    path = EXTRACT_DIR / name
    data = path.read_bytes()
    print(f"  Size: {len(data):,} bytes")

    strings_raw = re.findall(rb"[\x20-\x7e]{8,}", data)
    strings = [s.decode("ascii", errors="replace") for s in strings_raw]
    print(f"  Strings (>=8 chars): {len(strings)}")

    # 1. CREDENTIALS / PASSWORDS
    print(f"\n  {'='*50}")
    print("  1. CREDENTIALS & PASSWORDS")
    print(f"  {'='*50}")

    cred_patterns = [
        (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.I), "PASSWORD"),
        (re.compile(r"root:[^:]*:[0-9]+:[0-9]+:", re.I), "PASSWD_ENTRY"),
        (re.compile(r"\$[156]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+"), "SHADOW_HASH"),
        (re.compile(r"hiklinux", re.I), "HIK_DEFAULT_PASS"),
        (re.compile(r"default.?pass", re.I), "DEFAULT_PASS"),
        (re.compile(r"hardcoded.?(?:key|password|secret)", re.I), "HARDCODED"),
    ]
    for s in strings:
        for pat, label in cred_patterns:
            if pat.search(s):
                print(f"    [{label}] {s[:120]}")
                add_finding(f"F-HK4-{label}-{len(findings):03d}", "HIGH",
                            f"{label}: {s[:60]}", f"Found in {name}.", s[:200])
                break

    # 2. EMBEDDED FILESYSTEM / INITRAMFS
    print(f"\n  {'='*50}")
    print("  2. EMBEDDED FILESYSTEM (initramfs)")
    print(f"  {'='*50}")

    fs_patterns = [
        (re.compile(r"/etc/passwd|/etc/shadow|/etc/group"), "PASSWD_FILE"),
        (re.compile(r"/etc/init\.d/|/etc/rc\.d/"), "INIT_SCRIPT"),
        (re.compile(r"/usr/sbin/|/usr/bin/|/sbin/|/bin/"), "BINARY_PATH"),
        (re.compile(r"busybox|toybox"), "BUSYBOX"),
        (re.compile(r"dropbear|sshd|telnetd"), "REMOTE_ACCESS"),
        (re.compile(r"httpd|lighttpd|thttpd|boa|mini_httpd"), "WEB_SERVER"),
    ]
    for s in strings:
        for pat, label in fs_patterns:
            if pat.search(s):
                print(f"    [{label}] {s[:120]}")
                if label in ("PASSWD_FILE", "REMOTE_ACCESS"):
                    add_finding(f"F-HK4-FS-{label}-{len(findings):03d}", "MEDIUM",
                                f"{label}: {s[:60]}", f"In {name}.", s[:200])
                break

    # 3. NETWORK SERVICES & PROTOCOLS
    print(f"\n  {'='*50}")
    print("  3. NETWORK SERVICES")
    print(f"  {'='*50}")

    net_patterns = [
        (re.compile(r"telnetd|dropbear|sshd"), "SSH_TELNET"),
        (re.compile(r"httpd|http_server|web_server"), "HTTP"),
        (re.compile(r"rtsp|rtp|rtcp"), "RTSP"),
        (re.compile(r"onvif|discovery"), "ONVIF"),
        (re.compile(r"sadp|search.active.device"), "SADP"),
        (re.compile(r"upnp|ssdp|mdns"), "DISCOVERY"),
        (re.compile(r"ntp|ntpd|chronyd"), "TIME"),
        (re.compile(r"ftpd|tftpd|ftp_server"), "FTP"),
        (re.compile(r"snmp|snmpd"), "SNMP"),
        (re.compile(r"mqtt|amqp|coap"), "IOT_PROTOCOL"),
    ]
    seen_net = set()
    for s in strings:
        for pat, label in net_patterns:
            if pat.search(s.lower()) and label not in seen_net:
                print(f"    [{label}] {s[:120]}")
                seen_net.add(label)
                break

    # 4. KERNEL CONFIG (built-in)
    print(f"\n  {'='*50}")
    print("  4. KERNEL CONFIGURATION")
    print(f"  {'='*50}")

    security_configs = []
    network_configs = []
    debug_configs = []

    for s in strings:
        if s.startswith("CONFIG_"):
            if any(k in s for k in ["SECURITY", "SELINUX", "APPARMOR",
                                     "SECCOMP", "AUDIT", "STACK",
                                     "FORTIFY", "HARDEN", "RANDOMIZE",
                                     "KASLR", "KASAN", "UBSAN"]):
                security_configs.append(s)
            elif any(k in s for k in ["DEBUG", "PRINTK", "TRACE",
                                       "KGDB", "FTRACE"]):
                debug_configs.append(s)

    if security_configs:
        print("  Security configs:")
        for c in sorted(set(security_configs)):
            print(f"    {c}")
    else:
        print("  No kernel security configs found (likely stripped)")
        add_finding("F-HK4-KERN-NO-SEC-CFG", "MEDIUM",
                    "No kernel security configuration strings",
                    "Kernel appears to have security configs stripped.", "")

    if debug_configs:
        print(f"  Debug configs: {len(debug_configs)}")
        for c in sorted(set(debug_configs))[:10]:
            print(f"    {c}")
        add_finding("F-HK4-KERN-DEBUG", "LOW",
                    f"Debug kernel configs present ({len(debug_configs)})",
                    "Debug features may leak info.", str(debug_configs[:5]))

    # 5. COMMAND INJECTION SURFACES
    print(f"\n  {'='*50}")
    print("  5. COMMAND EXECUTION SURFACES")
    print(f"  {'='*50}")

    cmd_patterns = [
        (re.compile(r"call_usermodehelper"), "USERMODE_HELPER"),
        (re.compile(r"do_execve|do_exec"), "KERNEL_EXEC"),
        (re.compile(r"system\(|popen\("), "SYSTEM_CALL"),
        (re.compile(r"run_cmd|exec_cmd"), "CMD_EXEC"),
        (re.compile(r"/sbin/hotplug|/sbin/modprobe"), "HOTPLUG"),
        (re.compile(r"request_firmware"), "FW_LOAD"),
    ]
    for s in strings:
        for pat, label in cmd_patterns:
            if pat.search(s):
                print(f"    [{label}] {s[:120]}")
                break

    # 6. CRYPTO & KEYS
    print(f"\n  {'='*50}")
    print("  6. CRYPTOGRAPHY")
    print(f"  {'='*50}")

    crypto_strings = set()
    for s in strings:
        sl = s.lower()
        if any(k in sl for k in ["aes", "des_", "rsa", "sha1", "sha256",
                                   "sha512", "md5", "hmac", "cipher",
                                   "crypt", "ssl", "tls"]):
            crypto_strings.add(s[:80])

    for c in sorted(crypto_strings)[:30]:
        print(f"    {c}")

    # 7. HIKVISION-SPECIFIC
    print(f"\n  {'='*50}")
    print("  7. HIKVISION / HISILICON SPECIFIC")
    print(f"  {'='*50}")

    hik_strings = set()
    for s in strings:
        sl = s.lower()
        if any(k in sl for k in ["hikvision", "hikistor", "hisilicon",
                                   "davinci", "hik_", "hiklinux",
                                   "hicore", "webcore", "ptz",
                                   "ipc_", "nvr_", "dvr_"]):
            hik_strings.add(s[:100])

    for h in sorted(hik_strings)[:30]:
        print(f"    {h}")
        if "hiklinux" in h.lower():
            add_finding("F-HK4-HIKLINUX", "HIGH",
                        f"Default password reference: {h[:60]}",
                        "hiklinux is the default root password.", h[:200])

    # 8. DRIVER STRINGS & HARDWARE
    print(f"\n  {'='*50}")
    print("  8. HARDWARE & DRIVERS")
    print(f"  {'='*50}")

    hw_strings = set()
    for s in strings:
        sl = s.lower()
        if any(k in sl for k in ["hi3536", "hi3559", "hi3516", "hi3531",
                                   "hi3521", "hi3520",
                                   "arm926", "cortex",
                                   "uart", "i2c", "spi", "gpio",
                                   "pcie", "usb", "ethernet",
                                   "sensor", "isp"]):
            hw_strings.add(s[:100])

    for h in sorted(hw_strings)[:20]:
        print(f"    {h}")

    # 9. PRINTK / ERROR MESSAGES (may reveal logic)
    print(f"\n  {'='*50}")
    print("  9. INTERESTING LOG MESSAGES")
    print(f"  {'='*50}")

    log_count = 0
    for s in strings:
        if any(k in s.lower() for k in ["error:", "warning:", "failed to",
                                          "cannot ", "invalid ", "denied",
                                          "unauthorized", "overflow",
                                          "buffer", "inject", "exploit"]):
            if log_count < 30:
                print(f"    {s[:120]}")
                log_count += 1

    # 10. Embedded ELF / initramfs detection
    print(f"\n  {'='*50}")
    print("  10. EMBEDDED BINARIES")
    print(f"  {'='*50}")

    elf_count = 0
    pos = 0
    while pos < len(data) - 4:
        idx = data.find(b"\x7fELF", pos)
        if idx == -1:
            break
        ei_class = data[idx + 4] if idx + 4 < len(data) else 0
        bits = {1: 32, 2: 64}.get(ei_class, 0)
        if bits > 0:
            elf_count += 1
            if elf_count <= 10:
                print(f"    ELF @ 0x{idx:08X} ({bits}-bit)")
        pos = idx + 4

    print(f"  Total embedded ELFs: {elf_count}")

    # Check for CPIO/initramfs
    cpio_offsets = []
    pos = 0
    while pos < len(data) - 6:
        idx = data.find(b"070701", pos)
        if idx == -1:
            idx = data.find(b"070702", pos)
        if idx == -1:
            break
        cpio_offsets.append(idx)
        pos = idx + 6
        if len(cpio_offsets) >= 5:
            break

    if cpio_offsets:
        print(f"\n  CPIO/initramfs found at {len(cpio_offsets)} positions:")
        for off in cpio_offsets:
            # Parse CPIO header to get filename
            fname_size = int(data[off + 94:off + 102].decode("ascii", errors="0"), 16)
            if 0 < fname_size < 256:
                fname = data[off + 110:off + 110 + fname_size - 1].decode(
                    "ascii", errors="replace")
                print(f"    @ 0x{off:08X}: {fname}")
                add_finding(f"F-HK4-INITRAMFS-{len(findings):03d}", "INFO",
                            f"Initramfs file: {fname}",
                            f"Built-in filesystem in {name}.", fname)

    return len(strings)


def main():
    kernels = [
        "uImage_hi3536_lzma_8024.bin",
        "uImage_A8_lzma_17728.bin",
    ]

    total_strings = 0
    for k in kernels:
        path = EXTRACT_DIR / k
        if path.exists():
            total_strings += analyze_decompressed_kernel(k)

    # Generate report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    sev_counts = Counter(f["severity"] for f in findings)

    lines = [
        "# Hikvision V4.62 NVR — Decompressed Kernel Deep Analysis",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        f"> Total strings analyzed: {total_strings:,}",
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
        if f.get("evidence"):
            lines.append(f"- **Evidence**: `{f['evidence'][:200]}`")
        lines.append("")

    lines.append("---")
    lines.append("*Andre Henrique (@mrhenrike) | Uniao Geek*")

    path = REPORTS_DIR / "kernel_deep_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {path}")

    json_path = REPORTS_DIR / "kernel_deep_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str),
                         encoding="utf-8")

    print(f"\n{'=' * 70}")
    print(f"  COMPLETE: {len(findings)} findings from {total_strings:,} strings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
