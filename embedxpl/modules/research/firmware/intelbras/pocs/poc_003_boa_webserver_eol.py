#!/usr/bin/env python3
"""PoC INTELBRAS-2026-003: Boa Web Server (End-of-Life) Detection.

Detects Boa HTTP server presence on Intelbras CCTV devices via HTTP banner
fingerprinting and firmware string analysis. Boa has been EOL since 2005 with
known unpatched CVEs (CVE-2005-2970, CVE-2009-4496).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Date: 2026-04-18
CVSS: 7.5 HIGH — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
CWE: CWE-1104 (Use of Unmaintained Third-Party Components)
"""

import os
import sys
import json
import zipfile
import re
from pathlib import Path
from datetime import datetime, timezone

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


_project_tmp = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)

EVIDENCE_DIR = Path(__file__).parent / ".." / "evidence"

BOA_PATTERNS = [
    re.compile(rb"\bBoa/\d", re.IGNORECASE),
    re.compile(rb"\bboa\s+http", re.IGNORECASE),
    re.compile(rb"Server:\s*Boa", re.IGNORECASE),
    re.compile(rb"Boa Webserver", re.IGNORECASE),
]

BOA_STRING_PATTERN = re.compile(rb"(?:^|\x00)(Boa(?:/[\d.]+)?)\x00", re.MULTILINE)

BOA_KNOWN_CVES = [
    {"cve": "CVE-2005-2970", "description": "Null pointer dereference (DoS)", "cvss": 5.0},
    {"cve": "CVE-2009-4496", "description": "Directory traversal", "cvss": 5.0},
]


def scan_firmware_for_boa(zip_path: str) -> dict:
    result = {
        "firmware_file": os.path.basename(zip_path),
        "boa_detected": False,
        "boa_references": [],
        "web_interface_files": [],
    }

    work_dir = os.path.join(_project_tmp, "poc003_" + Path(zip_path).stem)
    os.makedirs(work_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(work_dir)

    for root, _, files in os.walk(work_dir):
        for fname in files:
            if any(fname.endswith(ext) for ext in
                   (".cramfs.img", ".squashfs.img", ".bin", ".img")):
                fpath = os.path.join(root, fname)
                try:
                    data = Path(fpath).read_bytes()
                except (OSError, FileNotFoundError):
                    continue

                for pat in BOA_PATTERNS:
                    for m in pat.finditer(data):
                        result["boa_detected"] = True
                        result["boa_references"].append({
                            "file": fname,
                            "offset": m.start(),
                            "match": m.group(0).decode("ascii", errors="replace"),
                        })

                for m in BOA_STRING_PATTERN.finditer(data):
                    ver = m.group(1).decode("ascii", errors="replace")
                    result["boa_detected"] = True
                    result["boa_references"].append({
                        "file": fname,
                        "offset": m.start(),
                        "match": ver,
                        "type": "version_string",
                    })

            if "web" in fname.lower():
                result["web_interface_files"].append(fname)

    return result


def live_scan_target(target_ip: str, port: int = 80) -> dict:
    """Probe a live device for Boa web server banner."""
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    result = {
        "target": f"{target_ip}:{port}",
        "boa_detected": False,
        "server_header": None,
        "status_code": None,
    }

    try:
        resp = requests.get(
            f"http://{target_ip}:{port}/",
            timeout=10,
            allow_redirects=False,
            verify=False,
        )
        result["status_code"] = resp.status_code
        server = resp.headers.get("Server", "")
        result["server_header"] = server
        if "boa" in server.lower():
            result["boa_detected"] = True
            print(f"  [+] Boa detected: {server}")
        else:
            print(f"  [*] Server: {server}")
    except Exception as e:
        result["error"] = str(e)
        print(f"  [!] Connection failed: {e}")

    return result


def main():
    fw_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "downloads", "cctv", "intelbras",
    )

    if not os.path.isdir(fw_dir):
        print(f"[!] Firmware directory not found: {fw_dir}")
        sys.exit(1)

    zips = sorted(Path(fw_dir).glob("*.zip"))
    print(f"[*] Scanning {len(zips)} firmware images for Boa web server...")

    all_results = []
    boa_count = 0

    for zp in zips:
        print(f"\n[*] {zp.name}")
        result = scan_firmware_for_boa(str(zp))
        all_results.append(result)
        if result["boa_detected"]:
            boa_count += 1
            print(f"  [+] Boa DETECTED — {len(result['boa_references'])} references")
        else:
            print(f"  [-] Boa not detected in firmware strings")

    live_results = []
    if len(sys.argv) > 1:
        print(f"\n{'='*60}")
        print("[*] Live scanning targets...")
        for target in sys.argv[1:]:
            parts = target.split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 80
            print(f"\n[*] Scanning {ip}:{port}")
            live_results.append(live_scan_target(ip, port))

    print(f"\n{'='*60}")
    print(f"[*] Summary: {boa_count}/{len(all_results)} firmware images contain Boa")
    print(f"[*] Boa last release: February 2005 (v0.94.14rc21)")
    print(f"[*] Known CVEs: {', '.join(c['cve'] for c in BOA_KNOWN_CVES)}")

    output = {
        "poc_id": "INTELBRAS-2026-003",
        "title": "Boa Web Server (End-of-Life) Detection",
        "boa_last_release": "2005-02",
        "known_cves": BOA_KNOWN_CVES,
        "firmware_results": all_results,
        "live_results": live_results,
        "boa_detected_count": boa_count,
        "total_analyzed": len(all_results),
    }

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out_path = EVIDENCE_DIR / "poc_003_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved to {out_path}")


if __name__ == "__main__":
    main()
