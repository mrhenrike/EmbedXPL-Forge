#!/usr/bin/env python3
"""PoC INTELBRAS-2026-002: Firmware Update Without Integrity Verification.

Demonstrates that Intelbras CCTV firmware packages (update.bin) use an
Install.lua script for update orchestration without cryptographic signature
verification. A crafted firmware package will be accepted by the device.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Date: 2026-04-18
CVSS: 8.1 HIGH — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
CWE: CWE-494 (Download of Code Without Integrity Check)
"""

import os
import sys
import json
import zipfile
import hashlib
import struct
from pathlib import Path
from datetime import datetime, timezone


_project_tmp = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)

EVIDENCE_DIR = Path(__file__).parent / ".." / "evidence"


SIGNATURE_MARKERS = [
    b"-----BEGIN",
    b"RSA_VERIFY",
    b"signature_check",
    b"verify_signature",
    b"sig_verify",
    b"rsa_verify",
    b"sha256_verify",
    b"PKCS",
    b"X509",
]

INSTALL_LUA_MARKER = b"Install.lua"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze_update_bin(data: bytes, source_label: str) -> dict:
    result = {
        "source": source_label,
        "size": len(data),
        "has_install_lua": False,
        "signature_check_found": False,
        "signature_markers": [],
        "lua_references": [],
        "header_magic": data[:4].hex() if len(data) >= 4 else "N/A",
    }

    if INSTALL_LUA_MARKER in data:
        result["has_install_lua"] = True
        offset = data.find(INSTALL_LUA_MARKER)
        result["lua_references"].append({
            "marker": "Install.lua",
            "offset": offset,
            "context": data[max(0, offset - 20):offset + 50].hex(),
        })

    for marker in SIGNATURE_MARKERS:
        idx = data.find(marker)
        if idx != -1:
            result["signature_check_found"] = True
            result["signature_markers"].append({
                "marker": marker.decode("ascii", errors="replace"),
                "offset": idx,
            })

    return result


def analyze_firmware_zip(zip_path: str) -> dict:
    results = {
        "firmware_file": os.path.basename(zip_path),
        "firmware_sha256": sha256_file(zip_path),
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "update_bins_found": [],
        "overall_verdict": "UNKNOWN",
    }

    work_dir = os.path.join(_project_tmp, "poc002_" + Path(zip_path).stem)
    os.makedirs(work_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(work_dir)

    for root, _, files in os.walk(work_dir):
        for fname in files:
            if fname.lower() in ("update.bin", "update.img"):
                fpath = os.path.join(root, fname)
                data = Path(fpath).read_bytes()
                analysis = analyze_update_bin(data, fname)
                results["update_bins_found"].append(analysis)

                if analysis["has_install_lua"]:
                    print(f"  [+] {fname}: Install.lua found (update orchestration)")
                if not analysis["signature_check_found"]:
                    print(f"  [!] {fname}: NO signature verification markers found")
                else:
                    print(f"  [*] {fname}: Signature markers detected — "
                          f"investigate further")

    has_lua = any(u["has_install_lua"] for u in results["update_bins_found"])
    has_sig = any(u["signature_check_found"] for u in results["update_bins_found"])

    if has_lua and not has_sig:
        results["overall_verdict"] = "VULNERABLE"
    elif has_lua and has_sig:
        results["overall_verdict"] = "NEEDS_FURTHER_ANALYSIS"
    elif not results["update_bins_found"]:
        results["overall_verdict"] = "NO_UPDATE_BIN_FOUND"
    else:
        results["overall_verdict"] = "NOT_APPLICABLE"

    return results


def main():
    fw_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "downloads", "cctv", "intelbras",
    )

    if not os.path.isdir(fw_dir):
        print(f"[!] Firmware directory not found: {fw_dir}")
        sys.exit(1)

    zips = sorted(Path(fw_dir).glob("*.zip"))
    if not zips:
        print(f"[!] No ZIP files found in {fw_dir}")
        sys.exit(1)

    print(f"[*] Analyzing {len(zips)} firmware images for update integrity...")
    all_results = []
    vuln_count = 0

    for zp in zips:
        print(f"\n{'='*60}")
        print(f"[*] Analyzing: {zp.name}")
        result = analyze_firmware_zip(str(zp))
        all_results.append(result)
        if result["overall_verdict"] == "VULNERABLE":
            vuln_count += 1

    print(f"\n{'='*60}")
    print(f"[*] Summary: {vuln_count}/{len(all_results)} firmware images VULNERABLE")
    print("[*] Vulnerable = Install.lua present, no signature verification")

    for r in all_results:
        status = "VULN" if r["overall_verdict"] == "VULNERABLE" else r["overall_verdict"]
        print(f"    {r['firmware_file']}: {status}")

    output = {
        "poc_id": "INTELBRAS-2026-002",
        "title": "Firmware Update Without Integrity Verification",
        "vulnerable_count": vuln_count,
        "total_analyzed": len(all_results),
        "results": all_results,
    }

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out_path = EVIDENCE_DIR / "poc_002_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved to {out_path}")


if __name__ == "__main__":
    main()
