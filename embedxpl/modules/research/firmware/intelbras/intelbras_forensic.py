#!/usr/bin/env python3
"""
intelbras_forensic.py — Forensic analysis of Intelbras CCTV firmware
Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

Performs automated forensic analysis on downloaded Intelbras firmware:
- ZIP extraction
- binwalk signature scan
- Entropy analysis
- strings grep for credentials, keys, CGI paths, library versions
- Platform/SoC identification
- Web server fingerprinting
- Generates per-model forensic_report.md

Usage:
    python scripts/intelbras_forensic.py --all
    python scripts/intelbras_forensic.py --model "VIP 3230 B SD"
"""

import argparse
import hashlib
import io
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ("utf-8", "utf8"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).resolve().parent.parent
DOWNLOADS_DIR = REPO_ROOT / "downloads" / "cctv" / "intelbras"
REPORTS_DIR = REPO_ROOT / "reports"
TMP_DIR = REPO_ROOT / ".tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)
os.environ["TMPDIR"] = str(TMP_DIR)
tempfile.tempdir = str(TMP_DIR)

CRED_PATTERNS = [
    (r"admin", "Default admin username"),
    (r"password\s*[:=]\s*\S+", "Hardcoded password assignment"),
    (r"root:\$[156]\$", "Shadow file hash (root)"),
    (r"root:[^:]*:0:0:", "Passwd entry (root UID 0)"),
    (r"default[_-]?pass", "Default password reference"),
    (r"telnet.*enable", "Telnet enable flag"),
    (r"ssh.*enable", "SSH enable flag"),
    (r"/cgi-bin/", "CGI handler path"),
    (r"\.cgi\b", "CGI file reference"),
    (r"\.lua\b", "Lua script reference"),
    (r"GoAhead", "GoAhead web server"),
    (r"[Bb]oa[/ ]", "Boa web server"),
    (r"[Ll]ighttpd", "Lighttpd web server"),
    (r"[Tt]httpd", "Thttpd web server"),
    (r"[Bb]usy[Bb]ox", "BusyBox multi-call binary"),
    (r"OpenSSL\s+[\d.]+", "OpenSSL version"),
    (r"glibc\s+[\d.]+|GLIBC_[\d.]+", "glibc version"),
    (r"uClibc", "uClibc library"),
    (r"HiSilicon|hi35\d+|Hi35\d+", "HiSilicon SoC"),
    (r"SigmaStar|SSC\d+", "SigmaStar SoC"),
    (r"Ambarella|amba", "Ambarella SoC"),
    (r"-----BEGIN.*KEY-----", "Private key header"),
    (r"-----BEGIN CERTIFICATE-----", "Certificate header"),
    (r"firmware.*upgrade|upgrade.*firmware", "Firmware upgrade reference"),
    (r"ONVIF|onvif", "ONVIF protocol"),
    (r"rtsp://", "RTSP URL"),
    (r"p2p.*cloud|P2P.*Cloud|DMSS|iDMSS", "P2P cloud module"),
    (r"DownloadCfg|downloadcfg|ConfigBackup", "Config download endpoint"),
    (r"update\.cgi|upgrade\.cgi|firmwareupgrade", "Firmware update CGI"),
    (r"NetworkCfg|UserCfg|SystemCfg", "Config file reference"),
]

FILESYSTEM_SIGNATURES = {
    b"hsqs": "SquashFS (little-endian)",
    b"sqsh": "SquashFS (big-endian)",
    b"\x85\x19\x01\xe0": "JFFS2 (little-endian)",
    b"\xe0\x01\x19\x85": "JFFS2 (big-endian)",
    b"\x28\xcd\x3d\x45": "CRAMFS",
    b"\x3d\xcd\x28\x45": "CRAMFS (big-endian)",
    b"\x1f\x8b": "Gzip compressed data",
    b"BZ": "Bzip2 compressed data",
    b"\xfd\x37\x7a\x58\x5a\x00": "XZ compressed data",
    b"\x89PNG": "PNG image",
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"UBI#": "UBI filesystem",
    b"\xd0\x0d\xfe\xed": "Device Tree Blob (DTB)",
}


def calculate_entropy(data: bytes, block_size: int = 256) -> list[float]:
    entropies = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < 16:
            continue
        counter = Counter(block)
        length = len(block)
        entropy = -sum((c / length) * math.log2(c / length) for c in counter.values() if c > 0)
        entropies.append(entropy)
    return entropies


def overall_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values() if c > 0)


def find_filesystem_signatures(data: bytes) -> list[dict]:
    found = []
    for sig, name in FILESYSTEM_SIGNATURES.items():
        offset = 0
        while True:
            idx = data.find(sig, offset)
            if idx == -1:
                break
            found.append({"offset": idx, "hex_offset": f"0x{idx:08X}", "signature": name})
            offset = idx + len(sig)
    return sorted(found, key=lambda x: x["offset"])


def extract_strings(data: bytes, min_length: int = 6) -> list[str]:
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [m.decode("ascii", errors="replace") for m in re.findall(pattern, data)]


def grep_patterns(strings: list[str]) -> list[dict]:
    findings = []
    seen = set()
    for s in strings:
        for pattern, desc in CRED_PATTERNS:
            matches = re.findall(pattern, s, re.IGNORECASE)
            for match in matches:
                key = (desc, match[:100])
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "category": desc,
                        "match": match[:200],
                        "context": s[:300],
                    })
    return findings


def run_binwalk(filepath: Path) -> str:
    try:
        result = subprocess.run(
            ["binwalk", "--signature", "--quiet", str(filepath)],
            capture_output=True, text=True, timeout=120, errors="replace"
        )
        return result.stdout
    except Exception as e:
        return f"binwalk error: {e}"


def analyze_firmware(zip_path: Path, model: str) -> dict:
    print(f"\n{'='*70}")
    print(f"  Analyzing: {model}")
    print(f"  File: {zip_path.name} ({zip_path.stat().st_size:,} bytes)")
    print(f"{'='*70}")

    report = {
        "model": model,
        "filename": zip_path.name,
        "file_size": zip_path.stat().st_size,
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "zip_contents": [],
        "binwalk_results": {},
        "filesystem_signatures": {},
        "entropy": {},
        "strings_findings": [],
        "cgi_handlers": [],
        "credentials": [],
        "libraries": [],
        "platform": {},
        "web_server": "unknown",
        "services": [],
        "firmware_update_mechanism": [],
        "p2p_cloud": [],
    }

    extract_dir = TMP_DIR / f"intelbras_{model.replace(' ', '_')}"
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                report["zip_contents"].append({
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                })
            zf.extractall(extract_dir)
            print(f"  Extracted {len(zf.infolist())} files to {extract_dir.name}")
    except zipfile.BadZipFile:
        print("  [WARN] Not a valid ZIP — treating as raw firmware binary")
        report["zip_contents"].append({
            "name": zip_path.name,
            "size": zip_path.stat().st_size,
            "note": "Raw binary (not ZIP)",
        })

    fw_files = list(extract_dir.rglob("*"))
    fw_files = [f for f in fw_files if f.is_file() and f.stat().st_size > 1024]
    if not fw_files:
        fw_files = [zip_path]

    for fw_file in fw_files:
        fname = fw_file.name
        fsize = fw_file.stat().st_size
        print(f"\n  --- {fname} ({fsize:,} bytes) ---")

        binwalk_out = run_binwalk(fw_file)
        report["binwalk_results"][fname] = binwalk_out
        bw_lines = [l for l in binwalk_out.strip().split("\n") if l.strip() and not l.startswith("DECIMAL")]
        print(f"  binwalk: {len(bw_lines)} signatures found")
        for line in bw_lines[:10]:
            print(f"    {line.strip()}")

        with open(fw_file, "rb") as f:
            data = f.read(min(fsize, 50 * 1024 * 1024))

        ent = overall_entropy(data[:1024*1024])
        report["entropy"][fname] = round(ent, 4)
        print(f"  Entropy (first 1MB): {ent:.4f}")

        fs_sigs = find_filesystem_signatures(data)
        if fs_sigs:
            report["filesystem_signatures"][fname] = fs_sigs
            for sig in fs_sigs[:5]:
                print(f"  FS: {sig['hex_offset']} — {sig['signature']}")

        strings = extract_strings(data)
        print(f"  Strings: {len(strings)} extracted")

        findings = grep_patterns(strings)
        for f_item in findings:
            cat = f_item["category"]

            if "CGI" in cat or "cgi" in f_item["match"].lower():
                if f_item not in report["cgi_handlers"]:
                    report["cgi_handlers"].append(f_item)
            elif "password" in cat.lower() or "hash" in cat.lower() or "passwd" in cat.lower() or "Default" in cat:
                if f_item not in report["credentials"]:
                    report["credentials"].append(f_item)
            elif "version" in cat.lower() or "library" in cat.lower() or "glibc" in cat.lower():
                if f_item not in report["libraries"]:
                    report["libraries"].append(f_item)
            elif "SoC" in cat or "HiSilicon" in cat or "SigmaStar" in cat or "Ambarella" in cat:
                report["platform"][f_item["match"]] = f_item["category"]
            elif "web server" in cat.lower():
                report["web_server"] = f_item["match"]
            elif "ONVIF" in cat or "RTSP" in cat or "Telnet" in cat or "SSH" in cat:
                report["services"].append(f_item)
            elif "Firmware" in cat or "update" in cat.lower() or "upgrade" in cat.lower():
                report["firmware_update_mechanism"].append(f_item)
            elif "P2P" in cat or "cloud" in cat.lower():
                report["p2p_cloud"].append(f_item)
            else:
                report["strings_findings"].append(f_item)

    print("\n  Summary:")
    print(f"    CGI handlers: {len(report['cgi_handlers'])}")
    print(f"    Credentials:  {len(report['credentials'])}")
    print(f"    Libraries:    {len(report['libraries'])}")
    print(f"    Platform:     {report['platform'] or 'unknown'}")
    print(f"    Web server:   {report['web_server']}")
    print(f"    Services:     {len(report['services'])}")

    import shutil
    shutil.rmtree(extract_dir, ignore_errors=True)

    return report


def generate_forensic_report_md(report: dict, output_path: Path):
    model = report["model"]
    lines = [
        f"# Forensic Analysis Report — Intelbras {model}",
        f"<!-- Generated: {report['analysis_date']} -->",
        "<!-- Author: André Henrique (@mrhenrike) | União Geek -->",
        "",
        "## Target Profile",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Model | {model} |",
        f"| Filename | `{report['filename']}` |",
        f"| File Size | {report['file_size']:,} bytes ({report['file_size']/1024/1024:.1f} MB) |",
        f"| Analysis Date | {report['analysis_date']} |",
        f"| Platform/SoC | {', '.join(report['platform'].keys()) if report['platform'] else 'Not identified'} |",
        f"| Web Server | {report['web_server']} |",
        "",
        "## ZIP Contents",
        "",
    ]

    if report["zip_contents"]:
        lines.append("| File | Size | Compressed |")
        lines.append("|---|---|---|")
        for zc in report["zip_contents"]:
            lines.append(f"| `{zc['name']}` | {zc['size']:,} | {zc.get('compressed_size', 'N/A')} |")
        lines.append("")

    lines.extend(["## Entropy Analysis", ""])
    for fname, ent in report["entropy"].items():
        enc_status = "HIGH — likely encrypted/compressed" if ent > 7.5 else "MODERATE — mixed data" if ent > 6.0 else "LOW — plaintext/sparse"
        lines.append(f"- `{fname}`: **{ent:.4f}** ({enc_status})")
    lines.append("")

    lines.extend(["## Filesystem Signatures", ""])
    for fname, sigs in report["filesystem_signatures"].items():
        lines.append(f"### `{fname}`")
        lines.append("| Offset | Signature |")
        lines.append("|---|---|")
        for sig in sigs[:20]:
            lines.append(f"| `{sig['hex_offset']}` | {sig['signature']} |")
        lines.append("")

    lines.extend(["## Binwalk Signature Scan", ""])
    for fname, bw in report["binwalk_results"].items():
        lines.append(f"### `{fname}`")
        lines.append("```")
        for line in bw.strip().split("\n")[:30]:
            lines.append(line)
        lines.append("```")
        lines.append("")

    if report["cgi_handlers"]:
        lines.extend(["## CGI Handlers & Web Endpoints", ""])
        lines.append("| Category | Match | Context (truncated) |")
        lines.append("|---|---|---|")
        seen = set()
        for f_item in report["cgi_handlers"][:50]:
            key = f_item["match"][:80]
            if key not in seen:
                seen.add(key)
                lines.append(f"| {f_item['category']} | `{f_item['match'][:80]}` | `{f_item['context'][:100]}` |")
        lines.append("")

    if report["credentials"]:
        lines.extend(["## Hardcoded Credentials & Secrets", ""])
        lines.append("| Category | Finding |")
        lines.append("|---|---|")
        seen = set()
        for f_item in report["credentials"][:30]:
            key = f_item["match"][:80]
            if key not in seen:
                seen.add(key)
                lines.append(f"| {f_item['category']} | `{f_item['match'][:120]}` |")
        lines.append("")

    if report["libraries"]:
        lines.extend(["## Library Versions", ""])
        lines.append("| Library | Version/Match |")
        lines.append("|---|---|")
        seen = set()
        for f_item in report["libraries"][:20]:
            key = f_item["match"][:60]
            if key not in seen:
                seen.add(key)
                lines.append(f"| {f_item['category']} | `{f_item['match'][:80]}` |")
        lines.append("")

    if report["services"]:
        lines.extend(["## Network Services", ""])
        for f_item in report["services"][:15]:
            lines.append(f"- **{f_item['category']}**: `{f_item['match'][:100]}`")
        lines.append("")

    if report["firmware_update_mechanism"]:
        lines.extend(["## Firmware Update Mechanism", ""])
        for f_item in report["firmware_update_mechanism"][:10]:
            lines.append(f"- **{f_item['category']}**: `{f_item['match'][:100]}`")
        lines.append("")

    if report["p2p_cloud"]:
        lines.extend(["## P2P Cloud Module", ""])
        for f_item in report["p2p_cloud"][:10]:
            lines.append(f"- **{f_item['category']}**: `{f_item['match'][:100]}`")
        lines.append("")

    lines.extend([
        "## Attack Surface Summary",
        "",
        "| # | Surface | Evidence | Risk |",
        "|---|---|---|---|",
    ])
    if report["cgi_handlers"]:
        lines.append(f"| 1 | Web CGI endpoints | {len(report['cgi_handlers'])} handlers found | HIGH |")
    if report["credentials"]:
        lines.append(f"| 2 | Hardcoded credentials | {len(report['credentials'])} findings | CRITICAL |")
    if report["services"]:
        lines.append(f"| 3 | Network services | {len(report['services'])} services | HIGH |")
    if report["firmware_update_mechanism"]:
        lines.append(f"| 4 | Firmware update | {len(report['firmware_update_mechanism'])} references | HIGH |")
    if report["p2p_cloud"]:
        lines.append(f"| 5 | P2P cloud | {len(report['p2p_cloud'])} references | MEDIUM |")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  Report saved: {output_path}")


def get_firmware_files() -> list[tuple[str, Path]]:
    import yaml
    manifest_file = REPO_ROOT / "manifests" / "download_manifest.yaml"
    with open(manifest_file, encoding="utf-8") as f:
        manifest = yaml.safe_load(f) or {}
    
    files = []
    for entry in manifest.get("downloads", []):
        if entry.get("brand") == "intelbras" and entry.get("status") == "ok":
            fp = REPO_ROOT / entry["filepath"]
            if fp.exists():
                files.append((entry["model"], fp))
    return files


def main():
    parser = argparse.ArgumentParser(description="Intelbras firmware forensic analysis")
    parser.add_argument("--all", action="store_true", help="Analyze all downloaded Intelbras firmwares")
    parser.add_argument("--model", help="Analyze specific model")
    args = parser.parse_args()

    if not (args.all or args.model):
        parser.print_help()
        return

    fw_files = get_firmware_files()
    
    if args.model:
        fw_files = [(m, p) for m, p in fw_files if args.model.lower() in m.lower()]
        if not fw_files:
            print(f"[ERROR] No firmware found for model: {args.model}")
            return

    all_reports = []
    for model, fw_path in fw_files:
        report = analyze_firmware(fw_path, model)
        all_reports.append(report)

        safe_model = model.lower().replace(" ", "_").replace("-", "_")
        report_dir = REPORTS_DIR / f"intelbras_{safe_model}"
        report_md = report_dir / "forensic_report.md"
        generate_forensic_report_md(report, report_md)

        evidence_dir = report_dir / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_json = evidence_dir / "forensic_data.json"

        serializable = {}
        for k, v in report.items():
            serializable[k] = v
        with open(evidence_json, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2, default=str)

    print(f"\n{'='*70}")
    print("FORENSIC ANALYSIS COMPLETE")
    print(f"{'='*70}")
    print(f"  Models analyzed: {len(all_reports)}")
    for r in all_reports:
        print(f"  - {r['model']}: {len(r['cgi_handlers'])} CGI, {len(r['credentials'])} creds, {r['web_server']}")


if __name__ == "__main__":
    main()
