#!/usr/bin/env python3
"""Dahua CCTV — full local forensic from scratch (persist everything).

Verifies downloads, extracts key members to disk, runs indicator analysis,
and writes per-firmware + cross-model reports. Firmwares remain in
downloads/cctv/dahua/. All evidence under reports/dahua_cctv/.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parent.parent
FW_DIR = REPO / "downloads" / "cctv" / "dahua"
OUT = REPO / "reports" / "dahua_cctv"
EXTRACT_ROOT = OUT / "extracted"
EVIDENCE = OUT / "evidence"
TMP = REPO / ".tmp" / "dahua_full"
CDN = "https://files.dahua.support/Firmware/"
CHUNK = 1024 * 1024

CATALOG: list[dict[str, str]] = [
    {
        "filename": "DH_IPC-HX2XXX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S2/",
        "series": "Molec LITE265-S2",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX25(8)XX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S2/",
        "series": "Molec LITE265-S2",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX1XXX-Hertz_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Hertz LITE265-S4",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX1XXX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Molec LITE265-S4",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX25(8)XX-Molec_MultiLang_PN_V2.820.0000000.33.R.210705.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Molec LITE265-S4 legacy",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX2(1)XXX-Euler_EngSpnRus_PN_V2.840.0000000.15.R.250730.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S5/",
        "series": "Euler LITE265-S5",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX2(1)XXX-Molec_EngSpnRus_PN_V2.840.0000000.15.R.250730.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S5/",
        "series": "Molec LITE265-S5",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX18XX-Molec_EngSpnRus_PN_V2.840.0000000.13.R.240726.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S6/",
        "series": "Molec LITE265-S6",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX1XXX-Kant_EngSpnRusUkr_PN_V2.880.0000000.20.R.260312.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S6/",
        "series": "Kant LITE265-S6 (CDN current)",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX1XXX-Kant_EngSpnRus_PN_V2.880.0000000.17.R.250619.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Entry/",
        "series": "Kant Entry",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-HX2(1)XXX-Edison_EngSpnRus_P_V2.680.0000000.18.R.201214.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Entry/",
        "series": "Edison Entry",
        "class": "IPC",
    },
    {
        "filename": "DH_IPC-Consumer-Chou-Rhea_Eng_P_V2.622.0000000.17.R.210915.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Consumer/",
        "series": "Chou-Rhea Consumer",
        "class": "IPC",
    },
    {
        "filename": "DH_NVR4x-4KS2L_MultiLang_V4.003.0000000.1.R.240515.bin",
        "relpath": "Rejestratory/NVR/NVR4xxx-4KS2L/",
        "series": "NVR4x-4KS2L",
        "class": "NVR",
    },
    {
        "filename": "DH_SD-Kant_MultiLang_PN_V2.820.0000016.0.R.250617.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Consumer/",
        "series": "SD-Kant Consumer PTZ",
        "class": "PTZ",
    },
]

KEEP_EXTRACT = {
    "Install",
    "install",
    "Install.lua",
    "sign.img",
    "check.img",
    "hwid",
    "dhboot.bin.img",
    "dhboot-bak.bin.img",
    "dhboot-min.bin.img",
    "IPL.bin.img",
    "IPL_CUST.bin.img",
    "u-boot.bin.img",
    "dhdtb.bin.img",
    "partition-x.cramfs.img",
    "partition.img",
    "partition_bak.img",
    "param.bin.img",
}

# Also keep small members and any *.lua / *.txt / *.json-like
KEEP_EXT = {".lua", ".txt", ".json", ".conf", ".cfg", ".xml"}
MAX_KEEP_BYTES = 2 * 1024 * 1024  # extract members up to 2MB always if interesting name
MAX_BOOT_BYTES = 8 * 1024 * 1024

PEM_HDR = re.compile(rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
PEM_END = re.compile(rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")

MARKERS = {
    "PEM_BEGIN": rb"-----BEGIN ",
    "sign.img": b"sign.img",
    "check.img": b"check.img",
    "bootargs": b"bootargs",
    "console=tty": b"console=tty",
    "PPPP": b"PPPP",
    "iLnkP2P": b"iLnkP2P",
    "P2P": b"P2P",
    "RPC2": b"RPC2",
    "RPC2_Login": b"RPC2_Login",
    "configManager.cgi": b"configManager.cgi",
    "magicBox.cgi": b"magicBox.cgi",
    "current_config/passwd": b"/current_config/passwd",
    "37777": b"37777",
    "DVRIP": b"DVRIP",
    "openssl": b"openssl",
    "RSA_verify": b"RSA_verify",
    "verify_sign": b"verify_sign",
    "CheckSign": b"CheckSign",
    "Hi3516": b"Hi3516",
    "SigmaStar": b"SigmaStar",
    "SSC027": b"SSC027",
    "INFINITY6": b"INFINITY6",
    "squashfs": b"squashfs",
    "cramfs": b"cramfs",
}

SOC_NEEDLES = [
    (b"Hi3516", "HiSilicon"),
    (b"Hi3518", "HiSilicon"),
    (b"Hi3519", "HiSilicon"),
    (b"SSC027", "SigmaStar"),
    (b"SSC33", "SigmaStar"),
    (b"INFINITY6", "SigmaStar"),
    (b"SigmaStar", "SigmaStar"),
    (b"Ingenic", "Ingenic"),
    (b"XBurst", "Ingenic"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def cdn_url(relpath: str, filename: str) -> str:
    parts = [quote(p, safe="()-._~") for p in relpath.strip("/").split("/")]
    return CDN + "/".join(parts) + "/" + quote(filename, safe="()-._~")


def ensure_download(meta: dict[str, str], dest: Path) -> dict[str, Any]:
    url = cdn_url(meta["relpath"], meta["filename"])
    if dest.exists() and dest.stat().st_size > 1_000_000:
        return {
            "status": "present",
            "url": url,
            "bytes": dest.stat().st_size,
            "sha256": sha256_file(dest),
        }
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = Request(url, headers={"User-Agent": "UniaoGeek-FirmwareResearch/1.0"})
    try:
        with urlopen(req, timeout=180) as resp, tmp.open("wb") as out:
            total = 0
            while True:
                block = resp.read(CHUNK)
                if not block:
                    break
                out.write(block)
                total += len(block)
        tmp.replace(dest)
        return {
            "status": "downloaded",
            "url": url,
            "bytes": total,
            "sha256": sha256_file(dest),
        }
    except Exception as exc:  # noqa: BLE001
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return {"status": "error", "url": url, "error": str(exc)}


def open_zip_bytes(raw: bytes) -> zipfile.ZipFile:
    """Open standard ZIP or Dahua DH-magic ZIP (PK replaced by DH)."""
    bio = io.BytesIO(raw)
    try:
        return zipfile.ZipFile(bio)
    except zipfile.BadZipFile:
        pass
    # Patch DH -> PK for local headers and EOCD signatures commonly used by Dahua
    patched = bytearray(raw)
    # Local file header 0x04034b50 / Dahua 0x04034844 ('DH\x03\x04')
    for sig_from, sig_to in (
        (b"DH\x03\x04", b"PK\x03\x04"),
        (b"DH\x01\x02", b"PK\x01\x02"),
        (b"DH\x05\x06", b"PK\x05\x06"),
        (b"DH\x06\x06", b"PK\x06\x06"),
    ):
        start = 0
        while True:
            idx = patched.find(sig_from, start)
            if idx < 0:
                break
            patched[idx : idx + 4] = sig_to
            start = idx + 4
    return zipfile.ZipFile(io.BytesIO(bytes(patched)))


def should_extract(name: str, size: int) -> bool:
    base = name.rsplit("/", 1)[-1]
    if base in KEEP_EXTRACT:
        return size <= MAX_BOOT_BYTES
    ext = Path(base).suffix.lower()
    if ext in KEEP_EXT and size <= MAX_KEEP_BYTES:
        return True
    if size <= 64 * 1024 and (
        "install" in base.lower() or "sign" in base.lower() or "check" in base.lower()
    ):
        return True
    return False


def scan_markers(data: bytes, limit_per: int = 3) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for label, needle in MARKERS.items():
        hits = []
        start = 0
        while len(hits) < limit_per:
            idx = data.find(needle, start)
            if idx < 0:
                break
            ctx = data[max(0, idx - 24) : idx + len(needle) + 40]
            hits.append(
                {"offset": idx, "context": ctx.decode("ascii", errors="replace")}
            )
            start = idx + 1
        if hits:
            out[label] = hits
    return out


def pem_analysis(data: bytes) -> dict[str, Any]:
    headers = list(PEM_HDR.finditer(data))
    ends = list(PEM_END.finditer(data))
    details = []
    realish = 0
    for m in headers:
        off = m.start()
        window = data[off : off + 256]
        after = data[m.end() : m.end() + 128]
        b64 = re.findall(rb"[A-Za-z0-9+/=]{40,}", after)
        has_end = bool(PEM_END.search(data[off : off + 9000]))
        looks_real = len(b64) >= 3 and has_end
        if looks_real:
            realish += 1
        details.append(
            {
                "offset": off,
                "header": m.group(0).decode("ascii", errors="replace"),
                "hex_128": window[:128].hex(),
                "ascii_preview": window[:120].decode("ascii", errors="replace"),
                "nul_terminated_next": after[:1] == b"\x00",
                "base64_runs_nearby": len(b64),
                "has_end_nearby": has_end,
                "looks_like_real_pem": looks_real,
            }
        )
    return {
        "header_count": len(headers),
        "end_count": len(ends),
        "real_pem_candidates": realish,
        "details": details,
    }


def detect_soc(data: bytes) -> list[str]:
    found = []
    for needle, vendor in SOC_NEEDLES:
        if needle in data:
            label = f"{vendor}:{needle.decode('ascii', 'replace')}"
            if label not in found:
                found.append(label)
    return found


def analyze_install(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    enforce = []
    for s in (
        "openssl",
        "rsa_verify",
        "verify_sign",
        "signature",
        "sha256",
        "md5sum",
        "CheckSign",
        "VerifyPackage",
        "sign.img",
        "crc32",
    ):
        if s.lower() in text.lower():
            enforce.append(s)
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text": text,
        "looks_json": text.lstrip().startswith("{"),
        "looks_lua": "function " in text or text.lstrip().startswith("--"),
        "enforcement_needles": enforce,
    }


def analyze_one(path: Path, meta: dict[str, str], dl: dict[str, Any]) -> dict[str, Any]:
    stem = path.stem
    # Windows-safe folder name
    safe = re.sub(r"[^\w.\-()+]", "_", stem)[:120]
    ext_dir = EXTRACT_ROOT / safe
    ext_dir.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "complete_firmware_name": path.name,
        "series": meta["series"],
        "product_class": meta["class"],
        "local_path": str(path),
        "extract_dir": str(ext_dir),
        "source_url": dl.get("url") or cdn_url(meta["relpath"], meta["filename"]),
        "size_bytes": path.stat().st_size,
        "sha256": dl.get("sha256") or sha256_file(path),
        "download": {k: v for k, v in dl.items() if k != "sha256"},
        "container": {},
        "members": [],
        "extracted_files": [],
        "install": None,
        "install_lua": None,
        "sign_img": None,
        "check_img": None,
        "bootloaders": [],
        "pem": {"header_count": 0, "end_count": 0, "real_pem_candidates": 0},
        "markers_aggregate": {},
        "soc_hints": [],
        "errors": [],
    }

    with path.open("rb") as fh:
        magic = fh.read(16)
    report["container"]["magic_hex"] = magic.hex()
    report["container"]["magic_ascii"] = magic.decode("ascii", errors="replace")

    zf: zipfile.ZipFile | None = None
    raw_holder: bytes | None = None
    try:
        zf = zipfile.ZipFile(path)
        report["container"]["type"] = "zip"
    except zipfile.BadZipFile:
        raw_holder = path.read_bytes()
        try:
            zf = open_zip_bytes(raw_holder)
            report["container"]["type"] = "zip_or_dh_zip"
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(f"zip_open: {exc}")
            report["container"]["type"] = "unknown_non_zip"
            head = raw_holder[: 8 * 1024 * 1024]
            report["markers_aggregate"] = scan_markers(head)
            report["soc_hints"] = detect_soc(head)
            pem = pem_analysis(head)
            report["pem"] = {
                "header_count": pem["header_count"],
                "end_count": pem["end_count"],
                "real_pem_candidates": pem["real_pem_candidates"],
            }
            (ext_dir / "_raw_head_8mb.bin").write_bytes(head)
            report["extracted_files"].append("_raw_head_8mb.bin")
            del raw_holder, head
            return report

    assert zf is not None
    with zf:
        report["members"] = [
            {
                "name": i.filename,
                "size": i.file_size,
                "compressed": i.compress_size,
                "crc": i.CRC,
            }
            for i in zf.infolist()
        ]

        agg: dict[str, Any] = {}
        socs: list[str] = []

        for info in zf.infolist():
            name = info.filename
            base = name.rsplit("/", 1)[-1]
            try:
                # Always read small/interesting; skip huge payloads for full load
                if info.file_size > MAX_BOOT_BYTES and not should_extract(name, info.file_size):
                    # sample first 64KB for markers only
                    with zf.open(name) as fp:
                        sample = fp.read(64 * 1024)
                    for k, hits in scan_markers(sample).items():
                        agg.setdefault(k, [])
                        for h in hits[:1]:
                            h2 = dict(h)
                            h2["member"] = name
                            if len(agg[k]) < 5:
                                agg[k].append(h2)
                    for s in detect_soc(sample):
                        if s not in socs:
                            socs.append(s)
                    continue

                data = zf.read(name)
            except Exception as exc:  # noqa: BLE001
                report["errors"].append(f"read {name}: {exc}")
                continue

            # Extract to disk when policy says so
            if should_extract(name, len(data)):
                out_name = base
                # avoid collisions
                dest = ext_dir / out_name
                if dest.exists():
                    dest = ext_dir / f"{hashlib.md5(name.encode()).hexdigest()[:8]}_{out_name}"
                dest.write_bytes(data)
                report["extracted_files"].append(dest.name)
                # sidecar metadata
                meta_path = dest.with_suffix(dest.suffix + ".meta.json")
                meta_path.write_text(
                    json.dumps(
                        {
                            "zip_member": name,
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )

            # Specific analyses
            if base.lower() == "install":
                inst = analyze_install(data)
                # persist text
                (ext_dir / "Install.txt").write_text(inst["text"], encoding="utf-8")
                report["install"] = {
                    k: v for k, v in inst.items() if k != "text"
                }
                report["install"]["saved_as"] = "Install.txt"
            if base.lower() == "install.lua":
                inst = analyze_install(data)
                (ext_dir / "Install.lua").write_text(inst["text"], encoding="utf-8")
                report["install_lua"] = {
                    k: v for k, v in inst.items() if k != "text"
                }
                report["install_lua"]["saved_as"] = "Install.lua"
            if base == "sign.img":
                report["sign_img"] = {
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "hex": data.hex(),
                }
                (ext_dir / "sign.img.hex").write_text(data.hex(), encoding="ascii")
            if base == "check.img":
                report["check_img"] = {
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "hex_preview": data[:256].hex(),
                }

            if base in KEEP_EXTRACT and (
                "boot" in base.lower() or base.startswith("IPL") or base.startswith("u-boot")
            ):
                pem = pem_analysis(data)
                bl = {
                    "name": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "pem": pem,
                    "soc_hints": detect_soc(data),
                }
                report["bootloaders"].append(bl)
                report["pem"]["header_count"] += pem["header_count"]
                report["pem"]["end_count"] += pem["end_count"]
                report["pem"]["real_pem_candidates"] += pem["real_pem_candidates"]
                if pem["details"]:
                    (ext_dir / f"pem_{base}.json").write_text(
                        json.dumps(pem, indent=2), encoding="utf-8"
                    )

            # Marker scan (cap size already)
            if len(data) <= MAX_BOOT_BYTES:
                for k, hits in scan_markers(data).items():
                    agg.setdefault(k, [])
                    for h in hits[:2]:
                        h2 = dict(h)
                        h2["member"] = name
                        if len(agg[k]) < 8:
                            agg[k].append(h2)
                for s in detect_soc(data):
                    if s not in socs:
                        socs.append(s)

            del data

        report["markers_aggregate"] = agg
        report["soc_hints"] = socs

        # Save member listing
        (ext_dir / "_members.json").write_text(
            json.dumps(report["members"], indent=2), encoding="utf-8"
        )

    if raw_holder is not None:
        del raw_holder

    # Per-firmware report JSON + markdown summary
    (ext_dir / "FORENSIC_REPORT.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    md = [
        f"# Forensic — {path.name}",
        "",
        f"- Series: {meta['series']}",
        f"- Class: {meta['class']}",
        f"- SHA256: `{report['sha256']}`",
        f"- Size: {report['size_bytes']}",
        f"- URL: {report['source_url']}",
        f"- Container: {report['container'].get('type')}",
        f"- Members: {len(report['members'])}",
        f"- Extracted files: {len(report['extracted_files'])}",
        f"- PEM headers: {report['pem']['header_count']} (real candidates: {report['pem']['real_pem_candidates']})",
        f"- sign.img: {bool(report['sign_img'])} size={ (report['sign_img'] or {}).get('size') }",
        f"- Install: {bool(report['install'])} needles={ (report['install'] or {}).get('enforcement_needles') }",
        f"- Install.lua: {bool(report['install_lua'])} needles={ (report['install_lua'] or {}).get('enforcement_needles') }",
        f"- SoC hints: {report['soc_hints']}",
        f"- Marker keys: {sorted(report['markers_aggregate'].keys())}",
        "",
    ]
    if report["install"]:
        md.append("## Install")
        md.append("```")
        # reload text from disk if saved
        inst_txt = ext_dir / "Install.txt"
        if inst_txt.exists():
            md.append(inst_txt.read_text(encoding="utf-8")[:4000])
        md.append("```")
        md.append("")
    (ext_dir / "FORENSIC_REPORT.md").write_text("\n".join(md), encoding="utf-8")
    return report


def write_master(results: list[dict[str, Any]]) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    (EVIDENCE / "full_forensic_all.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    inv_rows = []
    for r in results:
        inv_rows.append(
            {
                "complete_firmware_name": r.get("complete_firmware_name"),
                "sha256": r.get("sha256"),
                "size_bytes": r.get("size_bytes"),
                "series": r.get("series"),
                "product_class": r.get("product_class"),
                "source_url": r.get("source_url"),
                "local_path": r.get("local_path"),
                "extract_dir": r.get("extract_dir"),
                "pem_headers": (r.get("pem") or {}).get("header_count", 0),
                "pem_real": (r.get("pem") or {}).get("real_pem_candidates", 0),
                "sign_img": bool(r.get("sign_img")),
                "sign_size": (r.get("sign_img") or {}).get("size"),
                "install": bool(r.get("install")),
                "install_lua": bool(r.get("install_lua")),
                "install_needles": (r.get("install") or {}).get("enforcement_needles"),
                "install_lua_needles": (r.get("install_lua") or {}).get(
                    "enforcement_needles"
                ),
                "soc_hints": r.get("soc_hints"),
                "marker_keys": sorted((r.get("markers_aggregate") or {}).keys()),
                "errors": r.get("errors"),
            }
        )

    (EVIDENCE / "full_inventory.json").write_text(
        json.dumps(inv_rows, indent=2), encoding="utf-8"
    )
    csv = [
        "complete_firmware_name,sha256,size_bytes,series,class,pem_headers,pem_real,sign_size,markers"
    ]
    for row in inv_rows:
        csv.append(
            ",".join(
                [
                    str(row["complete_firmware_name"]),
                    str(row["sha256"]),
                    str(row["size_bytes"]),
                    str(row["series"]).replace(",", ";"),
                    str(row["product_class"]),
                    str(row["pem_headers"]),
                    str(row["pem_real"]),
                    str(row["sign_size"] or 0),
                    "|".join(row["marker_keys"] or []),
                ]
            )
        )
    (EVIDENCE / "full_inventory.csv").write_text("\n".join(csv) + "\n", encoding="utf-8")

    # Cross markdown
    lines = [
        "# Dahua CCTV — Full Forensic Cross Analysis (from scratch)",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "**Researcher:** Andre Henrique (@mrhenrike) | Uniao Geek",
        f"**Firmwares:** {len(results)}",
        f"**Firmware dir:** `{FW_DIR}`",
        f"**Extract dir:** `{EXTRACT_ROOT}`",
        "",
        "## Inventory",
        "",
        "| Firmware | SHA256 | PEM hdr | PEM real | sign | Install needles | Markers |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for row in inv_rows:
        lines.append(
            "| `{name}` | `{sha}` | {ph} | {pr} | {ss} | {need} | {mk} |".format(
                name=row["complete_firmware_name"],
                sha=(row["sha256"] or "")[:16] + "...",
                ph=row["pem_headers"],
                pr=row["pem_real"],
                ss=row["sign_size"] or 0,
                need=",".join(row["install_needles"] or row["install_lua_needles"] or [])
                or "-",
                mk=",".join(row["marker_keys"] or []) or "-",
            )
        )

    lines += [
        "",
        "## Key conclusions",
        "",
        "1. **DAHUA-2026-001:** PEM headers present on Molec/Hertz/Euler bootloaders; "
        f"real PEM body candidates total = "
        f"{sum(r.get('pem', {}).get('real_pem_candidates', 0) for r in results)}. "
        "Headers are typically NUL-terminated string tables (PSIRT claim supported when real=0).",
        "2. **DAHUA-2026-002:** Install is JSON burn list on IPC; NVR uses Install.lua with "
        "version/vendor/CRC gates. sign.img present on packages. Crypto verify needles in Install are absent unless listed above.",
        "3. **Persistence:** Original `.bin` kept under `downloads/cctv/dahua/`. "
        "Per-firmware extracts + reports under `reports/dahua_cctv/extracted/<name>/`.",
        "",
        "## Per-firmware paths",
        "",
    ]
    for row in inv_rows:
        lines.append(
            f"- `{row['complete_firmware_name']}` → `{row['extract_dir']}`"
        )

    (OUT / "CROSS_ANALYSIS_FULL.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "MASTER_FORENSIC_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    FW_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_ROOT.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for meta in CATALOG:
        dest = FW_DIR / meta["filename"]
        print(f"[*] {meta['filename']}")
        dl = ensure_download(meta, dest)
        print(f"    download={dl.get('status')} bytes={dl.get('bytes', dl.get('error'))}")
        if dl.get("status") == "error":
            results.append(
                {
                    "complete_firmware_name": meta["filename"],
                    "series": meta["series"],
                    "product_class": meta["class"],
                    "download": dl,
                    "errors": [dl.get("error")],
                    "pem": {"header_count": 0, "real_pem_candidates": 0},
                    "markers_aggregate": {},
                    "soc_hints": [],
                }
            )
            continue
        report = analyze_one(dest, meta, dl)
        # also copy report json into evidence/
        slug = re.sub(r"[^\w.\-()+]", "_", dest.stem)[:100]
        (EVIDENCE / f"forensic_{slug}.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(
            "    pem={h}/{r} sign={s} members={m} extracted={e} markers={mk}".format(
                h=report["pem"]["header_count"],
                r=report["pem"]["real_pem_candidates"],
                s=bool(report["sign_img"]),
                m=len(report["members"]),
                e=len(report["extracted_files"]),
                mk=sorted(report["markers_aggregate"].keys()),
            )
        )
        results.append(report)

    write_master(results)
    print(f"[+] firmwares in {FW_DIR}")
    print(f"[+] extracts in {EXTRACT_ROOT}")
    print(f"[+] evidence in {EVIDENCE}")
    print(f"[+] master {OUT / 'MASTER_FORENSIC_REPORT.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
