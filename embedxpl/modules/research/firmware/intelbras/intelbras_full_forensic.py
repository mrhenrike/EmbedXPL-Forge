#!/usr/bin/env python3
"""Intelbras CCTV — download, forensic, PoC evidence pack (local corpus).

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parent.parent
FW_DIR = REPO / "downloads" / "cctv" / "intelbras"
OUT = REPO / "reports" / "intelbras_cctv"
EXTRACT = OUT / "extracted"
EV = OUT / "evidence"
SEVEN = r"C:\Program Files\7-Zip\7z.exe"
CHUNK = 1024 * 1024

# 10 firmwares from original disclosure (status ok in manifest)
CATALOG = [
    {
        "filename": "intelbras_VIP_3230_B_SD_firmware.zip",
        "model": "VIP 3230 B SD",
        "url": "https://backend.intelbras.com/sites/default/files/2025-02/Firmware_VIP_3230_29-10-21_0.zip",
        "expected_sha256": "d908f2fd6e23275693849d8f322d9995ce5926b9f5430a68863d2282e8238028",
    },
    {
        "filename": "intelbras_VIP_1130_D_firmware.zip",
        "model": "VIP 1130 D",
        "url": "https://backend.intelbras.com/sites/default/files/2025-02/Firmware_VIP_1130_26-10-23.zip",
        "expected_sha256": "a0379e2761a1eae67aff9f6eed35dbc79dbe8d098844c3a4c2d8e12ed5b4ce49",
    },
    {
        "filename": "intelbras_VIP_S3020_G2_firmware.zip",
        "model": "VIP S3020 G2",
        "url": "https://backend.intelbras.com/sites/default/files/integration/atualizacao_vip_s3020-g2_s4020-g2_s3330-g2_s4320-g2_-_29-03-2016_0.zip",
        "expected_sha256": "d8890fb655686775eb08a080e8d5742d7eaa06d9b9a3ac7569969d80c6433d3f",
    },
    {
        "filename": "intelbras_MHDX_1004-C_firmware.zip",
        "model": "MHDX 1004-C",
        "url": "https://backend.intelbras.com/sites/default/files/2024-10/Atualiza%C3%A7%C3%A3o%20de%20Firmware%20-%20MHDX%201004-C%20-%2015-08-2024%20-%20Vers%C3%A3o%204.zip",
        "expected_sha256": "03e31c6be197d7dad784ec95b7606983bffd69f49f6fe25eb5454c92e98bf7f9",
    },
    {
        "filename": "intelbras_MHDX_1108-C_firmware.zip",
        "model": "MHDX 1108-C",
        "url": "https://backend.intelbras.com/sites/default/files/2025-07/Atualiza%C3%A7%C3%A3o%20MHDX%201108-C%2011-06-25.zip",
        "expected_sha256": "ddbaa00ba13d7376db11549118129bc5da3b3e92995457fdfc42d59f700af0d3",
    },
    {
        "filename": "intelbras_MHDX_3108_firmware.zip",
        "model": "MHDX 3108",
        "url": "https://backend.intelbras.com/sites/default/files/2021-11/firmware-mhdx-3108-18-10-2021.zip",
        "expected_sha256": "05b7b945bcceaac21d9a343fa3444603d589e6cfce6fb0ba430c37ef0b3c8bd5",
    },
    {
        "filename": "intelbras_MHDX_1108_G3_firmware.zip",
        "model": "MHDX 1108 G3",
        "url": "https://backend.intelbras.com/sites/default/files/2023-06/MHDX%201108%20-%2005-06-2023.zip",
        "expected_sha256": "6eca968f88b7d335f496d5e56bafa717e4dea72673aeeeb1478c4c4cd763d0ad",
    },
    {
        "filename": "intelbras_NVD_1208_P_firmware.zip",
        "model": "NVD 1208 P",
        "url": "https://backend.intelbras.com/sites/default/files/2019-12/Intelbras_NVD1208_20191104.zip",
        "expected_sha256": "b0ef622be22fa8453106f126f54bfd5bf278af0f0f8dacca462f0aed5bfc735d",
    },
    {
        "filename": "intelbras_NVD_3316-P_firmware.zip",
        "model": "NVD 3316-P",
        "url": "https://backend.intelbras.com/sites/default/files/2025-09/atualizacao%20de%20fw%20NVD%203300%20-%2008-08-2025.zip",
        "expected_sha256": "615bdad8ca64958340fcf75267e5e6f7118869664e99a1e38b0a4c6abaf258c6",
    },
    {
        "filename": "intelbras_NVD_1432-P_firmware.zip",
        "model": "NVD 1432-P",
        "url": "https://backend.intelbras.com/sites/default/files/2026-03/Atualiza%C3%A7%C3%A3o%20de%20Firmware%20-%20NVD1432%20-10-03-2026.zip",
        "expected_sha256": "2462d9a131dd01f45bd9db2ad8f3234d2237dad781bf35dcab6d31fbbc0194e8",
    },
]

BOOT_NAMES = {
    "u-boot.bin.img",
    "uboot.bin.img",
    "dhboot.bin.img",
    "dhboot-bak.bin.img",
    "dhboot-min.bin.img",
    "IPL.bin.img",
    "IPL_CUST.bin.img",
}

PEM_HDR = re.compile(rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
PEM_END = re.compile(rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
PEM_FULL = re.compile(
    rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----"
    rb".{20,12000}?"
    rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----",
    re.DOTALL,
)

MARKERS = {
    "Boa": b"Boa/",
    "boa": b"boa",
    "Server: Boa": b"Server: Boa",
    "ONVIF": b"ONVIF",
    "onvif": b"onvif",
    "device_service": b"device_service",
    "configManager.cgi": b"configManager.cgi",
    "magicBox.cgi": b"magicBox.cgi",
    "current_config": b"current_config",
    "passwd": b"/passwd",
    "RPC2": b"RPC2",
    "telnet": b"telnet",
    "telnetd": b"telnetd",
    "PPPP": b"PPPP",
    "P2P": b"P2P",
    "iLnkP2P": b"iLnkP2P",
    "Dahua": b"Dahua",
    "dahua": b"dahua",
    "sign.img": b"sign.img",
    "check.img": b"check.img",
    "Install": b"Install",
    "openssl": b"openssl",
    "verify_sign": b"verify_sign",
    "37777": b"37777",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def download(meta: dict[str, str], dest: Path) -> dict[str, Any]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1_000_000:
        digest = sha256_file(dest)
        return {
            "status": "present",
            "bytes": dest.stat().st_size,
            "sha256": digest,
            "sha256_match": digest.lower() == meta["expected_sha256"].lower(),
        }
    req = Request(meta["url"], headers={"User-Agent": "Mozilla/5.0 (compatible; UniaoGeek-Research/1.0)"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urlopen(req, timeout=300) as resp, tmp.open("wb") as out:
            total = 0
            while True:
                block = resp.read(CHUNK)
                if not block:
                    break
                out.write(block)
                total += len(block)
        tmp.replace(dest)
        digest = sha256_file(dest)
        return {
            "status": "downloaded",
            "bytes": total,
            "sha256": digest,
            "sha256_match": digest.lower() == meta["expected_sha256"].lower(),
            "url": meta["url"],
        }
    except Exception as exc:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return {"status": "error", "error": str(exc), "url": meta["url"]}


def pem_analysis(data: bytes) -> dict[str, Any]:
    headers = list(PEM_HDR.finditer(data))
    ends = list(PEM_END.finditer(data))
    full = list(PEM_FULL.finditer(data))
    details = []
    realish = 0
    for m in headers:
        off = m.start()
        window = data[off : off + 256]
        after = data[m.end() : m.end() + 128]
        b64 = re.findall(rb"[A-Za-z0-9+/=]{40,}", after)
        has_end = bool(PEM_END.search(data[off : off + 9000]))
        looks = len(b64) >= 3 and has_end
        if looks:
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
                "looks_like_real_pem": looks,
            }
        )
    return {
        "header_count": len(headers),
        "end_count": len(ends),
        "full_block_regex_hits": len(full),
        "real_pem_candidates": realish,
        "details": details,
    }


def scan_markers(data: bytes) -> dict[str, Any]:
    out = {}
    for label, needle in MARKERS.items():
        idx = data.find(needle)
        if idx >= 0:
            ctx = data[max(0, idx - 20) : idx + len(needle) + 40]
            out[label] = {
                "offset": idx,
                "context": ctx.decode("ascii", errors="replace"),
            }
    return out


def analyze_install_text(text: str) -> dict[str, Any]:
    needles = []
    for s in (
        "openssl",
        "rsa",
        "verify",
        "signature",
        "sha256",
        "md5",
        "sign.img",
        "check.img",
        "crc32",
        "burn",
    ):
        if s.lower() in text.lower():
            needles.append(s)
    return {
        "size": len(text.encode("utf-8", errors="replace")),
        "looks_json": text.lstrip().startswith("{"),
        "looks_lua": "function " in text or text.lstrip().startswith("--"),
        "looks_shell": text.lstrip().startswith("#!"),
        "needles": needles,
        "text_preview": text[:2000],
    }


def seven_list(path: Path) -> list[str]:
    if not Path(SEVEN).exists():
        return []
    proc = subprocess.run(
        [SEVEN, "l", "-ba", "-slt", str(path)],
        capture_output=True,
        text=True,
        errors="replace",
    )
    names = []
    for line in proc.stdout.splitlines():
        if line.startswith("Path = ") and not line.endswith(path.name):
            names.append(line[7:])
    return names


def extract_interesting(path: Path, dest: Path) -> list[str]:
    """Extract only bootloaders/Install/sign and small members (RAM/disk safe)."""
    dest.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    patterns = [
        "*u-boot*",
        "*uboot*",
        "*dhboot*",
        "*IPL*",
        "*Install*",
        "*sign.img*",
        "*check.img*",
        "*hwid*",
        "*update.bin*",
        "*update.img*",
    ]
    if Path(SEVEN).exists():
        for pat in patterns:
            subprocess.run(
                [SEVEN, "x", "-y", f"-o{dest}", str(path), pat, "-r"],
                capture_output=True,
                text=True,
                errors="replace",
            )
        # Also extract any small files (<=512KB) via listing + selective extract
        names = seven_list(path)
        for name in names:
            base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            low = base.lower()
            if any(
                x in low
                for x in (
                    "u-boot",
                    "uboot",
                    "dhboot",
                    "ipl",
                    "install",
                    "sign.img",
                    "check.img",
                    "hwid",
                )
            ):
                subprocess.run(
                    [SEVEN, "x", "-y", f"-o{dest}", str(path), name],
                    capture_output=True,
                    text=True,
                    errors="replace",
                )
        for p in dest.rglob("*"):
            if p.is_file():
                saved.append(str(p.relative_to(dest)))
        return saved

    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                low = base.lower()
                want = (
                    base in BOOT_NAMES
                    or "boot" in low
                    or low in {"install", "install.lua", "sign.img", "check.img", "hwid"}
                    or info.file_size <= 512 * 1024
                )
                if not want or info.file_size > 8 * 1024 * 1024:
                    continue
                data = zf.read(info.filename)
                out = dest / base
                if out.exists():
                    out = dest / f"{hashlib.md5(info.filename.encode()).hexdigest()[:6]}_{base}"
                out.write_bytes(data)
                saved.append(out.name)
    except zipfile.BadZipFile as exc:
        (dest / "_zip_error.txt").write_text(str(exc), encoding="utf-8")
    return saved


def analyze_one(meta: dict[str, str], dl: dict[str, Any], path: Path) -> dict[str, Any]:
    safe = re.sub(r"[^\w.\-]+", "_", meta["model"])[:80]
    ext_dir = EXTRACT / safe
    report: dict[str, Any] = {
        "model": meta["model"],
        "complete_firmware_name": meta["filename"],
        "source_url": meta["url"],
        "local_path": str(path),
        "sha256": dl.get("sha256"),
        "sha256_match_expected": dl.get("sha256_match"),
        "size_bytes": path.stat().st_size,
        "download": {k: v for k, v in dl.items() if k != "sha256"},
        "extract_dir": str(ext_dir),
        "members_sample": [],
        "bootloaders": [],
        "pem": {"header_count": 0, "real_pem_candidates": 0},
        "install": None,
        "sign_img": None,
        "check_img": None,
        "markers": {},
        "poc_indicators": {},
        "errors": [],
    }

    # List via 7z without full extract of huge trees when possible
    names = seven_list(path)
    report["members_sample"] = names[:80]
    report["member_count_listed"] = len(names)

    # Extract (full package for PoC reproducibility; disk is available)
    try:
        saved = extract_interesting(path, ext_dir)
        report["extracted_files"] = saved[:200]
    except Exception as exc:
        report["errors"].append(f"extract: {exc}")
        saved = []

    # Analyze extracted small/interesting files
    agg_markers: dict[str, Any] = {}
    for p in ext_dir.rglob("*"):
        if not p.is_file():
            continue
        size = p.stat().st_size
        base = p.name
        # Skip huge payloads for full load
        if size > 8 * 1024 * 1024 and base not in BOOT_NAMES:
            # sample head only
            data = p.read_bytes()[:64 * 1024]
            for k, v in scan_markers(data).items():
                agg_markers.setdefault(k, {"member": str(p.relative_to(ext_dir)), **v})
            continue
        try:
            data = p.read_bytes()
        except Exception as exc:
            report["errors"].append(f"read {p}: {exc}")
            continue

        if base in BOOT_NAMES or "boot" in base.lower() or base.startswith("u-boot"):
            pem = pem_analysis(data)
            report["bootloaders"].append(
                {
                    "name": str(p.relative_to(ext_dir)),
                    "size": size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "pem": pem,
                }
            )
            report["pem"]["header_count"] += pem["header_count"]
            report["pem"]["real_pem_candidates"] += pem["real_pem_candidates"]
            if pem["details"]:
                (ext_dir / f"pem_{base}.json").write_text(
                    json.dumps(pem, indent=2), encoding="utf-8"
                )

        if base.lower() == "install" or base.lower() == "install.lua":
            text = data.decode("utf-8", errors="replace")
            (ext_dir / f"{base}.txt").write_text(text, encoding="utf-8")
            report["install"] = {"name": base, **analyze_install_text(text)}

        if base == "sign.img":
            report["sign_img"] = {
                "size": size,
                "sha256": hashlib.sha256(data).hexdigest(),
                "hex": data.hex(),
            }
            (ext_dir / "sign.img.hex").write_text(data.hex(), encoding="ascii")
        if base == "check.img":
            report["check_img"] = {
                "size": size,
                "sha256": hashlib.sha256(data).hexdigest(),
                "hex_preview": data[:128].hex(),
            }

        if size <= 2 * 1024 * 1024:
            for k, v in scan_markers(data).items():
                agg_markers.setdefault(k, {"member": str(p.relative_to(ext_dir)), **v})

        del data

    report["markers"] = agg_markers
    # PoC indicator summary for PSIRT
    # Outer-archive string scan (catches Boa/ONVIF/Dahua even inside compressed members)
    try:
        with path.open("rb") as fh:
            offset = 0
            while True:
                chunk = fh.read(4 * 1024 * 1024)
                if not chunk:
                    break
                for k, v in scan_markers(chunk).items():
                    if k not in report["markers"]:
                        hit = dict(v)
                        hit["offset"] = offset + v["offset"]
                        hit["member"] = "(outer_archive_scan)"
                        report["markers"][k] = hit
                offset += len(chunk)
    except Exception as exc:
        report["errors"].append(f"outer_scan: {exc}")

    mk = report["markers"]
    report["poc_indicators"] = {
        "001_pem_headers": report["pem"]["header_count"] > 0,
        "001_real_pem_body": report["pem"]["real_pem_candidates"] > 0,
        "002_sign_img_present": report["sign_img"] is not None,
        "002_install_has_crypto_needles": bool(
            set((report.get("install") or {}).get("needles") or [])
            & {"openssl", "rsa", "verify", "signature", "sha256", "sign.img"}
        ),
        "003_boa_marker": any(k.lower().startswith("boa") for k in mk),
        "004_onvif_marker": any("onvif" in k.lower() for k in mk),
        "005_config_cgi_marker": any(
            k in mk for k in ("configManager.cgi", "magicBox.cgi", "current_config", "RPC2")
        ),
        "006_p2p_marker": any(k in mk for k in ("P2P", "PPPP", "iLnkP2P")),
        "007_telnet_marker": any(k in mk for k in ("telnet", "telnetd")),
        "008_dahua_marker": any(k.lower() == "dahua" for k in mk),
    }

    (ext_dir / "FORENSIC_REPORT.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def main() -> int:
    FW_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT.mkdir(parents=True, exist_ok=True)
    EV.mkdir(parents=True, exist_ok=True)

    results = []
    for meta in CATALOG:
        dest = FW_DIR / meta["filename"]
        print(f"[*] {meta['model']} -> {meta['filename']}")
        dl = download(meta, dest)
        print(
            f"    download={dl.get('status')} bytes={dl.get('bytes', dl.get('error'))} "
            f"sha_ok={dl.get('sha256_match')}"
        )
        if dl.get("status") == "error":
            results.append(
                {
                    "model": meta["model"],
                    "complete_firmware_name": meta["filename"],
                    "download": dl,
                    "errors": [dl.get("error")],
                    "poc_indicators": {},
                    "pem": {"header_count": 0, "real_pem_candidates": 0},
                }
            )
            continue
        report = analyze_one(meta, dl, dest)
        slug = re.sub(r"[^\w.\-]+", "_", meta["model"])
        (EV / f"forensic_{slug}.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(
            "    pem={h}/{r} sign={s} boa={b} onvif={o} dahua={d} markers={m}".format(
                h=report["pem"]["header_count"],
                r=report["pem"]["real_pem_candidates"],
                s=bool(report["sign_img"]),
                b=report["poc_indicators"].get("003_boa_marker"),
                o=report["poc_indicators"].get("004_onvif_marker"),
                d=report["poc_indicators"].get("008_dahua_marker"),
                m=sorted(report["markers"].keys())[:12],
            )
        )
        results.append(report)

    (EV / "full_forensic_all.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    inv = [
        {
            "model": r.get("model"),
            "complete_firmware_name": r.get("complete_firmware_name"),
            "sha256": r.get("sha256"),
            "size_bytes": r.get("size_bytes"),
            "source_url": r.get("source_url"),
            "pem_headers": (r.get("pem") or {}).get("header_count", 0),
            "pem_real": (r.get("pem") or {}).get("real_pem_candidates", 0),
            "poc_indicators": r.get("poc_indicators"),
            "marker_keys": sorted((r.get("markers") or {}).keys()),
        }
        for r in results
    ]
    (EV / "full_inventory.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")
    csv_lines = ["model,complete_firmware_name,sha256,size_bytes,pem_headers,pem_real"]
    for row in inv:
        csv_lines.append(
            f"{row['model']},{row['complete_firmware_name']},{row['sha256']},"
            f"{row['size_bytes']},{row['pem_headers']},{row['pem_real']}"
        )
    (EV / "full_inventory.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    print(f"[+] wrote inventory to {EV}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
