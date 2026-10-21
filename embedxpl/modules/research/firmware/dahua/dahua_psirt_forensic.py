#!/usr/bin/env python3
"""Dahua PSIRT validation forensic — memory-bounded re-analysis.

Downloads (optional) and analyzes the 14 official firmwares used in the
original disclosure. Produces evidence answering Dahua PSIRT questions:
complete firmware filenames, PEM block vs header-only analysis,
Install/sign.img verification surface, DTB/bootargs, CVE path markers.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

REPO = Path(__file__).resolve().parent.parent
FW_DIR = REPO / "downloads" / "cctv" / "dahua"
OUT_DIR = REPO / "reports" / "dahua_cctv" / "evidence"
TMP_DIR = REPO / ".tmp" / "dahua_psirt"
CDN_BASE = "https://files.dahua.support/Firmware/"

# Official CDN filenames (complete names for PSIRT validation)
FIRMWARES: list[dict[str, str]] = [
    {
        "id": "ipc-molec-s2-hx2xxx",
        "filename": "DH_IPC-HX2XXX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S2/",
        "series": "Molec LITE265-S2",
        "product_class": "IPC",
    },
    {
        "id": "ipc-molec-s2-hx258xx",
        "filename": "DH_IPC-HX25(8)XX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S2/",
        "series": "Molec LITE265-S2",
        "product_class": "IPC",
    },
    {
        "id": "ipc-hertz-s4-hx1xxx",
        "filename": "DH_IPC-HX1XXX-Hertz_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Hertz LITE265-S4",
        "product_class": "IPC",
    },
    {
        "id": "ipc-molec-s4-hx1xxx",
        "filename": "DH_IPC-HX1XXX-Molec_MultiLang_PN_V2.820.0000000.65.R.250121.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Molec LITE265-S4",
        "product_class": "IPC",
    },
    {
        "id": "ipc-molec-s4-legacy-hx258xx",
        "filename": "DH_IPC-HX25(8)XX-Molec_MultiLang_PN_V2.820.0000000.33.R.210705.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S4/",
        "series": "Molec LITE265-S4 legacy",
        "product_class": "IPC",
    },
    {
        "id": "ipc-euler-s5",
        "filename": "DH_IPC-HX2(1)XXX-Euler_EngSpnRus_PN_V2.840.0000000.15.R.250730.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S5/",
        "series": "Euler LITE265-S5",
        "product_class": "IPC",
    },
    {
        "id": "ipc-molec-s5",
        "filename": "DH_IPC-HX2(1)XXX-Molec_EngSpnRus_PN_V2.840.0000000.15.R.250730.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S5/",
        "series": "Molec LITE265-S5",
        "product_class": "IPC",
    },
    {
        "id": "ipc-molec-s6-hx18xx",
        "filename": "DH_IPC-HX18XX-Molec_EngSpnRus_PN_V2.840.0000000.13.R.240726.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S6/",
        "series": "Molec LITE265-S6",
        "product_class": "IPC",
    },
    {
        "id": "ipc-kant-s6",
        "filename": "DH_IPC-HX1XXX-Kant_EngSpnRus_PN_V2.880.0000000.18.R.251107.bin",
        "relpath": "Kamery -IP- stałopozycyjne/LITE265-S6/",
        "series": "Kant LITE265-S6",
        "product_class": "IPC",
    },
    {
        "id": "ipc-kant-entry",
        "filename": "DH_IPC-HX1XXX-Kant_EngSpnRus_PN_V2.880.0000000.17.R.250619.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Entry/",
        "series": "Kant Entry",
        "product_class": "IPC",
    },
    {
        "id": "ipc-edison-entry",
        "filename": "DH_IPC-HX2(1)XXX-Edison_EngSpnRus_P_V2.680.0000000.18.R.201214.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Entry/",
        "series": "Edison Entry",
        "product_class": "IPC",
    },
    {
        "id": "ipc-chou-rhea",
        "filename": "DH_IPC-Consumer-Chou-Rhea_Eng_P_V2.622.0000000.17.R.210915.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Consumer/",
        "series": "Chou-Rhea Consumer",
        "product_class": "IPC",
    },
    {
        "id": "nvr4x-4ks2l",
        "filename": "DH_NVR4x-4KS2L_MultiLang_V4.003.0000000.1.R.240515.bin",
        "relpath": "Rejestratory/NVR/NVR4xxx-4KS2L/",
        "series": "NVR4x-4KS2L",
        "product_class": "NVR",
    },
    {
        "id": "sd-kant-ptz",
        "filename": "DH_SD-Kant_MultiLang_PN_V2.820.0000016.0.R.250617.bin",
        "relpath": "Kamery -IP- stałopozycyjne/Consumer/",
        "series": "SD-Kant Consumer PTZ",
        "product_class": "PTZ",
    },
]

BOOT_NAMES = {
    "dhboot.bin.img",
    "dhboot-bak.bin.img",
    "dhboot-min.bin.img",
    "IPL.bin.img",
    "IPL_CUST.bin.img",
    "u-boot.bin.img",
}

PEM_FULL = re.compile(
    rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----"
    rb".{20,12000}?"
    rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----",
    re.DOTALL,
)
PEM_HEADER = re.compile(rb"-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
PEM_END = re.compile(rb"-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----")
BASE64_LINE = re.compile(rb"^[A-Za-z0-9+/=]{40,}$", re.MULTILINE)

VERIFY_NEEDLES = [
    b"sign.img",
    b"check.img",
    b"openssl",
    b"rsa_verify",
    b"RSA_verify",
    b"verify_sign",
    b"verifySign",
    b"signature",
    b"Signature",
    b"md5sum",
    b"sha256",
    b"SHA256",
    b"digest",
    b"pubkey",
    b"public_key",
    b"check_sign",
    b"CheckSign",
    b"fw_sign",
    b"VerifyPackage",
    b"verify_package",
]

CVE_MARKERS = {
    "DAHUA-2026-005_rpc2_login": [b"RPC2_Login", b"rpc2_Login", b"/RPC2"],
    "DAHUA-2026-006_configManager": [b"configManager.cgi", b"action=setConfig"],
    "DAHUA-2026-007_passwd_path": [b"/current_config/passwd", b"current_config/passwd"],
    "DAHUA-2026-008_tcp_37777": [b"37777", b"DVRIP", b"dvrip"],
    "DAHUA-2026-004_pppp": [b"PPPP", b"iLnkP2P", b"P2P_UID", b"p2pclient"],
    "DAHUA-2026-003_bootargs": [b"bootargs", b"console=tty", b"init=/"],
}

CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def cdn_url(relpath: str, filename: str) -> str:
    # Encode path segments but keep parentheses for CDN filenames.
    parts = [quote(p, safe="()-._~") for p in relpath.strip("/").split("/")]
    return CDN_BASE + "/".join(parts) + "/" + quote(filename, safe="()-._~")


def download_one(meta: dict[str, str], dest: Path) -> dict[str, Any]:
    url = cdn_url(meta["relpath"], meta["filename"])
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1_000_000:
        return {"status": "cached", "url": url, "bytes": dest.stat().st_size}
    req = Request(url, headers={"User-Agent": "UniaoGeek-FirmwareResearch/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with urlopen(req, timeout=120) as resp, tmp.open("wb") as out:
            total = 0
            while True:
                block = resp.read(CHUNK)
                if not block:
                    break
                out.write(block)
                total += len(block)
        tmp.replace(dest)
        return {"status": "downloaded", "url": url, "bytes": total}
    except Exception as exc:  # noqa: BLE001 — surface CDN errors in report
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return {"status": "error", "url": url, "error": str(exc)}


def _classify_pem_hits(data: bytes) -> dict[str, Any]:
    full_blocks: list[dict[str, Any]] = []
    for m in PEM_FULL.finditer(data):
        block = m.group(0)
        # Heuristic: real PEM needs base64 body between headers.
        body = block.split(b"-----", 2)
        body_text = body[2] if len(body) > 2 else b""
        b64_lines = [ln for ln in body_text.splitlines() if BASE64_LINE.match(ln.strip())]
        full_blocks.append(
            {
                "offset": m.start(),
                "length": len(block),
                "has_base64_body": len(b64_lines) >= 3,
                "base64_line_count": len(b64_lines),
                "preview": block[:120].decode("ascii", errors="replace"),
                "kind": (
                    "RSA_PRIVATE"
                    if b"RSA PRIVATE" in block
                    else "PRIVATE"
                    if b"PRIVATE" in block
                    else "PUBLIC"
                ),
            }
        )

    headers = list(PEM_HEADER.finditer(data))
    ends = list(PEM_END.finditer(data))
    header_only = []
    for h in headers:
        # Header-only if no END within next 12KB or full matcher already covered.
        window = data[h.start() : h.start() + 12000]
        has_end = bool(PEM_END.search(window))
        covered = any(h.start() == b["offset"] for b in full_blocks)
        if not covered and not has_end:
            header_only.append(
                {
                    "offset": h.start(),
                    "preview": data[h.start() : h.start() + 64].decode("ascii", errors="replace"),
                }
            )
        elif not covered and has_end:
            # BEGIN+END present but body failed full regex (truncated/binary noise).
            end_m = PEM_END.search(window)
            assert end_m is not None
            blob = window[: end_m.end()]
            b64_lines = [ln for ln in blob.splitlines() if BASE64_LINE.match(ln.strip())]
            full_blocks.append(
                {
                    "offset": h.start(),
                    "length": len(blob),
                    "has_base64_body": len(b64_lines) >= 3,
                    "base64_line_count": len(b64_lines),
                    "preview": blob[:120].decode("ascii", errors="replace"),
                    "kind": "PARTIAL_OR_NOISY",
                }
            )

    return {
        "header_count": len(headers),
        "end_count": len(ends),
        "full_or_partial_blocks": full_blocks,
        "header_only_markers": header_only,
        "real_key_material_candidates": [
            b for b in full_blocks if b.get("has_base64_body")
        ],
    }


def _scan_install(data: bytes) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    hits = []
    for needle in VERIFY_NEEDLES:
        if needle in data:
            # collect nearby lines
            nstr = needle.decode("ascii", errors="replace")
            for i, line in enumerate(lines):
                if nstr.lower() in line.lower():
                    hits.append({"needle": nstr, "line_no": i + 1, "line": line.strip()[:240]})
    # Deduplicate by (needle, line_no)
    uniq = {(h["needle"], h["line_no"]): h for h in hits}
    verify_needles_hit = sorted({h["needle"] for h in uniq.values()})
    # Conservative: signature enforcement strings excluding mere filenames
    enforce = [
        n
        for n in verify_needles_hit
        if n not in {"sign.img", "check.img"}
    ]
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "verify_related_needles": verify_needles_hit,
        "enforcement_like_needles": enforce,
        "sample_hits": list(uniq.values())[:40],
        "mentions_sign_img": b"sign.img" in data,
        "mentions_check_img": b"check.img" in data,
        "looks_like_shell": text.lstrip().startswith("#!") or "mount" in text.lower(),
    }


def _marker_scan(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, needles in CVE_MARKERS.items():
        found = []
        for n in needles:
            idx = data.find(n)
            if idx >= 0:
                ctx = data[max(0, idx - 24) : idx + len(n) + 40]
                found.append(
                    {
                        "needle": n.decode("ascii", errors="replace"),
                        "offset": idx,
                        "context": ctx.decode("ascii", errors="replace"),
                    }
                )
        out[key] = {"present": bool(found), "hits": found[:5]}
    return out


def analyze_firmware(path: Path, meta: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": meta["id"],
        "series": meta["series"],
        "product_class": meta["product_class"],
        "complete_firmware_name": meta["filename"],
        "local_path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "source_url": cdn_url(meta["relpath"], meta["filename"]),
        "is_zip": False,
        "zip_entries": [],
        "sign_img": None,
        "check_img": None,
        "install": None,
        "bootloaders": [],
        "pem_summary": {
            "header_count": 0,
            "end_count": 0,
            "real_key_material_candidates": 0,
            "header_only_markers": 0,
        },
        "markers_aggregate": {},
        "errors": [],
    }

    # Aggregate markers across selected members without loading whole archive.
    agg_markers: dict[str, Any] = {k: {"present": False, "hits": []} for k in CVE_MARKERS}

    try:
        with zipfile.ZipFile(path, "r") as zf:
            result["is_zip"] = True
            names = zf.namelist()
            result["zip_entries"] = [
                {"name": n, "size": zf.getinfo(n).file_size} for n in names
            ]

            for n in names:
                base = n.rsplit("/", 1)[-1]
                info = zf.getinfo(n)
                # Skip huge payloads for marker scan; still note presence.
                if info.file_size > 40 * 1024 * 1024:
                    continue
                # Always inspect Install / sign / check / boot / small scripts
                interesting = (
                    base in BOOT_NAMES
                    or base in {"Install", "install", "sign.img", "check.img"}
                    or base.endswith((".cgi", ".sh", ".conf", ".dtb", ".dts"))
                    or "boot" in base.lower()
                    or info.file_size <= 2 * 1024 * 1024
                )
                if not interesting and info.file_size > 512 * 1024:
                    continue
                try:
                    data = zf.read(n)
                except Exception as exc:  # noqa: BLE001
                    result["errors"].append(f"read {n}: {exc}")
                    continue

                if base in {"sign.img", "check.img"}:
                    entry = {
                        "name": n,
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "hex_preview": data[:64].hex(),
                    }
                    if base == "sign.img":
                        result["sign_img"] = entry
                    else:
                        result["check_img"] = entry

                if base in {"Install", "install"} or n.endswith("/Install"):
                    result["install"] = {"name": n, **_scan_install(data)}

                if base in BOOT_NAMES or ("dhboot" in base.lower()):
                    pem = _classify_pem_hits(data)
                    result["bootloaders"].append(
                        {
                            "name": n,
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "pem": pem,
                        }
                    )
                    result["pem_summary"]["header_count"] += pem["header_count"]
                    result["pem_summary"]["end_count"] += pem["end_count"]
                    result["pem_summary"]["real_key_material_candidates"] += len(
                        pem["real_key_material_candidates"]
                    )
                    result["pem_summary"]["header_only_markers"] += len(
                        pem["header_only_markers"]
                    )

                markers = _marker_scan(data)
                for k, v in markers.items():
                    if v["present"]:
                        agg_markers[k]["present"] = True
                        for hit in v["hits"]:
                            hit2 = dict(hit)
                            hit2["member"] = n
                            if len(agg_markers[k]["hits"]) < 8:
                                agg_markers[k]["hits"].append(hit2)

            # If Install not found by exact name, search case-insensitive.
            if result["install"] is None:
                for n in names:
                    if n.rsplit("/", 1)[-1].lower() == "install":
                        data = zf.read(n)
                        result["install"] = {"name": n, **_scan_install(data)}
                        break

    except zipfile.BadZipFile:
        result["is_zip"] = False
        # Stream-scan raw blob in chunks for PEM headers + markers only.
        with path.open("rb") as f:
            data = f.read()
        pem = _classify_pem_hits(data)
        result["bootloaders"].append({"name": path.name, "size": len(data), "pem": pem})
        result["pem_summary"]["header_count"] = pem["header_count"]
        result["pem_summary"]["end_count"] = pem["end_count"]
        result["pem_summary"]["real_key_material_candidates"] = len(
            pem["real_key_material_candidates"]
        )
        result["pem_summary"]["header_only_markers"] = len(pem["header_only_markers"])
        agg_markers = _marker_scan(data)
        # free
        del data

    result["markers_aggregate"] = agg_markers
    # Derived PSIRT-facing flags
    install = result.get("install") or {}
    result["psirt_flags"] = {
        "sign_img_present": result["sign_img"] is not None,
        "check_img_present": result["check_img"] is not None,
        "install_present": bool(install),
        "install_has_enforcement_like_needles": bool(
            install.get("enforcement_like_needles")
        ),
        "pem_headers_present": result["pem_summary"]["header_count"] > 0,
        "pem_real_key_material_candidates": result["pem_summary"][
            "real_key_material_candidates"
        ],
        "pppp_or_ilnk_markers": agg_markers.get("DAHUA-2026-004_pppp", {}).get(
            "present", False
        ),
        "rpc2_markers": agg_markers.get("DAHUA-2026-005_rpc2_login", {}).get(
            "present", False
        ),
        "configManager_markers": agg_markers.get(
            "DAHUA-2026-006_configManager", {}
        ).get("present", False),
        "passwd_path_markers": agg_markers.get("DAHUA-2026-007_passwd_path", {}).get(
            "present", False
        ),
        "tcp_37777_markers": agg_markers.get("DAHUA-2026-008_tcp_37777", {}).get(
            "present", False
        ),
        "bootargs_markers": agg_markers.get("DAHUA-2026-003_bootargs", {}).get(
            "present", False
        ),
    }
    return result


def build_psirt_validation(results: list[dict[str, Any]]) -> dict[str, Any]:
    fw_table = [
        {
            "complete_firmware_name": r["complete_firmware_name"],
            "sha256": r["sha256"],
            "size_bytes": r["size_bytes"],
            "series": r["series"],
            "product_class": r["product_class"],
            "source_url": r["source_url"],
            "download_ok": r.get("download", {}).get("status")
            in {"cached", "downloaded"},
        }
        for r in results
        if "sha256" in r
    ]

    pem_real = [r for r in results if r.get("psirt_flags", {}).get("pem_real_key_material_candidates", 0) > 0]
    pem_hdr = [r for r in results if r.get("psirt_flags", {}).get("pem_headers_present")]
    no_enforce = [
        r
        for r in results
        if r.get("psirt_flags", {}).get("sign_img_present")
        and not r.get("psirt_flags", {}).get("install_has_enforcement_like_needles")
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "researcher": "Andre Henrique (@mrhenrike) | Uniao Geek",
        "contact": "security.research@uniaogeek.com.br",
        "report_ids": [f"DAHUA-2026-{i:03d}" for i in range(1, 9)],
        "what_psirt_asked": {
            "1_evidence_attachments": "Share evidence files (attachments missing from original email)",
            "2_complete_firmware_names_for_005_008": "Provide complete firmware names used testing CVE-2021-33044/33045 and CVE-2013-6117",
            "3_their_rebuttals": {
                "001": "PEM headers exist but are not real private keys; used for conditional checks only",
                "002": "Verification is not in Install; separate mechanism exists",
                "003": "DTB unencrypted is industry practice; IPC/PTZ do not read bootargs",
                "004": "CVE-2019-11219/11220 are iLnkP2P; products do not use it",
                "006": "CVE-2021-36260 framed as third-party; products not impacted",
                "007": "CVE-2020-25078 framed as D-Link-related; products not affected",
                "005_008": "Historical CVEs patched; need complete firmware names",
            },
        },
        "complete_firmware_inventory": fw_table,
        "finding_evidence_summary": {
            "DAHUA-2026-001": {
                "firmwares_with_pem_headers": len(pem_hdr),
                "firmwares_with_base64_key_body_candidates": len(pem_real),
                "note": (
                    "If real_key_material_candidates==0, PSIRT claim (headers-only) is "
                    "consistent with static evidence; finding should be downgraded or "
                    "reframed as residual header strings. If >0, contest with hex dumps."
                ),
                "details": [
                    {
                        "firmware": r["complete_firmware_name"],
                        "pem_summary": r.get("pem_summary"),
                        "bootloaders": [
                            {
                                "name": b["name"],
                                "real_candidates": len(
                                    b.get("pem", {}).get(
                                        "real_key_material_candidates", []
                                    )
                                ),
                                "header_only": len(
                                    b.get("pem", {}).get("header_only_markers", [])
                                ),
                                "sample": (
                                    b.get("pem", {}).get(
                                        "real_key_material_candidates"
                                    )
                                    or b.get("pem", {}).get("header_only_markers")
                                    or b.get("pem", {}).get("full_or_partial_blocks")
                                    or []
                                )[:2],
                            }
                            for b in r.get("bootloaders", [])
                        ],
                    }
                    for r in results
                    if r.get("psirt_flags", {}).get("pem_headers_present")
                ],
            },
            "DAHUA-2026-002": {
                "firmwares_sign_img_without_install_enforcement_needles": len(no_enforce),
                "note": (
                    "Absence of verify strings in Install does not prove absence of a "
                    "separate verifier binary. Evidence documents Install surface only; "
                    "PSIRT must name the separate verifier path for independent audit."
                ),
                "details": [
                    {
                        "firmware": r["complete_firmware_name"],
                        "sign_img": r.get("sign_img"),
                        "check_img": r.get("check_img"),
                        "install": {
                            "name": (r.get("install") or {}).get("name"),
                            "enforcement_like_needles": (r.get("install") or {}).get(
                                "enforcement_like_needles"
                            ),
                            "verify_related_needles": (r.get("install") or {}).get(
                                "verify_related_needles"
                            ),
                            "sample_hits": (r.get("install") or {}).get("sample_hits"),
                        },
                    }
                    for r in results
                    if r.get("is_zip")
                ],
            },
            "DAHUA-2026-003": {
                "firmwares_with_bootargs_markers": sum(
                    1
                    for r in results
                    if r.get("psirt_flags", {}).get("bootargs_markers")
                ),
                "note": "Static presence of bootargs in DTB/strings; runtime read claim requires hardware UART validation.",
            },
            "DAHUA-2026-004": {
                "firmwares_with_pppp_or_ilnk_markers": sum(
                    1
                    for r in results
                    if r.get("psirt_flags", {}).get("pppp_or_ilnk_markers")
                ),
                "details": [
                    {
                        "firmware": r["complete_firmware_name"],
                        "hits": r.get("markers_aggregate", {})
                        .get("DAHUA-2026-004_pppp", {})
                        .get("hits", []),
                    }
                    for r in results
                    if r.get("psirt_flags", {}).get("pppp_or_ilnk_markers")
                ],
            },
            "DAHUA-2026-005": {
                "firmwares_with_rpc2_markers": sum(
                    1 for r in results if r.get("psirt_flags", {}).get("rpc2_markers")
                ),
                "tested_complete_firmware_names": [
                    r["complete_firmware_name"] for r in results if "sha256" in r
                ],
            },
            "DAHUA-2026-006": {
                "nvd_note": "CVE-2021-36260 is assigned to Zhejiang Dahua Technology Co., Ltd (not third-party).",
                "firmwares_with_configManager_markers": sum(
                    1
                    for r in results
                    if r.get("psirt_flags", {}).get("configManager_markers")
                ),
            },
            "DAHUA-2026-007": {
                "nvd_note": "CVE-2020-25078 is assigned to Zhejiang Dahua Technology Co., Ltd (also inherited by some OEM/D-Link rebrands).",
                "firmwares_with_passwd_path_markers": sum(
                    1
                    for r in results
                    if r.get("psirt_flags", {}).get("passwd_path_markers")
                ),
            },
            "DAHUA-2026-008": {
                "firmwares_with_37777_markers": sum(
                    1
                    for r in results
                    if r.get("psirt_flags", {}).get("tcp_37777_markers")
                ),
                "tested_complete_firmware_names": [
                    r["complete_firmware_name"] for r in results if "sha256" in r
                ],
            },
        },
    }


def main() -> int:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FW_DIR.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for meta in FIRMWARES:
        dest = FW_DIR / meta["filename"]
        print(f"[*] {meta['filename']}")
        dl = download_one(meta, dest)
        print(f"    download: {dl.get('status')} {dl.get('bytes', dl.get('error'))}")
        if dl.get("status") == "error":
            results.append(
                {
                    "id": meta["id"],
                    "complete_firmware_name": meta["filename"],
                    "series": meta["series"],
                    "product_class": meta["product_class"],
                    "source_url": cdn_url(meta["relpath"], meta["filename"]),
                    "download": dl,
                    "errors": [dl.get("error")],
                }
            )
            continue
        analysis = analyze_firmware(dest, meta)
        analysis["download"] = dl
        # Persist per-firmware JSON immediately (crash-safe).
        per = OUT_DIR / f"forensic_{meta['id']}.json"
        per.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        print(
            "    pem_hdr={hdr} pem_real={real} sign={sign} install_enforce={enf}".format(
                hdr=analysis["pem_summary"]["header_count"],
                real=analysis["pem_summary"]["real_key_material_candidates"],
                sign=bool(analysis["sign_img"]),
                enf=analysis["psirt_flags"]["install_has_enforcement_like_needles"],
            )
        )
        results.append(analysis)

    all_path = OUT_DIR / "psirt_forensic_all.json"
    all_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    validation = build_psirt_validation(results)
    val_path = OUT_DIR / "psirt_validation_package.json"
    val_path.write_text(json.dumps(validation, indent=2), encoding="utf-8")
    print(f"[+] wrote {all_path}")
    print(f"[+] wrote {val_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
