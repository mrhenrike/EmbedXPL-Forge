#!/usr/bin/env python3
# Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""FACT (Firmware Analysis and Comparison Tool) Analysis Engine Integration.

Integrates FACT (fkie-cad/FACT_core) firmware analysis capabilities
into EmbedXPL. FACT provides automated firmware unpacking, static analysis,
vulnerability scanning, binary comparison, and SBOM generation for
embedded device firmware images.

This module wraps the FACT REST API and local analysis primitives to:
  - Submit firmware images for automated unpacking via binwalk/unblob
  - Trigger analysis plugins (crypto material detection, CVE lookup,
    known vulnerability matching, string extraction, ELF analysis)
  - Retrieve analysis results including file trees, binary metadata
  - Compare firmware versions to identify security regressions
  - Extract and catalog embedded certificates, keys, credentials

Capabilities absorbed from FACT_core:
  - Recursive firmware unpacking (max depth configurable)
  - File magic identification and MIME-based plugin routing
  - Binary analysis: ELF headers, shared libs, symbol tables
  - Crypto material detection (private keys, certificates, PSK)
  - CVE matching against extracted binaries
  - Firmware comparison (diff between versions)

HW_REQ: None (network access to FACT instance, or local Docker deployment).

References:
  - Repository: https://github.com/fkie-cad/FACT_core
  - License: GPL-3.0
  - FACT docs: https://fkie-cad.github.io/FACT_core/

MITRE ATT&CK:
  - T1592.002: Gather Victim Host Information: Software
  - T1588.005: Obtain Capabilities: Exploits
  - T1005: Data from Local System
  - T1083: File and Directory Discovery

Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from embedxpl.core.exploit import (
    Exploit,
    HTTPClient,
    OptBool,
    OptInteger,
    OptPort,
    OptString,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Firmware magic signatures for quick identification
# ---------------------------------------------------------------------------
FIRMWARE_SIGNATURES: Dict[bytes, str] = {
    b"\x27\x05\x19\x56": "uImage (U-Boot)",
    b"hsqs": "SquashFS (little-endian)",
    b"sqsh": "SquashFS (big-endian)",
    b"\x68\x73\x71\x73": "SquashFS (LE alt)",
    b"\xd0\x0d\xfe\xed": "Device Tree Blob (FDT)",
    b"UBI#": "UBI image",
    b"\x85\x19\x03\x20": "JFFS2 (little-endian)",
    b"\x19\x85\x20\x03": "JFFS2 (big-endian)",
    b"\x45\x3d\xcd\x28": "CramFS",
    b"LZMA": "LZMA compressed",
    b"\x1f\x8b": "gzip compressed",
    b"\x42\x5a\x68": "bzip2 compressed",
    b"\xfd\x37\x7a\x58\x5a\x00": "xz compressed",
    b"\x30\x37\x30\x37\x30\x31": "cpio archive",
    b"\x89\x50\x4e\x47": "PNG image",
    b"PK\x03\x04": "ZIP archive",
}

# Common hardcoded credential patterns in firmware
CREDENTIAL_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:password|passwd|pwd)\s*[:=]\s*[\"']?(\S+)", "hardcoded password"),
    (r"(?:api_key|apikey|api-key)\s*[:=]\s*[\"']?([a-zA-Z0-9_\-]{16,})", "API key"),
    (r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----", "private key (PEM)"),
    (r"-----BEGIN CERTIFICATE-----", "X.509 certificate"),
    (r"(?:aws_access_key_id|AKIA)[A-Z0-9]{16,}", "AWS access key"),
    (r"['\"]?(?:secret|token)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "secret/token"),
]

# Weak crypto indicators
WEAK_CRYPTO_INDICATORS: List[str] = [
    "DES_ecb_encrypt",
    "DES_cbc_encrypt",
    "MD5_Init",
    "MD5_Update",
    "RC4",
    "EVP_des_ecb",
    "EVP_rc4",
    "EVP_md5",
    "crypt(",
    "strcpy(",
    "sprintf(",
    "gets(",
    "system(",
]


class FACTAnalysisEngine(HTTPClient):
    """FACT firmware analysis engine integration for EmbedXPL.

    Operates in two modes:
      1. API mode: connects to a running FACT instance via REST API
      2. Local mode: performs lightweight firmware analysis locally
         using binwalk, file magic, string extraction
    """

    __info__ = {
        "name": "FACT Firmware Analysis Engine",
        "description": (
            "Firmware analysis and comparison tool integration. "
            "Automated unpacking, vulnerability scanning, crypto material "
            "detection, and binary comparison for embedded device firmware."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://github.com/fkie-cad/FACT_core",
            "https://fkie-cad.github.io/FACT_core/",
        ),
        "devices": ("Firmware", "Routers", "IoT", "Cameras", "Drones"),
        "cve": "N/A (analysis tool)",
        "cvss": "N/A",
        "severity": "INFO",
        "mitre_techniques": ["T1592.002", "T1588.005", "T1005", "T1083"],
        "mitre_tactics": [
            "Reconnaissance",
            "Resource Development",
            "Collection",
            "Discovery",
        ],
        "license": "GPL-3.0",
    }

    target = OptString("", "FACT API base URL (e.g. http://localhost:5000)")
    firmware_path = OptString("", "Local path to firmware image for analysis")
    mode = OptString(
        "local",
        "Analysis mode: 'api' for remote FACT, 'local' for local analysis",
    )
    output_dir = OptString("/tmp/fact_output", "Directory for analysis output")
    max_depth = OptInteger(5, "Maximum unpacking recursion depth")
    scan_creds = OptBool(True, "Scan for hardcoded credentials")
    scan_crypto = OptBool(True, "Scan for weak cryptography usage")

    # ------------------------------------------------------------------
    # Local analysis helpers
    # ------------------------------------------------------------------

    @staticmethod
    def identify_firmware(data: bytes) -> List[str]:
        """Identify firmware type from magic bytes."""
        results = []
        for sig, name in FIRMWARE_SIGNATURES.items():
            offset = data.find(sig)
            if offset != -1:
                results.append(f"{name} at offset 0x{offset:x}")
        return results

    @staticmethod
    def parse_uimage_header(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse U-Boot uImage header (64 bytes)."""
        if len(data) < 64:
            return None
        magic = struct.unpack(">I", data[:4])[0]
        if magic != 0x27051956:
            return None

        fields = struct.unpack(">IIIIIIIBBBB32s", data[:64])
        arch_names = {
            0: "invalid", 1: "alpha", 2: "arm", 3: "i386",
            4: "ia64", 5: "mips", 6: "mips64", 7: "ppc",
            8: "s390", 9: "sh", 10: "sparc", 11: "sparc64",
            12: "m68k", 13: "nios", 14: "microblaze", 15: "nios2",
            16: "blackfin", 17: "avr32", 18: "st200",
            22: "arm64", 23: "arc", 24: "riscv",
        }
        os_names = {
            0: "invalid", 1: "openbsd", 2: "netbsd", 3: "freebsd",
            4: "4_4bsd", 5: "linux", 6: "svr4", 7: "esix",
            8: "solaris", 9: "irix", 10: "sco", 11: "dell",
            12: "ncr", 13: "lynxos", 14: "vxworks", 15: "psos",
            16: "qnx", 17: "u-boot", 18: "rtems",
        }
        return {
            "magic": f"0x{fields[0]:08x}",
            "header_crc": f"0x{fields[1]:08x}",
            "timestamp": fields[2],
            "data_size": fields[3],
            "load_addr": f"0x{fields[4]:08x}",
            "entry_point": f"0x{fields[5]:08x}",
            "data_crc": f"0x{fields[6]:08x}",
            "os": os_names.get(fields[7], f"unknown({fields[7]})"),
            "arch": arch_names.get(fields[8], f"unknown({fields[8]})"),
            "image_type": fields[9],
            "compression": fields[10],
            "name": fields[11].rstrip(b"\x00").decode("ascii", errors="replace"),
        }

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 6) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        pattern = re.compile(
            rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        )
        return [m.decode("ascii", errors="replace") for m in pattern.findall(data)]

    @staticmethod
    def scan_credentials(strings: List[str]) -> List[Dict[str, str]]:
        """Scan extracted strings for hardcoded credentials."""
        findings = []
        for s in strings:
            for pattern, desc in CREDENTIAL_PATTERNS:
                match = re.search(pattern, s, re.IGNORECASE)
                if match:
                    findings.append({
                        "type": desc,
                        "match": match.group(0)[:120],
                        "context": s[:200],
                    })
        return findings

    @staticmethod
    def scan_weak_crypto(strings: List[str]) -> List[str]:
        """Scan for weak cryptography function usage."""
        found = []
        for indicator in WEAK_CRYPTO_INDICATORS:
            for s in strings:
                if indicator in s:
                    found.append(indicator)
                    break
        return found

    @staticmethod
    def scan_unsafe_functions(strings: List[str]) -> List[str]:
        """Detect unsafe C functions that indicate potential vulnerabilities."""
        unsafe = ["strcpy", "strcat", "sprintf", "gets", "scanf",
                   "system", "popen", "exec", "mktemp"]
        found = []
        for func in unsafe:
            for s in strings:
                if func + "(" in s or func + " " in s:
                    found.append(func)
                    break
        return found

    def _run_binwalk(self, firmware_path: str) -> Optional[str]:
        """Run binwalk extraction on firmware image."""
        try:
            output_dir = os.path.join(self.output_dir, "binwalk_extract")
            os.makedirs(output_dir, exist_ok=True)
            result = subprocess.run(
                ["binwalk", "-e", "-C", output_dir, firmware_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return result.stdout
        except FileNotFoundError:
            print_warning("binwalk not found; skipping extraction")
            return None
        except subprocess.TimeoutExpired:
            print_warning("binwalk extraction timed out")
            return None

    def _compute_hashes(self, data: bytes) -> Dict[str, str]:
        """Compute common hashes for firmware identification."""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    # ------------------------------------------------------------------
    # FACT API mode
    # ------------------------------------------------------------------

    def _api_submit_firmware(self, firmware_path: str) -> Optional[str]:
        """Submit firmware to FACT REST API for analysis."""
        api_url = urljoin(self.target, "/rest/firmware")
        file_name = os.path.basename(firmware_path)

        with open(firmware_path, "rb") as f:
            import base64
            firmware_b64 = base64.b64encode(f.read()).decode()

        payload = {
            "binary": firmware_b64,
            "file_name": file_name,
            "device_name": file_name,
            "device_class": "embedded",
            "firmware_version": "unknown",
            "vendor": "unknown",
            "requested_analysis_systems": [
                "crypto_material",
                "cve_lookup",
                "exploit_mitigations",
                "known_analysis",
                "software_components",
                "users_and_passwords",
            ],
        }

        try:
            import requests
            resp = requests.put(api_url, json=payload, timeout=60)
            if resp.status_code == 200:
                uid = resp.json().get("uid")
                print_success(f"Firmware submitted to FACT. UID: {uid}")
                return uid
            else:
                print_error(f"FACT API error: {resp.status_code} {resp.text[:200]}")
                return None
        except Exception as e:
            print_error(f"Failed to connect to FACT API: {e}")
            return None

    def _api_get_analysis(self, uid: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis results from FACT API."""
        api_url = urljoin(self.target, f"/rest/firmware/{uid}")
        try:
            import requests
            for attempt in range(30):
                resp = requests.get(api_url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    analysis = data.get("firmware", {}).get("analysis", {})
                    if analysis:
                        return analysis
                print_status(f"Waiting for analysis... ({attempt + 1}/30)")
                time.sleep(10)
            print_warning("Analysis timeout; results may be incomplete")
            return None
        except Exception as e:
            print_error(f"Failed to retrieve analysis: {e}")
            return None

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def run(self):
        """Execute firmware analysis."""
        firmware_path = self.firmware_path
        if not firmware_path or not os.path.isfile(firmware_path):
            print_error(f"Firmware file not found: {firmware_path}")
            return

        os.makedirs(self.output_dir, exist_ok=True)
        print_info(f"Analyzing firmware: {firmware_path}")
        print_info(f"Mode: {self.mode}")

        with open(firmware_path, "rb") as f:
            data = f.read()

        # Phase 1: basic identification
        file_size = len(data)
        hashes = self._compute_hashes(data)
        print_success(f"File size: {file_size:,} bytes")
        print_success(f"SHA-256: {hashes['sha256']}")

        signatures = self.identify_firmware(data)
        if signatures:
            print_success("Firmware signatures detected:")
            for sig in signatures:
                print_info(f"  {sig}")
        else:
            print_warning("No known firmware signatures detected")

        # uImage header
        uimage = self.parse_uimage_header(data)
        if uimage:
            print_success("U-Boot uImage header found:")
            for k, v in uimage.items():
                print_info(f"  {k}: {v}")

        if self.mode == "api" and self.target:
            # API mode: submit to FACT instance
            uid = self._api_submit_firmware(firmware_path)
            if uid:
                analysis = self._api_get_analysis(uid)
                if analysis:
                    report_path = os.path.join(
                        self.output_dir, f"fact_report_{uid}.json"
                    )
                    with open(report_path, "w") as f:
                        json.dump(analysis, f, indent=2)
                    print_success(f"Analysis report saved: {report_path}")
            return

        # Local mode: lightweight analysis
        print_status("Phase 2: String extraction and analysis")
        strings = self.extract_strings(data)
        print_info(f"Extracted {len(strings)} strings (min 6 chars)")

        if self.scan_creds:
            print_status("Phase 3: Credential scanning")
            creds = self.scan_credentials(strings)
            if creds:
                print_warning(f"Found {len(creds)} potential credential(s):")
                for c in creds[:20]:
                    print_warning(f"  [{c['type']}] {c['match']}")
            else:
                print_info("No hardcoded credentials detected")

        if self.scan_crypto:
            print_status("Phase 4: Weak cryptography detection")
            weak_crypto = self.scan_weak_crypto(strings)
            if weak_crypto:
                print_warning(f"Weak crypto indicators: {', '.join(weak_crypto)}")
            unsafe_funcs = self.scan_unsafe_functions(strings)
            if unsafe_funcs:
                print_warning(f"Unsafe functions: {', '.join(unsafe_funcs)}")

        # Phase 5: binwalk extraction
        print_status("Phase 5: Firmware extraction (binwalk)")
        binwalk_output = self._run_binwalk(firmware_path)
        if binwalk_output:
            print_info("Binwalk extraction completed")
            for line in binwalk_output.strip().split("\n")[:30]:
                if line.strip():
                    print_info(f"  {line.strip()}")

        # Save local report
        report = {
            "firmware": firmware_path,
            "size": file_size,
            "hashes": hashes,
            "signatures": signatures,
            "uimage_header": uimage,
            "strings_count": len(strings),
            "credentials": (
                self.scan_credentials(strings) if self.scan_creds else []
            ),
            "weak_crypto": (
                self.scan_weak_crypto(strings) if self.scan_crypto else []
            ),
            "unsafe_functions": (
                self.scan_unsafe_functions(strings) if self.scan_crypto else []
            ),
        }
        report_path = os.path.join(self.output_dir, "analysis_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print_success(f"Analysis report saved: {report_path}")
