# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision EGLIBC/glibc Version & CVE Mapper (CWE-1104).

Identifies glibc/EGLIBC version in extracted firmware and maps to known
CVEs. Offline analysis — no network access required.

Version: 1.0.0
"""

import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *


_GLIBC_CVES: List[Tuple[str, str, str, str, str]] = [
    (
        "CVE-2015-0235",
        "GHOST: heap overflow in gethostbyname_r",
        "9.8",
        "2.2-2.17",
        "__nss_hostname_digits_dots",
    ),
    (
        "CVE-2015-7547",
        "getaddrinfo stack-based buffer overflow (DNS)",
        "8.1",
        "2.9-2.22",
        "getaddrinfo",
    ),
    (
        "CVE-2014-5119",
        "__gconv_translit_find heap corruption",
        "7.5",
        "2.10-2.19",
        "__gconv_translit_find",
    ),
    (
        "CVE-2014-0475",
        "Directory traversal in iconv/locale",
        "6.8",
        "2.0-2.19",
        "",
    ),
    (
        "CVE-2013-7423",
        "getaddrinfo AI_ADDRCONFIG DNS leak",
        "5.3",
        "2.0-2.20",
        "",
    ),
    (
        "CVE-2014-9761",
        "nan() stack overflow via long payload",
        "9.8",
        "2.0-2.22",
        "nan",
    ),
    (
        "CVE-2015-1781",
        "Buffer overflow in gethostbyname_r (IPv6)",
        "6.8",
        "2.0-2.21",
        "gethostbyname_r",
    ),
    (
        "CVE-2017-1000366",
        "Stack clash via LD_LIBRARY_PATH",
        "7.8",
        "2.0-2.25",
        "",
    ),
]


def _version_in_range(version: Tuple[int, ...], range_str: str) -> bool:
    """Check if version falls within a CVE-affected range like '2.2-2.17'."""
    match = re.match(r"(\d+)\.(\d+)-(\d+)\.(\d+)", range_str)
    if not match:
        return False
    low = (int(match.group(1)), int(match.group(2)))
    high = (int(match.group(3)), int(match.group(4)))
    v = version[:2]
    return low <= v <= high


class Exploit(Exploit):
    """Hikvision EGLIBC/glibc Version & CVE Mapper.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision EGLIBC/glibc Version & CVE Mapper",
        "description": (
            "Identifies glibc/EGLIBC version in extracted firmware and maps "
            "to known CVEs. Tests for CVE-2015-0235 (GHOST), CVE-2015-7547, "
            "CVE-2014-5119, etc. CWE-1104: Use of Unmaintained Third-Party "
            "Components."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2015-0235",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-7547",
            "https://cwe.mitre.org/data/definitions/1104.html",
        ),
        "devices": (
            "Hikvision NVR/DVR firmware V4.x",
            "Any ARM/MIPS embedded firmware with glibc/EGLIBC",
        ),
    }

    firmware_dir = OptString("", "Path to extracted firmware rootfs")
    libc_path = OptString("", "Direct path to libc.so binary (overrides firmware_dir)")

    def _find_libc(self) -> Optional[str]:
        """Locate libc binary in firmware directory."""
        if self.libc_path and os.path.isfile(self.libc_path):
            return self.libc_path

        if not self.firmware_dir or not os.path.isdir(self.firmware_dir):
            return None

        candidates = []
        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if fname.startswith("libc-") and fname.endswith(".so"):
                    candidates.append(os.path.join(root, fname))
                elif fname == "libc.so.6":
                    fpath = os.path.join(root, fname)
                    real = os.path.realpath(fpath)
                    if os.path.isfile(real):
                        candidates.append(real)

        return candidates[0] if candidates else None

    def _extract_version(self, libc_path: str) -> Optional[Tuple[int, ...]]:
        """Extract glibc version string from binary."""
        try:
            with open(libc_path, "rb") as f:
                data = f.read()
        except IOError:
            return None

        match = re.search(rb"release version (\d+)\.(\d+)(?:\.(\d+))?", data)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2))
            patch = int(match.group(3)) if match.group(3) else 0
            return (major, minor, patch)
        return None

    def _check_eglibc(self, libc_path: str) -> bool:
        """Check for EGLIBC-specific markers."""
        try:
            with open(libc_path, "rb") as f:
                data = f.read()
            return b"EGLIBC" in data
        except IOError:
            return False

    def _extract_compiler_info(self, libc_path: str) -> Optional[str]:
        """Extract compiler version from libc binary."""
        try:
            with open(libc_path, "rb") as f:
                data = f.read()
            match = re.search(rb"Compiled by (GNU CC version [^\x00]+)", data)
            if match:
                return match.group(1).decode("ascii", errors="replace").strip()
            match = re.search(rb"GCC: \(.*?\) (\d+\.\d+\.\d+)", data)
            if match:
                return "GCC {}".format(match.group(1).decode())
        except IOError:
            pass
        return None

    def _extract_build_info(self, libc_path: str) -> Dict[str, str]:
        """Extract build metadata from libc binary."""
        info: Dict[str, str] = {}
        try:
            with open(libc_path, "rb") as f:
                data = f.read()

            compiled_on = re.search(
                rb"Compiled on a Linux (\d+\.\d+\.\d+) system on (\d{4}-\d{2}-\d{2})",
                data,
            )
            if compiled_on:
                info["Build Kernel"] = compiled_on.group(1).decode()
                info["Build Date"] = compiled_on.group(2).decode()

            platform = re.search(rb"\(([A-Za-z]+_v\d+[A-Za-z]*)\)", data)
            if platform:
                info["Platform"] = platform.group(1).decode()

        except IOError:
            pass
        return info

    def _check_patched_symbols(self, libc_path: str) -> Dict[str, bool]:
        """Check for presence of symbols indicating patches."""
        results: Dict[str, bool] = {}

        try:
            output = subprocess.check_output(
                ["nm", "-D", libc_path],
                stderr=subprocess.DEVNULL,
                timeout=15,
            ).decode(errors="replace")
        except (OSError, subprocess.SubprocessError):
            try:
                output = subprocess.check_output(
                    ["arm-linux-gnueabi-nm", "-D", libc_path],
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                ).decode(errors="replace")
            except (OSError, subprocess.SubprocessError):
                try:
                    with open(libc_path, "rb") as f:
                        data = f.read()
                    for sym_name in ["__nss_hostname_digits_dots", "getaddrinfo",
                                     "__gconv_translit_find"]:
                        results[sym_name] = sym_name.encode() in data
                    return results
                except IOError:
                    return results

        for cve_id, _, _, _, check_sym in _GLIBC_CVES:
            if check_sym:
                results[check_sym] = check_sym in output

        return results

    def run(self) -> None:
        libc_path = self._find_libc()
        if not libc_path:
            print_error(
                "Cannot find libc binary. Set firmware_dir or libc_path."
            )
            return

        print_status("Analyzing: {}".format(libc_path))

        version = self._extract_version(libc_path)
        if not version:
            print_error("Cannot extract glibc version from binary")
            return

        ver_str = ".".join(str(v) for v in version)
        is_eglibc = self._check_eglibc(libc_path)
        lib_name = "EGLIBC" if is_eglibc else "glibc"

        print_success("Detected {} version {}".format(lib_name, ver_str))

        build_info = self._extract_build_info(libc_path)
        compiler = self._extract_compiler_info(libc_path)

        info_rows = [
            ("Library", lib_name),
            ("Version", ver_str),
        ]
        if compiler:
            info_rows.append(("Compiler", compiler))
        for key, val in build_info.items():
            info_rows.append((key, val))

        print_table(("Property", "Value"), *info_rows, title="Library Information")

        # CVE mapping
        print_status("Mapping version {} to known CVEs...".format(ver_str))
        symbols = self._check_patched_symbols(libc_path)

        cve_rows: List[Tuple[str, str, str, str, str]] = []
        affected_count = 0

        for cve_id, desc, cvss, affected_range, check_sym in _GLIBC_CVES:
            in_range = _version_in_range(version, affected_range)

            if not in_range:
                status = "Not in range"
            elif check_sym and check_sym in symbols:
                if symbols[check_sym]:
                    status = "VULNERABLE (symbol present)"
                else:
                    status = "Likely patched (symbol absent)"
            elif in_range:
                status = "IN RANGE - verify"

            if in_range:
                affected_count += 1

            cve_rows.append((cve_id, desc, affected_range, ver_str, status))

        print_table(
            ("CVE", "Description", "Affected Range", "This Version", "Status"),
            *cve_rows,
            title="CVE Analysis",
        )

        # Risk assessment
        if version[:2] <= (2, 17):
            age_years = 2026 - 2012
            risk = "CRITICAL"
            print_warning(
                "{} {} is {} years old — end-of-life, no security patches. "
                "Risk: {}".format(lib_name, ver_str, age_years, risk)
            )
        elif version[:2] <= (2, 22):
            risk = "HIGH"
            print_warning(
                "{} {} is outdated — limited security support. Risk: {}".format(
                    lib_name, ver_str, risk
                )
            )
        else:
            risk = "MEDIUM"
            print_info(
                "{} {} — check specific CVE patches. Risk: {}".format(
                    lib_name, ver_str, risk
                )
            )

        print_status("CVEs potentially affecting this version: {}/{}".format(
            affected_count, len(_GLIBC_CVES)
        ))
        print_info(
            "Recommendation: Upgrade to glibc 2.38+ or musl libc for embedded systems"
        )
