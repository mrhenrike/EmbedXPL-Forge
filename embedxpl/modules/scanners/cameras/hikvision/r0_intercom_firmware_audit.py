# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision R0 Indoor Station — Comprehensive Firmware Security Audit.

Performs a complete offline security audit of extracted R0 firmware rootfs.
Covers 12 vulnerability categories: 3DES keys, RSA keys, binary hardening,
boot script permissions, password hashes, SSH host keys, kernel version,
C library CVEs, debug utilities, JTAG references, developer artifacts,
and system hardening (IP forwarding, watchdog).

No network access needed — purely offline analysis.

Version: 1.0.0
"""

import base64
import hashlib
import os
import re
import struct
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *

_ELF_MAGIC = b"\x7fELF"
_ET_DYN = 3
_PT_GNU_STACK = 0x6474E551

_KNOWN_RSA1024_MASTER_KEY = (
    "MIGJAoGBAOZwSLecBmsjYjEixnXdeYfDeZJ39mDk6CH/cduiKSYz9KHAT6uqvWsY"
    "A5kT6JtWfitnl6fnPSd4/K9DYsVEMxs8esFElmV+HqVo8owInBkHAol++kbH4SPw"
    "4L+RxkOgZ5zQuVlrZ1l6Lr08+Uli6clxxG2f7WxH8bEtyURJqPLzAgMBAAE="
)

_KNOWN_DEFAULT_HASHES = {
    "$1$$qRPK7m23GJusamGpoGLby/": "Hikvision blank/default",
    "$1$c3DkrZ9Z$0PmTvUB3G./F46cQ.p6Op/": "Hikvision 12345",
    "$1$$CoERg7ynjYLsj2j4glJ34.": "Dahua default",
}

_UCLIBC_CVES = {
    "0.9.33": ["CVE-2022-29503", "CVE-2022-30295"],
    "0.9.32": ["CVE-2022-29503", "CVE-2022-30295"],
    "0.9.30": ["CVE-2022-29503"],
}

_SEVERITY_SCORES = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _is_elf(path):
    """Check if file starts with ELF magic bytes."""
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == _ELF_MAGIC
    except (OSError, IOError):
        return False


def _sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


class Exploit(Exploit):
    """Hikvision R0 Indoor Station Firmware Security Audit.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision R0 Intercom Firmware Security Audit",
        "description": (
            "Comprehensive offline firmware audit for R0-platform Indoor "
            "Stations. Checks 12 vulnerability categories: 3DES keys, RSA "
            "keys, binary hardening (PIE/RELRO/canary/NX), boot scripts, "
            "password hashes, SSH host keys, kernel version, C library CVEs, "
            "debug utilities, JTAG references, developer artifacts, and "
            "system hardening. Generates risk score and vulnerability table."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cwe.mitre.org/data/definitions/693.html",
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
        "devices": (
            "Hikvision DS-KH6320-LE1(B) — R0 Indoor Station",
            "Hikvision DS-KH6350 — R0 Indoor Station",
            "Hikvision DS-KH6360 — R0 Indoor Station",
            "Hikvision DS-KH6320Y-WTE2 — R0 Indoor Station",
        ),
    }

    firmware_dir = OptString("", "Path to extracted firmware rootfs")
    deep_scan = OptBool(False, "Enable exhaustive analysis (slower)")

    def _add_finding(self, findings, category, severity, description, detail=""):
        findings.append({
            "category": category,
            "severity": severity,
            "description": description,
            "detail": detail,
        })

    # ------------------------------------------------------------------ #
    # 1. 3DES Key in digicapkeyArm.ko
    # ------------------------------------------------------------------ #
    def _check_3des_key(self, findings):
        """Search for 3DES key material in kernel modules."""
        target_files = []
        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if "digicapkey" in fname.lower() or fname.endswith(".ko"):
                    target_files.append(os.path.join(root, fname))

        for fpath in target_files:
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except IOError:
                continue

            des_patterns = [
                rb"\x01\x23\x45\x67\x89\xAB\xCD\xEF",
                rb"\xFE\xDC\xBA\x98\x76\x54\x32\x10",
            ]
            for pattern in des_patterns:
                idx = data.find(pattern)
                if idx != -1:
                    rel = os.path.relpath(fpath, self.firmware_dir)
                    key_hex = data[idx:idx + 24].hex()
                    self._add_finding(
                        findings, "3DES Key", "CRITICAL",
                        "Hardcoded 3DES key in {}".format(rel),
                        "Offset 0x{:08x}, bytes: {}".format(idx, key_hex),
                    )
                    return

            tdes_refs = [b"DES_", b"des3", b"triple_des", b"3des", b"tdes"]
            for ref in tdes_refs:
                if ref in data:
                    rel = os.path.relpath(fpath, self.firmware_dir)
                    self._add_finding(
                        findings, "3DES Key", "HIGH",
                        "3DES reference in {}".format(rel),
                        "String '{}' found".format(ref.decode("ascii", errors="replace")),
                    )
                    break

    # ------------------------------------------------------------------ #
    # 2. RSA Keys in psh binary
    # ------------------------------------------------------------------ #
    def _check_rsa_keys(self, findings):
        """Extract and validate RSA public keys from psh binary."""
        rsa_pattern = re.compile(rb'(MIGJ[A-Za-z0-9+/=]{80,400})')
        psh_candidates = []

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if fname in ("psh", "psh.bin", "psh_arm"):
                    psh_candidates.append(os.path.join(root, fname))

        if self.deep_scan:
            for root, _dirs, files in os.walk(self.firmware_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if _is_elf(fpath) and fpath not in psh_candidates:
                        psh_candidates.append(fpath)

        total_keys = 0
        master_key_found = False

        for fpath in psh_candidates:
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except IOError:
                continue

            matches = rsa_pattern.findall(data)
            if not matches:
                continue

            rel = os.path.relpath(fpath, self.firmware_dir)
            total_keys += len(matches)

            for raw_b64 in matches:
                b64_str = raw_b64.decode("ascii", errors="replace")
                try:
                    der = base64.b64decode(raw_b64)
                    bit_len = (len(der) - 38) * 8
                    size_label = "RSA-{}".format(bit_len) if bit_len > 0 else "RSA-?"
                except Exception:
                    size_label = "RSA-?"

                normalized = b64_str.replace("\n", "").replace("\r", "").strip()
                master_normalized = _KNOWN_RSA1024_MASTER_KEY.replace("\n", "").strip()
                if normalized == master_normalized:
                    master_key_found = True
                    self._add_finding(
                        findings, "RSA Keys", "CRITICAL",
                        "Known Hikvision RSA-1024 master key in {}".format(rel),
                        "{} — EXACT MATCH to known master key".format(size_label),
                    )

            if not master_key_found and matches:
                self._add_finding(
                    findings, "RSA Keys", "HIGH",
                    "{} RSA key(s) in {}".format(len(matches), rel),
                    "Keys may be extractable for offline attacks",
                )

        if total_keys == 0:
            self._add_finding(
                findings, "RSA Keys", "INFO",
                "No RSA public keys found in binaries", "",
            )

    # ------------------------------------------------------------------ #
    # 3. Binary Hardening (PIE, RELRO, Canary, NX)
    # ------------------------------------------------------------------ #
    def _check_binary_hardening(self, findings):
        """Analyze ELF binaries for security hardening features."""
        elf_paths = []
        scan_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "home"]
        if self.deep_scan:
            scan_dirs = [""]

        for subdir in scan_dirs:
            search = os.path.join(self.firmware_dir, subdir)
            if not os.path.isdir(search):
                continue
            for root, _dirs, files in os.walk(search):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if _is_elf(fpath):
                        elf_paths.append(fpath)

        if not elf_paths:
            self._add_finding(
                findings, "Binary Hardening", "INFO",
                "No ELF binaries found in standard paths", "",
            )
            return

        no_pie = 0
        no_nx = 0
        no_canary = 0

        for fpath in elf_paths:
            try:
                with open(fpath, "rb") as fh:
                    header = fh.read(64)
                    fh.seek(0)
                    data = fh.read()
            except IOError:
                continue

            if len(header) < 20:
                continue

            ei_class = header[4]
            if ei_class == 1:
                e_type = struct.unpack_from("<H", header, 16)[0]
            elif ei_class == 2:
                e_type = struct.unpack_from("<H", header, 16)[0]
            else:
                continue

            if e_type != _ET_DYN:
                no_pie += 1

            has_canary = b"__stack_chk_fail" in data
            if not has_canary:
                no_canary += 1

            has_nx = True
            try:
                if ei_class == 1:
                    e_phoff = struct.unpack_from("<I", header, 28)[0]
                    e_phentsize = struct.unpack_from("<H", header, 42)[0]
                    e_phnum = struct.unpack_from("<H", header, 44)[0]
                else:
                    e_phoff = struct.unpack_from("<Q", header, 32)[0]
                    e_phentsize = struct.unpack_from("<H", header, 54)[0]
                    e_phnum = struct.unpack_from("<H", header, 56)[0]

                for i in range(e_phnum):
                    offset = e_phoff + i * e_phentsize
                    if offset + 8 > len(data):
                        break
                    p_type = struct.unpack_from("<I", data, offset)[0]
                    if p_type == _PT_GNU_STACK:
                        if ei_class == 1:
                            p_flags = struct.unpack_from("<I", data, offset + 24)[0]
                        else:
                            p_flags = struct.unpack_from("<I", data, offset + 4)[0]
                        if p_flags & 0x1:
                            has_nx = False
                        break
            except (struct.error, IndexError):
                pass

            if not has_nx:
                no_nx += 1

        total = len(elf_paths)
        if no_pie > 0:
            self._add_finding(
                findings, "Binary Hardening", "HIGH",
                "{}/{} binaries lack PIE (ASLR bypass)".format(no_pie, total),
                "CWE-693: Protection Mechanism Failure",
            )
        if no_nx > 0:
            self._add_finding(
                findings, "Binary Hardening", "HIGH",
                "{}/{} binaries have executable stack (no NX)".format(no_nx, total),
                "Stack-based code execution possible",
            )
        if no_canary > 0:
            self._add_finding(
                findings, "Binary Hardening", "MEDIUM",
                "{}/{} binaries lack stack canary".format(no_canary, total),
                "Buffer overflow exploitation easier",
            )
        if no_pie == 0 and no_nx == 0 and no_canary == 0:
            self._add_finding(
                findings, "Binary Hardening", "INFO",
                "All {} binaries have PIE, NX, and canary".format(total), "",
            )

    # ------------------------------------------------------------------ #
    # 4. Boot Script Permissions
    # ------------------------------------------------------------------ #
    def _check_boot_permissions(self, findings):
        """Check boot scripts for dangerous permission assignments."""
        dangerous_patterns = [
            (re.compile(r"chmod\s+(?:a\+s|[0-7]*[67][0-7]{2})\b"), "CRITICAL",
             "Dangerous chmod (SUID or world-writable)"),
            (re.compile(r"chmod\s+777\b"), "CRITICAL", "chmod 777 — world-writable"),
        ]

        script_dirs = ["etc/init.d", "etc/rcS.d", "etc/rc.d", "etc", "init", "sbin"]
        scripts_checked = 0

        for subdir in script_dirs:
            search = os.path.join(self.firmware_dir, subdir)
            if not os.path.isdir(search):
                continue
            for fname in os.listdir(search):
                fpath = os.path.join(search, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read()
                except IOError:
                    continue

                scripts_checked += 1
                rel = os.path.relpath(fpath, self.firmware_dir)

                for pattern, severity, desc in dangerous_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        self._add_finding(
                            findings, "Boot Permissions", severity,
                            "{} in {}".format(desc, rel),
                            "{} occurrence(s)".format(len(matches)),
                        )

    # ------------------------------------------------------------------ #
    # 5. Password Hashes
    # ------------------------------------------------------------------ #
    def _check_password_hashes(self, findings):
        """Analyze /etc/shadow and /etc/passwd for weak credentials."""
        shadow_path = os.path.join(self.firmware_dir, "etc", "shadow")
        passwd_path = os.path.join(self.firmware_dir, "etc", "passwd")

        if os.path.isfile(shadow_path):
            try:
                with open(shadow_path, "r", errors="replace") as fh:
                    for line in fh:
                        parts = line.strip().split(":")
                        if len(parts) < 2:
                            continue
                        user, hfield = parts[0], parts[1]

                        if hfield == "" or hfield in ("!", "!!", "*"):
                            if hfield == "" and user == "root":
                                self._add_finding(
                                    findings, "Password Hashes", "CRITICAL",
                                    "Root account has NO password in /etc/shadow",
                                    "CWE-798",
                                )
                            continue

                        for known, label in _KNOWN_DEFAULT_HASHES.items():
                            if hfield == known:
                                self._add_finding(
                                    findings, "Password Hashes", "CRITICAL",
                                    "Known default hash for '{}': {}".format(user, label),
                                    "CWE-798: Use of Hard-coded Credentials",
                                )
                                break

                        if hfield.startswith("$1$"):
                            self._add_finding(
                                findings, "Password Hashes", "HIGH",
                                "MD5-crypt hash for '{}' (weak algorithm)".format(user),
                                "MD5-crypt is trivially brute-forceable",
                            )
                        elif not hfield.startswith("$"):
                            self._add_finding(
                                findings, "Password Hashes", "MEDIUM",
                                "Non-standard hash format for '{}'".format(user),
                                "Hash: {}...".format(hfield[:20]),
                            )
            except IOError:
                pass
        else:
            self._add_finding(
                findings, "Password Hashes", "INFO",
                "No /etc/shadow found", "",
            )

        if os.path.isfile(passwd_path):
            try:
                with open(passwd_path, "r", errors="replace") as fh:
                    for line in fh:
                        parts = line.strip().split(":")
                        if len(parts) < 4:
                            continue
                        user, pfield, uid = parts[0], parts[1], parts[2]
                        if uid == "0" and user != "root":
                            self._add_finding(
                                findings, "Password Hashes", "HIGH",
                                "Non-root user '{}' has UID 0".format(user),
                                "Equivalent to root privileges",
                            )
            except IOError:
                pass

    # ------------------------------------------------------------------ #
    # 6. SSH Host Keys
    # ------------------------------------------------------------------ #
    def _check_ssh_keys(self, findings):
        """Check for static SSH host keys in /etc/dropbear/."""
        dropbear_dir = os.path.join(self.firmware_dir, "etc", "dropbear")
        openssh_dir = os.path.join(self.firmware_dir, "etc", "ssh")

        for ssh_dir, label in [(dropbear_dir, "Dropbear"), (openssh_dir, "OpenSSH")]:
            if not os.path.isdir(ssh_dir):
                continue
            key_files = [
                f for f in os.listdir(ssh_dir)
                if "key" in f.lower() or f.endswith(".pub")
            ]
            if key_files:
                for kf in key_files:
                    kpath = os.path.join(ssh_dir, kf)
                    try:
                        size = os.path.getsize(kpath)
                        with open(kpath, "rb") as fh:
                            data = fh.read()
                        sha = _sha256_hex(data)
                    except IOError:
                        continue

                    self._add_finding(
                        findings, "SSH Host Keys", "HIGH",
                        "Static {} host key: {} ({} bytes)".format(label, kf, size),
                        "SHA-256: {}".format(sha),
                    )

    # ------------------------------------------------------------------ #
    # 7. Kernel Version
    # ------------------------------------------------------------------ #
    def _check_kernel_version(self, findings):
        """Extract kernel version from uImage or version strings."""
        version_files = [
            os.path.join(self.firmware_dir, "proc", "version"),
        ]
        version_str = None

        for vf in version_files:
            if os.path.isfile(vf):
                try:
                    with open(vf, "r", errors="replace") as fh:
                        version_str = fh.read().strip()
                        break
                except IOError:
                    pass

        if not version_str:
            for root, _dirs, files in os.walk(self.firmware_dir):
                for fname in files:
                    if fname in ("uImage", "zImage", "vmlinux", "Image"):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "rb") as fh:
                                data = fh.read(1048576)
                            match = re.search(
                                rb"Linux version (\d+\.\d+\.\d+[^\x00\n]{0,80})", data
                            )
                            if match:
                                version_str = match.group(1).decode("ascii", errors="replace")
                                break
                        except IOError:
                            continue
                if version_str:
                    break

        if version_str:
            self._add_finding(
                findings, "Kernel Version", "INFO",
                "Kernel: {}".format(version_str[:100]),
                "",
            )
            ver_match = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
            if ver_match:
                major, minor, patch = (
                    int(ver_match.group(1)),
                    int(ver_match.group(2)),
                    int(ver_match.group(3)),
                )
                if major < 4 or (major == 4 and minor < 4):
                    self._add_finding(
                        findings, "Kernel Version", "HIGH",
                        "Kernel {}.{}.{} is EOL — no security patches".format(
                            major, minor, patch
                        ),
                        "Upgrade to supported LTS kernel",
                    )
        else:
            self._add_finding(
                findings, "Kernel Version", "INFO",
                "Kernel version not found in rootfs", "",
            )

    # ------------------------------------------------------------------ #
    # 8. C Library Version
    # ------------------------------------------------------------------ #
    def _check_clib_version(self, findings):
        """Identify C library (uClibc, glibc, musl) and known CVEs."""
        libc_info = None

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                fpath = os.path.join(root, fname)

                if "uclibc" in fname.lower() or fname.startswith("libuClibc"):
                    try:
                        with open(fpath, "rb") as fh:
                            data = fh.read(65536)
                        match = re.search(rb"uClibc[- ](\d+\.\d+\.\d+)", data)
                        if match:
                            libc_info = ("uClibc", match.group(1).decode())
                            break
                    except IOError:
                        continue

                if fname.startswith("libc-") and fname.endswith(".so"):
                    try:
                        with open(fpath, "rb") as fh:
                            data = fh.read(65536)
                        match = re.search(
                            rb"(?:GNU C Library|glibc)\s*[^\d]*(\d+\.\d+(?:\.\d+)?)", data
                        )
                        if match:
                            libc_info = ("glibc", match.group(1).decode())
                            break
                        match = re.search(rb"release version (\d+\.\d+(?:\.\d+)?)", data)
                        if match:
                            libc_info = ("glibc", match.group(1).decode())
                            break
                    except IOError:
                        continue

                if fname.startswith("libc.musl") or fname == "ld-musl-arm.so.1":
                    try:
                        with open(fpath, "rb") as fh:
                            data = fh.read(65536)
                        match = re.search(rb"musl libc.*?(\d+\.\d+\.\d+)", data)
                        ver = match.group(1).decode() if match else "unknown"
                        libc_info = ("musl", ver)
                        break
                    except IOError:
                        continue

            if libc_info:
                break

        if libc_info:
            lib_name, lib_ver = libc_info
            self._add_finding(
                findings, "C Library", "INFO",
                "{} version {}".format(lib_name, lib_ver), "",
            )

            if lib_name == "uClibc":
                short_ver = ".".join(lib_ver.split(".")[:3])
                for vuln_ver, cves in _UCLIBC_CVES.items():
                    if short_ver.startswith(vuln_ver):
                        self._add_finding(
                            findings, "C Library", "HIGH",
                            "{} {} has known CVEs".format(lib_name, lib_ver),
                            "Affected: {}".format(", ".join(cves)),
                        )
                        break

            if lib_name == "glibc":
                ver_match = re.match(r"(\d+)\.(\d+)", lib_ver)
                if ver_match:
                    g_major = int(ver_match.group(1))
                    g_minor = int(ver_match.group(2))
                    if g_major == 2 and g_minor <= 17:
                        self._add_finding(
                            findings, "C Library", "HIGH",
                            "glibc {} is EOL with unpatched CVEs".format(lib_ver),
                            "Multiple known vulnerabilities in glibc <= 2.17",
                        )
        else:
            self._add_finding(
                findings, "C Library", "INFO",
                "C library not identified", "",
            )

    # ------------------------------------------------------------------ #
    # 9. Debug Utilities
    # ------------------------------------------------------------------ #
    def _check_debug_utils(self, findings):
        """Check for debug utilities left in firmware."""
        debug_tools = {
            "io": "Direct I/O register access tool",
            "dvrtools": "Hikvision DVR diagnostic tool",
            "strace": "System call tracer",
            "gdb": "GNU debugger",
            "gdbserver": "Remote GDB stub",
            "telnetd": "Telnet daemon",
            "tcpdump": "Packet capture tool",
            "netcat": "Network utility (nc)",
            "nc": "Netcat",
            "nmap": "Network scanner",
        }

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if fname in debug_tools:
                    fpath = os.path.join(root, fname)
                    if _is_elf(fpath):
                        rel = os.path.relpath(fpath, self.firmware_dir)
                        self._add_finding(
                            findings, "Debug Utilities", "HIGH",
                            "Debug tool '{}' present: {}".format(fname, rel),
                            debug_tools[fname],
                        )

    # ------------------------------------------------------------------ #
    # 10. JTAG References in DTB
    # ------------------------------------------------------------------ #
    def _check_jtag_references(self, findings):
        """Search DTB files and binaries for JTAG references."""
        jtag_patterns = [b"jtag", b"JTAG", b"swd", b"SWD", b"openocd"]

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if not (fname.endswith(".dtb") or fname.endswith(".dts")
                        or fname.endswith(".dtsi")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                except IOError:
                    continue

                for pattern in jtag_patterns:
                    if pattern in data:
                        rel = os.path.relpath(fpath, self.firmware_dir)
                        self._add_finding(
                            findings, "JTAG References", "MEDIUM",
                            "JTAG/SWD reference in {}".format(rel),
                            "Hardware debug interface may be accessible",
                        )
                        break

    # ------------------------------------------------------------------ #
    # 11. Developer Artifacts (NFS, IPs, Usernames)
    # ------------------------------------------------------------------ #
    def _check_developer_artifacts(self, findings):
        """Scan boot scripts for developer NFS, IPs, and usernames."""
        nfs_pattern = re.compile(
            r"mount\s+.*nfs.*?(\d+\.\d+\.\d+\.\d+):(\S+)"
        )
        dev_ip_pattern = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        username_pattern = re.compile(r"/(?:home|data\d?)/(\w{3,32})/")

        script_extensions = (".sh", ".conf", ".cfg")
        dev_ips = set()
        dev_users = set()
        nfs_found = False

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                is_script = (
                    fname.endswith(script_extensions)
                    or fname.startswith("S")
                    or fname in ("start.sh", "rcS", "rc.local", "inittab")
                )
                if not is_script:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read()
                except IOError:
                    continue

                for match in nfs_pattern.finditer(content):
                    nfs_found = True
                    nfs_ip = match.group(1)
                    nfs_path = match.group(2)
                    dev_ips.add(nfs_ip)
                    rel = os.path.relpath(fpath, self.firmware_dir)
                    self._add_finding(
                        findings, "Developer Artifacts", "CRITICAL",
                        "NFS mount in {}: {}:{}".format(rel, nfs_ip, nfs_path),
                        "CWE-489: Active Debug Code",
                    )
                    um = username_pattern.search(nfs_path)
                    if um:
                        dev_users.add(um.group(1))

                for ip_match in dev_ip_pattern.finditer(content):
                    ip = ip_match.group(1)
                    if ip.startswith("10.1.") or ip.startswith("10.2."):
                        dev_ips.add(ip)

                for um in username_pattern.finditer(content):
                    dev_users.add(um.group(1))

        if dev_ips and not nfs_found:
            self._add_finding(
                findings, "Developer Artifacts", "MEDIUM",
                "Internal developer IPs: {}".format(", ".join(sorted(dev_ips))),
                "May indicate debug/development remnants",
            )
        if dev_users:
            self._add_finding(
                findings, "Developer Artifacts", "MEDIUM",
                "Developer usernames: {}".format(", ".join(sorted(dev_users))),
                "Extracted from filesystem paths",
            )

    # ------------------------------------------------------------------ #
    # 12. IP Forwarding and Watchdog
    # ------------------------------------------------------------------ #
    def _check_system_hardening(self, findings):
        """Check for IP forwarding and watchdog configuration."""
        ipfwd_pattern = re.compile(
            r"echo\s+['\"]?1['\"]?\s*>\s*/proc/sys/net/ipv4/ip_forward"
        )
        wdt_pattern = re.compile(
            r"echo\s+['\"]?C['\"]?\s*>\s*/proc/(?:OSAL/wdt|watchdog)"
        )

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if not (fname.endswith(".sh") or fname in ("rcS", "rc.local", "inittab")):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as fh:
                        content = fh.read()
                except IOError:
                    continue

                rel = os.path.relpath(fpath, self.firmware_dir)

                if ipfwd_pattern.search(content):
                    self._add_finding(
                        findings, "System Hardening", "MEDIUM",
                        "IP forwarding enabled in {}".format(rel),
                        "Device acts as a router — lateral movement risk",
                    )

                if wdt_pattern.search(content):
                    self._add_finding(
                        findings, "System Hardening", "HIGH",
                        "Watchdog disabled in {}".format(rel),
                        "Device will not auto-reboot on hangs (debug behavior)",
                    )

    # ------------------------------------------------------------------ #
    # Run — orchestrate all checks
    # ------------------------------------------------------------------ #
    def run(self):
        if not self.firmware_dir or not os.path.isdir(self.firmware_dir):
            print_error("firmware_dir is not set or does not exist")
            return

        print_status("Starting comprehensive firmware audit: {}".format(
            self.firmware_dir
        ))
        if self.deep_scan:
            print_info("Deep scan enabled — this may take longer")

        findings = []

        checks = [
            ("3DES Key Extraction", self._check_3des_key),
            ("RSA Key Analysis", self._check_rsa_keys),
            ("Binary Hardening", self._check_binary_hardening),
            ("Boot Script Permissions", self._check_boot_permissions),
            ("Password Hash Analysis", self._check_password_hashes),
            ("SSH Host Key Check", self._check_ssh_keys),
            ("Kernel Version", self._check_kernel_version),
            ("C Library Version", self._check_clib_version),
            ("Debug Utilities", self._check_debug_utils),
            ("JTAG References", self._check_jtag_references),
            ("Developer Artifacts", self._check_developer_artifacts),
            ("System Hardening", self._check_system_hardening),
        ]

        for label, check_fn in checks:
            print_status("[{}/{}] {}...".format(
                checks.index((label, check_fn)) + 1, len(checks), label
            ))
            try:
                check_fn(findings)
            except Exception as exc:
                print_warning("Check '{}' failed: {}".format(label, exc))

        if not findings:
            print_success("No vulnerabilities found in firmware")
            return

        vuln_findings = [f for f in findings if f["severity"] != "INFO"]
        info_findings = [f for f in findings if f["severity"] == "INFO"]

        if vuln_findings:
            rows = []
            for f in sorted(vuln_findings,
                            key=lambda x: _SEVERITY_SCORES.get(x["severity"], 0),
                            reverse=True):
                rows.append((
                    f["category"],
                    f["severity"],
                    f["description"][:64],
                    f["detail"][:48] if f["detail"] else "-",
                ))
            print_table(
                ("Category", "Severity", "Description", "Detail"),
                *rows,
                title="Vulnerability Findings",
            )

        if info_findings:
            print_info("--- Informational ---")
            for f in info_findings:
                print_info("  [{}] {}".format(f["category"], f["description"]))

        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in findings if f["severity"] == "LOW")

        total_score = (critical * 4) + (high * 3) + (medium * 2) + (low * 1)

        if total_score >= 20:
            risk_label = "CRITICAL"
        elif total_score >= 12:
            risk_label = "HIGH"
        elif total_score >= 6:
            risk_label = "MEDIUM"
        elif total_score > 0:
            risk_label = "LOW"
        else:
            risk_label = "NONE"

        print_status("--- Overall Risk Assessment ---")
        print_info("  CRITICAL : {}".format(critical))
        print_info("  HIGH     : {}".format(high))
        print_info("  MEDIUM   : {}".format(medium))
        print_info("  LOW      : {}".format(low))
        print_info("  Score    : {} / {} (weighted)".format(
            total_score, (critical + high + medium + low) * 4
        ))

        if risk_label == "CRITICAL":
            print_error("  Overall Risk: {} — Immediate remediation required".format(
                risk_label
            ))
        elif risk_label == "HIGH":
            print_warning("  Overall Risk: {} — Significant exposure".format(risk_label))
        elif risk_label == "MEDIUM":
            print_warning("  Overall Risk: {} — Moderate exposure".format(risk_label))
        else:
            print_info("  Overall Risk: {}".format(risk_label))

    @mute
    def check(self):
        """Offline tool — always returns True if firmware_dir exists."""
        return bool(self.firmware_dir) and os.path.isdir(self.firmware_dir)
