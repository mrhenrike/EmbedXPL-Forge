# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Hikvision Boot Script Permission Audit (CWE-732).

Scans boot/init scripts for insecure permission assignments, dangerous
services left enabled, and hardcoded credentials. Offline analysis of
extracted firmware rootfs.

Version: 1.0.0
"""

import os
import re
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *


_SEVERITY_MAP = {
    "chmod_777": ("CRITICAL", "World-writable permission on filesystem path"),
    "chmod_666": ("HIGH", "World-readable/writable file permission"),
    "chmod_755_suid": ("HIGH", "SUID binary with broad permissions"),
    "telnetd": ("CRITICAL", "Debug telnet service enabled in production"),
    "dropbear": ("HIGH", "Debug SSH service (dropbear) enabled"),
    "mount_nosec": ("MEDIUM", "Mount without noexec/nosuid options"),
    "hardcoded_pass": ("CRITICAL", "Hardcoded password in script"),
    "curl_wget": ("HIGH", "External URL fetch in boot script"),
    "root_no_pass": ("CRITICAL", "Root account without password"),
    "default_hash": ("CRITICAL", "Known default password hash"),
    "extra_uid0": ("HIGH", "Non-root user with UID 0"),
    "psh_rsa_conf": ("HIGH", "PSH RSA config with insecure permissions"),
}

_KNOWN_DEFAULT_HASHES = {
    "$1$$qRPK7m23GJusamGpoGLby/": "Hikvision blank/default",
    "$1$c3DkrZ9Z$0PmTvUB3G./F46cQ.p6Op/": "Hikvision 12345",
    "$1$$CoERg7ynjYLsj2j4glJ34.": "Dahua default",
}

_DANGEROUS_MOUNT_OPTS = re.compile(
    r"\bmount\b.*?(?:(?!noexec|nosuid|nodev))",
    re.IGNORECASE,
)


class Exploit(Exploit):
    """Hikvision Boot Script Permission Audit.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Hikvision Boot Script Permission Audit",
        "description": (
            "Scans boot/init scripts for insecure permission assignments "
            "(chmod 777, chmod 666) and dangerous operations (telnetd, "
            "dropbear, insecure mounts, hardcoded passwords). CWE-732."
        ),
        "authors": (
            "André Henrique (@mrhenrike) — EmbedXPL-Forge",
        ),
        "references": (
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
        "devices": (
            "Hikvision NVR/DVR firmware V4.x",
            "Any embedded firmware with shell init scripts",
        ),
    }

    firmware_dir = OptString("", "Path to extracted firmware rootfs")

    def _find_init_scripts(self) -> List[str]:
        """Find all init/boot scripts in the firmware rootfs."""
        scripts: List[str] = []
        search_dirs = [
            "etc/rcS.d", "etc/init.d", "etc/rc.d",
            "etc/rc.local", "init", "sbin",
        ]

        for subdir in search_dirs:
            full_path = os.path.join(self.firmware_dir, subdir)
            if os.path.isfile(full_path):
                scripts.append(full_path)
            elif os.path.isdir(full_path):
                for fname in os.listdir(full_path):
                    fpath = os.path.join(full_path, fname)
                    if os.path.isfile(fpath):
                        scripts.append(fpath)

        for root, _dirs, files in os.walk(self.firmware_dir):
            for fname in files:
                if fname.endswith(".sh") or fname.startswith("S") or fname.startswith("K"):
                    fpath = os.path.join(root, fname)
                    if fpath not in scripts:
                        scripts.append(fpath)

        return scripts

    def _scan_script(self, filepath: str) -> List[Tuple[int, str, str, str]]:
        """Scan a single script file for security issues. Returns list of (line, finding, severity, detail)."""
        findings: List[Tuple[int, str, str, str]] = []

        try:
            with open(filepath, "r", errors="replace") as f:
                lines = f.readlines()
        except IOError:
            return findings

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if re.search(r"chmod\s+777\b", stripped):
                sev, desc = _SEVERITY_MAP["chmod_777"]
                findings.append((line_num, stripped[:80], sev, desc))

            if re.search(r"chmod\s+666\b", stripped):
                sev, desc = _SEVERITY_MAP["chmod_666"]
                findings.append((line_num, stripped[:80], sev, desc))

            if re.search(r"\btelnetd\b", stripped):
                sev, desc = _SEVERITY_MAP["telnetd"]
                findings.append((line_num, stripped[:80], sev, desc))

            if re.search(r"\bdropbear\b", stripped):
                sev, desc = _SEVERITY_MAP["dropbear"]
                findings.append((line_num, stripped[:80], sev, desc))

            if re.search(r"\bmount\b", stripped) and not re.search(
                r"noexec|nosuid", stripped
            ):
                if not re.search(r"^#|umount", stripped):
                    sev, desc = _SEVERITY_MAP["mount_nosec"]
                    findings.append((line_num, stripped[:80], sev, desc))

            pass_match = re.search(
                r"(?:password|passwd|pass|pwd)\s*[=:]\s*['\"]?(\S+)",
                stripped, re.IGNORECASE,
            )
            if pass_match:
                sev, desc = _SEVERITY_MAP["hardcoded_pass"]
                findings.append((
                    line_num,
                    "password=***REDACTED***",
                    sev,
                    desc,
                ))

            if re.search(r"\b(?:curl|wget)\s+https?://", stripped):
                sev, desc = _SEVERITY_MAP["curl_wget"]
                findings.append((line_num, stripped[:80], sev, desc))

            if re.search(r"psh_rsa\.conf", stripped):
                sev, desc = _SEVERITY_MAP["psh_rsa_conf"]
                findings.append((line_num, stripped[:80], sev, desc))

        return findings

    def _check_passwd_shadow(self) -> List[Tuple[str, str, str, str]]:
        """Check /etc/passwd and /etc/shadow for credential issues."""
        findings: List[Tuple[str, str, str, str]] = []

        passwd_path = os.path.join(self.firmware_dir, "etc", "passwd")
        shadow_path = os.path.join(self.firmware_dir, "etc", "shadow")

        if os.path.isfile(passwd_path):
            try:
                with open(passwd_path, "r", errors="replace") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) < 7:
                            continue
                        user, passwd_field, uid = parts[0], parts[1], parts[2]

                        if uid == "0" and user != "root":
                            sev, desc = _SEVERITY_MAP["extra_uid0"]
                            findings.append(("etc/passwd", user, sev, desc))

                        if passwd_field in ("", "x", "*"):
                            continue
                        if passwd_field == "":
                            sev, desc = _SEVERITY_MAP["root_no_pass"]
                            findings.append(("etc/passwd", user, sev, desc))
            except IOError:
                pass

        if os.path.isfile(shadow_path):
            try:
                with open(shadow_path, "r", errors="replace") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if len(parts) < 2:
                            continue
                        user, hash_field = parts[0], parts[1]

                        if hash_field in ("", "!", "*", "!!"):
                            if hash_field == "" and user == "root":
                                sev, desc = _SEVERITY_MAP["root_no_pass"]
                                findings.append(("etc/shadow", user, sev, desc))
                            continue

                        for known_hash, known_desc in _KNOWN_DEFAULT_HASHES.items():
                            if hash_field == known_hash:
                                sev, desc = _SEVERITY_MAP["default_hash"]
                                findings.append((
                                    "etc/shadow",
                                    "{} ({})".format(user, known_desc),
                                    sev,
                                    desc,
                                ))
            except IOError:
                pass

        return findings

    def run(self) -> None:
        if not self.firmware_dir or not os.path.isdir(self.firmware_dir):
            print_error("firmware_dir is not set or does not exist")
            return

        print_status("Scanning boot scripts in {}...".format(self.firmware_dir))

        scripts = self._find_init_scripts()
        if not scripts:
            print_warning("No init/boot scripts found")
        else:
            print_status("Found {} scripts to analyze".format(len(scripts)))

        all_findings: List[Tuple[str, int, str, str, str]] = []

        for script_path in scripts:
            rel_path = os.path.relpath(script_path, self.firmware_dir)
            findings = self._scan_script(script_path)
            for line_num, content, severity, description in findings:
                all_findings.append((rel_path, line_num, content, severity, description))

        # Credential checks
        print_status("Checking /etc/passwd and /etc/shadow...")
        cred_findings = self._check_passwd_shadow()
        for file_name, detail, severity, description in cred_findings:
            all_findings.append((file_name, 0, detail, severity, description))

        if not all_findings:
            print_success("No security issues found in boot scripts")
            return

        rows = [
            (f, str(ln) if ln else "-", content[:60], sev, desc)
            for f, ln, content, sev, desc in all_findings
        ]
        print_table(
            ("File", "Line", "Finding", "Severity", "Description"),
            *rows,
            title="Boot Script Security Findings",
        )

        # Summary
        critical = sum(1 for _, _, _, s, _ in all_findings if s == "CRITICAL")
        high = sum(1 for _, _, _, s, _ in all_findings if s == "HIGH")
        medium = sum(1 for _, _, _, s, _ in all_findings if s == "MEDIUM")

        print_status("Summary: {} CRITICAL, {} HIGH, {} MEDIUM findings".format(
            critical, high, medium
        ))

        if critical > 0:
            print_warning(
                "CVSS 7.8 (CWE-732): Incorrect Permission Assignment for Critical Resource"
            )
        if any("telnetd" in f[4] for f in all_findings):
            print_warning(
                "CVSS 9.8: Debug telnet service enabled — full remote access risk"
            )
