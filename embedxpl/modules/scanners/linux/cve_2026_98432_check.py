"""CVE-2026-98432 — Linux kernel TCP use-after-free via MPTCP (CVSS 9.8).

Remotely exploitable use-after-free in IPv4 TCP stack triggered through
MPTCP listeners with IP options. No public exploit PoC as of 2026-11.

Affected kernel ranges (unfixed):
  < 5.10.272, < 5.15.223, < 6.1.190, < 6.6.159,
  < 6.12.113, < 6.18.56, < 7.2.10
EOL (no fix): 4.4, 4.9, 4.14, 4.19, 5.4

Validation reference: https://github.com/akamai/cve-2026-98432-validation-mitigation
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

__info__ = {
    "name": "CVE-2026-98432 Linux TCP MPTCP Scanner",
    "description": "Check if a Linux target has a kernel vulnerable to CVE-2026-98432",
    "authors": ["mrhenrike"],
    "references": [
        "https://github.com/akamai/cve-2026-98432-validation-mitigation",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-98432",
    ],
    "cve": ["CVE-2026-98432"],
    "cvss": 9.8,
    "category": "scanner",
    "target_type": ["linux", "embedded", "iot"],
}

# Vulnerable kernel version ranges: (min_inclusive, max_exclusive) as tuples of ints
VULNERABLE_RANGES = [
    # (series floor, series ceiling)
    ((5, 10, 0), (5, 10, 272)),
    ((5, 15, 0), (5, 15, 223)),
    ((6, 1, 0), (6, 1, 190)),
    ((6, 6, 0), (6, 6, 159)),
    ((6, 12, 0), (6, 12, 113)),
    ((6, 18, 0), (6, 18, 56)),
    ((7, 2, 0), (7, 2, 10)),
]

EOL_SERIES = [(4, 4), (4, 9), (4, 14), (4, 19), (5, 4)]


def _parse_kernel_version(uname_str: str) -> tuple[int, ...] | None:
    """Parse 'Linux x.y.z-...' → (x, y, z)."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", uname_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def is_vulnerable(uname_str: str) -> dict[str, object]:
    """
    Given the output of `uname -r` or /proc/version, determine if the
    kernel is vulnerable to CVE-2026-98432.

    Returns a dict with keys:
      - vulnerable: bool
      - eol: bool (True if kernel series is EOL, no patch available)
      - version: str
      - reason: str
    """
    version = _parse_kernel_version(uname_str)
    if not version:
        return {"vulnerable": False, "eol": False, "version": uname_str, "reason": "Could not parse kernel version"}

    series = (version[0], version[1])

    if series in EOL_SERIES:
        return {
            "vulnerable": True,
            "eol": True,
            "version": ".".join(str(x) for x in version),
            "reason": f"Kernel {series[0]}.{series[1]} is EOL — no patch available",
        }

    for lo, hi in VULNERABLE_RANGES:
        if lo[:2] == series and lo <= version < hi:
            return {
                "vulnerable": True,
                "eol": False,
                "version": ".".join(str(x) for x in version),
                "reason": f"Kernel {'.'.join(str(x) for x in version)} in vulnerable range < {'.'.join(str(x) for x in hi)}",
            }

    return {
        "vulnerable": False,
        "eol": False,
        "version": ".".join(str(x) for x in version),
        "reason": "Kernel version not in any known vulnerable range",
    }


def check_mptcp_enabled(proc_net_mptcp: str) -> bool:
    """Parse /proc/net/mptcp_net/mptcp_listener or sysctl output to detect MPTCP listener."""
    return bool(proc_net_mptcp and proc_net_mptcp.strip())


class CVE202698432Scanner:
    """
    Scanner module for CVE-2026-98432.
    Connects via SSH/Telnet to a target and reads kernel version + MPTCP state.
    """

    def __init__(self) -> None:
        self.target: str = ""
        self.port: int = 22
        self.username: str = ""
        self.password: str = ""
        self.options: dict[str, object] = {}

    def run(self) -> dict[str, object]:
        try:
            import paramiko  # type: ignore[import-untyped]
        except ImportError:
            return {"error": "paramiko not installed — pip install paramiko"}

        result: dict[str, object] = {
            "target": self.target,
            "cve": "CVE-2026-98432",
            "vulnerable": False,
            "eol": False,
            "mptcp_active": False,
            "kernel_version": "",
            "reason": "",
        }

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.target, port=self.port, username=self.username,
                           password=self.password, timeout=10)

            _, stdout, _ = client.exec_command("uname -r")
            uname = stdout.read().decode().strip()

            _, stdout2, _ = client.exec_command(
                "cat /proc/net/mptcp_net/mptcp_listener 2>/dev/null || sysctl net.mptcp.enabled 2>/dev/null"
            )
            mptcp_out = stdout2.read().decode().strip()
            client.close()

            vuln_info = is_vulnerable(uname)
            result.update(vuln_info)
            result["mptcp_active"] = check_mptcp_enabled(mptcp_out)

            if result["vulnerable"] and result["mptcp_active"]:
                result["severity"] = "CRITICAL — vulnerable kernel with active MPTCP listener"
            elif result["vulnerable"]:
                result["severity"] = "HIGH — vulnerable kernel (MPTCP not confirmed active)"
            else:
                result["severity"] = "LOW — not vulnerable"

        except Exception as exc:
            result["error"] = str(exc)

        return result
