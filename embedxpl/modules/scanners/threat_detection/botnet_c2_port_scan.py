# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Botnet C2 port scanner and banner fingerprinter.

Scans a set of TCP/UDP ports commonly used by Mirai, Condi, Gafgyt, Mozi,
QBot, and similar IoT botnets for their command-and-control (C2) channels.
For each open port, fetches the initial banner and computes an MD5 hash for
offline correlation with known C2 infrastructure.

C2 port list (rationale):
  23    — Telnet (Mirai propagation + C2 fallback)
  2323  — Alt-Telnet (Mirai/Gafgyt)
  3778  — Mirai/Condi CnC bot listener (decoded: table.c bytes[0x2C,0xE0] XOR 0xdeadbeef)
  9555  — Mirai scan-callback / loader report port (decoded: [0x07,0x71] XOR 0xdeadbeef)
  7547  — TR-069 CWMP (Mirai Eir variant, CVE-2016-10372)
  37215 — Huawei HG532 TR-069 (CVE-2017-17215, Satori/Mirai)
  52869 — MiniUPnP (CVE-2013-0230, Mirai)
  8080  — HTTP alt (Condi / generic C2)
  9001  — Tor OR port / generic C2 (Mozi / Hajime)
  6667  — IRC (classic botnet C2 / Mirai variants)
  8443  — HTTPS alt C2 (Condi 2025)
  48101 — Mirai-specific C2 beacon port
  46266 — Mozi DHT peer port

MITRE ATT&CK:
  T1571   — Non-Standard Port
  T1095   — Non-Application Layer Protocol
  T1219   — Remote Access Software (C2 beaconing)

References:
  https://www.cisecurity.org/insights/blog/mirai-botnet
  https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/mirai
  https://securelist.com/mozi-botnet/

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import socket
import time
from typing import Dict, List, Optional

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptBool,
    OptIP,
    OptInt,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.scanners.threat_detection.botnet_c2_port_scan")

# Known C2 ports with associated botnet family labels
_C2_PORTS: Dict[int, str] = {
    23:    "Telnet — Mirai/Gafgyt propagation",
    2323:  "Alt-Telnet — Mirai/Gafgyt/Condi",
    3778:  "Mirai/Condi CnC bot listener (table.c decoded)",
    9555:  "Mirai scan-callback / loader report (table.c decoded)",
    7547:  "TR-069 CWMP — Mirai Eir (CVE-2016-10372)",
    37215: "Huawei TR-069 — Satori/Mirai (CVE-2017-17215)",
    52869: "MiniUPnP — Mirai (CVE-2013-0230)",
    8080:  "HTTP-alt C2 — Condi/generic",
    9001:  "Tor/generic C2 — Mozi/Hajime",
    6667:  "IRC C2 — Mirai variants",
    8443:  "HTTPS-alt C2 — Condi 2025",
    48101: "Mirai C2 beacon",
    46266: "Mozi DHT peer",
}

# Partial banner strings that correlate with known C2 or botnet binaries
_C2_BANNER_SIGNATURES: Dict[bytes, str] = {
    b"mirai":     "Mirai binary string",
    b"gafgyt":    "Gafgyt binary string",
    b"condi":     "Condi botnet binary",
    b"mozi":      "Mozi DHT",
    b"satori":    "Satori variant",
    b"fbot":      "Fbot botnet",
    b"hajime":    "Hajime botnet",
    b"IoT":       "Generic IoT C2 hint",
    b"busybox":   "BusyBox shell (IoT indicator)",
}


class Exploit(BaseExploit):
    """Botnet C2 port scanner and banner fingerprinter.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Botnet C2 Port Scanner",
        "description": (
            "Scans TCP ports commonly used by Mirai/Condi/Gafgyt/Mozi C2 channels. "
            "Fetches banners from open ports, computes MD5 for correlation, and "
            "flags strings matching known botnet signatures. Detection only."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://www.cisecurity.org/insights/blog/mirai-botnet",
            "https://securelist.com/mozi-botnet/",
        ],
        "devices": [
            "Generic IoT / SOHO Routers",
            "IP Cameras",
            "DVR/NVR",
            "Any networked device",
        ],
        "severity": "medium",
        "apt_groups": ["Mirai Botnet", "Condi Botnet", "Gafgyt", "Mozi"],
        "mitre": ["T1571", "T1095", "T1219"],
    }

    target = OptIP("", "Target IPv4 address")
    timeout = OptInt(3, "TCP connect/read timeout in seconds")
    banner_bytes = OptInt(256, "Maximum bytes to read from banner")
    verbose = OptBool(False, "Print closed ports too")

    @mute
    def check(self) -> bool:
        """Check if any C2 port is reachable on the target.

        Returns:
            True if at least one C2 port is open.
        """
        for port in list(_C2_PORTS.keys())[:5]:
            if self._tcp_open(self.target, port, self.timeout):
                return True
        return False

    def run(self) -> None:
        """Scan all C2 ports and fingerprint banners."""
        print_status("[C2Scan] Scanning {} for botnet C2 ports...".format(self.target))

        open_count = 0
        findings: List[str] = []

        for port, label in _C2_PORTS.items():
            if not self._tcp_open(self.target, port, self.timeout):
                if self.verbose:
                    print_info("[C2Scan] Port {}/tcp CLOSED ({})".format(port, label))
                continue

            open_count += 1
            banner = self._grab_banner(self.target, port)
            banner_hash = hashlib.md5(banner).hexdigest() if banner else "N/A"
            banner_preview = repr(banner[:64]) if banner else "(no banner)"

            matched_sigs = [
                desc for sig, desc in _C2_BANNER_SIGNATURES.items()
                if sig in banner.lower()
            ] if banner else []

            finding = "[C2Scan] OPEN {}/tcp | {} | hash={} | banner={} | sigs={}".format(
                port, label, banner_hash, banner_preview,
                matched_sigs if matched_sigs else "none"
            )
            findings.append(finding)

            if matched_sigs:
                print_warning(finding)
            else:
                print_success(finding)

        print_info("[C2Scan] Summary: {}/{} C2 ports open on {}".format(
            open_count, len(_C2_PORTS), self.target))

        if open_count == 0:
            print_status("[C2Scan] No known C2 ports open -- host likely clean or firewalled.")
        elif open_count >= 3:
            print_warning(
                "[C2Scan] {} C2 ports open -- elevated risk of C2 channel or exposed "
                "Telnet/UPnP management. Investigate immediately.".format(open_count)
            )

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _tcp_open(self, host: str, port: int, timeout: int) -> bool:
        """Return True if the TCP port accepts a connection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            return True
        except (OSError, socket.timeout):
            return False
        finally:
            sock.close()

    def _grab_banner(self, host: str, port: int) -> Optional[bytes]:
        """Connect and read the initial banner from a port.

        Args:
            host: Target IP.
            port: Port number.

        Returns:
            Raw bytes received, or None if the connection failed.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            time.sleep(0.2)
            try:
                return sock.recv(self.banner_bytes)
            except socket.timeout:
                return b""
        except (OSError, socket.timeout):
            return None
        finally:
            sock.close()
