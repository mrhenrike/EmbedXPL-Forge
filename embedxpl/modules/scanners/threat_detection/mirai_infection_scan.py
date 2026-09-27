# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mirai-family infection indicator scanner.

Probes a target host for the combination of signals that indicate an active
Mirai/Condi/Gafgyt botnet infection:

  1. Open Telnet port (23 / 2323) — primary propagation vector.
  2. Default credentials accepted (root:root, admin:admin, root:vizxv …).
  3. BusyBox shell banner returned on successful login.

A device is flagged as likely infected (CheckResult.VULNERABLE) if at least
two indicators are positive.  The module is purely passive/read from a
network perspective: it opens a TCP socket, sends credential pairs, and
reads the response.  No payloads are dropped.

MITRE ATT&CK (ICS / Enterprise):
  T1078.001 — Valid Accounts: Default Accounts
  T1133    — External Remote Services (Telnet)
  T1595.001 — Active Scanning: Scanning IP Blocks

References:
  https://unit42.paloaltonetworks.com/mirai-botnet/
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c

Version: 1.0.0
"""

from __future__ import annotations

import logging
import socket
import time
from typing import List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptIP,
    OptString,
    OptInt,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.scanners.threat_detection.mirai_infection_scan")

# Mirai scanner default credential pairs (from mirai/bot/scanner.c table)
_MIRAI_CREDS: List[Tuple[str, str]] = [
    ("root",    "root"),
    ("admin",   "admin"),
    ("root",    "vizxv"),
    ("root",    "xc3511"),
    ("root",    "Zte521"),
    ("admin",   "1234"),
    ("admin",   "12345"),
    ("admin",   "password"),
    ("root",    "888888"),
    ("root",    "666666"),
    ("guest",   "guest"),
    ("root",    "xmhdipc"),
    ("root",    "defaultpassword"),
    ("root",    "juantech"),
    ("root",    "anko"),
    ("root",    "7ujMko0admin"),
    ("admin",   "7ujMko0admin"),
    ("root",    ""),
    ("admin",   ""),
    ("support", "support"),
    ("user",    "user"),
    ("ubnt",    "ubnt"),
    ("pi",      "raspberry"),
]

# BusyBox/ash banners emitted after Mirai-style Telnet login
_BUSYBOX_MARKERS = (
    b"busybox",
    b"BusyBox",
    b"/ #",
    b"# ",
    b"$ ",
    b"login:",
    b"password:",
    b"ash",
)


class Exploit(BaseExploit):
    """Mirai-family infection indicator scanner.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mirai Infection Indicator Scanner",
        "description": (
            "Probes Telnet ports (23, 2323) for open access and tests a subset "
            "of Mirai/Condi default credentials.  Flags a device as likely infected "
            "when >= 2 indicators are positive (open port + default creds + BusyBox banner). "
            "Detection only -- no payload dropped."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://unit42.paloaltonetworks.com/mirai-botnet/",
            "https://github.com/jgamblin/Mirai-Source-Code",
        ],
        "devices": [
            "Generic IoT / SOHO Routers",
            "IP Cameras",
            "DVR/NVR Devices",
            "Network Switches",
        ],
        "severity": "high",
        "apt_groups": ["Mirai Botnet", "Condi Botnet", "Gafgyt"],
        "mitre": ["T1078.001", "T1133", "T1595.001"],
    }

    target = OptIP("", "Target IPv4 address to probe")
    port_list = OptString("23,2323", "Comma-separated Telnet port list")
    timeout = OptInt(5, "TCP connect/read timeout in seconds")

    @mute
    def check(self) -> bool:
        """Check if any Telnet port is open on the target.

        Returns:
            True if at least one Telnet port is reachable.
        """
        for port in self._parse_ports():
            if self._tcp_connect(self.target, port, self.timeout):
                return True
        return False

    def run(self) -> None:
        """Execute multi-indicator Mirai infection scan."""
        print_status("[MiraiScan] Scanning {} for Mirai infection indicators...".format(self.target))

        indicators: int = 0
        open_ports: List[int] = []
        hit_creds: List[Tuple[str, str]] = []

        # Indicator 1: open Telnet ports
        for port in self._parse_ports():
            if self._tcp_connect(self.target, port, self.timeout):
                open_ports.append(port)
                indicators += 1
                print_success("[MiraiScan] Telnet port {}/{} OPEN on {}".format(
                    port, "tcp", self.target))

        if not open_ports:
            print_status("[MiraiScan] No Telnet ports open -- host likely not Mirai-targeted.")
            return

        # Indicator 2 + 3: default creds + BusyBox banner
        for port in open_ports:
            result = self._try_telnet_creds(self.target, port)
            if result:
                user, pwd, banner = result
                hit_creds.append((user, pwd))
                indicators += 1
                print_success("[MiraiScan] Default creds accepted: {}:{} on port {}".format(
                    user, pwd, port))
                if any(m in banner for m in _BUSYBOX_MARKERS):
                    indicators += 1
                    print_success("[MiraiScan] BusyBox/shell banner detected -- "
                                  "device likely runs IoT firmware: {!r}".format(
                                      banner[:80]))

        # Verdict
        print_info("[MiraiScan] Indicators: {} | Open ports: {} | Valid creds: {}".format(
            indicators, open_ports, hit_creds))

        if indicators >= 2:
            print_warning(
                "[MiraiScan] LIKELY INFECTED or HIGHLY VULNERABLE -- {} indicators positive on {}.".format(
                    indicators, self.target)
            )
            print_info("[MiraiScan] Recommendation: isolate device, reflash firmware, "
                       "change all default credentials.")
        else:
            print_status("[MiraiScan] Single indicator -- low confidence. Monitor or re-scan.")

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _parse_ports(self) -> List[int]:
        """Parse port_list option into list of integers."""
        result = []
        for part in str(self.port_list).split(","):
            part = part.strip()
            if part.isdigit():
                result.append(int(part))
        return result or [23, 2323]

    def _tcp_connect(self, host: str, port: int, timeout: int) -> bool:
        """Attempt a raw TCP connection and return True if it succeeds."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            return True
        except (OSError, socket.timeout):
            return False
        finally:
            sock.close()

    def _try_telnet_creds(
        self, host: str, port: int
    ) -> Optional[Tuple[str, str, bytes]]:
        """Try each Mirai default credential against a Telnet service.

        Returns:
            (username, password, banner_bytes) on first successful login,
            or None if all credentials fail.
        """
        for user, pwd in _MIRAI_CREDS:
            banner = self._telnet_probe(host, port, user, pwd)
            if banner is not None:
                return user, pwd, banner
        return None

    def _telnet_probe(self, host: str, port: int, user: str, pwd: str) -> Optional[bytes]:
        """Attempt a raw Telnet credential probe.

        Sends username + password and checks for a shell prompt or BusyBox
        marker in the response.

        Args:
            host: Target IP address.
            port: Telnet port number.
            user: Username to attempt.
            pwd: Password to attempt.

        Returns:
            Response bytes if authentication appears successful, None otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            time.sleep(0.3)
            banner = b""
            try:
                banner = sock.recv(512)
            except socket.timeout:
                pass

            # Negotiate away Telnet IAC options (strip them for simplicity)
            sock.sendall((user + "\n").encode("latin-1", errors="replace"))
            time.sleep(0.3)
            try:
                banner += sock.recv(256)
            except socket.timeout:
                pass

            sock.sendall((pwd + "\n").encode("latin-1", errors="replace"))
            time.sleep(0.5)
            try:
                response = sock.recv(512)
                banner += response
            except socket.timeout:
                response = b""

            # Accept if we see a shell prompt or a known BusyBox marker
            combined = banner.lower()
            success_markers = (b"/ #", b"# ", b"$ ", b"busybox", b"ash", b"sh-")
            failure_markers = (b"incorrect", b"failed", b"invalid", b"login incorrect")
            if any(m in combined for m in failure_markers):
                return None
            if any(m in combined for m in success_markers):
                return banner
            return None
        except (OSError, socket.timeout):
            return None
        finally:
            sock.close()
