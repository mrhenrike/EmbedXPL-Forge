# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mirai default credential sweep — full table from Mirai source code.

Iterates through the 62 username/password pairs extracted from the original
Mirai botnet source code (``mirai/bot/scanner.c``, ``loader/src/headers/table.c``)
and tests each pair against the target's Telnet service (port 23 / 2323) or
HTTP Basic Auth.

This module is detection-oriented: it confirms whether a device still has
factory-default credentials that made it susceptible to Mirai-family infection.
No malicious payload is deployed.

Attack path in real Mirai:
  1. Scanner thread connects to Telnet port 23 or 2323.
  2. Tries each cred pair from the embedded table.
  3. On success, sends a shell command to download + execute the arm7/mips bot ELF.

References:
  https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c
  https://krebsonsecurity.com/2016/10/source-code-for-iot-attack-tool-mirai-released/
  https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf

MITRE ATT&CK:
  T1078.001 — Valid Accounts: Default Accounts
  T1110.001 — Brute Force: Password Guessing

v1.0.0: initial 62-pair table (mirai/bot/scanner.c generic + table.c)
v1.1.0: extended with Condi-Mirai scanner.c XOR-decoded pairs
        (lion001am-condi/bot/scanner.c, jgamblin-mirai-source/mirai/bot/scanner.c)
        Added: hi3518, cat1029, GM8182, 7ujMko0vizxv, uClinux, 5up, jvc,
               jvbzd, ivdev, zlxx, calvin, fidel123, epicrouter, ZmqVfoSIP,
               motorola, OxhlwSG8, tlJwpbo6, S2fGqNFs (18 new pairs)

Version: 1.1.0
"""

from __future__ import annotations

import logging
import socket
import time
from typing import List, Optional, Tuple

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptIP,
    OptInt,
    OptPort,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.scanners.threat_detection.mirai_default_creds_sweep")

# Full credential table from Mirai source (scanner.c + table.c)
# Source: https://github.com/jgamblin/Mirai-Source-Code
_MIRAI_FULL_CREDS: List[Tuple[str, str]] = [
    ("root",       "xc3511"),
    ("root",       "vizxv"),
    ("root",       "admin"),
    ("admin",      "admin"),
    ("root",       "888888"),
    ("root",       "xmhdipc"),
    ("root",       "default"),
    ("root",       "juantech"),
    ("root",       "123456"),
    ("root",       "54321"),
    ("support",    "support"),
    ("root",       ""),
    ("admin",      "password"),
    ("root",       "root"),
    ("root",       "12345"),
    ("user",       "user"),
    ("admin",      ""),
    ("root",       "pass"),
    ("admin",      "admin1234"),
    ("root",       "1111"),
    ("admin",      "smcadmin"),
    ("admin",      "1111"),
    ("root",       "666666"),
    ("root",       "password"),
    ("root",       "1234"),
    ("root",       "klv123"),
    ("Administrator", "admin"),
    ("service",    "service"),
    ("supervisor", "supervisor"),
    ("guest",      "guest"),
    ("guest",      "12345"),
    ("guest",      ""),
    ("admin1",     "password"),
    ("administrator", "1234"),
    ("666666",     "666666"),
    ("888888",     "888888"),
    ("ubnt",       "ubnt"),
    ("root",       "klv1234"),
    ("root",       "Zte521"),
    ("root",       "HuiZhouDGT"),
    ("root",       "GiMiShare"),
    ("root",       "OxhlwSG8"),
    ("root",       "mobile"),
    ("root",       "tsgoingon"),
    ("root",       "7ujMko0admin"),
    ("admin",      "7ujMko0admin"),
    ("admin",      "1234"),
    ("admin",      "12345"),
    ("admin",      "54321"),
    ("admin",      "123456"),
    ("admin",      "user"),
    ("admin",      "default"),
    ("admin",      "pass"),
    ("user",       "1234"),
    ("pi",         "raspberry"),
    ("osmc",       "osmc"),
    ("tech",       "tech"),
    ("mother",     "f**ker"),
    ("mother",     "fucker"),
    ("admin",      "admin123"),
    ("root",       "r00tme"),
    ("root",       "root1234"),
    # Extended: lion001am-condi/bot/scanner.c XOR-decoded pairs
    # Source: jgamblin-mirai-source/mirai/bot/scanner.c comments
    ("root",       "hi3518"),
    ("root",       "cat1029"),
    ("root",       "GM8182"),
    ("root",       "7ujMko0vizxv"),
    ("root",       "7ujMko0admin"),
    ("root",       "uClinux"),
    ("root",       "5up"),
    ("root",       "jvc"),
    ("root",       "jvbzd"),
    ("root",       "ivdev"),
    ("root",       "klv123"),
    ("root",       "klv1234"),
    ("root",       "zlxx"),
    ("root",       "calvin"),
    ("root",       "fidel123"),
    ("admin",      "epicrouter"),
    ("admin",      "ZmqVfoSIP"),
    ("admin",      "motorola"),
    ("default",    "OxhlwSG8"),
    ("default",    "tlJwpbo6"),
    ("default",    "S2fGqNFs"),
    # Condi-specific additional creds
    ("root",       "Zte521"),
    ("root",       "HuiZhouDGT"),
    ("root",       "GiMiShare"),
    ("root",       "mobile"),
    ("root",       "tsgoingon"),
]


class Exploit(BaseExploit):
    """Mirai default credential sweep for Telnet IoT targets.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mirai Default Credentials Sweep",
        "description": (
            "Tests all 62 credential pairs from the Mirai botnet source code "
            "against a target Telnet service. Confirms factory-default credential "
            "exposure that enabled Mirai propagation. Detection only -- "
            "no malicious payload deployed."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://github.com/jgamblin/Mirai-Source-Code",
            "https://krebsonsecurity.com/2016/10/source-code-for-iot-attack-tool-mirai-released/",
        ],
        "devices": [
            "Generic IoT / SOHO Routers",
            "IP Cameras / DVR / NVR",
            "Network Switches",
            "Any Telnet-enabled device",
        ],
        "severity": "critical",
        "apt_groups": ["Mirai Botnet", "Condi Botnet", "Gafgyt"],
        "mitre": ["T1078.001", "T1110.001"],
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(23, "Telnet port (default 23; use 2323 for alt-Telnet)")
    timeout = OptInt(4, "TCP connect/read timeout in seconds")
    stop_on_first = OptString("true", "Stop after first successful credential pair")

    @mute
    def check(self) -> bool:
        """Check if Telnet port is reachable on target.

        Returns:
            True if TCP connection to the configured port succeeds.
        """
        return self._tcp_open(self.target, self.port, self.timeout)

    def run(self) -> None:
        """Sweep all Mirai default credentials against the target Telnet."""
        print_status("[MiraiCreds] Starting credential sweep on {}:{}...".format(
            self.target, self.port))
        print_info("[MiraiCreds] {} credential pairs to test.".format(len(_MIRAI_FULL_CREDS)))

        if not self._tcp_open(self.target, self.port, self.timeout):
            print_error("[MiraiCreds] Port {}/tcp is closed or filtered on {}.".format(
                self.port, self.target))
            return

        valid: List[Tuple[str, str]] = []
        stop_first = str(self.stop_on_first).lower() in ("true", "1", "yes")

        for idx, (user, pwd) in enumerate(_MIRAI_FULL_CREDS, start=1):
            result = self._telnet_probe(self.target, self.port, user, pwd)
            if result:
                valid.append((user, pwd))
                print_warning(
                    "[MiraiCreds] [{}/{}] VALID creds: {}:{} on {}:{}".format(
                        idx, len(_MIRAI_FULL_CREDS), user, pwd, self.target, self.port
                    )
                )
                if stop_first:
                    break
            else:
                logger.debug("Creds %s:%s -- failed", user, pwd)

        print_info("[MiraiCreds] Sweep complete. Valid pairs: {}".format(len(valid)))
        if valid:
            print_warning(
                "[MiraiCreds] Device {}:{} accepts Mirai default credentials: {}".format(
                    self.target, self.port, valid
                )
            )
            print_info("[MiraiCreds] Recommendation: change default credentials immediately "
                       "and disable Telnet access from WAN.")
        else:
            print_success("[MiraiCreds] No Mirai default credentials accepted -- "
                          "device appears hardened against this vector.")

    # -------------------------------------------------------------------------
    # Internal helpers
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

    def _telnet_probe(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Attempt a single credential pair against a Telnet service.

        Args:
            host: Target IP address.
            port: Telnet port.
            user: Username to test.
            pwd: Password to test.

        Returns:
            True if the credential pair appears accepted (shell prompt returned).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            time.sleep(0.25)

            # Drain initial banner / IAC negotiation
            try:
                sock.recv(512)
            except socket.timeout:
                pass

            sock.sendall((user + "\n").encode("latin-1", errors="replace"))
            time.sleep(0.25)
            try:
                sock.recv(256)
            except socket.timeout:
                pass

            sock.sendall((pwd + "\n").encode("latin-1", errors="replace"))
            time.sleep(0.4)
            try:
                response = sock.recv(512)
            except socket.timeout:
                response = b""

            failure_markers = (b"incorrect", b"failed", b"invalid", b"login incorrect")
            success_markers = (b"/ #", b"# ", b"$ ", b"busybox", b"sh-", b"ash")

            lower = response.lower()
            if any(m in lower for m in failure_markers):
                return False
            if any(m in lower for m in success_markers):
                return True
            # Ambiguous -- treat as failure to avoid false positives
            return False
        except (OSError, socket.timeout):
            return False
        finally:
            sock.close()
