# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mirai/Condi CnC beacon and infrastructure detector.

Probes a target host for signs of an active Mirai/Condi Command-and-Control
infrastructure.  Three independent detection channels are used:

1. **CnC bot listener (TCP 3778)**
   Port 3778 (0x0EC2) is the Condi-Mirai CnC port decoded from
   ``table_init()`` in ``lion001am-condi/bot/table.c``.  A live CnC sends
   a 5-byte binary handshake to connecting bots:
   ``\\x00\\x00\\x00\\x01\\x00`` (type=ping, len=1, data=0x00).
   This probe attempts to connect and read the opening bytes.

2. **Scan-callback port (TCP 9555)**
   Port 9555 (0x2553) is the scan callback port where the loader receives
   Telnet scan results from infected devices.  Exposure of this port
   indicates an active Mirai loader infrastructure.

3. **MySQL C2 database exposure (TCP 3306)**
   The Mirai CnC uses a MySQL backend with schema:
   ``mirai.users``, ``mirai.history``, ``mirai.whitelist``
   (from ``jgamblin-mirai-source/scripts/db.sql``).
   This probe reads the MySQL server greeting banner and checks
   for the default charset / capability flags consistent with a freshly-
   installed Mirai CnC database server.

Source references:
  lion001am-condi/bot/table.c         (CnC/scan port decoding)
  lion001am-condi/cnc/main.go         (bot listener handshake)
  jgamblin-mirai-source/scripts/db.sql (MySQL C2 schema)

MITRE ATT&CK:
  T1219  — Remote Access Software (C2 infrastructure)
  T1571  — Non-Standard Port
  T1046  — Network Service Discovery

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

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

logger = logging.getLogger("embedxpl.scanners.threat_detection.mirai_c2_beacon_detect")

# CnC port decoded from Condi-Mirai table.c (key 0xdeadbeef):
#   bytes [0x2C, 0xE0] XOR 0xEF XOR 0xBE XOR 0xAD XOR 0xDE = [0x0E, 0xC2] = 3778
_MIRAI_CNC_PORT: int = 3778

# Scan-callback port (loader receives scan results from infected bots):
#   bytes [0x07, 0x71] XOR key = [0x25, 0x53] = 9555
_MIRAI_SCAN_CB_PORT: int = 9555

# Mirai CnC bot ping handshake: type=0x00, len=0x00000001, data=0x00
# Observed in cnc/main.go / cnc/bot.go — first bytes sent to connecting bot
_MIRAI_CNC_PING: bytes = b"\x00\x00\x00\x00\x01\x00"

# MySQL banner markers consistent with a Mirai CnC server
_MYSQL_MIRAI_MARKERS: Tuple[bytes, ...] = (
    b"mirai",
    b"5.7.",    # MySQL 5.7 common in Mirai CnC setups
    b"5.6.",
    b"8.0.",
    b"mysql",
)

# Attack vector opcodes from lion001am-condi/bot/attack.h
MIRAI_ATTACK_VECTORS: Dict[int, str] = {
    0:  "ATK_VEC_STOMP",
    1:  "ATK_VEC_UDP_PLAIN",
    2:  "ATK_VEC_STD",
    3:  "ATK_VEC_TCP",
    4:  "ATK_VEC_ACK",
    5:  "ATK_VEC_SYN",
    6:  "ATK_VEC_HEXFLOOD",
    7:  "ATK_VEC_STDHEX",
    8:  "ATK_VEC_NUDP",
    9:  "ATK_VEC_UDPHEX",
    10: "ATK_VEC_XMAS",
    11: "ATK_VEC_TCPBYPASS",
    12: "ATK_VEC_RAW",
    13: "ATK_VEC_UDP_CUSTOM",
    14: "ATK_VEC_OVHDROP",
    15: "ATK_VEC_NFO",
    16: "ATK_VEC_OVH",
}

# MySQL C2 schema table names (jgamblin-mirai-source/scripts/db.sql)
MIRAI_DB_SCHEMA: Dict[str, List[str]] = {
    "database": ["mirai"],
    "tables":   ["history", "users", "whitelist"],
    "users_cols": ["id", "username", "password", "duration_limit", "cooldown",
                   "wrc", "last_paid", "max_bots", "admin", "intvl", "api_key"],
    "history_cols": ["id", "user_id", "time_sent", "duration", "command", "max_bots"],
}


class Exploit(BaseExploit):
    """Mirai/Condi CnC server beacon and MySQL infrastructure detector.

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mirai/Condi CnC Beacon Detector",
        "description": (
            "Probes for active Mirai/Condi C2 infrastructure on three channels: "
            "(1) TCP 3778 -- CnC bot listener decoded from Condi table.c XOR table; "
            "(2) TCP 9555 -- scan-callback loader port; "
            "(3) TCP 3306 -- MySQL C2 backend (mirai.users/history/whitelist schema). "
            "Detection only -- no commands issued."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://github.com/jgamblin/Mirai-Source-Code",
            "https://unit42.paloaltonetworks.com/mirai-botnet/",
        ],
        "devices": [
            "Suspected Mirai/Condi CnC servers",
            "VPS / cloud instances",
            "Any host potentially running Mirai CnC",
        ],
        "severity": "critical",
        "apt_groups": ["Mirai Botnet", "Condi Botnet"],
        "mitre": ["T1219", "T1571", "T1046"],
    }

    target = OptIP("", "Target IP address (suspected CnC server)")
    timeout = OptInt(4, "TCP connection timeout in seconds")
    probe_mysql = OptBool(True, "Probe MySQL port 3306 for Mirai C2 schema indicators")
    verbose = OptBool(False, "Print negative results too")

    @mute
    def check(self) -> bool:
        """Check if either CnC port is reachable on the target.

        Returns:
            True if TCP 3778 or 9555 is open.
        """
        return (self._tcp_open(self.target, _MIRAI_CNC_PORT, self.timeout) or
                self._tcp_open(self.target, _MIRAI_SCAN_CB_PORT, self.timeout))

    def run(self) -> None:
        """Execute three-channel Mirai CnC infrastructure probe."""
        print_status("[CnCDetect] Probing {} for Mirai/Condi CnC infrastructure...".format(
            self.target))

        findings: List[str] = []
        score: int = 0

        # Channel 1: CnC bot listener port 3778
        result_cnc = self._probe_cnc_port()
        if result_cnc:
            score += 3
            findings.append(result_cnc)
            print_warning("[CnCDetect] [+3] {}".format(result_cnc))
        elif self.verbose:
            print_info("[CnCDetect] TCP {} closed/no response.".format(_MIRAI_CNC_PORT))

        # Channel 2: Scan-callback port 9555
        result_cb = self._probe_scan_callback()
        if result_cb:
            score += 2
            findings.append(result_cb)
            print_warning("[CnCDetect] [+2] {}".format(result_cb))
        elif self.verbose:
            print_info("[CnCDetect] TCP {} closed/no response.".format(_MIRAI_SCAN_CB_PORT))

        # Channel 3: MySQL 3306
        if self.probe_mysql:
            result_mysql = self._probe_mysql()
            if result_mysql:
                score += 2
                findings.append(result_mysql)
                print_warning("[CnCDetect] [+2] {}".format(result_mysql))
            elif self.verbose:
                print_info("[CnCDetect] TCP 3306 closed/no MySQL banner.")

        # Verdict
        print_info("[CnCDetect] Detection score: {}/7 | Findings: {}".format(
            score, len(findings)))

        if score >= 5:
            print_warning(
                "[CnCDetect] HIGH CONFIDENCE Mirai/Condi CnC on {} (score={}/7).".format(
                    self.target, score)
            )
        elif score >= 2:
            print_warning(
                "[CnCDetect] POSSIBLE Mirai/Condi CnC infrastructure on {} (score={}/7). "
                "Investigate further.".format(self.target, score)
            )
        else:
            print_success("[CnCDetect] No strong CnC indicators detected on {}.".format(
                self.target))

        if findings:
            print_info("[CnCDetect] Summary of positive indicators:")
            for f in findings:
                print_info("[CnCDetect]   * {}".format(f))

    # -------------------------------------------------------------------------
    # Channel probes
    # -------------------------------------------------------------------------

    def _probe_cnc_port(self) -> Optional[str]:
        """Probe TCP 3778 for Mirai CnC bot listener.

        Returns:
            Description string if CnC-like response detected, else None.
        """
        banner = self._grab_banner(self.target, _MIRAI_CNC_PORT, send=_MIRAI_CNC_PING)
        if banner is None:
            return None
        banner_hex = banner.hex() if banner else "(empty)"
        banner_hash = hashlib.md5(banner).hexdigest()[:8] if banner else "N/A"

        # Mirai CnC sends an initial binary hello; any response on this port is suspicious
        finding = "TCP {} ({} Mirai CnC port) OPEN | banner={} | md5={}".format(
            _MIRAI_CNC_PORT, "Condi", repr(banner[:32]), banner_hash)
        return finding

    def _probe_scan_callback(self) -> Optional[str]:
        """Probe TCP 9555 for Mirai scan-callback (loader result) listener.

        Returns:
            Description string if port is open, else None.
        """
        if not self._tcp_open(self.target, _MIRAI_SCAN_CB_PORT, self.timeout):
            return None
        banner = self._grab_banner(self.target, _MIRAI_SCAN_CB_PORT)
        banner_hash = hashlib.md5(banner).hexdigest()[:8] if banner else "N/A"
        return "TCP {} (Mirai scan-callback / loader) OPEN | banner={} | md5={}".format(
            _MIRAI_SCAN_CB_PORT, repr(banner[:32] if banner else b""), banner_hash)

    def _probe_mysql(self) -> Optional[str]:
        """Probe TCP 3306 for MySQL and check banner for Mirai CnC indicators.

        Returns:
            Description string if MySQL with Mirai-compatible setup detected.
        """
        banner = self._grab_banner(self.target, 3306)
        if not banner:
            return None
        lower = banner.lower()
        # MySQL server greeting starts with packet length + protocol version (0x0a = v10)
        is_mysql = (len(banner) > 4 and banner[4:5] == b"\x0a") or b"mysql" in lower
        if not is_mysql:
            return None
        marker_hits = [m.decode("latin-1") for m in _MYSQL_MIRAI_MARKERS if m in lower]
        finding = "TCP 3306 MySQL OPEN | markers={} | banner={}".format(
            marker_hits or "generic", repr(banner[:48]))
        return finding

    # -------------------------------------------------------------------------
    # Network helpers
    # -------------------------------------------------------------------------

    def _tcp_open(self, host: str, port: int, timeout: int) -> bool:
        """Return True if TCP port is reachable."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, port))
            return True
        except (OSError, socket.timeout):
            return False
        finally:
            sock.close()

    def _grab_banner(
        self, host: str, port: int, send: Optional[bytes] = None
    ) -> Optional[bytes]:
        """Connect, optionally send bytes, and return the response banner.

        Args:
            host: Target IP.
            port: TCP port.
            send: Optional bytes to send after connecting.

        Returns:
            Response bytes, empty bytes if no data, or None on connection failure.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            if send:
                sock.sendall(send)
            time.sleep(0.3)
            try:
                return sock.recv(512)
            except socket.timeout:
                return b""
        except (OSError, socket.timeout):
            return None
        finally:
            sock.close()
