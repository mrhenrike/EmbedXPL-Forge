"""Network Target Discovery Engine.

Scans a subnet to find live hosts, fingerprints network devices,
and matches them against the EmbedXPL module catalog to identify
potential exploit targets.

Scanning strategy (multi-phase, with automatic fallback):
  Phase 0 — ARP sweep (L2, same-subnet, fastest, requires admin/root)
  Phase 1 — Nmap smart host discovery (multi-method: TCP SYN/ACK + ICMP + UDP)
            For single hosts (/32): uses -Pn (skip discovery, scan the specific target)
            For subnets: uses -PS/-PA/-PE/-PP/-PU to discover live hosts first
  Phase 1b — Masscan (fast SYN scanner, ideal for large subnets when nmap unavailable)
  Phase 2 — Scapy ARP scan (if nmap and masscan unavailable)
  Phase 3 — Socket-based TCP probe (universal fallback, no special privileges)

IMPORTANT: -Pn is ONLY used for single-host targets.  Using -Pn on
subnets causes Nmap to scan every IP in the range even if the host
is down, leading to extreme delays and false positives (ports shown
as "filtered" on non-existent hosts).

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.5.0
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

PROBE_PORTS: List[int] = [
    80, 443, 8080, 8443, 8081, 8888, 8090, 8888,
    22, 23, 21, 53,
    161, 162,
    5555, 37215, 37443, 7547, 4567,
    1900, 49152,
    830, 10000,
]

PROBE_PORTS_EXTENDED: List[int] = PROBE_PORTS + [
    25, 110, 143, 993, 995, 587,
    3306, 5432, 1433, 6379, 27017,
    8000, 8181, 9090, 9443, 10443,
    5060, 5061, 1723, 500,
    30005, 49153, 49154, 32764,
    554, 8554, 37080,
]


_HOST_DISCOVERY_ARGS = (
    "-PS22,23,80,443,8080,37443"  # TCP SYN ping to common router ports
    " -PA80,443"                   # TCP ACK ping
    " -PE"                         # ICMP echo
    " -PP"                         # ICMP timestamp (works when echo blocked)
    " -PU53,161"                   # UDP ping to DNS/SNMP
)
"""Multi-method host discovery arguments for subnet scans.

Uses five probe types in parallel so hosts that block ICMP are still
found via TCP SYN/ACK, and vice versa.  This replaces the old
blanket ``-Pn`` which assumed ALL hosts are up and caused Nmap to
scan every IP in a /24 — extremely slow and full of false positives.
"""


@dataclass
class TimingProfile:
    """Nmap-style timing template (T0-T5).

    Controls parallelism, timeouts, and probe intensity.

    ``nmap_extra_subnet`` is used when scanning a subnet (host discovery
    via TCP/ICMP/UDP probes).  ``nmap_extra_host`` is used for a single
    host target where ``-Pn`` is appropriate (we explicitly chose this IP).
    """
    name: str
    nmap_flag: str
    timeout: float
    max_workers: int
    probe_delay: float
    ports: List[int]
    nmap_extra_host: str
    nmap_extra_subnet: str
    banner_grab: bool
    deep_fingerprint: bool

    @property
    def nmap_extra(self) -> str:
        """Backward-compat alias (defaults to host mode)."""
        return self.nmap_extra_host

    def nmap_args_for(self, target: str) -> str:
        """Return the appropriate nmap_extra string for the given target.

        Single host (/32 or bare IP) -> ``-Pn`` (skip discovery).
        Subnet                       -> multi-method discovery probes.
        """
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.prefixlen >= 32:
                return self.nmap_extra_host
        except ValueError:
            return self.nmap_extra_host
        return self.nmap_extra_subnet

    @staticmethod
    def get(level: int) -> "TimingProfile":
        """Return a TimingProfile for the given level (0-5)."""
        profiles = {
            0: TimingProfile(
                name="T0-Paranoid",
                nmap_flag="-T0",
                timeout=10.0,
                max_workers=5,
                probe_delay=5.0,
                ports=PROBE_PORTS[:8],
                nmap_extra_host="-Pn --max-rate 10",
                nmap_extra_subnet=f"{_HOST_DISCOVERY_ARGS} --max-rate 10",
                banner_grab=False,
                deep_fingerprint=False,
            ),
            1: TimingProfile(
                name="T1-Sneaky",
                nmap_flag="-T1",
                timeout=8.0,
                max_workers=10,
                probe_delay=2.0,
                ports=PROBE_PORTS[:12],
                nmap_extra_host="-Pn --max-rate 50",
                nmap_extra_subnet=f"{_HOST_DISCOVERY_ARGS} --max-rate 50",
                banner_grab=False,
                deep_fingerprint=False,
            ),
            2: TimingProfile(
                name="T2-Polite",
                nmap_flag="-T2",
                timeout=5.0,
                max_workers=20,
                probe_delay=1.0,
                ports=PROBE_PORTS[:16],
                nmap_extra_host="-Pn --max-rate 200",
                nmap_extra_subnet=f"{_HOST_DISCOVERY_ARGS} --max-rate 200",
                banner_grab=True,
                deep_fingerprint=False,
            ),
            3: TimingProfile(
                name="T3-Normal",
                nmap_flag="-T3",
                timeout=3.0,
                max_workers=50,
                probe_delay=0.0,
                ports=PROBE_PORTS,
                nmap_extra_host="-Pn",
                nmap_extra_subnet=_HOST_DISCOVERY_ARGS,
                banner_grab=True,
                deep_fingerprint=True,
            ),
            4: TimingProfile(
                name="T4-Aggressive",
                nmap_flag="-T4",
                timeout=2.0,
                max_workers=100,
                probe_delay=0.0,
                ports=PROBE_PORTS_EXTENDED,
                nmap_extra_host="-Pn --max-retries 2 -A",
                nmap_extra_subnet=f"{_HOST_DISCOVERY_ARGS} --max-retries 2 -A",
                banner_grab=True,
                deep_fingerprint=True,
            ),
            5: TimingProfile(
                name="T5-Insane",
                nmap_flag="-T5",
                timeout=1.0,
                max_workers=200,
                probe_delay=0.0,
                ports=PROBE_PORTS_EXTENDED,
                nmap_extra_host="-Pn --max-retries 1 --host-timeout 30s -A",
                nmap_extra_subnet=(
                    f"{_HOST_DISCOVERY_ARGS} --max-retries 1 --host-timeout 30s -A"
                ),
                banner_grab=True,
                deep_fingerprint=True,
            ),
        }
        level = max(0, min(5, level))
        return profiles[level]


def _detect_oem_encoding() -> str:
    """Detect the Windows OEM codepage for subprocess output decoding.

    Windows system commands (ipconfig, arp, ping, etc.) output text in
    the console's OEM codepage — typically cp850 (Western European) or
    cp437 (US).  Using utf-8 corrupts accented characters.
    On non-Windows systems, returns utf-8.
    """
    if sys.platform != "win32":
        return "utf-8"
    try:
        r = subprocess.run(
            ["chcp"],
            capture_output=True, text=True, shell=True, timeout=5,
        )
        m = re.search(r"(\d+)", r.stdout)
        if m:
            cp = "cp{}".format(m.group(1))
            "x".encode(cp)
            return cp
    except Exception:
        pass
    return "cp850"


_OEM_ENCODING: str = _detect_oem_encoding()



@dataclass
class DiscoveredHost:
    """A single host discovered during a network scan."""
    ip: str
    mac: str = ""
    hostname: str = ""
    open_ports: List[int] = field(default_factory=list)
    banners: Dict[int, str] = field(default_factory=dict)
    vendor_guess: str = ""
    model_guess: str = ""
    fingerprint_confidence: float = 0.0
    matched_modules: List[str] = field(default_factory=list)
    has_wireless: bool = False
    wireless_ssids: List[str] = field(default_factory=list)
    wireless_recommendation: str = ""

    def summary(self) -> str:
        """One-line display."""
        ports = ",".join(str(p) for p in self.open_ports[:6])
        host_part = self.hostname or self.ip
        mac_part = " ({})".format(self.mac) if self.mac else ""
        vendor_part = " [{}]".format(self.vendor_guess) if self.vendor_guess else ""
        model_part = " {}".format(self.model_guess) if self.model_guess else ""
        mods = " | {} modules".format(len(self.matched_modules)) if self.matched_modules else ""
        wifi = " | WiFi" if self.has_wireless else ""
        return "{}{} ports:{}{}{}{}{} ".format(
            host_part, mac_part, ports, vendor_part, model_part, mods, wifi,
        )


