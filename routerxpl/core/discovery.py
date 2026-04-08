"""Network Target Discovery Engine.

Scans a subnet to find live hosts, fingerprints network devices,
and matches them against the RouterXPL module catalog to identify
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
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

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


class NetworkDiscovery:
    """Discovers live hosts in a subnet and fingerprints network devices."""

    def __init__(
        self,
        target: str,
        *,
        ports: Optional[List[int]] = None,
        timeout: float = 3.0,
        max_workers: int = 50,
        use_nmap: bool = True,
        use_scapy: bool = True,
        timing: int = 3,
    ):
        """Initialize the discovery engine.

        Args:
            target: Subnet in CIDR notation (e.g. ``192.168.1.0/24``) or single IP.
            ports: Ports to probe. Defaults to profile-based list.
            timeout: Socket timeout in seconds for probes.
            max_workers: Thread pool size for parallel probing.
            use_nmap: Try to use nmap if available.
            use_scapy: Try to use scapy ARP if available.
            timing: Nmap-style timing level (0-5). T0=Paranoid, T3=Normal, T5=Insane.
        """
        self.timing_profile = TimingProfile.get(timing)
        self.target = target
        self.ports = ports or list(self.timing_profile.ports)
        self.timeout = timeout if timeout != 3.0 else self.timing_profile.timeout
        self.max_workers = (
            max_workers if max_workers != 50 else self.timing_profile.max_workers
        )
        self.use_nmap = use_nmap
        self.use_scapy = use_scapy
        self._hosts: List[DiscoveredHost] = []
        self._known_vendors: Set[str] = set()
        self._module_index: Dict[str, List[str]] = {}
        logger.info(
            "Discovery initialized — timing=%s, workers=%d, timeout=%.1fs, ports=%d",
            self.timing_profile.name, self.max_workers, self.timeout,
            len(self.ports),
        )

    def _build_module_index(self) -> None:
        """Build vendor/category -> module list mapping from the catalog.

        Index structure maps a key (vendor folder name or category) to
        the list of module dotted paths under it.  Example keys:
        ``huawei``, ``gpon``, ``multi``, ``generic``.

        Only the *direct parent folder* of each module is used as its
        primary index key, avoiding false cross-indexing.
        """
        if self._module_index:
            return

        modules = self._walk_modules()

        for mod_path in modules:
            parts = mod_path.replace("\\", ".").replace("/", ".").split(".")
            meaningful = [
                p.lower() for p in parts
                if p.lower() not in (
                    "routerxpl", "modules", "exploits", "creds",
                    "routers", "scanners", "py", "__init__", "",
                )
            ]

            if meaningful:
                vendor_or_cat = meaningful[0]
                self._module_index.setdefault(vendor_or_cat, []).append(mod_path)
                self._known_vendors.add(vendor_or_cat)

    def _walk_modules(self) -> List[str]:
        """Walk the modules directory to discover all exploit modules."""
        result: List[str] = []
        base = os.path.join(os.path.dirname(__file__), "..", "modules")
        base = os.path.normpath(base)
        if not os.path.isdir(base):
            return result
        for dirpath, _, filenames in os.walk(base):
            for fn in filenames:
                if fn.endswith(".py") and fn != "__init__.py":
                    rel = os.path.relpath(os.path.join(dirpath, fn), base)
                    dotted = rel.replace(os.sep, ".").replace("/", ".")
                    if dotted.endswith(".py"):
                        dotted = dotted[:-3]
                    result.append(dotted)
        return result

    def scan(self, callback: Optional[Callable] = None) -> List[DiscoveredHost]:
        """Run the full discovery pipeline.

        Multi-phase: ARP sweep -> Nmap -> Scapy -> Socket fallback.
        Always tries ARP first on local subnets for fast L2 discovery,
        then enriches with service/version detection.

        Args:
            callback: Optional callable(stage: str, detail: str) for progress.

        Returns:
            List of discovered hosts with fingerprint and module matches.
        """
        self._build_module_index()
        self._hosts = []
        seen_ips: Set[str] = set()

        if callback:
            callback("scan", "Starting host discovery on {}".format(self.target))

        # Phase 0: ARP sweep (fast L2, only same subnet)
        if self._is_local_subnet():
            self._arp_sweep(callback, seen_ips)

        # Phase 1+: Nmap -> Masscan -> Scapy -> Socket fallback
        if self.use_nmap and self._nmap_available():
            if callback:
                callback("scan", "Using Nmap scanner")
            self._scan_nmap(callback, seen_ips)
        elif self._masscan_available():
            if callback:
                callback("scan", "Using Masscan (fast SYN scanner)")
            self._scan_masscan(callback, seen_ips)
        elif self.use_scapy and self._scapy_available():
            if callback:
                callback("scan", "Using Scapy ARP scanner")
            self._scan_scapy(callback, seen_ips)
        else:
            if callback:
                callback("scan", "Using TCP socket scanner (fallback)")
            self._scan_socket(callback, seen_ips)

        if callback:
            callback("fingerprint", "Fingerprinting {} hosts".format(len(self._hosts)))
        self._fingerprint_all(callback)

        if callback:
            callback("match", "Matching against {} module vendors".format(len(self._known_vendors)))
        self._match_catalog()

        self._detect_wireless_capability(callback)
        self._generate_wireless_recommendations()

        return self._hosts

    def _is_local_subnet(self) -> bool:
        """Check if target is a local subnet (not a single host)."""
        try:
            net = ipaddress.ip_network(self.target, strict=False)
            return net.prefixlen < 32
        except ValueError:
            return False

    def _arp_sweep(self, callback: Optional[Callable], seen_ips: Set[str]) -> None:
        """Phase 0: fast ARP sweep using system arp table + optional ping sweep."""
        if callback:
            callback("scan", "Phase 0: ARP sweep on {}".format(self.target))

        try:
            network = ipaddress.ip_network(self.target, strict=False)
        except ValueError:
            return

        self._read_arp_table(network, seen_ips)

        self._ping_sweep(network, callback)

        self._read_arp_table(network, seen_ips)

    def _read_arp_table(
        self,
        network: ipaddress.IPv4Network,
        seen_ips: Set[str],
    ) -> None:
        """Read the OS ARP table and add discovered hosts."""
        if sys.platform == "win32":
            cmd = ["arp", "-a"]
            dynamic_marker = "din"
        else:
            cmd = ["arp", "-n"]
            dynamic_marker = None

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, timeout=15,
            )
            output = result.stdout.decode(_OEM_ENCODING, errors="replace")
        except Exception as exc:
            logger.debug("ARP table read failed: %s", exc)
            return

        if result.returncode != 0:
            return

        for line in output.splitlines():
            parts = line.split()
            if sys.platform == "win32":
                if len(parts) < 3 or (dynamic_marker and dynamic_marker not in line.lower()):
                    continue
                ip_str = parts[0].strip()
                mac_str = parts[1].strip().upper().replace("-", ":")
            else:
                if len(parts) < 3:
                    continue
                ip_str = parts[0]
                mac_str = parts[2].upper()

            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj in network and ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    dh = DiscoveredHost(ip=ip_str, mac=mac_str)
                    dh.vendor_guess = self._oui_lookup(mac_str)
                    self._hosts.append(dh)
            except ValueError:
                pass

        if callback:
            callback("scan", "ARP sweep found {} hosts".format(len(self._hosts)))

    def _ping_sweep(
        self,
        network: ipaddress.IPv4Network,
        callback: Optional[Callable],
    ) -> None:
        """Parallel ICMP ping sweep to populate ARP cache."""
        hosts = list(network.hosts())
        if len(hosts) > 254:
            hosts = hosts[:254]

        if callback:
            callback("scan", "Ping sweeping {} hosts...".format(len(hosts)))

        def ping_one(ip_str: str) -> None:
            try:
                if sys.platform == "win32":
                    subprocess.run(
                        ["ping", "-n", "1", "-w", "500", ip_str],
                        capture_output=True, timeout=3,
                    )
                else:
                    subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip_str],
                        capture_output=True, timeout=3,
                    )
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=min(64, len(hosts))) as pool:
            list(pool.map(ping_one, [str(h) for h in hosts]))

    # ------------------------------------------------------------------
    # Backend availability checks
    # ------------------------------------------------------------------

    @staticmethod
    def _nmap_available() -> bool:
        """Check if nmap binary + python-nmap are usable."""
        try:
            import nmap
            nm = nmap.PortScanner()
            return True
        except Exception:
            return False

    @staticmethod
    def _masscan_available() -> bool:
        """Check if masscan binary is in PATH."""
        try:
            r = subprocess.run(
                ["masscan", "--version"],
                capture_output=True, timeout=5,
            )
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _scapy_available() -> bool:
        """Check if scapy is importable and ARP is usable."""
        try:
            from scapy.all import ARP, Ether, srp
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Scan backends
    # ------------------------------------------------------------------

    def _scan_nmap(self, callback: Optional[Callable] = None, seen_ips: Optional[Set[str]] = None) -> None:
        """Host discovery + service scan via Nmap.

        For single-host targets: uses ``-Pn`` (treat host as up).
        For subnets: uses multi-method discovery (TCP SYN/ACK + ICMP
        echo/timestamp + UDP) so only *confirmed live* hosts are
        port-scanned.  This prevents the old problem where ``-Pn`` on
        a /24 would scan all 254 IPs — extremely slow and full of
        false-positive "filtered" ports on non-existent hosts.

        If the ARP sweep already found hosts, they are passed as an
        explicit target list with ``-Pn`` (we know they're alive).
        """
        if seen_ips is None:
            seen_ips = set()

        import nmap
        nm = nmap.PortScanner()

        port_str = ",".join(str(p) for p in self.ports)

        discovery_args = self.timing_profile.nmap_args_for(self.target)

        is_single_host = False
        try:
            net = ipaddress.ip_network(self.target, strict=False)
            is_single_host = net.prefixlen >= 32
        except ValueError:
            is_single_host = True

        if seen_ips and not is_single_host:
            nmap_targets = " ".join(sorted(seen_ips))
            nmap_args = "-Pn -sV -sT --open -O --osscan-limit --max-retries 2"
            if callback:
                callback(
                    "scan",
                    "Nmap scanning {} ARP-confirmed hosts with -Pn".format(len(seen_ips)),
                )
        else:
            nmap_targets = self.target
            nmap_args = "{} -sV -sT --open -O --osscan-limit --max-retries 2".format(
                discovery_args,
            )
            if is_single_host:
                if callback:
                    callback("scan", "Nmap scanning single host {} with -Pn".format(self.target))
            else:
                if callback:
                    callback(
                        "scan",
                        "Nmap subnet discovery on {} (multi-probe, no -Pn)".format(self.target),
                    )

        nmap_args += " {}".format(self.timing_profile.nmap_flag)

        try:
            nm.scan(
                hosts=nmap_targets,
                ports=port_str,
                arguments=nmap_args,
                timeout=300,
            )
        except nmap.PortScannerError as exc:
            logger.warning("Nmap scan failed: %s -- trying minimal scan", exc)
            if callback:
                callback("scan", "Nmap full scan failed, trying minimal...")
            fallback_discovery = "-Pn" if is_single_host else _HOST_DISCOVERY_ARGS
            try:
                nm.scan(
                    hosts=nmap_targets,
                    ports="22,23,53,80,443,8080",
                    arguments="{} -sT -T4 --open".format(fallback_discovery),
                    timeout=180,
                )
            except Exception as exc2:
                logger.warning("Nmap minimal scan also failed: %s", exc2)
                if callback:
                    callback("scan", "Nmap failed completely, falling back to sockets")
                self._scan_socket(callback, seen_ips)
                return
        except Exception as exc:
            logger.warning("Nmap unexpected error: %s", exc)
            self._scan_socket(callback, seen_ips)
            return

        new_hosts = 0
        for host_ip in nm.all_hosts():
            host_data = nm[host_ip]
            state = host_data.get("status", {}).get("state", "down")
            if state != "up":
                continue

            mac = ""
            vendor_str = ""
            addresses = host_data.get("addresses", {})
            if "mac" in addresses:
                mac = addresses["mac"].upper()

            vendor_nmap = host_data.get("vendor", {})
            if mac and mac in vendor_nmap:
                vendor_str = vendor_nmap[mac]

            hostname = ""
            hostnames = host_data.get("hostnames", [])
            if hostnames and isinstance(hostnames[0], dict):
                hostname = hostnames[0].get("name", "")

            open_ports: List[int] = []
            banners: Dict[int, str] = {}
            for proto in ("tcp", "udp"):
                proto_data = host_data.get(proto, {})
                for port_num, port_info in proto_data.items():
                    if port_info.get("state") == "open":
                        open_ports.append(int(port_num))
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")
                        extra = port_info.get("extrainfo", "")
                        banner_parts = [p for p in (product, version, extra) if p]
                        if banner_parts:
                            banners[int(port_num)] = " ".join(banner_parts)

            if host_ip in seen_ips:
                for existing in self._hosts:
                    if existing.ip == host_ip:
                        existing.open_ports = sorted(set(existing.open_ports + open_ports))
                        existing.banners.update(banners)
                        if mac and not existing.mac:
                            existing.mac = mac
                        if hostname and not existing.hostname:
                            existing.hostname = hostname
                        if vendor_str and not existing.vendor_guess:
                            existing.vendor_guess = self._normalize_vendor(vendor_str)
                        break
            else:
                seen_ips.add(host_ip)
                dh = DiscoveredHost(
                    ip=host_ip,
                    mac=mac,
                    hostname=hostname,
                    open_ports=sorted(open_ports),
                    banners=banners,
                )
                if vendor_str:
                    dh.vendor_guess = self._normalize_vendor(vendor_str)
                elif mac:
                    dh.vendor_guess = self._oui_lookup(mac)
                self._hosts.append(dh)
                new_hosts += 1

        if callback:
            callback("scan", "Nmap found {} new hosts (total: {})".format(new_hosts, len(self._hosts)))

    def _scan_masscan(self, callback: Optional[Callable] = None, seen_ips: Optional[Set[str]] = None) -> None:
        """Fast host discovery via masscan (ideal for large subnets)."""
        if seen_ips is None:
            seen_ips = set()
        port_str = ",".join(str(p) for p in self.ports[:20])
        rate = str(self.timing_profile.max_workers * 100)

        cmd = [
            "masscan", self.target,
            "-p", port_str,
            "--rate", rate,
            "--wait", "3",
            "-oL", "-",
        ]

        if callback:
            callback("scan", "Masscan scanning {} (rate {})".format(self.target, rate))

        logger.info("Running masscan: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Masscan timed out after 120s")
            return
        except Exception as exc:
            logger.warning("Masscan failed: %s", exc)
            return

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "open":
                ip = parts[3]
                port = int(parts[2])
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    host = self._create_host(ip)
                    host.open_ports.append(port)
                    self._hosts.append(host)
                else:
                    for h in self._hosts:
                        if h.ip == ip and port not in h.open_ports:
                            h.open_ports.append(port)

        if callback:
            callback("scan", "Masscan found {} live hosts".format(
                len([h for h in self._hosts if h.ip in seen_ips])
            ))

    def _scan_scapy(self, callback: Optional[Callable] = None, seen_ips: Optional[Set[str]] = None) -> None:
        """ARP scan for same-subnet discovery via scapy."""
        if seen_ips is None:
            seen_ips = set()
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0
        except ImportError:
            self._scan_socket(callback, seen_ips)
            return

        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target),
                timeout=self.timeout,
                retry=1,
                verbose=False,
            )
        except PermissionError:
            if callback:
                callback("scan", "ARP scan requires admin/root -- falling back to sockets")
            self._scan_socket(callback, seen_ips)
            return
        except Exception as exc:
            logger.debug("Scapy ARP failed: %s", exc)
            self._scan_socket(callback, seen_ips)
            return

        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc.upper()
            if ip not in seen_ips:
                seen_ips.add(ip)
                dh = DiscoveredHost(ip=ip, mac=mac)
                dh.vendor_guess = self._oui_lookup(mac)
                self._hosts.append(dh)

        if callback:
            callback("scan", "Scapy ARP found {} live hosts".format(len(self._hosts)))

        self._probe_ports_parallel(callback)

    def _scan_socket(self, callback: Optional[Callable] = None, seen_ips: Optional[Set[str]] = None) -> None:
        """TCP connect scan using raw sockets (universal fallback)."""
        if seen_ips is None:
            seen_ips = set()
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            targets = [str(ip) for ip in network.hosts() if str(ip) not in seen_ips]
        except ValueError:
            targets = [self.target] if self.target not in seen_ips else []

        if len(targets) > 1024:
            targets = targets[:1024]
            if callback:
                callback("scan", "Limiting socket scan to first 1024 hosts")

        live_ips: List[str] = []
        lock = threading.Lock()

        def probe_host(ip: str) -> None:
            for port in self.ports[:6]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, port))
                    s.close()
                    if result == 0:
                        with lock:
                            live_ips.append(ip)
                        return
                except (socket.error, OSError):
                    pass

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(probe_host, ip) for ip in targets]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        for ip in sorted(set(live_ips), key=lambda x: socket.inet_aton(x)):
            seen_ips.add(ip)
            self._hosts.append(DiscoveredHost(ip=ip))

        if callback:
            callback("scan", "Socket scan found {} live hosts (total: {})".format(len(live_ips), len(self._hosts)))

        self._probe_ports_parallel(callback)

    def _probe_ports_parallel(self, callback=None) -> None:
        """Probe all configured ports on discovered hosts."""
        def probe(host: DiscoveredHost, port: int) -> Optional[Tuple[DiscoveredHost, int, str]]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                if s.connect_ex((host.ip, port)) == 0:
                    banner = ""
                    try:
                        if port in (22, 23, 21):
                            s.settimeout(2.0)
                            banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                        elif port in (80, 8080, 8081, 8443, 8888, 443):
                            req = "GET / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host.ip)
                            s.sendall(req.encode())
                            s.settimeout(3.0)
                            resp = s.recv(4096).decode("utf-8", errors="replace")
                            server_match = re.search(r"Server:\s*(.+)", resp, re.IGNORECASE)
                            title_match = re.search(r"<title>(.+?)</title>", resp, re.IGNORECASE | re.DOTALL)
                            parts = []
                            if server_match:
                                parts.append(server_match.group(1).strip())
                            if title_match:
                                parts.append(title_match.group(1).strip())
                            banner = " | ".join(parts)
                    except Exception:
                        pass
                    s.close()
                    return (host, port, banner)
                s.close()
            except (socket.error, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = []
            for host in self._hosts:
                for port in self.ports:
                    futures.append(pool.submit(probe, host, port))
            for f in as_completed(futures):
                try:
                    result = f.result()
                    if result:
                        host, port, banner = result
                        if port not in host.open_ports:
                            host.open_ports.append(port)
                            host.open_ports.sort()
                        if banner:
                            host.banners[port] = banner
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint_all(self, callback: Optional[Callable] = None) -> None:
        """Run fingerprinting on all discovered hosts.

        Includes aggressive HTTP/HTTPS banner grabbing to extract model info
        from web management interfaces common on routers and switches.
        """
        for host in self._hosts:
            self._deep_banner_grab(host, callback)
            self._fingerprint_host(host)
        if callback:
            identified = sum(1 for h in self._hosts if h.vendor_guess)
            callback("fingerprint", "Identified {} out of {} hosts".format(identified, len(self._hosts)))

    def _deep_banner_grab(self, host: DiscoveredHost, callback: Optional[Callable] = None) -> None:
        """Aggressive HTTP/HTTPS banner grab to extract device model from web UI."""
        http_ports = [p for p in host.open_ports if p in (80, 8080, 8081, 8888, 8090, 443, 8443, 4567, 10000)]
        if not http_ports:
            http_ports = [80, 443]

        for port in http_ports:
            use_ssl = port in (443, 8443)
            banner = self._http_banner(host.ip, port, use_ssl)
            if banner:
                if port not in host.banners or len(banner) > len(host.banners.get(port, "")):
                    host.banners[port] = banner
                if port not in host.open_ports:
                    host.open_ports.append(port)
                    host.open_ports.sort()

    def _http_banner(self, ip: str, port: int, use_ssl: bool = False) -> str:
        """Raw HTTP/HTTPS request to grab server headers and HTML title/model info."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout + 2)
            s.connect((ip, port))

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)

            req = "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n".format(ip)
            s.sendall(req.encode())

            chunks = []
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(b"".join(chunks)) > 32768:
                        break
                except (socket.timeout, ssl.SSLError):
                    break
            s.close()

            raw = b"".join(chunks).decode("utf-8", errors="replace")
            parts = []

            server_m = re.search(r"Server:\s*(.+?)[\r\n]", raw, re.IGNORECASE)
            if server_m:
                parts.append("Server: " + server_m.group(1).strip())

            title_m = re.search(r"<title>(.+?)</title>", raw, re.IGNORECASE | re.DOTALL)
            if title_m:
                parts.append("Title: " + title_m.group(1).strip()[:120])

            model_patterns = [
                r"(?:modelName|ProductName|product_name|DeviceModel|deviceModel)\s*[:=]\s*['\"]?([^'\"<>\r\n;,]+)",
                r"(?:HG\d{4}[A-Z]*|EG\d{4}[A-Z]*\d*|ZXHN\s*[A-Z]\d+[A-Z]*|DG\d{3,4}[A-Z]*)",
                r"(?:RT-[A-Z]{2,4}\d+|DIR-\d{3,4}|TL-[A-Z]{2,3}\d+|Archer\s*[A-Z]\d+)",
                r"(?:RB\d{3,4}|CCR\d{4}|CRS\d{3}|hAP\s*\w+)",
                r"(?:USG|UDM|EdgeRouter\s*\w+|UniFi\s*\w+)",
                r"(?:FortiGate-?\d+[A-Z]*|FG-?\d+[A-Z]*)",
                r"(?:RV\d{3}[A-Z]*|SG\d{3}[A-Z]*|Catalyst\s*\d+)",
            ]
            for pat in model_patterns:
                m = re.search(pat, raw, re.IGNORECASE)
                if m:
                    model_str = m.group(0) if not m.lastindex else m.group(1)
                    parts.append("Model: " + model_str.strip()[:80])
                    break

            return " | ".join(parts) if parts else ""

        except Exception:
            return ""

    def _fingerprint_host(self, host: DiscoveredHost) -> None:
        """Fingerprint a single host using banners, MAC OUI, and ML."""
        if host.mac and not host.vendor_guess:
            host.vendor_guess = self._oui_lookup(host.mac)

        best_confidence = host.fingerprint_confidence
        for port, banner in host.banners.items():
            vendor, model, conf = self._match_banner(banner)
            if conf > best_confidence:
                best_confidence = conf
                if vendor:
                    host.vendor_guess = vendor
                if model:
                    host.model_guess = model
                host.fingerprint_confidence = conf

        if not host.vendor_guess and host.banners:
            self._ml_fingerprint(host)

    @staticmethod
    def _oui_lookup(mac: str) -> str:
        """Look up vendor from MAC address OUI prefix via IEEE database."""
        from routerxpl.core.oui import lookup
        return lookup(mac)

    def _match_banner(self, banner: str) -> Tuple[str, str, float]:
        """Match a banner string against known patterns.

        Returns:
            (vendor, model, confidence)
        """
        if not banner:
            return ("", "", 0.0)

        try:
            from routerxpl.core.ml.banner_fingerprint import BannerFingerprinter
            fp = BannerFingerprinter()
            matches = fp.match(banner)
            if matches and matches[0].confidence >= 0.5:
                top = matches[0]
                return (top.vendor, top.model, top.confidence)
        except Exception as exc:
            logger.debug("BannerFingerprinter failed: %s", exc)

        banner_lower = banner.lower()

        model_extracted = ""
        model_m = re.search(r"Model:\s*(.+?)(?:\s*\||$)", banner, re.IGNORECASE)
        if model_m:
            model_extracted = model_m.group(1).strip()

        vendor_keywords = {
            "dlink": ["d-link", "dlink", "dir-", "dsl-", "dap-", "dcs-", "dwr-"],
            "tplink": ["tp-link", "tplink", "archer", "tl-wr", "tl-mr", "tl-wa", "deco"],
            "netgear": ["netgear", "nighthawk", "orbi"],
            "asus": ["asus", "rt-ac", "rt-ax", "rt-n", "rt-be", "zenwifi"],
            "linksys": ["linksys", "cisco-linksys", "velop"],
            "cisco": ["cisco", "catalyst", "isr", "asr"],
            "huawei": ["huawei", "hg8245", "hg8240", "hg8546", "hg8010",
                       "eg8145", "eg8245", "echolife", "optixstar",
                       "ar161", "ar169", "s5700", "s5720", "s6720",
                       "usg6", "ce6800", "ne40e"],
            "zte": ["zte", "zxhn", "zxv10", "zxa10"],
            "mikrotik": ["mikrotik", "routeros", "routerboard", "hap", "ccr", "crs"],
            "ubiquiti": ["ubiquiti", "unifi", "edgerouter", "airos", "udm", "usg", "uap"],
            "fortinet": ["fortinet", "fortigate", "fortiswitch", "fortiap"],
            "tenda": ["tenda"],
            "arris": ["arris", "touchstone", "surfboard"],
            "comtrend": ["comtrend"],
            "trendnet": ["trendnet"],
            "belkin": ["belkin"],
            "draytek": ["draytek", "vigor"],
            "totolink": ["totolink"],
            "wavlink": ["wavlink"],
            "xiaomi": ["xiaomi", "miwifi", "redmi router"],
            "intelbras": ["intelbras", "action", "wrn"],
            "fiberhome": ["fiberhome", "an5506"],
            "sagem": ["sagem", "sagemcom", "livebox"],
            "juniper": ["juniper", "junos", "srx", "ex2", "ex3", "ex4"],
            "sonicwall": ["sonicwall", "sonicpoint", "tz", "nsa"],
            "ruckus": ["ruckus", "unleashed", "zonedirector"],
        }

        for vendor, keywords in vendor_keywords.items():
            for kw in keywords:
                if kw in banner_lower:
                    return (vendor, model_extracted, 0.7 if model_extracted else 0.6)

        return ("", model_extracted, 0.3 if model_extracted else 0.0)

    def _ml_fingerprint(self, host: DiscoveredHost) -> None:
        """Use ML banner fingerprinter as last resort."""
        try:
            from routerxpl.core.ml.banner_fingerprint import BannerFingerprinter
            fp = BannerFingerprinter()
            all_banners = " ".join(host.banners.values())
            matches = fp.match(all_banners)
            if matches:
                top = matches[0]
                if top.confidence > host.fingerprint_confidence:
                    host.vendor_guess = top.vendor
                    host.model_guess = top.model
                    host.fingerprint_confidence = top.confidence
        except Exception as exc:
            logger.debug("ML fingerprint failed: %s", exc)

    # ------------------------------------------------------------------
    # Catalog matching
    # ------------------------------------------------------------------

    def _match_catalog(self) -> None:
        """Match discovered hosts against the RouterXPL module catalog.

        Strict matching rules to avoid false positives:
          1. Vendor modules: only if the host vendor matches the module vendor
             folder (e.g. ``huawei/`` modules only for Huawei devices).
          2. Generic scanners (``generic/``): matched by detected protocol/tech
             (UPnP scanner for any host with UPnP, etc.).  These are tools,
             not exploits, so vendor doesn't matter.
          3. GPON category modules: only for hosts positively identified as
             GPON/ONT/ONU devices.  Vendor-specific GPON modules (e.g.
             Alcatel, Skyworth) are excluded unless vendor matches.
          4. Multi-vendor modules (``multi/``): only if the module name or
             ``__info__`` references the detected vendor or is explicitly
             vendor-agnostic (e.g. ``gpon_home_gateway_rce``).
        """
        for host in self._hosts:
            matched: List[str] = []
            vendor = host.vendor_guess.lower()
            is_gpon = self._host_is_gpon(host)

            if vendor:
                vendor_mods = [
                    m for m in self._module_index.get(vendor, [])
                    if self._module_is_under_vendor(m, vendor)
                ]
                matched.extend(vendor_mods)

            if is_gpon:
                gpon_mods = self._module_index.get("gpon", [])
                for m in gpon_mods:
                    if m in matched:
                        continue
                    if self._gpon_module_applies(m, vendor):
                        matched.append(m)

            multi_mods = self._module_index.get("multi", [])
            for m in multi_mods:
                if m in matched:
                    continue
                if self._multi_module_applies(m, vendor, is_gpon):
                    matched.append(m)

            generic_mods = self._module_index.get("generic", [])
            for m in generic_mods:
                if m in matched:
                    continue
                if self._generic_tool_applies(m, host):
                    matched.append(m)

            host.matched_modules = sorted(set(matched))

    def _host_is_gpon(self, host: DiscoveredHost) -> bool:
        """Determine if a host is a GPON/ONT/ONU device."""
        all_text = " ".join([
            host.model_guess or "",
            host.vendor_guess or "",
            " ".join(host.banners.values()),
        ]).lower()

        gpon_indicators = [
            "gpon", "ont", "onu", "epon", "xpon", "ftth",
            "optical network", "echolife", "optixstar",
            "eg8", "hg8", "an5506", "zxa10",
        ]
        return any(kw in all_text for kw in gpon_indicators)

    @staticmethod
    def _module_is_under_vendor(module_path: str, vendor: str) -> bool:
        """Check if a module lives under the given vendor's directory."""
        parts = module_path.lower().replace("\\", "/").split("/")
        dot_parts = module_path.lower().split(".")
        all_parts = parts + dot_parts
        return vendor in all_parts

    @staticmethod
    def _gpon_module_applies(module_path: str, host_vendor: str) -> bool:
        """Check if a GPON-category module applies to the given host.

        Generic GPON modules (no vendor in name) apply to any GPON device.
        Vendor-specific GPON modules only apply if vendor matches.
        """
        m_lower = module_path.lower()

        other_vendors_in_gpon = [
            "alcatel", "nokia", "skyworth", "fiberhome", "calix",
            "zhone", "genexis", "technicolor",
        ]
        for ov in other_vendors_in_gpon:
            if ov in m_lower:
                return host_vendor and ov in host_vendor
        return True

    @staticmethod
    def _multi_module_applies(
        module_path: str, host_vendor: str, is_gpon: bool
    ) -> bool:
        """Check if a multi-vendor module applies to the host.

        Only include if the module explicitly references the host vendor
        or a technology the host uses (e.g. gpon for GPON devices).
        """
        m_lower = module_path.lower()

        if host_vendor and host_vendor in m_lower:
            return True

        if is_gpon and "gpon" in m_lower:
            other_vendors = [
                "genexis", "plc_wireless", "techview", "ruckus",
                "f5_big", "citrix",
            ]
            return not any(ov in m_lower for ov in other_vendors)

        return False

    @staticmethod
    def _generic_tool_applies(module_path: str, host: DiscoveredHost) -> bool:
        """Check if a generic tool/scanner applies to the host by protocol."""
        m_lower = module_path.lower()

        protocol_port_map = {
            "upnp": [1900, 49152, 37443, 37215, 5000],
            "ssdp": [1900, 49152, 37443],
            "snmp": [161, 162],
            "tr069": [7547],
            "cwmp": [7547],
        }

        for proto, ports in protocol_port_map.items():
            if proto in m_lower:
                if any(p in host.open_ports for p in ports):
                    return True
                all_text = " ".join(host.banners.values()).lower()
                if proto in all_text:
                    return True

        return False

    # ------------------------------------------------------------------
    # Wireless capability detection & WirelessXPL-Forge recommendation
    # ------------------------------------------------------------------

    _WIRELESS_INDICATORS = [
        "wireless", "wifi", "wi-fi", "wlan", "ssid", "wpa",
        "802.11", "radio", "antenna", "channel",
        "2.4ghz", "5ghz", "6ghz", "2,4ghz",
    ]

    _ROUTER_VENDOR_TYPES = {
        "huawei", "zte", "tplink", "dlink", "netgear", "asus", "linksys",
        "cisco", "mikrotik", "ubiquiti", "arris", "comtrend", "tenda",
        "totolink", "xiaomi", "intelbras", "fiberhome", "sagem",
        "draytek", "wavlink", "trendnet", "belkin", "ruckus",
        "fortinet", "sonicwall",
    }

    def _detect_wireless_capability(self, callback: Optional[Callable] = None) -> None:
        """Identify hosts that likely have wireless/WiFi capabilities.

        Checks banners, model names, vendor type, and nearby SSIDs
        associated with the host MAC (via BSSID correlation).
        """
        nearby_ssids = self._scan_nearby_ssids()

        for host in self._hosts:
            reasons: List[str] = []

            # 1. Banner analysis
            all_banners = " ".join(host.banners.values()).lower()
            for kw in self._WIRELESS_INDICATORS:
                if kw in all_banners:
                    reasons.append("banner:{}".format(kw))
                    break

            # 2. Known router/AP vendor (virtually all have WiFi)
            vendor_lower = host.vendor_guess.lower()
            if vendor_lower in self._ROUTER_VENDOR_TYPES:
                reasons.append("vendor:{}".format(vendor_lower))

            # 3. Model name contains WiFi/wireless hint
            model_lower = (host.model_guess or "").lower()
            wifi_model_patterns = [
                "wap", "wrt", "wlan", "wifi", "wireless",
                "archer", "deco", "nighthawk", "orbi", "velop",
                "unifi", "airos", "hap", "eg8", "hg8",
                "ont", "gpon", "echolife", "optixstar",
            ]
            for pat in wifi_model_patterns:
                if pat in model_lower:
                    reasons.append("model:{}".format(pat))
                    break

            # 4. BSSID/MAC correlation with nearby SSIDs
            if host.mac:
                mac_prefix = host.mac.replace(":", "").replace("-", "")[:6].upper()
                for ssid_name, ssid_bssid in nearby_ssids:
                    bssid_prefix = ssid_bssid.replace(":", "").replace("-", "")[:6].upper()
                    if mac_prefix == bssid_prefix:
                        host.has_wireless = True
                        if ssid_name and ssid_name not in host.wireless_ssids:
                            host.wireless_ssids.append(ssid_name)
                        reasons.append("bssid_match:{}".format(ssid_name or ssid_bssid))

            if reasons:
                host.has_wireless = True

        if callback:
            wifi_count = sum(1 for h in self._hosts if h.has_wireless)
            if wifi_count:
                callback("wireless", "{} host(s) with wireless capability detected".format(wifi_count))

    @staticmethod
    def _scan_nearby_ssids() -> List[Tuple[str, str]]:
        """Return (ssid, bssid) pairs from the OS wireless scan cache."""
        result: List[Tuple[str, str]] = []
        if sys.platform != "win32":
            return result
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, timeout=10,
            )
            output = r.stdout.decode(_OEM_ENCODING, errors="replace")
        except Exception:
            return result

        current_ssid = ""
        for line in output.splitlines():
            ssid_m = re.match(r"\s*SSID\s+\d+\s*:\s*(.+)", line, re.IGNORECASE)
            if ssid_m:
                current_ssid = ssid_m.group(1).strip()
            bssid_m = re.match(r"\s*BSSID\s+\d+\s*:\s*([\da-fA-F:]+)", line, re.IGNORECASE)
            if bssid_m:
                bssid = bssid_m.group(1).strip().upper()
                result.append((current_ssid, bssid))
        return result

    _WXPL_RECOMMENDATION = (
        "This device has wireless (WiFi) capabilities but RouterXPL-Forge "
        "focuses on wired/web-based exploit testing. For wireless-specific "
        "attacks (WPA/WPA2/WPA3 cracking, deauth, evil twin, PMKID capture, "
        "handshake sniffing, rogue AP, and other active/passive wireless "
        "attacks), use WirelessXPL-Forge — a dedicated tool for online/offline "
        "wireless security testing. See: submodules/IoT/WirelessXPL-Forge"
    )

    def _generate_wireless_recommendations(self) -> None:
        """Add WirelessXPL-Forge recommendation for wireless-capable hosts.

        Targets two scenarios:
          1. Host has WiFi but NO RouterXPL exploit modules matched
             -> strong recommendation (primary attack surface is wireless)
          2. Host has WiFi AND RouterXPL modules matched
             -> complementary note (wireless is an additional attack surface)
        """
        for host in self._hosts:
            if not host.has_wireless:
                continue

            ssid_note = ""
            if host.wireless_ssids:
                ssid_note = " Detected SSIDs: {}.".format(", ".join(host.wireless_ssids))

            if not host.matched_modules:
                host.wireless_recommendation = (
                    "[RECOMMENDED] No wired/web exploits matched for this device, "
                    "but it has wireless capabilities.{} {}".format(
                        ssid_note, self._WXPL_RECOMMENDATION,
                    )
                )
            else:
                host.wireless_recommendation = (
                    "[COMPLEMENTARY] This device has {} RouterXPL module(s) for "
                    "wired/web testing, but also exposes wireless interfaces.{} "
                    "For a comprehensive assessment, complement with "
                    "WirelessXPL-Forge for wireless-layer attacks "
                    "(WPA cracking, deauth, PMKID, evil twin, etc.). "
                    "See: submodules/IoT/WirelessXPL-Forge".format(
                        len(host.matched_modules), ssid_note,
                    )
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_vendor(vendor_str: str) -> str:
        """Normalize a vendor name to match module naming conventions."""
        from routerxpl.core.oui import normalize_vendor
        return normalize_vendor(vendor_str)

    @property
    def hosts(self) -> List[DiscoveredHost]:
        """Return discovered hosts."""
        return list(self._hosts)

    def hosts_with_modules(self) -> List[DiscoveredHost]:
        """Return only hosts that have matching exploit modules."""
        return [h for h in self._hosts if h.matched_modules]

    def hosts_with_wireless(self) -> List[DiscoveredHost]:
        """Return hosts that have wireless capabilities."""
        return [h for h in self._hosts if h.has_wireless]
