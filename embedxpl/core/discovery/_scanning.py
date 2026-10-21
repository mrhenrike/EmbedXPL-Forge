"""Network discovery - scanning methods."""
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

from embedxpl.core.discovery._models import (
    TimingProfile, DiscoveredHost, _detect_oem_encoding,
    PROBE_PORTS, PROBE_PORTS_EXTENDED, _HOST_DISCOVERY_ARGS,
)

class _NetworkDiscoveryScanning:
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
                    "embedxpl", "modules", "exploits", "creds",
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
            from scapy.all import ARP, Ether, conf, srp
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

