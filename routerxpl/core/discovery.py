"""Network Target Discovery Engine.

Scans a subnet to find live hosts, fingerprints network devices,
and matches them against the RouterXPL module catalog to identify
potential exploit targets.

Scanning backends (in priority order):
  1. Nmap via python-nmap (most robust, requires ``nmap`` binary)
  2. Scapy ARP scan (L2, same-subnet only, requires root/admin)
  3. Socket-based TCP probe (universal fallback, no special privileges)

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 0.1.0
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

PROBE_PORTS: List[int] = [80, 443, 8080, 8443, 22, 23, 161, 8081, 8888, 53]

_OUI_VENDORS: Dict[str, str] = {
    "00:1A:2B": "asus",
    "00:1E:58": "dlink",
    "1C:7E:E5": "dlink",
    "28:10:7B": "dlink",
    "B8:A3:86": "dlink",
    "C4:A8:1D": "tplink",
    "EC:08:6B": "tplink",
    "50:C7:BF": "tplink",
    "30:B5:C2": "tplink",
    "14:CC:20": "tplink",
    "60:32:B1": "tplink",
    "A4:2B:B0": "tplink",
    "AC:84:C6": "tplink",
    "78:44:76": "tplink",
    "20:CF:30": "asus",
    "38:D5:47": "asus",
    "04:D9:F5": "asus",
    "1C:87:2C": "asus",
    "2C:56:DC": "asus",
    "F0:79:59": "asus",
    "08:60:6E": "asus",
    "00:18:E7": "cisco",
    "00:1B:D4": "cisco",
    "00:25:45": "cisco",
    "58:97:1E": "cisco",
    "D0:D0:FD": "cisco",
    "00:04:ED": "cisco",
    "3C:5A:B4": "netgear",
    "C4:3D:C7": "netgear",
    "6C:B0:CE": "netgear",
    "20:0C:C8": "netgear",
    "B0:7F:B9": "netgear",
    "B0:4E:26": "netgear",
    "28:80:88": "netgear",
    "E4:F4:C6": "netgear",
    "44:94:FC": "ubiquiti",
    "80:2A:A8": "ubiquiti",
    "FC:EC:DA": "ubiquiti",
    "24:5A:4C": "ubiquiti",
    "78:8A:20": "ubiquiti",
    "68:D7:9A": "ubiquiti",
    "18:E8:29": "ubiquiti",
    "B4:FB:E4": "ubiquiti",
    "C8:3A:35": "tenda",
    "D8:F1:5B": "tenda",
    "CC:2D:E0": "tenda",
    "00:1F:CE": "linksys",
    "98:FC:11": "linksys",
    "C0:56:27": "linksys",
    "20:AA:4B": "linksys",
    "14:91:82": "linksys",
    "00:14:BF": "linksys",
    "E8:65:D4": "trendnet",
    "D8:EB:97": "trendnet",
    "00:40:05": "trendnet",
    "C8:3A:35": "tenda",
    "00:E0:4C": "multi",       # Realtek
    "00:0A:EB": "huawei",
    "00:25:9E": "huawei",
    "00:E0:FC": "huawei",
    "20:F3:A3": "huawei",
    "48:46:FB": "huawei",
    "70:72:3C": "huawei",
    "88:53:D4": "huawei",
    "AC:4E:91": "huawei",
    "CC:A2:23": "zte",
    "00:19:CB": "zte",
    "00:1A:2A": "zte",
    "00:26:ED": "mikrotik",
    "48:8F:5A": "mikrotik",
    "D4:CA:6D": "mikrotik",
    "B8:69:F4": "mikrotik",
    "E4:8D:8C": "mikrotik",
    "2C:C8:1B": "mikrotik",
    "B4:75:0E": "belkin",
    "94:10:3E": "belkin",
    "EC:1A:59": "belkin",
    "08:86:3B": "belkin",
    "00:1C:DF": "belkin",
    "00:17:3F": "belkin",
    "00:24:01": "draytek",
    "00:1D:AA": "draytek",
    "00:50:7F": "draytek",
    "00:01:36": "arris",
    "00:15:96": "arris",
    "00:1D:CD": "arris",
    "00:26:D8": "arris",
    "10:86:8C": "arris",
    "20:3D:66": "arris",
    "F8:C0:91": "arris",
}


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

    def summary(self) -> str:
        """One-line display."""
        ports = ",".join(str(p) for p in self.open_ports[:6])
        host_part = self.hostname or self.ip
        mac_part = " ({})".format(self.mac) if self.mac else ""
        vendor_part = " [{}]".format(self.vendor_guess) if self.vendor_guess else ""
        model_part = " {}".format(self.model_guess) if self.model_guess else ""
        mods = " | {} modules".format(len(self.matched_modules)) if self.matched_modules else ""
        return "{}{} ports:{}{}{}{} ".format(host_part, mac_part, ports, vendor_part, model_part, mods)


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
    ):
        """Initialize the discovery engine.

        Args:
            target: Subnet in CIDR notation (e.g. ``192.168.1.0/24``) or single IP.
            ports: Ports to probe. Defaults to ``PROBE_PORTS``.
            timeout: Socket timeout in seconds for probes.
            max_workers: Thread pool size for parallel probing.
            use_nmap: Try to use nmap if available.
            use_scapy: Try to use scapy ARP if available.
        """
        self.target = target
        self.ports = ports or list(PROBE_PORTS)
        self.timeout = timeout
        self.max_workers = max_workers
        self.use_nmap = use_nmap
        self.use_scapy = use_scapy
        self._hosts: List[DiscoveredHost] = []
        self._known_vendors: Set[str] = set()
        self._module_index: Dict[str, List[str]] = {}

    def _build_module_index(self) -> None:
        """Build vendor -> module list mapping from the RouterXPL catalog."""
        if self._module_index:
            return
        try:
            from routerxpl.core.exploit.utils import index_modules
            modules = index_modules()
            for mod in modules:
                parts = mod.split(".")
                if len(parts) >= 3:
                    vendor = parts[2].lower()
                    self._module_index.setdefault(vendor, []).append(mod)
                    self._known_vendors.add(vendor)
        except Exception as exc:
            logger.debug("Failed to build module index: %s", exc)

    def scan(self, callback=None) -> List[DiscoveredHost]:
        """Run the full discovery pipeline.

        Args:
            callback: Optional callable(stage: str, detail: str) for progress.

        Returns:
            List of discovered hosts with fingerprint and module matches.
        """
        self._build_module_index()
        self._hosts = []

        if callback:
            callback("scan", "Starting host discovery on {}".format(self.target))

        if self.use_nmap and self._nmap_available():
            if callback:
                callback("scan", "Using Nmap scanner")
            self._scan_nmap(callback)
        elif self.use_scapy and self._scapy_available():
            if callback:
                callback("scan", "Using Scapy ARP scanner")
            self._scan_scapy(callback)
        else:
            if callback:
                callback("scan", "Using TCP socket scanner (fallback)")
            self._scan_socket(callback)

        if callback:
            callback("fingerprint", "Fingerprinting {} hosts".format(len(self._hosts)))
        self._fingerprint_all(callback)

        if callback:
            callback("match", "Matching against {} module vendors".format(len(self._known_vendors)))
        self._match_catalog()

        return self._hosts

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

    def _scan_nmap(self, callback=None) -> None:
        """Host discovery + service scan via nmap."""
        import nmap
        nm = nmap.PortScanner()

        port_str = ",".join(str(p) for p in self.ports)
        try:
            nm.scan(
                hosts=self.target,
                ports=port_str,
                arguments="-sV -T4 --open -O --osscan-limit",
                timeout=120,
            )
        except nmap.PortScannerError as exc:
            logger.warning("Nmap scan failed: %s -- falling back to socket scan", exc)
            if callback:
                callback("scan", "Nmap failed ({}), falling back to sockets".format(exc))
            self._scan_socket(callback)
            return
        except Exception as exc:
            logger.warning("Nmap unexpected error: %s", exc)
            self._scan_socket(callback)
            return

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

            open_ports = []
            banners = {}
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

            dh = DiscoveredHost(
                ip=host_ip,
                mac=mac,
                hostname=hostname,
                open_ports=sorted(open_ports),
                banners=banners,
            )
            if vendor_str:
                dh.vendor_guess = self._normalize_vendor(vendor_str)
            self._hosts.append(dh)

        if callback:
            callback("scan", "Nmap found {} live hosts".format(len(self._hosts)))

    def _scan_scapy(self, callback=None) -> None:
        """ARP scan for same-subnet discovery via scapy."""
        try:
            from scapy.all import ARP, Ether, srp, conf
            conf.verb = 0
        except ImportError:
            self._scan_socket(callback)
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
            self._scan_socket(callback)
            return
        except Exception as exc:
            logger.debug("Scapy ARP failed: %s", exc)
            self._scan_socket(callback)
            return

        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc.upper().replace(":", ":")
            dh = DiscoveredHost(ip=ip, mac=mac)
            self._hosts.append(dh)

        if callback:
            callback("scan", "ARP scan found {} live hosts".format(len(self._hosts)))

        self._probe_ports_parallel(callback)

    def _scan_socket(self, callback=None) -> None:
        """TCP connect scan using raw sockets (no special privileges)."""
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        except ValueError:
            targets = [self.target]

        if len(targets) > 1024:
            targets = targets[:1024]
            if callback:
                callback("scan", "Limiting scan to first 1024 hosts")

        live_ips: List[str] = []
        lock = threading.Lock()

        def probe_host(ip: str) -> None:
            for port in self.ports[:4]:
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
            self._hosts.append(DiscoveredHost(ip=ip))

        if callback:
            callback("scan", "Socket scan found {} live hosts".format(len(self._hosts)))

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

    def _fingerprint_all(self, callback=None) -> None:
        """Run fingerprinting on all discovered hosts."""
        for host in self._hosts:
            self._fingerprint_host(host)
        if callback:
            identified = sum(1 for h in self._hosts if h.vendor_guess)
            callback("fingerprint", "Identified {} out of {} hosts".format(identified, len(self._hosts)))

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

    def _oui_lookup(self, mac: str) -> str:
        """Look up vendor from MAC address OUI prefix."""
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        parts = mac_clean.split(":")
        if len(parts) >= 3:
            prefix = ":".join(parts[:3])
            return _OUI_VENDORS.get(prefix, "")
        return ""

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
        vendor_keywords = {
            "dlink": ["d-link", "dlink", "dir-", "dsl-", "dap-"],
            "tplink": ["tp-link", "tplink", "archer", "tl-wr", "tl-mr"],
            "netgear": ["netgear"],
            "asus": ["asus", "rt-ac", "rt-ax", "rt-n"],
            "linksys": ["linksys", "cisco-linksys"],
            "cisco": ["cisco"],
            "huawei": ["huawei", "hg8245", "echolife"],
            "zte": ["zte", "zxhn", "zxv10"],
            "mikrotik": ["mikrotik", "routeros"],
            "ubiquiti": ["ubiquiti", "unifi", "edgerouter", "airos"],
            "fortinet": ["fortinet", "fortigate"],
            "tenda": ["tenda"],
            "arris": ["arris", "touchstone"],
            "comtrend": ["comtrend"],
            "trendnet": ["trendnet"],
            "belkin": ["belkin"],
            "draytek": ["draytek", "vigor"],
            "totolink": ["totolink"],
            "wavlink": ["wavlink"],
            "xiaomi": ["xiaomi", "miwifi"],
            "intelbras": ["intelbras"],
        }

        for vendor, keywords in vendor_keywords.items():
            for kw in keywords:
                if kw in banner_lower:
                    return (vendor, "", 0.6)

        return ("", "", 0.0)

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
        """Match discovered hosts against the RouterXPL module catalog."""
        for host in self._hosts:
            vendor = host.vendor_guess.lower()
            if not vendor:
                continue

            matching_mods = self._module_index.get(vendor, [])

            if host.model_guess:
                model_lower = host.model_guess.lower().replace("-", "_").replace(" ", "_")
                model_matches = [
                    m for m in matching_mods
                    if model_lower in m.lower() or any(
                        part in m.lower()
                        for part in model_lower.split("_") if len(part) > 2
                    )
                ]
                if model_matches:
                    host.matched_modules = model_matches
                else:
                    host.matched_modules = matching_mods
            else:
                host.matched_modules = matching_mods

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_vendor(vendor_str: str) -> str:
        """Normalize a vendor name to match module naming conventions."""
        v = vendor_str.strip().lower()
        aliases = {
            "tp-link": "tplink",
            "tp link": "tplink",
            "d-link": "dlink",
            "d link": "dlink",
            "cisco systems": "cisco",
            "cisco-linksys": "linksys",
            "huawei technologies": "huawei",
            "zte corporation": "zte",
            "arris group": "arris",
            "netgear inc": "netgear",
            "netgear, inc.": "netgear",
            "asus computer": "asus",
            "asustek computer": "asus",
            "belkin international": "belkin",
            "ubiquiti networks": "ubiquiti",
            "ubiquiti inc": "ubiquiti",
            "mikrotikls": "mikrotik",
            "fortinet inc": "fortinet",
            "fortinet, inc.": "fortinet",
            "sonicwall": "sonicwall",
            "dell sonicwall": "sonicwall",
        }
        for alias, canonical in aliases.items():
            if alias in v:
                return canonical
        for known in ("dlink", "tplink", "netgear", "asus", "linksys", "cisco",
                       "huawei", "zte", "mikrotik", "ubiquiti", "fortinet",
                       "tenda", "arris", "comtrend", "trendnet", "belkin",
                       "draytek", "totolink", "wavlink", "xiaomi", "intelbras",
                       "juniper", "sonicwall", "fiberhome", "gpon"):
            if known in v:
                return known
        return v.split()[0] if v else ""

    @property
    def hosts(self) -> List[DiscoveredHost]:
        """Return discovered hosts."""
        return list(self._hosts)

    def hosts_with_modules(self) -> List[DiscoveredHost]:
        """Return only hosts that have matching exploit modules."""
        return [h for h in self._hosts if h.matched_modules]
