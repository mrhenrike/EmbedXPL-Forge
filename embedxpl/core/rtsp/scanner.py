# Author: André Henrique (LinkedIn/X: @mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""EmbedXPL-Forge — RTSP Network Scanner.

Port of cameradar's network discovery to Python. Supports:
  - nmap-based RTSP port discovery (with service identification)
  - masscan-based fast scanning (large networks)
  - Direct socket probe (skip-scan mode — no external tool required)
  - CIDR, range, and host expansion

References:
  - cameradar: https://github.com/ullaakut/cameradar (MIT, Ullaakut)

Author: André Henrique (@mrhenrike) | União Geek
Version: 1.0.0
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from embedxpl.core.rtsp.models import RTSPStream

logger = logging.getLogger(__name__)

# Default RTSP ports (matching cameradar defaults)
DEFAULT_RTSP_PORTS = [554, 5554, 8554]
# Extended port set (additional common RTSP ports)
EXTENDED_RTSP_PORTS = [554, 5554, 8554, 10554, 8080, 9000, 3554, 4554,
                        7447, 1935, 1554, 2554, 37777, 34567, 34568]


def _parse_octet_range(value: str):
    """Parse a single octet or octet range (e.g. '1', '1-3').

    Returns:
        List of int values, or None if not a valid octet spec.
    """
    value = value.strip()
    if not value:
        return None
    if "-" in value:
        parts = value.split("-", 1)
        try:
            lo, hi = int(parts[0].strip()), int(parts[1].strip())
            if 0 <= lo <= 255 and 0 <= hi <= 255 and lo <= hi:
                return list(range(lo, hi + 1))
        except ValueError:
            pass
        return None
    try:
        v = int(value)
        if 0 <= v <= 255:
            return [v]
    except ValueError:
        pass
    return None


def _expand_ipv4_multirange(target: str) -> List[str]:
    """Expand multi-octet IPv4 range (e.g. ``192.168.1-2.0-255``).

    Mirrors cameradar's parseIPv4Range logic from internal/scan/skip/skip.go.
    Supports ranges in any octet position.

    Args:
        target: String like ``192.168.1-3.0-255`` or ``192.168.1.10-20``.

    Returns:
        List of IP address strings, or empty list if not a range format.
    """
    parts = target.split(".")
    if len(parts) != 4:
        return []

    ranges = []
    for part in parts:
        parsed = _parse_octet_range(part)
        if parsed is None:
            return []
        ranges.append(parsed)

    ips = []
    for a in ranges[0]:
        for b in ranges[1]:
            for c in ranges[2]:
                for d in ranges[3]:
                    ips.append(f"{a}.{b}.{c}.{d}")
    return ips


def _expand_target(target: str) -> List[str]:
    """Expand a target spec into individual IP addresses.

    Supports all formats from cameradar:
      - Single IP: ``192.168.1.1``
      - CIDR: ``192.168.1.0/24``
      - Last-octet range: ``192.168.1.10-20``
      - Multi-octet range: ``192.168.1-2.0-255`` (full cameradar compat)
      - Full-IP range (masscan): ``192.168.1.1-192.168.1.254``
      - Hostname: ``camera.local`` (resolved via DNS)

    Args:
        target: Target specification string.

    Returns:
        List of IP address strings.
    """
    target = target.strip()

    # CIDR — try first
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # Full-IP range: 192.168.1.1-192.168.1.254
    full_range_m = re.match(
        r'^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$', target
    )
    if full_range_m:
        try:
            start_int = int(ipaddress.IPv4Address(full_range_m.group(1)))
            end_int = int(ipaddress.IPv4Address(full_range_m.group(2)))
            return [str(ipaddress.IPv4Address(i))
                    for i in range(start_int, min(end_int + 1, start_int + 65536))]
        except Exception:
            pass

    # Multi-octet range: 192.168.1-2.0-255
    if re.search(r'\d-\d', target):
        expanded = _expand_ipv4_multirange(target)
        if expanded:
            return expanded

    # Single valid IP
    try:
        ipaddress.IPv4Address(target)
        return [target]
    except ValueError:
        pass

    # Hostname — DNS resolution
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
        return list({info[4][0] for info in infos})
    except socket.gaierror:
        pass

    return [target]


def _infer_scheme(port: int, service_name: str = "") -> str:
    """Infer RTSP scheme from port number and service name."""
    sn = service_name.lower().strip()
    if sn in ("rtsps", "https", "http"):
        return sn
    if port in (443, 8443):
        return "https"
    if port in (80, 8080):
        return "http"
    return ""


class RTSPScanner:
    """RTSP camera network scanner.

    Discovers RTSP-speaking devices on the network using nmap,
    masscan, or direct socket probes.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    @staticmethod
    def parse_ports(ports_spec) -> List[int]:
        """Parse port specification string or list.

        Mirrors cameradar's parsePorts (internal/scan/skip/skip.go).
        Supports: single ports, ranges, comma-separated, service names.

        Args:
            ports_spec: ``int | List[int] | str`` like ``"554,19000-19010"``.

        Returns:
            Deduplicated sorted list of port numbers.
        """
        if ports_spec is None:
            return list(DEFAULT_RTSP_PORTS)
        if isinstance(ports_spec, (list, tuple)):
            return sorted(set(int(p) for p in ports_spec if 1 <= int(p) <= 65535))

        seen: set = set()
        result = []
        for token in str(ports_spec).split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                parts = token.split("-", 1)
                try:
                    lo, hi = int(parts[0].strip()), int(parts[1].strip())
                    for p in range(lo, hi + 1):
                        if 1 <= p <= 65535 and p not in seen:
                            seen.add(p)
                            result.append(p)
                    continue
                except ValueError:
                    pass
            try:
                p = int(token)
                if 1 <= p <= 65535 and p not in seen:
                    seen.add(p)
                    result.append(p)
            except ValueError:
                # Try service name lookup
                try:
                    p = socket.getservbyname(token, "tcp")
                    if p not in seen:
                        seen.add(p)
                        result.append(p)
                except OSError:
                    pass
        return result

    def __init__(
        self,
        ports=None,
        timeout: float = 3.0,
        max_workers: int = 100,
        scan_speed: int = 4,
        scanner: str = "auto",
    ) -> None:
        """Initialise the RTSP scanner.

        Args:
            ports: List of RTSP ports to scan (defaults to 554, 5554, 8554).
                   Accepts ``List[int]``, or a comma-separated string like
                   ``"554,5554,19000-19010"`` (matches cameradar --ports flag).
            timeout: Socket timeout for direct probes.
            max_workers: Parallel workers for direct probe mode.
            scan_speed: nmap timing template (1-5).
            scanner: 'nmap', 'masscan', 'direct', or 'auto' (auto-detect).
        """
        self.ports = self.parse_ports(ports) if ports is not None else list(DEFAULT_RTSP_PORTS)
        self.timeout = timeout
        self.max_workers = max_workers
        self.scan_speed = scan_speed
        self.scanner = scanner

    def scan(self, targets: List[str]) -> List[RTSPStream]:
        """Discover RTSP hosts on the given targets.

        Args:
            targets: List of targets (IPs, CIDRs, hostnames).

        Returns:
            List of discovered :class:`~embedxpl.core.rtsp.models.RTSPStream` objects.
        """
        scanner = self.scanner
        if scanner == "auto":
            if shutil.which("nmap"):
                scanner = "nmap"
            elif shutil.which("masscan"):
                scanner = "masscan"
            else:
                scanner = "direct"

        if scanner == "nmap":
            return self._scan_nmap(targets)
        if scanner == "masscan":
            return self._scan_masscan(targets)
        return self._scan_direct(targets)

    def skip_scan(self, targets: List[str]) -> List[RTSPStream]:
        """Skip discovery — treat every target:port as an RTSP stream candidate.

        Mirrors cameradar's --skip-scan mode (internal/scan/skip/skip.go).
        Resolves hostnames via DNS, expands CIDRs and multi-octet ranges,
        and builds one stream per (ip, port) pair.

        Args:
            targets: List of IP/CIDR/range/hostname strings.
                     If a target contains ':', the port is parsed from it.

        Returns:
            List of RTSPStream objects for all expanded targets.
        """
        streams = []
        seen: set = set()
        for target in targets:
            # Support "host:port" notation in skip-scan
            port_override: Optional[int] = None
            if target.count(":") == 1 and not target.startswith("["):
                host_part, port_part = target.rsplit(":", 1)
                try:
                    port_override = int(port_part)
                    target = host_part
                except ValueError:
                    pass

            ips = _expand_target(target)
            ports = [port_override] if port_override else self.ports
            for ip in ips:
                for port in ports:
                    key = (ip, port)
                    if key not in seen:
                        seen.add(key)
                        streams.append(RTSPStream(address=ip, port=port))
        return streams

    # ── Scanner Backends ──────────────────────────────────────────────────────

    def _scan_nmap(self, targets: List[str]) -> List[RTSPStream]:
        """Discover RTSP streams via nmap with service identification."""
        if not shutil.which("nmap"):
            logger.warning("[RTSPScanner] nmap not found, falling back to direct scan")
            return self._scan_direct(targets)

        ports_str = ",".join(str(p) for p in self.ports)
        targets_str = " ".join(targets)
        cmd = [
            "nmap",
            "-sV",            # Service version detection
            "-p", ports_str,
            f"-T{self.scan_speed}",
            "--open",          # Only open ports
            "-oX", "-",        # XML output to stdout
        ] + targets

        logger.info("[RTSPScanner] nmap: %s", " ".join(cmd))
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            xml = result.stdout.decode("utf-8", errors="replace")
            return self._parse_nmap_xml(xml)
        except subprocess.TimeoutExpired:
            logger.error("[RTSPScanner] nmap timed out")
            return []
        except Exception as exc:
            logger.error("[RTSPScanner] nmap error: %s", exc)
            return []

    def _parse_nmap_xml(self, xml: str) -> List[RTSPStream]:
        """Parse nmap XML output and extract RTSP streams."""
        streams = []
        # Extract hosts and open ports
        host_blocks = re.findall(
            r'<host[^>]*>.*?</host>', xml, re.DOTALL
        )
        for host_block in host_blocks:
            # Extract IP address
            addr_m = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', host_block)
            if not addr_m:
                continue
            ip = addr_m.group(1)

            # Extract open ports with service info
            port_blocks = re.findall(
                r'<port protocol="tcp" portid="(\d+)">(.*?)</port>',
                host_block, re.DOTALL
            )
            for portid, port_block in port_blocks:
                state_m = re.search(r'<state state="([^"]+)"', port_block)
                if not state_m or state_m.group(1) != "open":
                    continue

                port = int(portid)
                svc_name = ""
                svc_product = ""
                svc_m = re.search(r'<service name="([^"]*)"[^>]*product="([^"]*)"', port_block)
                if svc_m:
                    svc_name = svc_m.group(1)
                    svc_product = svc_m.group(2)
                else:
                    svc_m2 = re.search(r'<service name="([^"]*)"', port_block)
                    if svc_m2:
                        svc_name = svc_m2.group(1)

                # Classify as RTSP candidate
                is_rtsp = (
                    "rtsp" in svc_name.lower()
                    or port in self.ports
                    or _infer_scheme(port, svc_name) != ""
                )
                if not is_rtsp:
                    continue

                scheme = _infer_scheme(port, svc_name)
                streams.append(RTSPStream(
                    address=ip,
                    port=port,
                    device=svc_product,
                    scheme=scheme or "rtsp",
                ))
                logger.debug("[RTSPScanner] nmap found %s:%d (%s)", ip, port, svc_product)

        logger.info("[RTSPScanner] nmap: found %d RTSP streams", len(streams))
        return streams

    def _scan_masscan(self, targets: List[str]) -> List[RTSPStream]:
        """Discover RTSP streams via masscan (faster for large networks)."""
        if not shutil.which("masscan"):
            logger.warning("[RTSPScanner] masscan not found, falling back to direct scan")
            return self._scan_direct(targets)

        ports_str = ",".join(str(p) for p in self.ports)
        cmd = ["masscan"] + targets + [
            "-p", ports_str,
            "--rate", "1000",
            "-oL", "-",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=300)
            output = result.stdout.decode("utf-8", errors="replace")
            return self._parse_masscan_output(output)
        except Exception as exc:
            logger.error("[RTSPScanner] masscan error: %s", exc)
            return []

    def _parse_masscan_output(self, output: str) -> List[RTSPStream]:
        """Parse masscan -oL output."""
        streams = []
        for line in output.splitlines():
            # Format: open tcp PORT IP TIMESTAMP
            m = re.match(r'^open\s+tcp\s+(\d+)\s+([\d.]+)', line)
            if m:
                port = int(m.group(1))
                ip = m.group(2)
                streams.append(RTSPStream(address=ip, port=port))
        logger.info("[RTSPScanner] masscan: found %d open ports", len(streams))
        return streams

    def _scan_direct(self, targets: List[str]) -> List[RTSPStream]:
        """Discover RTSP streams via direct TCP socket probes."""
        all_targets = []
        for target in targets:
            ips = _expand_target(target)
            for ip in ips:
                for port in self.ports:
                    all_targets.append((ip, port))

        logger.info("[RTSPScanner] direct probe: %d targets", len(all_targets))

        streams = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self._probe_rtsp, ip, port): (ip, port)
                for ip, port in all_targets
            }
            for future in as_completed(future_to_target):
                ip, port = future_to_target[future]
                try:
                    stream = future.result()
                    if stream:
                        streams.append(stream)
                except Exception:
                    pass

        logger.info("[RTSPScanner] direct: found %d RTSP hosts", len(streams))
        return streams

    def _probe_rtsp(self, ip: str, port: int) -> Optional[RTSPStream]:
        """Probe a single IP:port for RTSP service."""
        from embedxpl.core.rtsp.client import RTSPClient
        client = RTSPClient(ip, port, timeout=self.timeout)
        if not client.is_rtsp():
            return None
        banner = client.banner()
        return RTSPStream(
            address=ip,
            port=port,
            device=banner,
            server_banner=banner,
        )
