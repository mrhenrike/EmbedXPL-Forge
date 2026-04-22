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


def _expand_target(target: str) -> List[str]:
    """Expand a target spec into individual IP addresses.

    Supports:
      - Single IP: ``192.168.1.1``
      - CIDR: ``192.168.1.0/24``
      - Range: ``192.168.1.10-20``
      - Hostname: ``camera.local``

    Args:
        target: Target specification string.

    Returns:
        List of IP address strings.
    """
    target = target.strip()
    ips = []

    # CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # IP range: 192.168.1.10-20 or 192.168.1-2.0-255
    range_m = re.match(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)$', target)
    if range_m:
        a, b, c = int(range_m.group(1)), int(range_m.group(2)), int(range_m.group(3))
        start, end = int(range_m.group(4)), int(range_m.group(5))
        return [f"{a}.{b}.{c}.{d}" for d in range(start, end + 1)]

    # Single IP or hostname
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

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        timeout: float = 3.0,
        max_workers: int = 100,
        scan_speed: int = 4,
        scanner: str = "auto",
    ) -> None:
        """Initialise the RTSP scanner.

        Args:
            ports: List of RTSP ports to scan (defaults to 554, 5554, 8554).
            timeout: Socket timeout for direct probes.
            max_workers: Parallel workers for direct probe mode.
            scan_speed: nmap timing template (1-5).
            scanner: 'nmap', 'masscan', 'direct', or 'auto' (auto-detect).
        """
        self.ports = ports or DEFAULT_RTSP_PORTS
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

        Mirrors cameradar's --skip-scan mode.

        Args:
            targets: List of 'ip:port' or 'ip' strings.

        Returns:
            List of RTSPStream objects for all expanded targets.
        """
        streams = []
        for target in targets:
            ips = _expand_target(target)
            for ip in ips:
                for port in self.ports:
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
