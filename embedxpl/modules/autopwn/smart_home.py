"""EmbedXPL AutoPwn  -  Smart Home segment.

Automated discovery and exploitation of smart home hubs and IoT devices
(Philips Hue, Samsung SmartThings, Tuya, Google Home, Amazon Echo, etc).
Probes UPnP/SSDP, mDNS, MQTT, HTTP, and common management ports to
fingerprint devices before running exploit modules.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
# authorized use only
"""
from __future__ import annotations

import http.client
import importlib
import inspect
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from embedxpl.modules.autopwn.base import AutoPwnReport, SegmentAutoPwn


# ---------------------------------------------------------------------------
# Fingerprint dataclass
# ---------------------------------------------------------------------------

@dataclass
class SmartHomeFingerprint:
    """Fingerprint for a single smart home device."""

    target: str
    vendor: str = "unknown"
    device_type: str = ""           # hub, bulb, plug, speaker, camera, thermostat
    model: str = ""
    firmware: str = ""
    ssdp_usn: str = ""
    ssdp_server: str = ""
    ssdp_location: str = ""
    http_server: str = ""
    mdns_name: str = ""
    mqtt_open: bool = False
    open_ports: list[int] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        parts = [self.vendor.upper()]
        if self.device_type:
            parts.append(self.device_type)
        if self.model:
            parts.append(self.model)
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Vendor signatures
# ---------------------------------------------------------------------------

_VENDOR_SIGNATURES: dict[str, list[str]] = {
    "philips_hue": [
        "philips", "hue", "signify", "meethue",
        "hue bridge", "hue-bridgeid",
    ],
    "samsung_smartthings": [
        "smartthings", "samsung", "samsungiot",
    ],
    "tuya": [
        "tuya", "smart life", "smartlife",
    ],
    "google": [
        "google home", "google-home", "chromecast", "google nest",
        "google inc", "googlecast",
    ],
    "amazon": [
        "amazon", "alexa", "echo", "amzn", "fire tv",
    ],
    "tp_link": [
        "tp-link", "tplink", "kasa", "tapo", "deco",
    ],
    "ikea": [
        "ikea", "tradfri", "dirigera",
    ],
    "xiaomi": [
        "xiaomi", "yeelight", "aqara", "mijia", "roborock",
    ],
    "wemo": [
        "wemo", "belkin",
    ],
    "ring": [
        "ring",
    ],
    "sonos": [
        "sonos",
    ],
    "home_assistant": [
        "home assistant", "hass", "homeassistant",
    ],
    "hubitat": [
        "hubitat",
    ],
}

# Ports to probe
_SMART_HOME_PORTS = [80, 443, 1883, 1900, 5353, 8080, 8443, 8883, 49152, 49153]

# SSDP multicast address
_SSDP_MCAST = "239.255.255.250"
_SSDP_PORT = 1900


# ---------------------------------------------------------------------------
# SmartHomeAutoPwn
# ---------------------------------------------------------------------------

class SmartHomeAutoPwn(SegmentAutoPwn):
    """AutoPwn for smart home hubs, plugs, bulbs, speakers, and IoT devices.

    Discovery methods:
      1. SSDP M-SEARCH broadcast on 239.255.255.250:1900
      2. HTTP header fingerprinting on common management ports
      3. MQTT port probing (1883/8883)
      4. mDNS name resolution

    Args:
        targets:           IP/hostname or list of them.
        check_only:        If True, only run check() on modules.
        verbose:           Print progress to stdout.
        ssdp_timeout:      SSDP M-SEARCH response timeout in seconds.
        http_timeout:       HTTP probe timeout in seconds.
        discover_ssdp:     If True, send SSDP M-SEARCH for device discovery.
        discover_mdns:     If True, probe mDNS on port 5353.
    """

    def __init__(
        self,
        targets: str | list[str],
        check_only: bool = True,
        verbose: bool = True,
        ssdp_timeout: int = 4,
        http_timeout: int = 5,
        discover_ssdp: bool = True,
        discover_mdns: bool = True,
        **kw: Any,
    ) -> None:
        super().__init__(segment="smart_home", targets=targets,
                         check_only=check_only, verbose=verbose, **kw)
        self.ssdp_timeout = ssdp_timeout
        self.http_timeout = http_timeout
        self.discover_ssdp = discover_ssdp
        self.discover_mdns = discover_mdns
        self.fingerprints: dict[str, SmartHomeFingerprint] = {}
        self.discovered_targets: list[str] = []

    # ------------------------------------------------------------------
    # TCP port check
    # ------------------------------------------------------------------

    def _tcp_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except (OSError, socket.error):
            return False

    def _scan_ports(self, host: str) -> list[int]:
        open_ports: list[int] = []
        for port in _SMART_HOME_PORTS:
            if self._tcp_port_open(host, port):
                open_ports.append(port)
        return open_ports

    # ------------------------------------------------------------------
    # SSDP M-SEARCH discovery
    # ------------------------------------------------------------------

    def _ssdp_discover(self) -> list[dict[str, str]]:
        """Send SSDP M-SEARCH and collect responding devices.

        Returns a list of dicts with keys: ip, usn, server, location, st.
        """
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {_SSDP_MCAST}:{_SSDP_PORT}\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 3\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        devices: list[dict[str, str]] = []
        seen_ips: set[str] = set()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(self.ssdp_timeout)

                # Send M-SEARCH to multicast group
                s.sendto(msearch, (_SSDP_MCAST, _SSDP_PORT))

                deadline = time.time() + self.ssdp_timeout
                while time.time() < deadline:
                    try:
                        data, addr = s.recvfrom(4096)
                        ip = addr[0]
                        if ip in seen_ips:
                            continue
                        seen_ips.add(ip)

                        text = data.decode("utf-8", errors="replace")
                        headers = self._parse_ssdp_headers(text)
                        headers["ip"] = ip
                        devices.append(headers)
                    except socket.timeout:
                        break
                    except (OSError, socket.error):
                        continue
        except (OSError, socket.error):
            pass

        return devices

    @staticmethod
    def _parse_ssdp_headers(text: str) -> dict[str, str]:
        """Parse SSDP response headers into a dict."""
        result: dict[str, str] = {}
        for line in text.split("\r\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                key_lower = key.strip().lower()
                if key_lower in ("usn", "server", "location", "st",
                                 "cache-control", "ext"):
                    result[key_lower] = val.strip()
        return result

    # ------------------------------------------------------------------
    # HTTP fingerprinting
    # ------------------------------------------------------------------

    def _http_fingerprint(self, host: str, port: int = 80,
                          use_ssl: bool = False) -> dict[str, str]:
        headers: dict[str, str] = {}
        try:
            if use_ssl:
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    host, port, timeout=self.http_timeout, context=ctx,
                )
            else:
                conn = http.client.HTTPConnection(
                    host, port, timeout=self.http_timeout,
                )
            conn.request("GET", "/", headers={"User-Agent": "Mozilla/5.0"})
            resp = conn.getresponse()
            for hdr, val in resp.getheaders():
                headers[hdr.lower()] = val
            body = resp.read(4096).decode("utf-8", errors="replace")
            headers["_body_snippet"] = body[:2048]
            conn.close()
        except Exception:
            pass
        return headers

    # ------------------------------------------------------------------
    # MQTT probe
    # ------------------------------------------------------------------

    def _mqtt_probe(self, host: str, port: int = 1883) -> bool:
        """Try a minimal MQTT CONNECT to check if the broker responds.

        Sends a CONNECT packet and checks for a CONNACK.
        """
        # Minimal MQTT 3.1.1 CONNECT: protocol name, level 4, clean session
        client_id = b"embedxpl"
        proto_name = b"\x00\x04MQTT"
        proto_level = b"\x04"
        connect_flags = b"\x02"  # clean session
        keep_alive = b"\x00\x3c"  # 60s
        client_id_enc = struct.pack("!H", len(client_id)) + client_id
        payload = proto_name + proto_level + connect_flags + keep_alive + client_id_enc
        # Fixed header: CONNECT (0x10), remaining length
        remaining = len(payload)
        fixed_header = bytes([0x10]) + bytes([remaining & 0x7F])

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((host, port))
                s.sendall(fixed_header + payload)
                resp = s.recv(4)
                # CONNACK starts with 0x20
                if resp and resp[0] == 0x20:
                    return True
        except (OSError, socket.error, socket.timeout):
            pass
        return False

    # ------------------------------------------------------------------
    # mDNS probe (simple unicast query for _http._tcp.local)
    # ------------------------------------------------------------------

    def _mdns_probe(self, host: str) -> str:
        """Send a unicast mDNS query for any _http._tcp.local service.

        Returns the service name if found, empty string otherwise.
        """
        # Build a minimal DNS query for _http._tcp.local
        # Transaction ID: 0x0000, Flags: standard query, 1 question
        dns_header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        # QNAME: _http._tcp.local
        qname = (
            b"\x05_http\x04_tcp\x05local\x00"
        )
        # QTYPE: PTR (0x000C), QCLASS: IN (0x0001) with unicast bit
        question = qname + b"\x00\x0c\x80\x01"

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(dns_header + question, (host, 5353))
                data, _ = s.recvfrom(4096)
                if len(data) > 12:
                    # Simple extraction: look for printable service name
                    text = data[12:].decode("utf-8", errors="replace")
                    # Find sequences of printable chars
                    parts = re.findall(r"[\x20-\x7e]{4,}", text)
                    if parts:
                        return parts[0]
        except (OSError, socket.error, socket.timeout):
            pass
        return ""

    # ------------------------------------------------------------------
    # Vendor classification
    # ------------------------------------------------------------------

    def _classify_vendor(self, fp: SmartHomeFingerprint) -> str:
        blob = " ".join([
            fp.http_server, fp.ssdp_usn, fp.ssdp_server,
            fp.ssdp_location, fp.mdns_name,
            fp.raw_headers.get("_body_snippet", ""),
            fp.raw_headers.get("www-authenticate", ""),
        ]).lower()

        for vendor, keywords in _VENDOR_SIGNATURES.items():
            for kw in keywords:
                if kw in blob:
                    return vendor
        return "unknown"

    def _detect_device_type(self, fp: SmartHomeFingerprint) -> str:
        """Attempt to classify device type from fingerprint data."""
        blob = " ".join([
            fp.http_server, fp.ssdp_usn, fp.ssdp_server,
            fp.mdns_name,
            fp.raw_headers.get("_body_snippet", ""),
        ]).lower()

        type_keywords: dict[str, list[str]] = {
            "hub": ["bridge", "hub", "gateway", "controller", "coordinator"],
            "bulb": ["bulb", "light", "lamp", "led"],
            "plug": ["plug", "socket", "outlet", "switch"],
            "speaker": ["speaker", "media", "sonos", "chromecast", "echo"],
            "camera": ["camera", "cam", "ipcam", "webcam"],
            "thermostat": ["thermostat", "hvac", "nest", "ecobee"],
            "sensor": ["sensor", "motion", "temperature", "humidity"],
            "lock": ["lock", "deadbolt", "doorbell"],
        }

        for dtype, keywords in type_keywords.items():
            for kw in keywords:
                if kw in blob:
                    return dtype
        return "unknown"

    # ------------------------------------------------------------------
    # Full fingerprint pipeline
    # ------------------------------------------------------------------

    def _fingerprint_target(self, host: str,
                            ssdp_data: Optional[dict[str, str]] = None,
                            ) -> SmartHomeFingerprint:
        fp = SmartHomeFingerprint(target=host)

        # Port scan
        fp.open_ports = self._scan_ports(host)

        # Populate from SSDP data if available
        if ssdp_data:
            fp.ssdp_usn = ssdp_data.get("usn", "")
            fp.ssdp_server = ssdp_data.get("server", "")
            fp.ssdp_location = ssdp_data.get("location", "")

        # HTTP fingerprint
        http_probes: list[tuple[int, bool]] = [
            (80, False), (8080, False), (443, True), (8443, True),
        ]
        for port, ssl_flag in http_probes:
            if port not in fp.open_ports:
                continue
            hdrs = self._http_fingerprint(host, port, use_ssl=ssl_flag)
            if hdrs:
                fp.raw_headers.update(hdrs)
                fp.http_server = (
                    hdrs.get("server", fp.http_server) or fp.http_server
                )
                if fp.http_server:
                    break

        # MQTT probe
        if 1883 in fp.open_ports:
            fp.mqtt_open = self._mqtt_probe(host, 1883)
        elif 8883 in fp.open_ports:
            fp.mqtt_open = self._mqtt_probe(host, 8883)

        # mDNS
        if self.discover_mdns and 5353 in fp.open_ports:
            fp.mdns_name = self._mdns_probe(host)

        # Classify
        fp.vendor = self._classify_vendor(fp)
        fp.device_type = self._detect_device_type(fp)

        return fp

    # ------------------------------------------------------------------
    # Module prioritization
    # ------------------------------------------------------------------

    def _prioritize_modules(self, modules: list[Any],
                            vendor: str) -> list[Any]:
        if vendor == "unknown":
            return modules

        vendor_first: list[Any] = []
        others: list[Any] = []
        vendor_lower = vendor.lower().replace("_", "")

        for rec in modules:
            path_lower = rec.path.lower()
            name_lower = getattr(rec, "name", "").lower()
            vendors_lower = [v.lower() for v in getattr(rec, "vendors", [])]

            if (vendor_lower in path_lower
                    or vendor_lower in name_lower
                    or any(vendor_lower in v for v in vendors_lower)):
                vendor_first.append(rec)
            else:
                others.append(rec)

        return vendor_first + others

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> AutoPwnReport:
        """Discover smart home devices via SSDP, fingerprint, and run modules."""
        t0 = time.time()
        modules = self._get_modules()

        report = AutoPwnReport(
            segment=self.segment,
            targets=list(self.targets),
        )

        if self.verbose:
            print(f"\n[*] Smart Home AutoPwn  -  {len(modules)} modules, "
                  f"{len(self.targets)} target(s), "
                  f"mode={'check' if self.check_only else 'exploit'}")

        # Phase 0: SSDP discovery (find additional targets on the network)
        ssdp_map: dict[str, dict[str, str]] = {}
        if self.discover_ssdp:
            if self.verbose:
                print("[*] Sending SSDP M-SEARCH for device discovery ...")
            devices = self._ssdp_discover()
            for dev in devices:
                ip = dev.get("ip", "")
                if ip:
                    ssdp_map[ip] = dev
                    if ip not in self.targets:
                        self.discovered_targets.append(ip)
            if self.verbose:
                print(f"    SSDP found {len(devices)} device(s), "
                      f"{len(self.discovered_targets)} new target(s)")

        # Merge discovered targets with explicit targets
        all_targets = list(self.targets) + self.discovered_targets
        report.targets = all_targets

        for target in all_targets:
            # Phase 1: fingerprint
            if self.verbose:
                print(f"\n[*] Fingerprinting {target} ...")
            fp = self._fingerprint_target(target, ssdp_data=ssdp_map.get(target))
            self.fingerprints[target] = fp

            if self.verbose:
                print(f"    Vendor: {fp.vendor}  Type: {fp.device_type or 'n/a'}  "
                      f"Model: {fp.model or 'n/a'}")
                if fp.ssdp_server:
                    print(f"    SSDP:   {fp.ssdp_server}")
                if fp.mqtt_open:
                    print("    MQTT:   OPEN (unauthenticated broker)")
                if fp.open_ports:
                    print(f"    Ports:  {', '.join(str(p) for p in fp.open_ports)}")

            # Phase 2: prioritize and run modules
            ordered = self._prioritize_modules(modules, fp.vendor)

            for rec in ordered:
                try:
                    mod = importlib.import_module(rec.path)
                    cls = next(
                        (obj for _, obj in inspect.getmembers(mod, inspect.isclass)
                         if hasattr(obj, "check") or hasattr(obj, "run")),
                        None,
                    )
                    if not cls:
                        continue

                    inst = cls()
                    for attr in ("rhost", "host", "target", "ip"):
                        if hasattr(inst, attr):
                            setattr(inst, attr, target)
                            break

                    status = "not_vulnerable"
                    detail = ""

                    if self.check_only and hasattr(inst, "check"):
                        r = inst.check()
                        if r is True or (isinstance(r, dict) and r.get("vulnerable")):
                            status = "vulnerable"
                            detail = str(r) if isinstance(r, dict) else "check() returned True"
                    elif not self.check_only and hasattr(inst, "run"):
                        r = inst.run()
                        if isinstance(r, dict):
                            status = ("vulnerable"
                                      if r.get("success") or r.get("returncode") == 0
                                      else "not_vulnerable")
                            detail = str(r.get("stdout", ""))[:200]
                        else:
                            detail = str(r)[:200]
                    else:
                        status = "skipped"

                    report.results.append((rec.path, target, status, detail))
                    report.modules_run += 1
                    if status == "vulnerable":
                        report.modules_vulnerable += 1

                    if self.verbose:
                        icon = {"vulnerable": "[+]", "not_vulnerable": "[-]",
                                "error": "[!]", "skipped": "[~]"}.get(status, "[?]")
                        short = rec.path.split(".")[-1]
                        print(f"  {icon} {short:<50} {status}  {detail[:60]}")

                except Exception as exc:
                    report.results.append((rec.path, target, "error", str(exc)[:200]))
                    report.modules_run += 1
                    if self.verbose:
                        print(f"  [!] {rec.path.split('.')[-1]:<50} error  {exc}")

        report.elapsed_s = time.time() - t0
        if self.verbose:
            print(report.summary())
        return report
