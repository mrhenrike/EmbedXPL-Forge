"""EmbedXPL AutoPwn  -  Generic IoT segment.

Multi-protocol fingerprinting engine for unknown or mixed IoT environments.
Combines TCP banner grabs, HTTP fingerprinting, UPnP/SSDP, mDNS, MQTT,
and CoAP probes to classify device type. When a specific device class is
detected (camera, router, NAS, smart_home, voip), delegates to the
appropriate specialized AutoPwn class.

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
class IoTFingerprint:
    """Fingerprint result for a generic IoT target."""

    target: str
    device_class: str = "unknown"     # camera, router, nas, smart_home, voip, industrial, printer, unknown
    vendor: str = "unknown"
    model: str = ""
    firmware: str = ""
    http_server: str = ""
    http_powered_by: str = ""
    ssdp_server: str = ""
    ssdp_usn: str = ""
    mdns_name: str = ""
    mqtt_open: bool = False
    coap_responds: bool = False
    banners: dict[int, str] = field(default_factory=dict)
    open_ports: list[int] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        parts = [f"class={self.device_class}"]
        if self.vendor != "unknown":
            parts.append(f"vendor={self.vendor}")
        if self.model:
            parts.append(f"model={self.model}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Device class signatures
# ---------------------------------------------------------------------------

_CLASS_SIGNATURES: dict[str, list[str]] = {
    "camera": [
        "ipcam", "webcam", "hikvision", "dahua", "axis", "foscam",
        "amcrest", "reolink", "onvif", "rtsp", "vivotek",
        "camera", "dvr", "nvr", "cctv",
    ],
    "router": [
        "router", "gateway", "dlink", "d-link", "tp-link", "tplink",
        "netgear", "asus", "linksys", "mikrotik", "routeros",
        "ubiquiti", "openwrt", "dd-wrt", "tomato",
    ],
    "nas": [
        "qnap", "synology", "diskstation", "readynas", "mycloud",
        "my cloud", "western digital", "wd ", "terramaster",
        "nas", "qts", "dsm",
    ],
    "smart_home": [
        "hue", "smartthings", "tuya", "smart life", "wemo",
        "ikea", "tradfri", "homeassistant", "home assistant",
        "hubitat", "zigbee", "z-wave",
    ],
    "voip": [
        "sip", "voip", "polycom", "yealink", "grandstream",
        "avaya", "cisco spa", "cisco cp", "snom", "fanvil",
        "audiocodes", "pbx", "asterisk", "freepbx",
    ],
    "industrial": [
        "plc", "scada", "modbus", "s7comm", "dnp3",
        "bacnet", "siemens", "allen-bradley", "rockwell",
        "schneider", "ics", "hmi", "rtu",
    ],
    "printer": [
        "printer", "jetdirect", "brother", "canon", "epson",
        "hp laserjet", "xerox", "lexmark", "ipp", "cups",
        "pjl", "pcl",
    ],
}

# Broad port set for IoT fingerprinting
_IOT_PORTS = [
    21, 22, 23, 25, 53, 80, 102, 161, 443, 502, 554, 631,
    1883, 1900, 2000, 2049, 4840, 5060, 5353, 5683, 6668,
    8080, 8443, 8883, 9090, 9100, 44818, 47808,
]

# Port-to-class hints (not definitive; combined with other evidence)
_PORT_CLASS_HINTS: dict[int, str] = {
    554:   "camera",       # RTSP
    9100:  "printer",      # JetDirect/RAW
    631:   "printer",      # IPP/CUPS
    502:   "industrial",   # Modbus
    102:   "industrial",   # S7comm
    44818: "industrial",   # EtherNet/IP
    47808: "industrial",   # BACnet
    4840:  "industrial",   # OPC UA
    5060:  "voip",         # SIP
    1883:  "smart_home",   # MQTT
    5353:  "smart_home",   # mDNS
}


# ---------------------------------------------------------------------------
# IoTGenericAutoPwn
# ---------------------------------------------------------------------------

class IoTGenericAutoPwn(SegmentAutoPwn):
    """Generic IoT AutoPwn with multi-protocol fingerprinting and delegation.

    When a specific device class is identified, delegates to:
      - NASAutoPwn        for NAS devices
      - VoIPAutoPwn       for VoIP/telephony
      - SmartHomeAutoPwn  for smart home hubs/devices
      - CameraAutoPwn     for IP cameras
      - RouterAutoPwn     for routers

    Falls back to running generic IoT modules for unclassified targets.

    Args:
        targets:         IP/hostname or list of IPs.
        check_only:      If True, only run check() on modules.
        verbose:         Print progress to stdout.
        http_timeout:    HTTP probe timeout.
        banner_timeout:  TCP banner grab timeout.
        ssdp_timeout:    SSDP M-SEARCH timeout.
        delegate:        If True, delegate to specialized AutoPwn when possible.
    """

    # Maps device_class to specialized AutoPwn (module_path, class_name)
    _DELEGATE_MAP: dict[str, tuple[str, str]] = {
        "nas":        ("embedxpl.modules.autopwn.nas", "NASAutoPwn"),
        "voip":       ("embedxpl.modules.autopwn.voip", "VoIPAutoPwn"),
        "smart_home": ("embedxpl.modules.autopwn.smart_home", "SmartHomeAutoPwn"),
        "camera":     ("embedxpl.modules.autopwn.camera", "CameraAutoPwn"),
        "router":     ("embedxpl.modules.autopwn.router", "RouterAutoPwn"),
        "printer":    ("embedxpl.modules.autopwn.printer", "PrinterAutoPwn"),
        "firewall":   ("embedxpl.modules.autopwn.firewall", "FirewallAutoPwn"),
    }

    def __init__(
        self,
        targets: str | list[str],
        check_only: bool = True,
        verbose: bool = True,
        http_timeout: int = 5,
        banner_timeout: int = 3,
        ssdp_timeout: int = 4,
        delegate: bool = True,
        **kw: Any,
    ) -> None:
        super().__init__(segment="iot", targets=targets,
                         check_only=check_only, verbose=verbose, **kw)
        self.http_timeout = http_timeout
        self.banner_timeout = banner_timeout
        self.ssdp_timeout = ssdp_timeout
        self.delegate = delegate
        self.fingerprints: dict[str, IoTFingerprint] = {}

    # ------------------------------------------------------------------
    # TCP helpers
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
        for port in _IOT_PORTS:
            if self._tcp_port_open(host, port):
                open_ports.append(port)
        return open_ports

    # ------------------------------------------------------------------
    # TCP banner grabbing
    # ------------------------------------------------------------------

    def _banner_grab(self, host: str, port: int) -> str:
        """Connect to a TCP port and read whatever the service sends."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.banner_timeout)
                s.connect((host, port))
                # Some services need a nudge
                if port in (80, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
                elif port == 21:
                    pass  # FTP sends banner on connect
                elif port == 23:
                    pass  # Telnet sends banner on connect
                elif port == 25:
                    pass  # SMTP sends banner on connect
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()
        except (OSError, socket.error, socket.timeout):
            return ""

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
    # SSDP M-SEARCH (unicast to specific target)
    # ------------------------------------------------------------------

    def _ssdp_unicast_probe(self, host: str) -> dict[str, str]:
        """Send a unicast SSDP M-SEARCH to a specific host and parse response."""
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {host}:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("utf-8")

        headers: dict[str, str] = {}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.ssdp_timeout)
                s.sendto(msearch, (host, 1900))
                data, _ = s.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                for line in text.split("\r\n"):
                    if ":" in line:
                        key, _, val = line.partition(":")
                        key_lower = key.strip().lower()
                        if key_lower in ("usn", "server", "location", "st"):
                            headers[key_lower] = val.strip()
        except (OSError, socket.timeout, socket.error):
            pass
        return headers

    # ------------------------------------------------------------------
    # mDNS probe
    # ------------------------------------------------------------------

    def _mdns_probe(self, host: str) -> str:
        """Unicast mDNS query for _http._tcp.local service name."""
        dns_header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b"\x05_http\x04_tcp\x05local\x00"
        question = qname + b"\x00\x0c\x80\x01"  # PTR, unicast

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(dns_header + question, (host, 5353))
                data, _ = s.recvfrom(4096)
                if len(data) > 12:
                    text = data[12:].decode("utf-8", errors="replace")
                    parts = re.findall(r"[\x20-\x7e]{4,}", text)
                    if parts:
                        return parts[0]
        except (OSError, socket.error, socket.timeout):
            pass
        return ""

    # ------------------------------------------------------------------
    # MQTT probe
    # ------------------------------------------------------------------

    def _mqtt_probe(self, host: str, port: int = 1883) -> bool:
        """Attempt minimal MQTT CONNECT and check for CONNACK."""
        client_id = b"embedxpl"
        proto_name = b"\x00\x04MQTT"
        proto_level = b"\x04"
        connect_flags = b"\x02"
        keep_alive = b"\x00\x3c"
        client_id_enc = struct.pack("!H", len(client_id)) + client_id
        payload = proto_name + proto_level + connect_flags + keep_alive + client_id_enc
        fixed_header = bytes([0x10]) + bytes([len(payload) & 0x7F])

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3.0)
                s.connect((host, port))
                s.sendall(fixed_header + payload)
                resp = s.recv(4)
                if resp and resp[0] == 0x20:
                    return True
        except (OSError, socket.error, socket.timeout):
            pass
        return False

    # ------------------------------------------------------------------
    # CoAP probe (confirmable GET /.well-known/core)
    # ------------------------------------------------------------------

    def _coap_probe(self, host: str, port: int = 5683) -> bool:
        """Send a CoAP GET /.well-known/core and check for a response.

        CoAP header: Ver=1, Type=CON(0), TKL=1, Code=GET(0.01), MsgID=0x0001
        """
        # Version 1, Type CON (0), Token Length 1
        header = bytes([0x41])
        # Code 0.01 (GET)
        code = bytes([0x01])
        # Message ID
        msg_id = bytes([0x00, 0x01])
        # Token (1 byte)
        token = bytes([0xAB])
        # Option: Uri-Path ".well-known" (option delta 11, length 11)
        opt1 = bytes([0xBB]) + b".well-known"
        # Option: Uri-Path "core" (option delta 0, length 4)
        opt2 = bytes([0x04]) + b"core"

        packet = header + code + msg_id + token + opt1 + opt2

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(3.0)
                s.sendto(packet, (host, port))
                data, _ = s.recvfrom(4096)
                # Any response with CoAP version 1 (top 2 bits = 01)
                if data and (data[0] >> 6) == 1:
                    return True
        except (OSError, socket.error, socket.timeout):
            pass
        return False

    # ------------------------------------------------------------------
    # Device classification
    # ------------------------------------------------------------------

    def _classify_device(self, fp: IoTFingerprint) -> str:
        """Classify device type from all collected evidence."""
        # Build evidence blob
        blob_parts = [
            fp.http_server, fp.http_powered_by,
            fp.ssdp_server, fp.ssdp_usn, fp.mdns_name,
            fp.raw_headers.get("_body_snippet", ""),
        ]
        for banner in fp.banners.values():
            blob_parts.append(banner)
        blob = " ".join(blob_parts).lower()

        # Score each class
        scores: dict[str, int] = {}
        for device_class, keywords in _CLASS_SIGNATURES.items():
            score = 0
            for kw in keywords:
                if kw in blob:
                    score += 1
            if score > 0:
                scores[device_class] = score

        # Add port-based hints
        for port in fp.open_ports:
            hint = _PORT_CLASS_HINTS.get(port)
            if hint:
                scores[hint] = scores.get(hint, 0) + 1

        # Protocol-based hints
        if fp.mqtt_open:
            scores["smart_home"] = scores.get("smart_home", 0) + 2
        if fp.coap_responds:
            scores["industrial"] = scores.get("industrial", 0) + 1

        if not scores:
            return "unknown"

        # Return highest scoring class
        best = max(scores, key=lambda k: scores[k])
        return best

    def _extract_vendor(self, fp: IoTFingerprint) -> str:
        """Try to identify vendor from banner and header data."""
        blob = " ".join([
            fp.http_server, fp.http_powered_by,
            fp.ssdp_server, fp.ssdp_usn, fp.mdns_name,
        ] + list(fp.banners.values())).lower()

        # Common vendor keywords
        vendor_map: dict[str, list[str]] = {
            "hikvision": ["hikvision"],
            "dahua": ["dahua"],
            "dlink": ["d-link", "dlink", "dir-"],
            "tplink": ["tp-link", "tplink"],
            "netgear": ["netgear"],
            "cisco": ["cisco"],
            "qnap": ["qnap"],
            "synology": ["synology", "diskstation"],
            "ubiquiti": ["ubiquiti", "ubnt", "unifi"],
            "mikrotik": ["mikrotik", "routeros"],
            "huawei": ["huawei"],
            "zte": ["zte"],
            "philips": ["philips", "hue"],
            "tuya": ["tuya"],
            "xiaomi": ["xiaomi", "yeelight"],
        }

        for vendor, keywords in vendor_map.items():
            for kw in keywords:
                if kw in blob:
                    return vendor
        return "unknown"

    # ------------------------------------------------------------------
    # Full fingerprint pipeline
    # ------------------------------------------------------------------

    def _fingerprint_target(self, host: str) -> IoTFingerprint:
        fp = IoTFingerprint(target=host)

        # Phase 1: port scan
        fp.open_ports = self._scan_ports(host)

        # Phase 2: TCP banner grabs on interesting ports
        banner_ports = [p for p in fp.open_ports if p in (21, 22, 23, 25, 554, 9100)]
        for port in banner_ports:
            banner = self._banner_grab(host, port)
            if banner:
                fp.banners[port] = banner[:512]

        # Phase 3: HTTP fingerprinting
        http_probes: list[tuple[int, bool]] = [
            (80, False), (8080, False), (9090, False),
            (443, True), (8443, True),
        ]
        for port, ssl_flag in http_probes:
            if port not in fp.open_ports:
                continue
            hdrs = self._http_fingerprint(host, port, use_ssl=ssl_flag)
            if hdrs:
                fp.raw_headers.update(hdrs)
                fp.http_server = hdrs.get("server", fp.http_server) or fp.http_server
                fp.http_powered_by = (
                    hdrs.get("x-powered-by", fp.http_powered_by)
                    or fp.http_powered_by
                )
                if fp.http_server:
                    break

        # Phase 4: SSDP unicast probe
        if 1900 in fp.open_ports or not fp.open_ports:
            ssdp = self._ssdp_unicast_probe(host)
            fp.ssdp_server = ssdp.get("server", "")
            fp.ssdp_usn = ssdp.get("usn", "")

        # Phase 5: mDNS
        if 5353 in fp.open_ports:
            fp.mdns_name = self._mdns_probe(host)

        # Phase 6: MQTT
        if 1883 in fp.open_ports:
            fp.mqtt_open = self._mqtt_probe(host, 1883)
        elif 8883 in fp.open_ports:
            fp.mqtt_open = self._mqtt_probe(host, 8883)

        # Phase 7: CoAP
        if 5683 in fp.open_ports:
            fp.coap_responds = self._coap_probe(host)

        # Classify
        fp.device_class = self._classify_device(fp)
        fp.vendor = self._extract_vendor(fp)

        return fp

    # ------------------------------------------------------------------
    # Delegation to specialized AutoPwn
    # ------------------------------------------------------------------

    def _delegate_to_specialist(
        self,
        device_class: str,
        target: str,
    ) -> Optional[AutoPwnReport]:
        """Import and run a specialized AutoPwn for the detected class.

        Returns the specialist's report, or None if delegation is not
        possible or the class has no specialist.
        """
        entry = self._DELEGATE_MAP.get(device_class)
        if not entry:
            return None

        mod_path, cls_name = entry
        try:
            mod = importlib.import_module(mod_path)
            specialist_cls = getattr(mod, cls_name)
            specialist = specialist_cls(
                targets=target,
                check_only=self.check_only,
                verbose=self.verbose,
            )
            return specialist.run()
        except Exception as exc:
            if self.verbose:
                print(f"  [!] Delegation to {cls_name} failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Run generic modules
    # ------------------------------------------------------------------

    def _run_generic_modules(self, target: str, modules: list[Any],
                             report: AutoPwnReport) -> None:
        """Run IoT modules against a target (no delegation)."""
        for rec in modules:
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

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> AutoPwnReport:
        """Multi-protocol IoT fingerprinting with automatic delegation."""
        t0 = time.time()
        modules = self._get_modules()

        report = AutoPwnReport(
            segment=self.segment,
            targets=list(self.targets),
        )

        if self.verbose:
            print(f"\n[*] IoT Generic AutoPwn  -  {len(modules)} modules, "
                  f"{len(self.targets)} target(s), "
                  f"mode={'check' if self.check_only else 'exploit'}")
            if self.delegate:
                print("[*] Delegation enabled: detected devices will be "
                      "forwarded to specialized AutoPwn engines")

        for target in self.targets:
            # Phase 1: multi-protocol fingerprint
            if self.verbose:
                print(f"\n[*] Fingerprinting {target} ...")
            fp = self._fingerprint_target(target)
            self.fingerprints[target] = fp

            if self.verbose:
                print(f"    Class:  {fp.device_class}")
                print(f"    Vendor: {fp.vendor}")
                if fp.http_server:
                    print(f"    HTTP:   {fp.http_server}")
                if fp.ssdp_server:
                    print(f"    SSDP:   {fp.ssdp_server}")
                if fp.mdns_name:
                    print(f"    mDNS:   {fp.mdns_name}")
                if fp.mqtt_open:
                    print("    MQTT:   OPEN")
                if fp.coap_responds:
                    print("    CoAP:   responds")
                if fp.banners:
                    for port, banner in fp.banners.items():
                        print(f"    Banner[{port}]: {banner[:60]}")
                if fp.open_ports:
                    print(f"    Ports:  {', '.join(str(p) for p in fp.open_ports)}")

            # Phase 2: delegate or run generic
            delegated = False
            if (self.delegate
                    and fp.device_class != "unknown"
                    and fp.device_class in self._DELEGATE_MAP):
                if self.verbose:
                    print(f"\n[*] Delegating {target} to "
                          f"{fp.device_class.upper()} AutoPwn ...")
                sub_report = self._delegate_to_specialist(fp.device_class, target)
                if sub_report is not None:
                    # Merge sub-report results into our report
                    report.results.extend(sub_report.results)
                    report.modules_run += sub_report.modules_run
                    report.modules_vulnerable += sub_report.modules_vulnerable
                    delegated = True

            if not delegated:
                # Run generic IoT modules
                if self.verbose and fp.device_class != "unknown":
                    print(f"[*] Running generic IoT modules for {target} "
                          f"(class: {fp.device_class})")
                self._run_generic_modules(target, modules, report)

        report.elapsed_s = time.time() - t0
        if self.verbose:
            print(report.summary())
        return report
