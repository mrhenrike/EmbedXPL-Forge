"""EmbedXPL AutoPwn  -  NAS segment.

Automated fingerprinting and exploitation of NAS devices (QNAP, Synology,
Western Digital, Netgear ReadyNAS). Identifies vendor and model via HTTP
headers and SNMP sysDescr, then runs matching exploit modules prioritized
by detected vendor.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
# authorized use only
"""
from __future__ import annotations

import http.client
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from embedxpl.modules.autopwn.base import AutoPwnReport, SegmentAutoPwn


# ---------------------------------------------------------------------------
# Fingerprint result
# ---------------------------------------------------------------------------

@dataclass
class NASFingerprint:
    """Fingerprint result for a single NAS target."""

    target: str
    vendor: str = "unknown"
    model: str = ""
    firmware: str = ""
    http_server: str = ""
    http_powered_by: str = ""
    snmp_sysdescr: str = ""
    open_ports: list[int] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)

    def summary_line(self) -> str:
        parts = [self.vendor.upper()]
        if self.model:
            parts.append(self.model)
        if self.firmware:
            parts.append(f"fw={self.firmware}")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# Vendor signatures for header matching
# ---------------------------------------------------------------------------

_VENDOR_SIGNATURES: dict[str, list[str]] = {
    "qnap": [
        "qnap", "qts", "quts", "qumagic", "photostation",
        "myqnapcloud", "qsync",
    ],
    "synology": [
        "synology", "diskstation", "dsm", "rackstation",
        "synologynas", "webstation",
    ],
    "western_digital": [
        "wd ", "western digital", "my cloud", "mycloud",
        "wdmycloud", "wd my cloud", "my book",
    ],
    "netgear": [
        "netgear", "readynas", "ready nas", "readycloud",
    ],
    "asustor": [
        "asustor", "adm",
    ],
    "terramaster": [
        "terramaster", "tos",
    ],
    "buffalo": [
        "buffalo", "linkstation", "terastation",
    ],
    "drobo": [
        "drobo",
    ],
}

# NAS-common ports: HTTP, HTTPS, admin alt, SMB, NFS, SSH, SNMP, AFP
_NAS_PORTS = [80, 443, 8080, 8443, 445, 2049, 22, 161, 548, 5000, 5001, 9090]


# ---------------------------------------------------------------------------
# NASAutoPwn
# ---------------------------------------------------------------------------

class NASAutoPwn(SegmentAutoPwn):
    """AutoPwn for NAS devices with vendor-aware fingerprinting.

    Probes each target via HTTP headers and SNMP sysDescr to identify the
    vendor and model, then runs applicable exploit modules sorted so that
    vendor-specific modules execute first.

    Args:
        targets:       IP/hostname or list of IPs/hostnames.
        check_only:    If True, run check() only (no exploitation).
        verbose:       Print progress to stdout.
        http_timeout:  Timeout in seconds for HTTP fingerprint probes.
        snmp_timeout:  Timeout in seconds for SNMP sysDescr probes.
        snmp_community: SNMP v1/v2c community string for probing.
        scan_ports:    If True, do a quick TCP port scan on each target.
    """

    def __init__(
        self,
        targets: str | list[str],
        check_only: bool = True,
        verbose: bool = True,
        http_timeout: int = 5,
        snmp_timeout: int = 3,
        snmp_community: str = "public",
        scan_ports: bool = True,
        **kw: Any,
    ) -> None:
        super().__init__(segment="nas", targets=targets, check_only=check_only,
                         verbose=verbose, **kw)
        self.http_timeout = http_timeout
        self.snmp_timeout = snmp_timeout
        self.snmp_community = snmp_community
        self.scan_ports = scan_ports
        self.fingerprints: dict[str, NASFingerprint] = {}

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    def _tcp_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Quick TCP connect check on a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except (OSError, socket.error):
            return False

    def _scan_ports(self, host: str) -> list[int]:
        """Scan NAS-common ports and return those that are open."""
        open_ports: list[int] = []
        for port in _NAS_PORTS:
            if self._tcp_port_open(host, port):
                open_ports.append(port)
        return open_ports

    # ------------------------------------------------------------------
    # HTTP fingerprinting
    # ------------------------------------------------------------------

    def _http_fingerprint(self, host: str, port: int = 80,
                          use_ssl: bool = False) -> dict[str, str]:
        """Send HTTP GET / and extract response headers for fingerprinting."""
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
            # Also store a snippet of the body for further fingerprinting
            body = resp.read(4096).decode("utf-8", errors="replace")
            headers["_body_snippet"] = body[:2048]
            conn.close()
        except Exception:
            pass
        return headers

    # ------------------------------------------------------------------
    # SNMP sysDescr probe (v1/v2c GET, OID 1.3.6.1.2.1.1.1.0)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_snmp_get_request(community: str) -> bytes:
        """Build a minimal SNMPv2c GET request for sysDescr.0.

        OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        """

        def _encode_length(length: int) -> bytes:
            if length < 0x80:
                return bytes([length])
            if length < 0x100:
                return bytes([0x81, length])
            return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

        def _encode_int(value: int) -> bytes:
            payload = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
            return b"\x02" + _encode_length(len(payload)) + payload

        def _encode_str(value: str) -> bytes:
            encoded = value.encode("ascii")
            return b"\x04" + _encode_length(len(encoded)) + encoded

        def _encode_oid() -> bytes:
            # sysDescr: 1.3.6.1.2.1.1.1.0
            oid_bytes = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            return b"\x06" + _encode_length(len(oid_bytes)) + oid_bytes

        # Varbind: OID + NULL value
        oid_enc = _encode_oid()
        null_val = b"\x05\x00"
        varbind = b"\x30" + _encode_length(len(oid_enc) + len(null_val)) + oid_enc + null_val

        # VarbindList
        varbind_list = b"\x30" + _encode_length(len(varbind)) + varbind

        # PDU: GetRequest (0xA0), request-id=1, error-status=0, error-index=0
        req_id = _encode_int(1)
        err_status = _encode_int(0)
        err_index = _encode_int(0)
        pdu_payload = req_id + err_status + err_index + varbind_list
        pdu = b"\xa0" + _encode_length(len(pdu_payload)) + pdu_payload

        # Message: version (1 = SNMPv2c) + community + PDU
        version = _encode_int(1)
        community_enc = _encode_str(community)
        msg_payload = version + community_enc + pdu
        message = b"\x30" + _encode_length(len(msg_payload)) + msg_payload
        return message

    @staticmethod
    def _parse_snmp_response(data: bytes) -> str:
        """Extract the sysDescr string value from an SNMP GET-Response.

        Returns the decoded string, or empty on parse failure.
        """

        def _read_length(buf: bytes, offset: int) -> tuple[int, int]:
            if offset >= len(buf):
                return 0, offset
            b = buf[offset]
            if b < 0x80:
                return b, offset + 1
            num_bytes = b & 0x7F
            if num_bytes == 0 or offset + 1 + num_bytes > len(buf):
                return 0, offset + 1
            length = int.from_bytes(buf[offset + 1: offset + 1 + num_bytes], "big")
            return length, offset + 1 + num_bytes

        try:
            # Walk through ASN.1 to find the first OctetString (0x04) value
            # in the varbind response.
            idx = 0
            while idx < len(data) - 2:
                if data[idx] == 0x04:
                    length, start = _read_length(data, idx + 1)
                    if length > 0 and start + length <= len(data):
                        # Skip community string (first 0x04); sysDescr is a later one
                        candidate = data[start: start + length].decode(
                            "utf-8", errors="replace",
                        )
                        # Community is usually short; sysDescr is longer
                        if len(candidate) > 8:
                            return candidate
                idx += 1
        except Exception:
            pass
        return ""

    def _snmp_sysdescr(self, host: str, port: int = 161) -> str:
        """Query SNMP sysDescr.0 via UDP, return the value string."""
        try:
            pkt = self._build_snmp_get_request(self.snmp_community)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.snmp_timeout)
                s.sendto(pkt, (host, port))
                data, _ = s.recvfrom(4096)
                return self._parse_snmp_response(data)
        except (OSError, socket.timeout, socket.error):
            return ""

    # ------------------------------------------------------------------
    # Vendor classification
    # ------------------------------------------------------------------

    def _classify_vendor(self, fp: NASFingerprint) -> str:
        """Determine vendor from collected fingerprint data."""
        # Combine all textual evidence into a single searchable blob
        blob = " ".join([
            fp.http_server,
            fp.http_powered_by,
            fp.snmp_sysdescr,
            fp.raw_headers.get("_body_snippet", ""),
            fp.raw_headers.get("www-authenticate", ""),
            fp.raw_headers.get("set-cookie", ""),
        ]).lower()

        for vendor, keywords in _VENDOR_SIGNATURES.items():
            for kw in keywords:
                if kw in blob:
                    return vendor
        return "unknown"

    def _extract_model_firmware(self, fp: NASFingerprint) -> None:
        """Try to extract model and firmware from fingerprint data."""
        import re

        blob = " ".join([
            fp.http_server, fp.http_powered_by, fp.snmp_sysdescr,
            fp.raw_headers.get("_body_snippet", ""),
        ])

        # QNAP: QTS x.y.z, model TS-xxx
        m = re.search(r"(TS-\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1)
        m = re.search(r"QTS\s*([\d.]+)", blob, re.I)
        if m:
            fp.firmware = f"QTS {m.group(1)}"
            return

        # Synology: DSM x.y, model DS/RS
        m = re.search(r"((?:DS|RS)\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1)
        m = re.search(r"DSM\s*([\d.]+)", blob, re.I)
        if m:
            fp.firmware = f"DSM {m.group(1)}"
            return

        # WD My Cloud
        m = re.search(r"(My\s*Cloud\s*\w+)", blob, re.I)
        if m:
            fp.model = m.group(1).strip()

        # Netgear ReadyNAS
        m = re.search(r"(ReadyNAS\s*\w+)", blob, re.I)
        if m:
            fp.model = m.group(1).strip()

        # Generic firmware version
        m = re.search(r"(?:firmware|version|fw)[:\s]*([\d.]+)", blob, re.I)
        if m:
            fp.firmware = m.group(1)

    # ------------------------------------------------------------------
    # Full fingerprint pipeline
    # ------------------------------------------------------------------

    def _fingerprint_target(self, host: str) -> NASFingerprint:
        """Run HTTP + SNMP fingerprinting on a single target."""
        fp = NASFingerprint(target=host)

        # Port scan
        if self.scan_ports:
            fp.open_ports = self._scan_ports(host)

        # HTTP fingerprint: try port 80, then 8080, then 443/8443 with SSL
        http_probes: list[tuple[int, bool]] = [
            (80, False), (8080, False), (5000, False),
            (443, True), (8443, True), (5001, True),
        ]
        for port, ssl_flag in http_probes:
            if self.scan_ports and port not in fp.open_ports:
                continue
            hdrs = self._http_fingerprint(host, port, use_ssl=ssl_flag)
            if hdrs:
                fp.raw_headers.update(hdrs)
                fp.http_server = hdrs.get("server", fp.http_server) or fp.http_server
                fp.http_powered_by = (
                    hdrs.get("x-powered-by", fp.http_powered_by)
                    or fp.http_powered_by
                )
                if fp.http_server or fp.http_powered_by:
                    break

        # SNMP sysDescr
        fp.snmp_sysdescr = self._snmp_sysdescr(host)

        # Classify
        fp.vendor = self._classify_vendor(fp)
        self._extract_model_firmware(fp)

        return fp

    # ------------------------------------------------------------------
    # Module prioritization
    # ------------------------------------------------------------------

    def _prioritize_modules(
        self,
        modules: list[Any],
        vendor: str,
    ) -> list[Any]:
        """Sort modules so vendor-specific ones run first."""
        if vendor == "unknown":
            return modules

        vendor_first: list[Any] = []
        others: list[Any] = []
        vendor_lower = vendor.lower().replace("_", "")

        for rec in modules:
            path_lower = rec.path.lower()
            vendors_lower = [v.lower() for v in getattr(rec, "vendors", [])]
            name_lower = getattr(rec, "name", "").lower()

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
        """Fingerprint NAS targets, prioritize by vendor, run exploit modules."""
        t0 = time.time()
        modules = self._get_modules()

        report = AutoPwnReport(
            segment=self.segment,
            targets=self.targets,
        )

        if self.verbose:
            print(f"\n[*] NAS AutoPwn  -  {len(modules)} modules, "
                  f"{len(self.targets)} target(s), "
                  f"mode={'check' if self.check_only else 'exploit'}")

        for target in self.targets:
            # Phase 1: fingerprint
            if self.verbose:
                print(f"\n[*] Fingerprinting {target} ...")
            fp = self._fingerprint_target(target)
            self.fingerprints[target] = fp

            if self.verbose:
                print(f"    Vendor: {fp.vendor}  Model: {fp.model or 'n/a'}  "
                      f"FW: {fp.firmware or 'n/a'}")
                if fp.http_server:
                    print(f"    Server: {fp.http_server}")
                if fp.snmp_sysdescr:
                    print(f"    SNMP:   {fp.snmp_sysdescr[:80]}")
                if fp.open_ports:
                    print(f"    Ports:  {', '.join(str(p) for p in fp.open_ports)}")

            # Phase 2: prioritize modules by vendor
            ordered = self._prioritize_modules(modules, fp.vendor)

            # Phase 3: run modules
            import importlib
            import inspect

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
