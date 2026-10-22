"""EmbedXPL AutoPwn  -  VoIP segment.

Automated fingerprinting and exploitation of VoIP/IP telephony devices
(Cisco, Polycom, Yealink, Grandstream, Avaya, Mitel, Fanvil, Snom).
Probes targets via SIP OPTIONS, SNMP sysDescr, and HTTP admin interfaces
to identify vendor and model before running exploit modules.

Author: Andre Henrique (LinkedIn/X: @mrhenrike)
# authorized use only
"""
from __future__ import annotations

import http.client
import importlib
import inspect
import random
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from embedxpl.modules.autopwn.base import AutoPwnReport, SegmentAutoPwn


# ---------------------------------------------------------------------------
# Fingerprint dataclass
# ---------------------------------------------------------------------------

@dataclass
class VoIPFingerprint:
    """Fingerprint result for a single VoIP target."""

    target: str
    vendor: str = "unknown"
    model: str = ""
    firmware: str = ""
    sip_user_agent: str = ""
    sip_server: str = ""
    sip_allow: str = ""
    snmp_sysdescr: str = ""
    http_server: str = ""
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
# Vendor signatures
# ---------------------------------------------------------------------------

_VENDOR_SIGNATURES: dict[str, list[str]] = {
    "cisco": [
        "cisco", "spa", "cp-", "cucm", "callmanager",
        "unified", "webex", "ata18",
    ],
    "polycom": [
        "polycom", "poly", "soundpoint", "soundstation",
        "vvx", "trio", "realpresence",
    ],
    "yealink": [
        "yealink", "sip-t", "sip t",
    ],
    "grandstream": [
        "grandstream", "gxp", "gxv", "grp", "ht8",
        "ucm", "gwn",
    ],
    "avaya": [
        "avaya", "aura", "ip office", "j1", "b1",
        "one-x",
    ],
    "mitel": [
        "mitel", "aastra", "mivo",
    ],
    "fanvil": [
        "fanvil",
    ],
    "snom": [
        "snom",
    ],
    "audiocodes": [
        "audiocodes", "mediant",
    ],
    "panasonic": [
        "panasonic", "kx-",
    ],
    "linphone": [
        "linphone",
    ],
    "asterisk": [
        "asterisk", "fpbx", "freepbx", "sangoma",
    ],
}

# Common VoIP ports: SIP, SIP-TLS, HTTP, HTTPS, SNMP, SCCP, RTP
_VOIP_PORTS = [80, 443, 161, 2000, 5060, 5061, 8080, 8443]


# ---------------------------------------------------------------------------
# VoIPAutoPwn
# ---------------------------------------------------------------------------

class VoIPAutoPwn(SegmentAutoPwn):
    """AutoPwn for VoIP/IP telephony devices with SIP fingerprinting.

    Discovery and fingerprinting:
      1. SIP OPTIONS probe via UDP to target:5060
      2. SNMP sysDescr query
      3. HTTP admin interface fingerprinting

    Args:
        targets:         IP/hostname or list of IPs/hostnames.
        check_only:      If True, only run check() on modules.
        verbose:         Print progress to stdout.
        sip_timeout:     Timeout in seconds for SIP probes.
        http_timeout:    Timeout in seconds for HTTP probes.
        snmp_timeout:    Timeout in seconds for SNMP probes.
        snmp_community:  SNMP v2c community string.
        sip_port:        SIP port to probe (default 5060).
    """

    def __init__(
        self,
        targets: str | list[str],
        check_only: bool = True,
        verbose: bool = True,
        sip_timeout: int = 4,
        http_timeout: int = 5,
        snmp_timeout: int = 3,
        snmp_community: str = "public",
        sip_port: int = 5060,
        **kw: Any,
    ) -> None:
        super().__init__(segment="voip", targets=targets,
                         check_only=check_only, verbose=verbose, **kw)
        self.sip_timeout = sip_timeout
        self.http_timeout = http_timeout
        self.snmp_timeout = snmp_timeout
        self.snmp_community = snmp_community
        self.sip_port = sip_port
        self.fingerprints: dict[str, VoIPFingerprint] = {}

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
        for port in _VOIP_PORTS:
            if self._tcp_port_open(host, port):
                open_ports.append(port)
        return open_ports

    # ------------------------------------------------------------------
    # SIP OPTIONS fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_branch() -> str:
        """Generate a SIP Via branch parameter (RFC 3261 magic cookie)."""
        rand_hex = "".join(f"{random.randint(0, 255):02x}" for _ in range(8))
        return f"z9hG4bK{rand_hex}"

    @staticmethod
    def _generate_call_id() -> str:
        rand_hex = "".join(f"{random.randint(0, 255):02x}" for _ in range(12))
        return f"{rand_hex}@embedxpl"

    @staticmethod
    def _generate_tag() -> str:
        return "".join(f"{random.randint(0, 255):02x}" for _ in range(6))

    def _build_sip_options(self, target: str, port: int) -> bytes:
        """Build a SIP OPTIONS request for fingerprinting."""
        branch = self._generate_branch()
        call_id = self._generate_call_id()
        tag = self._generate_tag()

        # Use a non-routable local address as the contact; this is a probe only
        local_ip = "0.0.0.0"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, port))
                local_ip = s.getsockname()[0]
        except (OSError, socket.error):
            pass

        lines = [
            f"OPTIONS sip:{target}:{port} SIP/2.0",
            f"Via: SIP/2.0/UDP {local_ip}:5060;branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:probe@{local_ip}>;tag={tag}",
            f"To: <sip:{target}:{port}>",
            f"Call-ID: {call_id}",
            "CSeq: 1 OPTIONS",
            f"Contact: <sip:probe@{local_ip}:5060>",
            "Accept: application/sdp",
            "Content-Length: 0",
            "User-Agent: EmbedXPL/1.0",
            "",
            "",
        ]
        return "\r\n".join(lines).encode("utf-8")

    def _sip_options_probe(self, host: str, port: int = 5060,
                           ) -> dict[str, str]:
        """Send SIP OPTIONS via UDP and parse the response headers.

        Returns a dict of SIP response headers (lowercase keys).
        """
        headers: dict[str, str] = {}
        try:
            pkt = self._build_sip_options(host, port)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.sip_timeout)
                s.sendto(pkt, (host, port))
                data, _ = s.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")

                for line in text.split("\r\n"):
                    if not line:
                        continue
                    # Status line
                    if line.startswith("SIP/"):
                        headers["_status_line"] = line
                        continue
                    if ":" in line:
                        key, _, val = line.partition(":")
                        headers[key.strip().lower()] = val.strip()
        except (OSError, socket.timeout, socket.error):
            pass
        return headers

    # ------------------------------------------------------------------
    # SNMP sysDescr
    # ------------------------------------------------------------------

    @staticmethod
    def _build_snmp_get(community: str) -> bytes:
        """Build SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""

        def _enc_len(n: int) -> bytes:
            if n < 0x80:
                return bytes([n])
            if n < 0x100:
                return bytes([0x81, n])
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

        def _enc_int(v: int) -> bytes:
            p = v.to_bytes((v.bit_length() + 8) // 8, "big", signed=True)
            return b"\x02" + _enc_len(len(p)) + p

        def _enc_str(v: str) -> bytes:
            e = v.encode("ascii")
            return b"\x04" + _enc_len(len(e)) + e

        oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        varbind = b"\x30" + _enc_len(len(oid) + 2) + oid + b"\x05\x00"
        vbl = b"\x30" + _enc_len(len(varbind)) + varbind
        rid = _enc_int(1)
        es = _enc_int(0)
        ei = _enc_int(0)
        pdu_body = rid + es + ei + vbl
        pdu = b"\xa0" + _enc_len(len(pdu_body)) + pdu_body
        ver = _enc_int(1)
        comm = _enc_str(community)
        msg_body = ver + comm + pdu
        return b"\x30" + _enc_len(len(msg_body)) + msg_body

    @staticmethod
    def _parse_snmp_sysdescr(data: bytes) -> str:
        """Extract sysDescr string from SNMP response."""
        idx = 0
        found_community = False
        while idx < len(data) - 2:
            if data[idx] == 0x04:
                # Read length
                off = idx + 1
                if off >= len(data):
                    break
                b = data[off]
                if b < 0x80:
                    length = b
                    start = off + 1
                elif b == 0x81 and off + 1 < len(data):
                    length = data[off + 1]
                    start = off + 2
                else:
                    idx += 1
                    continue

                if start + length <= len(data):
                    candidate = data[start: start + length].decode(
                        "utf-8", errors="replace",
                    )
                    if found_community and length > 4:
                        return candidate
                    found_community = True
                idx = start + length
            else:
                idx += 1
        return ""

    def _snmp_sysdescr(self, host: str) -> str:
        try:
            pkt = self._build_snmp_get(self.snmp_community)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.snmp_timeout)
                s.sendto(pkt, (host, 161))
                data, _ = s.recvfrom(4096)
                return self._parse_snmp_sysdescr(data)
        except (OSError, socket.timeout, socket.error):
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
    # Vendor classification
    # ------------------------------------------------------------------

    def _classify_vendor(self, fp: VoIPFingerprint) -> str:
        blob = " ".join([
            fp.sip_user_agent, fp.sip_server,
            fp.snmp_sysdescr, fp.http_server,
            fp.raw_headers.get("_body_snippet", ""),
        ]).lower()

        for vendor, keywords in _VENDOR_SIGNATURES.items():
            for kw in keywords:
                if kw in blob:
                    return vendor
        return "unknown"

    def _extract_model_firmware(self, fp: VoIPFingerprint) -> None:
        """Extract model and firmware from SIP/SNMP/HTTP data."""
        blob = " ".join([
            fp.sip_user_agent, fp.sip_server, fp.snmp_sysdescr,
            fp.http_server,
            fp.raw_headers.get("_body_snippet", ""),
        ])

        # Cisco SPA/CP patterns
        m = re.search(r"((?:SPA|CP)-?\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1)

        # Polycom VVX/SoundPoint
        m = re.search(r"((?:VVX|SoundPoint|SoundStation|Trio)\s*\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1).strip()

        # Yealink SIP-T
        m = re.search(r"(SIP-?T\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1)

        # Grandstream GXP/GRP/HT
        m = re.search(r"((?:GXP|GRP|GXV|HT)\d+\w*)", blob, re.I)
        if m:
            fp.model = m.group(1)

        # Avaya
        m = re.search(r"((?:J1|B1|96\d+)\w*)", blob, re.I)
        if m and fp.vendor == "avaya":
            fp.model = m.group(1)

        # Generic firmware version
        m = re.search(
            r"(?:firmware|version|fw|v)[:\s/]*([\d]+(?:\.[\d]+){1,4})",
            blob, re.I,
        )
        if m:
            fp.firmware = m.group(1)

    # ------------------------------------------------------------------
    # Full fingerprint pipeline
    # ------------------------------------------------------------------

    def _fingerprint_target(self, host: str) -> VoIPFingerprint:
        fp = VoIPFingerprint(target=host)

        # Port scan
        fp.open_ports = self._scan_ports(host)

        # SIP OPTIONS probe (always via UDP, not gated by TCP scan)
        sip_hdrs = self._sip_options_probe(host, self.sip_port)
        if sip_hdrs:
            fp.sip_user_agent = sip_hdrs.get("user-agent", "")
            fp.sip_server = sip_hdrs.get("server", "")
            fp.sip_allow = sip_hdrs.get("allow", "")
            fp.raw_headers["sip_status"] = sip_hdrs.get("_status_line", "")

        # SNMP
        fp.snmp_sysdescr = self._snmp_sysdescr(host)

        # HTTP
        http_probes: list[tuple[int, bool]] = [
            (80, False), (8080, False), (443, True), (8443, True),
        ]
        for port, ssl_flag in http_probes:
            if port not in fp.open_ports:
                continue
            hdrs = self._http_fingerprint(host, port, use_ssl=ssl_flag)
            if hdrs:
                fp.raw_headers.update(hdrs)
                fp.http_server = hdrs.get("server", fp.http_server) or fp.http_server
                if fp.http_server:
                    break

        # Classify
        fp.vendor = self._classify_vendor(fp)
        self._extract_model_firmware(fp)

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
        """Fingerprint VoIP targets via SIP/SNMP/HTTP and run exploit modules."""
        t0 = time.time()
        modules = self._get_modules()

        report = AutoPwnReport(
            segment=self.segment,
            targets=list(self.targets),
        )

        if self.verbose:
            print(f"\n[*] VoIP AutoPwn  -  {len(modules)} modules, "
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
                if fp.sip_user_agent:
                    print(f"    SIP UA: {fp.sip_user_agent}")
                if fp.sip_server:
                    print(f"    SIP Server: {fp.sip_server}")
                if fp.sip_allow:
                    print(f"    SIP Allow: {fp.sip_allow[:80]}")
                if fp.snmp_sysdescr:
                    print(f"    SNMP: {fp.snmp_sysdescr[:80]}")
                if fp.open_ports:
                    print(f"    Ports: {', '.join(str(p) for p in fp.open_ports)}")

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
