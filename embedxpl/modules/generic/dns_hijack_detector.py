# Author: André Henrique (LinkedIn/X: @mrhenrike)
import socket
import struct
import random

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import Exploit as BaseExploit


class Exploit(BaseExploit):
    """DNS Hijack Detector — APT28 Campaign Detection (Defensive).

    Queries APT28-targeted Outlook/O365 domains through the target router
    and compares results with a trusted resolver. Mismatches indicate
    DNS hijack compromise.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DNS Hijack Detector (APT28 Campaign)",
        "description": (
            "Defensive scanner that detects DNS hijacking on routers by "
            "querying APT28-targeted domains (Outlook, O365) through the "
            "target and comparing with a trusted resolver. Mismatches "
            "indicate compromise per NCSC advisory (April 2026)."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": (
            "https://www.tomshardware.com/tech-industry/cyber-security/ncsc-says-russian-gru-hackers-are-hijacking-tp-link-and-mikrotik-routers",
        ),
        "devices": ("Any router or gateway acting as DNS resolver",),
    }

    target = OptIP("", "Target router IP (used as DNS resolver)")
    port = OptPort(53, "DNS port")
    trusted_dns = OptString("8.8.8.8", "Trusted public DNS for comparison")

    _DOMAINS = [
        "autodiscover-s.outlook.com",
        "imap-mail.outlook.com",
        "outlook.live.com",
        "outlook.office.com",
        "outlook.office365.com",
        "login.microsoftonline.com",
        "smtp-mail.outlook.com",
    ]

    def _query(self, domain: str, server: str, dns_port: int = 53) -> list:
        tx = random.randint(0, 65535)
        hdr = struct.pack(">HHHHHH", tx, 0x0100, 1, 0, 0, 0)
        q = b""
        for label in domain.split("."):
            q += struct.pack("B", len(label)) + label.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(hdr + q, (server, dns_port))
            data, _ = s.recvfrom(1024)
            s.close()
        except Exception:
            return []

        ips = []
        if len(data) < 12:
            return ips
        an = struct.unpack(">H", data[6:8])[0]
        off = 12
        for _ in range(struct.unpack(">H", data[4:6])[0]):
            while off < len(data) and data[off] != 0:
                if data[off] & 0xC0 == 0xC0:
                    off += 2; break
                off += data[off] + 1
            else:
                off += 1
            off += 4
        for _ in range(an):
            if off >= len(data):
                break
            if data[off] & 0xC0 == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    off += data[off] + 1
                off += 1
            if off + 10 > len(data):
                break
            rt, _, _, rdl = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rt == 1 and rdl == 4 and off + 4 <= len(data):
                ips.append(".".join(str(b) for b in data[off:off + 4]))
            off += rdl
        return ips

    def run(self) -> None:
        print_status("DNS Hijack Scan: {} (target) vs {} (trusted)".format(
            self.target, self.trusted_dns))

        compromised = []
        for domain in self._DOMAINS:
            tgt = self._query(domain, str(self.target), int(self.port))
            ref = self._query(domain, str(self.trusted_dns))
            if not tgt:
                print_status("  {} — no response".format(domain))
                continue
            if set(tgt) == set(ref) or set(tgt) & set(ref):
                print_status("  {} — OK ({})".format(domain, ", ".join(tgt)))
            else:
                compromised.append((domain, tgt, ref))
                print_error("  {} — HIJACKED! {} (expected {})".format(domain, tgt, ref))

        if compromised:
            print_error("ALERT: {} domain(s) hijacked — matches APT28 TTP".format(len(compromised)))
        else:
            print_success("No DNS hijack detected on {} domains".format(len(self._DOMAINS)))

    @mute
    def check(self) -> bool:
        for d in self._DOMAINS[:2]:
            t = self._query(d, str(self.target), int(self.port))
            r = self._query(d, str(self.trusted_dns))
            if t and r and set(t) != set(r):
                return True
        return False
