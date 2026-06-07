"""
firewallxpl/modules/net/ssl_inspector.py - SSL/TLS Certificate Inspector.

Inspects SSL/TLS certificates on target hosts to detect:
  - Self-signed certificates (common on IoT/embedded devices)
  - Expired certificates
  - No-TLS (plain HTTP on HTTPS port)
  - Certificate details: issuer, subject, validity

Native port from:
  submodules/Safelabs-Mantis/phish-finder/phish_finder/utils/ssl_certificate_validator.py

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"


@dataclass
class SslProfile:
    """SSL/TLS profile of a target host."""
    host: str
    port: int
    has_tls: bool = False
    valid: bool = False
    self_signed: bool = False
    expired: bool = False
    expiry_days: int = 0
    issuer: str = ""
    subject: str = ""
    san: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    error: str = ""

    @property
    def risk_level(self) -> str:
        if not self.has_tls:
            return "CRITICAL"  # No TLS at all
        if self.expired:
            return "HIGH"
        if self.self_signed:
            return "MEDIUM"
        if 0 < self.expiry_days < 30:
            return "LOW"
        return "INFO"

    @property
    def findings(self) -> List[str]:
        issues = []
        if not self.has_tls:
            issues.append("No TLS/SSL - credentials transmitted in plaintext")
        if self.expired:
            issues.append(f"Certificate expired {abs(self.expiry_days)} days ago")
        if self.self_signed:
            issues.append("Self-signed certificate - MITM susceptible")
        if 0 < self.expiry_days < 30:
            issues.append(f"Certificate expires in {self.expiry_days} days")
        return issues


class DeviceSslInspector:
    """SSL/TLS inspector for network device admin panels.

    Usage:
        inspector = DeviceSslInspector()
        profile = inspector.inspect("192.168.1.1", port=443)
        print(profile.risk_level)
        for finding in profile.findings:
            print(f"[!] {finding}")
    """

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def inspect(self, host: str, port: int = 443) -> SslProfile:
        """Inspect SSL/TLS configuration of a host.

        Args:
            host: Target hostname or IP.
            port: HTTPS port to inspect (default 443).

        Returns:
            SslProfile with certificate details and risk assessment.
        """
        profile = SslProfile(host=host, port=port)

        # First check if port is open
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(self.timeout)
            test_sock.connect((host, port))
            test_sock.close()
        except Exception as exc:
            profile.error = f"Port {port} unreachable: {exc}"
            return profile

        # Attempt TLS handshake
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # accept self-signed for inspection

        try:
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host,
            ) as ssock:
                ssock.settimeout(self.timeout)
                ssock.connect((host, port))
                cert = ssock.getpeercert()
                profile.has_tls = True

                if cert:
                    profile.valid = True
                    profile = self._parse_cert(profile, cert)

        except ssl.SSLError as exc:
            if "NO_PROTOCOLS_AVAILABLE" in str(exc) or "WRONG_VERSION" in str(exc):
                # Port is open but no TLS
                profile.has_tls = False
                profile.error = f"No TLS: {exc}"
            else:
                # TLS error but connection worked - still TLS
                profile.has_tls = True
                profile.error = str(exc)

        except Exception as exc:
            profile.has_tls = False
            profile.error = str(exc)

        return profile

    def _parse_cert(self, profile: SslProfile, cert: Dict[str, Any]) -> SslProfile:
        """Extract certificate fields into SslProfile."""
        # Subject
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        profile.subject = subject_dict.get("commonName", "") or subject_dict.get("organizationName", "")

        # Issuer
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        profile.issuer = issuer_dict.get("commonName", "") or issuer_dict.get("organizationName", "")

        # Self-signed: issuer == subject
        profile.self_signed = profile.issuer == profile.subject

        # SANs
        san_list = []
        for ext_name, ext_data in cert.get("subjectAltName", []):
            san_list.append(ext_data)
        profile.san = san_list

        # Validity dates
        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        profile.not_after = not_after
        profile.not_before = not_before

        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                days = (expiry - now).days
                profile.expiry_days = days
                profile.expired = days < 0
            except ValueError:
                pass

        return profile

    def batch_inspect(
        self,
        targets: List[tuple],  # [(host, port), ...]
        delay_sec: float = 0.5,
    ) -> List[SslProfile]:
        """Inspect multiple targets with rate limiting.

        Args:
            targets: List of (host, port) tuples.
            delay_sec: Delay between inspections.

        Returns:
            List of SslProfile objects.
        """
        import time
        results = []
        for host, port in targets:
            results.append(self.inspect(host, port))
            if delay_sec > 0:
                time.sleep(delay_sec)
        return results
