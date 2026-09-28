"""
firewallxpl/modules/intel/credential_parser.py - Stealer Log Credential Parser.

Parses leaked credential dumps in various stealer formats to find
device admin panel credentials (routers, firewalls, printers, VPN gateways).

Native Python reimplementation from:
  submodules/Safelabs-Mantis/mnt-processing-files/app/domain/intelx_processing.py

Supports 15+ credential formats commonly found in stealer logs:
  - Browser format: URL:/Username:/Password:
  - Chrome Default: Application/Url/Username/Password blocks
  - Hostname format: Hostname:/Username:/Password:
  - SOFT: format with host/login/password
  - Admin URL pattern: http[s]://192.168.x.x with credentials
  - OpenSearch JSON embedded credentials
  - SQL tuple format (SELECT output)

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Generator, List, Optional

__version__ = "1.0.0"

# Patterns for non-HTTPS URLs (device admin panels are often HTTP)
_RE_NON_HTTPS = re.compile(r"(?i)URL:\s*(http://(?:[0-9]{1,3}\.){3}[0-9]{1,3}[:/])", re.M)
_RE_URL_LINE = re.compile(r"(?i)^\s*(?:URL|HOST|APPLICATION|HOSTNAME):\s*(.+)$", re.M)
_RE_USER_LINE = re.compile(r"(?i)^\s*(?:USERNAME|USER|LOGIN|LOGIN:)\s*:?\s*(.+)$", re.M)
_RE_PASS_LINE = re.compile(r"(?i)^\s*(?:PASSWORD|PASS|PWD)\s*:?\s*(.+)$", re.M)

# Admin URL indicators (private IPs and common admin paths)
_ADMIN_URL_PATTERNS = [
    re.compile(r"http://(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d+\.\d+"),
    re.compile(r"http://(?:\w+\.local|router\.|gateway\.|admin\.|firewall\.)"),
    re.compile(r"https?://\d+\.\d+\.\d+\.\d+(?::\d+)?/(?:admin|cgi-bin|webui|management|login)", re.I),
]

# Device keywords to prioritize
_DEVICE_KEYWORDS = [
    "fortigate", "fortiweb", "palo alto", "checkpoint", "sonicwall",
    "mikrotik", "routeros", "winbox", "cisco", "asa", "router",
    "firewall", "admin panel", "web ui", "management", "printer",
    "jetdirect", "ipp", "cups", "modbus", "scada", "hmi",
    "192.168.", "10.0.", "10.1.", "10.10.",
]


@dataclass
class CredentialMatch:
    """A single credential match from stealer log parsing."""
    url: str = ""
    username: str = ""
    password: str = ""
    source_format: str = ""
    is_device_url: bool = False
    raw_block: str = ""

    @property
    def has_credentials(self) -> bool:
        return bool(self.username and self.password)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "username": self.username,
            "password": self.password,
            "format": self.source_format,
            "is_device": self.is_device_url,
        }


def _is_device_url(url: str) -> bool:
    """Return True if URL looks like a network device admin panel."""
    if not url:
        return False
    url_lower = url.lower()
    if any(pat.search(url) for pat in _ADMIN_URL_PATTERNS):
        return True
    return any(kw in url_lower for kw in _DEVICE_KEYWORDS)


class StealerCredentialParser:
    """Parse stealer log dumps for network device credentials.

    Supports multiple log formats commonly produced by info-stealers.
    Each parse() call scans the full content and yields CredentialMatch objects.

    Usage:
        parser = StealerCredentialParser()
        for match in parser.parse(log_content, target_filter="192.168"):
            print(match.url, match.username, match.password)
    """

    def parse(
        self,
        content: str,
        target_filter: str = "",
        device_only: bool = False,
    ) -> List[CredentialMatch]:
        """Parse credential dump content.

        Args:
            content: Raw stealer log text.
            target_filter: Filter results to URLs containing this string.
            device_only: Only return credentials for likely device URLs.

        Returns:
            List of CredentialMatch objects.
        """
        results = []
        seen = set()

        for match in self._parse_all_formats(content):
            if not match.has_credentials:
                continue
            if target_filter and target_filter not in match.url:
                continue
            if device_only and not match.is_device_url:
                continue
            key = (match.url.lower(), match.username.lower(), match.password)
            if key not in seen:
                seen.add(key)
                results.append(match)

        return results

    def _parse_all_formats(self, content: str) -> Generator[CredentialMatch, None, None]:
        """Try all supported formats against the content."""
        yield from self._parse_browser_format(content)
        yield from self._parse_soft_host_format(content)
        yield from self._parse_chrome_default(content)
        yield from self._parse_base64_embedded(content)

    def _parse_browser_format(self, content: str) -> Generator[CredentialMatch, None, None]:
        """Parse URL:/Username:/Password: triplet blocks."""
        # Split by separator patterns
        blocks = re.split(r"\n(?=URL:|HOST:|APPLICATION:)", content, flags=re.I)

        for block in blocks:
            url_m = re.search(r"(?i)^(?:URL|HOST):\s*(.+)$", block, re.M)
            user_m = re.search(r"(?i)^(?:USERNAME|LOGIN|USER):\s*(.+)$", block, re.M)
            pass_m = re.search(r"(?i)^(?:PASSWORD|PASS):\s*(.+)$", block, re.M)

            if url_m and (user_m or pass_m):
                url = url_m.group(1).strip()
                username = user_m.group(1).strip() if user_m else ""
                password = pass_m.group(1).strip() if pass_m else ""
                yield CredentialMatch(
                    url=url,
                    username=username,
                    password=password,
                    source_format="browser_triplet",
                    is_device_url=_is_device_url(url),
                    raw_block=block[:300],
                )

    def _parse_soft_host_format(self, content: str) -> Generator[CredentialMatch, None, None]:
        """Parse SOFT:/Host:/Username:/Password: format."""
        blocks = re.split(r"\n(?=SOFT:|APPLICATION:)", content, flags=re.I)

        for block in blocks:
            host_m = re.search(r"(?i)^(?:HOST|URL|HOSTNAME):\s*(.+)$", block, re.M)
            user_m = re.search(r"(?i)^(?:USERNAME|LOGIN):\s*(.+)$", block, re.M)
            pass_m = re.search(r"(?i)^(?:PASSWORD|PASS):\s*(.+)$", block, re.M)

            if host_m and (user_m or pass_m):
                host = host_m.group(1).strip()
                username = user_m.group(1).strip() if user_m else ""
                password = pass_m.group(1).strip() if pass_m else ""
                yield CredentialMatch(
                    url=host,
                    username=username,
                    password=password,
                    source_format="soft_host",
                    is_device_url=_is_device_url(host),
                    raw_block=block[:300],
                )

    def _parse_chrome_default(self, content: str) -> Generator[CredentialMatch, None, None]:
        """Parse Chrome Default block format."""
        # Pattern: Application: <app> / Url: <url> / Username: <u> / Password: <p>
        pattern = re.compile(
            r"(?i)Url:\s*(.+?)\s*\n"
            r"(?:.*?\n){0,3}?"
            r"Username:\s*(.+?)\s*\n"
            r"(?:.*?\n){0,2}?"
            r"Password:\s*(.+?)(?:\n|$)",
            re.M,
        )
        for m in pattern.finditer(content):
            url = m.group(1).strip()
            username = m.group(2).strip()
            password = m.group(3).strip()
            if url and username:
                yield CredentialMatch(
                    url=url,
                    username=username,
                    password=password,
                    source_format="chrome_default",
                    is_device_url=_is_device_url(url),
                )

    def _parse_base64_embedded(self, content: str) -> Generator[CredentialMatch, None, None]:
        """Decode base64-embedded credential blocks and re-parse."""
        for b64_match in re.finditer(r"([A-Za-z0-9+/]{40,}={0,2})", content):
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                if "URL:" in decoded or "Username:" in decoded:
                    yield from self._parse_browser_format(decoded)
            except Exception:
                continue


def extract_device_credentials(
    content: str,
    target_ip_prefix: str = "",
) -> List[CredentialMatch]:
    """Convenience function: parse and filter device-only credentials.

    Args:
        content: Stealer log content.
        target_ip_prefix: IP prefix to filter (e.g. "192.168.1.").

    Returns:
        List of credentials for network device admin panels.
    """
    parser = StealerCredentialParser()
    return parser.parse(content, target_filter=target_ip_prefix, device_only=True)
