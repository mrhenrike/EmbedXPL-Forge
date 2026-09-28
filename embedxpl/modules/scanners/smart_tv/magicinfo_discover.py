# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Samsung MagicINFO 9 Server Discovery Scanner.

Probes ports 7001, 7002, 80, and 443 for the MagicINFO management server
banner. Sends HTTP GET requests to /MagicInfo/ and /MagicInfoPremium/ and
extracts the server version from response headers and body content.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""
import re
from typing import Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_MAGICINFO_PATHS = ("/MagicInfo/", "/MagicInfoPremium/", "/MagicInfo/index.do")
_PROBE_PORTS = (7001, 7002, 80, 443)
_VERSION_PATTERNS = (
    re.compile(r"MagicInfo(?:Premium)?\s*(?:Server\s*)?v?(\d+[\d.]+)", re.IGNORECASE),
    re.compile(r"<title>[^<]*MagicInfo[^<]*v?(\d+[\d.]+)[^<]*</title>", re.IGNORECASE),
    re.compile(r'"version"\s*:\s*"(\d+[\d.]+)"'),
    re.compile(r'X-MagicInfo-Version:\s*(\S+)', re.IGNORECASE),
)


def _extract_version(text: str) -> Optional[str]:
    """Search text for a MagicINFO version string.

    Args:
        text: HTTP response body or headers as a string.

    Returns:
        Version string if found, None otherwise.
    """
    for pattern in _VERSION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(1)
    return None


def _is_magicinfo_response(body: str, headers: str) -> bool:
    """Determine whether the response originates from a MagicINFO server.

    Args:
        body: HTTP response body.
        headers: HTTP response headers as a string.

    Returns:
        True if MagicINFO indicators are present.
    """
    combined = (body + headers).lower()
    indicators = ("magicinfo", "samsung magicinfo", "magicinfopremium", "samsung cms")
    return any(ind in combined for ind in indicators)


class Exploit(HTTPClient):
    """Samsung MagicINFO 9 Server Discovery Scanner.

    Probes the four known MagicINFO service ports and attempts to fingerprint
    the server by requesting well-known management paths. Extracts the
    installed version from response content when available.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung MagicINFO 9 Server Discovery",
        "description": (
            "Discovers Samsung MagicINFO 9 CMS servers by probing ports 7001, 7002, "
            "80, and 443. Issues HTTP GET requests to /MagicInfo/ and /MagicInfoPremium/ "
            "and extracts the server version from response content."
        ),
        "authors": (
            "André Henrique (@mrhenrike) - EmbedXPL-Forge port",
        ),
        "references": (
            "https://www.samsung.com/global/business/display/magicinfo/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-4632",
        ),
        "devices": ("Samsung MagicINFO 9 Server",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(7001, "Primary MagicINFO HTTP port (7001, 7002, 80, or 443)")
    timeout = OptInteger(8, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the MagicINFO discovery scan across all known ports."""
        print_status(
            "Starting Samsung MagicINFO discovery on {}".format(self.target)
        )
        found_any = False

        for probe_port in _PROBE_PORTS:
            for path in _MAGICINFO_PATHS:
                result = self._probe(probe_port, path)
                if result:
                    found_any = True
                    version, banner_snippet = result
                    msg = "MagicINFO server at {}:{}{} — version: {}".format(
                        self.target, probe_port, path, version or "unknown"
                    )
                    print_success(msg)
                    if banner_snippet:
                        print_status("  Banner excerpt: {}".format(banner_snippet[:120]))
                    break

        if not found_any:
            print_error(
                "No Samsung MagicINFO service detected on {} (ports {})".format(
                    self.target, ", ".join(str(p) for p in _PROBE_PORTS)
                )
            )

    def _probe(self, probe_port: int, path: str) -> Optional[Tuple[Optional[str], str]]:
        """Send a single HTTP GET probe to the given port and path.

        Args:
            probe_port: TCP port to connect to.
            path: URL path to request.

        Returns:
            Tuple of (version_string_or_None, banner_excerpt) if MagicINFO
            indicators are detected, otherwise None.
        """
        original_port = self.port
        self.port = probe_port
        try:
            resp = self.http_request(
                "GET",
                path,
                headers={"User-Agent": "EmbedXPL-Forge/1.0"},
                timeout=int(self.timeout),
            )
        except Exception:
            self.port = original_port
            return None
        finally:
            self.port = original_port

        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        raw_headers = str(getattr(resp, "headers", ""))
        status = getattr(resp, "status_code", 0)

        if status in (404, 0) and not _is_magicinfo_response(body, raw_headers):
            return None

        if _is_magicinfo_response(body, raw_headers):
            version = _extract_version(body) or _extract_version(raw_headers)
            excerpt = body.replace("\n", " ").replace("\r", "")[:200]
            return (version, excerpt)

        return None

    @mute
    def check(self) -> bool:
        """Check whether any MagicINFO service is reachable on the target.

        Returns:
            True if at least one MagicINFO probe succeeds.
        """
        for probe_port in _PROBE_PORTS:
            if self._probe(probe_port, "/MagicInfo/") is not None:
                return True
        return False
